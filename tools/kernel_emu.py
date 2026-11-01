#!/usr/bin/env python3
"""F286 Unicorn emulator: emulate the stock Mocor kernel's DSP boot sequence.

Maps the entire kernel binary + init data + hardware MMIO space.
Stubs ThreadX OS calls. Hooks all MMIO. Traces every instruction that
touches hardware. Models DSP responses.

Usage: python kernel_emu.py [--trace-all] [--start VA] [--verbose]
"""

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_R0
import struct, sys, argparse, os

# ---- Kernel layout ----
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import fwpaths  # noqa: E402
KERNEL_FILE = fwpaths.KERNEL
INIT_DATA = fwpaths.INIT_DATA   # decompressed init-data segment (see mocor_emu.preload_modules)
# NOTE: BASE below is the early, wrong load base (0x70 below the real one, see
# mocor_emu.KBASE). Kept as the first isolated DSP-boot tracer; mocor_emu.py and
# emu_call.py replace it.
BASE = 0x80a05dc8       # kernel.bin file_off 0x38 maps to this VA
INIT_BASE = 0x81700000   # init_data_dec.bin maps here

# ---- Emulation memory layout ----
KERN_LO    = 0x80a06000   # kernel payload start (aligned)
KERN_HI    = 0x81700000   # kernel end
KERN_SIZE  = KERN_HI - KERN_LO

INIT_LO    = 0x81700000
INIT_HI    = 0x81760000
INIT_SIZE  = INIT_HI - INIT_LO

STACK_BASE = 0xC0000000
STACK_SIZE = 0x00100000

SCRATCH_BASE = 0x81800000   # .bss / heap
SCRATCH_SIZE = 0x01000000

DSP_WIN    = 0x80400000
DSP_WIN_SZ = 0x600000

GSM_WIN    = 0x800E0000
GSM_WIN_SZ = 0x300000

MMIO_LO    = 0x40000000
MMIO_HI    = 0x50000000
MMIO_SIZE  = MMIO_HI - MMIO_LO

# ---- OS functions to stub (BL targets that touch ThreadX internals) ----
OS_STUBS = {
    # OS event/semaphore primitives
    0x811bef3c: 0,   # OS event alloc -> r0=0 (success)
    0x811befa2: 0,   # OS event wait -> r0=0
    0x811befa6: 0,   # OS event give -> r0=0 (void)
    0x811befde: 0,   # OS event give variant
    0x811bef7c: 0,   # OS event related
    0x811befa4: 0,   # OS event related
    # Mutex
    0x8109d572: 0,   # mutex take -> r0=0
    0x8109d660: 0,   # mutex put
    0x81099378: 0,   # assert/log
    # Sleep/timer
    0x8109c25a: 0,   # sleep/delay
    0x8124df74: 0,   # another delay
    # Logger functions
    0x8109e2e6: 0,   # log -> void
    0x81099300: 0,   # log variant
    0x80a0b00e: 0,   # log format -> void
    0x80a0b0e4: 0,   # log output -> void
    0x80a0b042: 0,   # log warning
    0x80a4577a: 0,   # another logger
    # Queue/ring (we model these)
    0x81182086: 0,   # unlock -> void
    0x8109d660: 0,   # unlock variant
    # Memory
    0x810a0870: 0,   # memcpy variant -> void
    0x80a077b6: 0,   # byte output (trace)
    # Misc calls from the boot fn
    0x8118203e: 0,   # queue put wrapper
    0x8118208e: 0,   # lock
}

# Hardware register model
hw = {}

# Trace log
trace_log = []
trace_enabled = False

def hw_read(uc, addr, size):
    """Model hardware reads"""
    addr &= ~3  # align
    # PMU
    if addr == 0x402B00C0: return hw.get(0x402B00C0, 0x00039CE0)
    if addr == 0x402B00C4: return hw.get(0x402B00C4, 0x00000000)
    if addr == 0x402B00D4: return hw.get(0x402B00D4, 0x00600066)
    if addr == 0x402B0034: return hw.get(0x402B0034, 0x01010402)
    if addr == 0x402B0044: return hw.get(0x402B0044, 0x00010105)
    if addr == 0x402B00CC: return hw.get(0x402B00CC, 0x00000080)
    if addr == 0x402B2034: return hw.get(0x402B2034, 0x01010402)  # CLR reads orig
    if addr == 0x402B2044: return hw.get(0x402B2044, 0x00010105)
    if addr == 0x402B20CC: return hw.get(0x402B20CC, 0x00000080)
    # AON
    if addr == 0x402E0248: return hw.get(0x402E0248, 0x18000000)
    if addr == 0x402E0130: return hw.get(0x402E0130, 0x00030000)
    if addr == 0x402E024C: return hw.get(0x402E024C, 0x00000001)
    if addr == 0x402E0250: return hw.get(0x402E0250, 0x04009000)
    if addr == 0x402E0254: return hw.get(0x402E0254, 0x00000001)
    if addr == 0x402E006C: return hw.get(0x402E006C, 0x80009620)
    if addr == 0x402E0140: return hw.get(0x402E0140, 0x44160000)
    if addr == 0x402E0144: return hw.get(0x402E0144, 0x0000001A)
    if addr == 0x402E00FC: return 0x98180001  # chip ID
    # Whale APB
    if 0x60830000 <= addr < 0x60840000:
        off = addr - 0x60830000
        return hw.get(addr, 0x00000000)  # gated -> reads 0
    # Die-local (these would hang on real HW; in emu return 0)
    if 0xD15D0000 <= addr < 0xD15F0000:
        return hw.get(addr, 0x00000000)
    if 0x515D0000 <= addr < 0x515F0000:
        return hw.get(addr, 0x00000000)
    # DSP windows
    # (handled by mapped memory)
    # Default
    return hw.get(addr, 0)

def mmio_read_hook(uc, access, address, size, value, user_data):
    """Hook for MMIO range reads"""
    addr = address & ~3
    val = hw_read(uc, addr, size)
    uc.mem_write(address, val.to_bytes(size, 'little'))
    if trace_enabled:
        trace_log.append(f"[R] {address:08x} = {val:08x}")
    return True  # continue

def mmio_write_hook(uc, access, address, size, value, user_data):
    """Hook for MMIO range writes"""
    addr = address & ~3
    hw[addr] = value
    ann = annotate(addr, value)
    line = f"[W] {address:08x} <- {value:08x}  {ann}"
    trace_log.append(line)
    if trace_enabled or ann:
        print(line)
    return True  # continue

def annotate(addr, val):
    annotations = {
        0x402B2034: "PMU_CLR LDSP_CFG (b25:24 power request)",
        0x402B2038: "PMU_CLR TGDSP_CFG",
        0x402B203C: "PMU_CLR HU3GE_A",
        0x402B2044: "PMU_CLR WTLCP_SYS (b25:24)",
        0x402B20CC: "PMU_CLR SLEEP_CTRL (b17,b21)",
        0x402E006C: f"AON_REG_PROT {'UNLOCK 0x9620' if val & 0xFFFF == 0x9620 else 'LOCK'}",
        0x402E0130: f"APB_RST2 {'LDSP HOLD' if val & 0x10000 else 'LDSP RELEASE'}"
                    f"{' TGDSP HOLD' if val & 0x20000 else ''}"
                    f"{' TGDSP RELEASE' if not val & 0x20000 else ''}",
        0x402E0248: f"LDSP_BOOT_VECTOR = {val:#x} (entry={val*2:#x})",
        0x402E024C: f"LDSP_BOOT {'START' if val & 1 else 'STOP'}",
        0x402E0250: f"TGDSP_BOOT_VECTOR = {val:#x}",
        0x402E0254: f"TGDSP_BOOT {'START' if val & 1 else 'STOP'}",
        0x402E1144: "AUTO_GATE_CTRL1 SET (wcdma force-en 0x1a)",
        0x402E0144: "AUTO_GATE_CTRL1 (0x1a = wcdma force)",
        0x60831034: f"WHALE APB gate 0x34 = {val:#x}",
        0x60831044: f"WHALE APB int/module 0x44 = {val:#x}",
        0x60831060: f"WHALE APB gate 0x60 = {val:#x}",
        0x402D02B4: f"DSP CLK MUX = {val & 3} ({['26M','38.4M','51.2M','?'][val & 3]})",
    }
    for base, name in [(0xD15E0000, "DIE-LOCAL 0xD15E"),
                       (0xD15D0000, "DIE-LOCAL 0xD15D"),
                       (0x515E0000, "DIE-LOCAL 0x515E"),
                       (0x515D0000, "DIE-LOCAL 0x515D")]:
        if base <= addr < base + 0x10000:
            return f"*** DIE-LOCAL {name}+{addr-base:#x} = {val:#x} (would hang on HW) ***"
    return annotations.get(addr, "")

def hook_mem_access(uc, access, address, size, value, user_data):
    """Catch unmapped accesses"""
    if access == UC_MEM_WRITE_UNMAPPED:
        print(f"[!] UNMAPPED WRITE at {address:#x} size={size} val={value:#x}")
        # Map it on the fly
        page = address & ~0xFFF
        try:
            uc.mem_map(page, 0x1000, UC_PROT_ALL)
            return True
        except:
            return False
    elif access == UC_MEM_READ_UNMAPPED:
        page = address & ~0xFFF
        try:
            uc.mem_map(page, 0x1000, UC_PROT_ALL)
            return True
        except:
            return False
    elif access == UC_HOOK_MEM_FETCH_UNMAPPED:
        print(f"[!] UNMAPPED FETCH at {address:#x} - PC ran off into the weeds")
        return False  # stop
    return True

def hook_blk_mem(uc, access, address, size, value, user_data):
    pass

def hook_intr(uc, intno, user_data):
    pass  # ignore interrupts

# ---- OS function stubbing ----
# These are BL targets that touch ThreadX internals.
# We return from them immediately with appropriate r0 values.
os_stub_count = 0

def hook_code_skip_os(uc, address, size, user_data):
    """Check if the current instruction is a BL to an OS function.
    If so, skip it by setting PC=LR and r0=stub value."""
    global os_stub_count
    # Read the instruction
    code = uc.mem_read(address, 4)
    if len(code) < 2:
        return
    hw = struct.unpack('<H', code[:2])[0]
    # Check for BL (Thumb): 1111 0xxx xxxxxxxx + 11x1 xxxxxxxx
    if (hw & 0xF800) == 0xF000 or (hw & 0xF800) == 0xF800:
        # This is a 32-bit Thumb instruction, could be BL
        if len(code) < 4:
            code2 = uc.mem_read(address + 2, 2)
            hw2 = struct.unpack('<H', code2[:2])[0]
        else:
            hw2 = struct.unpack('<H', code[2:4])[0]
        if (hw2 & 0xD000) == 0xD000:  # BL suffix
            # Compute target
            s = (hw >> 10) & 1
            imm10 = hw & 0x3FF
            j1 = (hw2 >> 13) & 1
            j2 = (hw2 >> 11) & 1
            imm11 = hw2 & 0x7FF
            i1 = ~(j1 ^ s) & 1
            i2 = ~(j2 ^ s) & 1
            imm25 = (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
            if s:
                imm25 |= 0xFE000000
            target = (address + 4 + imm25) & 0xFFFFFFFF
            # Check if target is an OS stub
            if target in OS_STUBS:
                # Skip: set PC to LR, set r0 to stub value
                lr = uc.reg_read(UC_ARM_REG_LR)
                r0_val = OS_STUBS[target]
                uc.reg_write(UC_ARM_REG_R0, r0_val)
                uc.reg_write(UC_ARM_REG_PC, lr | 1)  # return in Thumb
                os_stub_count += 1

def main():
    global trace_enabled
    
    parser = argparse.ArgumentParser(description='F286 Unicorn DSP boot emulator')
    parser.add_argument('--trace-all', action='store_true', help='trace every instruction')
    parser.add_argument('--start', type=lambda x: int(x, 0), default=0x80e2d9ae,
                        help='start address (default: LTE DSP boot fn)')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--max-insns', type=int, default=100000)
    args = parser.parse_args()
    
    trace_enabled = args.verbose
    
    # Read kernel binary
    data = open(fwpaths.need(KERNEL_FILE, 'kernel partition'), 'rb').read()
    init_data = open(fwpaths.need(INIT_DATA, 'decompressed init data'), 'rb').read()
    
    # Init Unicorn: ARM Cortex-A7, Thumb
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB + UC_MODE_MCLASS)
    
    # Map memory regions
    def map_aligned(base, size, perms=UC_PROT_ALL):
        page = base & ~0xFFF
        end = (base + size + 0xFFF) & ~0xFFF
        sz = end - page
        mu.mem_map(page, sz, perms)
        return page, sz
    
    # Kernel text+data
    kern_lo = 0x80a06000 & ~0xFFF
    kern_sz = 0x81700000 - kern_lo
    map_aligned(kern_lo, kern_sz)
    # Write kernel payload into the mapping
    kern_off_in_file = kern_lo - BASE
    kern_payload = data[kern_off_in_file:kern_off_in_file + kern_sz]
    mu.mem_write(kern_lo, kern_payload)
    
    # Init data
    map_aligned(INIT_LO, INIT_SIZE)
    mu.mem_write(INIT_LO, init_data)
    
    # Stack
    map_aligned(STACK_BASE, STACK_SIZE)
    
    # Scratch (bss/heap)
    map_aligned(SCRATCH_BASE, SCRATCH_SIZE)
    
    # DSP windows
    map_aligned(DSP_WIN, DSP_WIN_SZ)
    map_aligned(GSM_WIN, GSM_WIN_SZ)
    
    # MMIO space
    map_aligned(MMIO_LO, MMIO_SIZE)
    
    # Fill .bss region with 0 ( Unicorn maps as zero already )
    
    # ---- Hooks ----
    # MMIO read: provide hardware values
    mu.hook_add(UC_HOOK_MEM_READ, mmio_read_hook,
                begin=MMIO_LO, end=MMIO_HI)
    # MMIO write: log + model
    mu.hook_add(UC_HOOK_MEM_WRITE, mmio_write_hook,
                begin=MMIO_LO, end=MMIO_HI)
    # Unmapped access handler
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_access)
    # OS function skipping via code hook
    mu.hook_add(UC_HOOK_CODE, hook_code_skip_os)
    
    # ---- Set up execution context ----
    sp = STACK_BASE + STACK_SIZE - 0x1000
    mu.reg_write(UC_ARM_REG_SP, sp)
    
    # Set up the "card" struct pointer that the boot fn expects
    # The boot fn accesses [r4] etc. - these point to the DSP control block
    # For now, allocate a scratch area
    card_ptr = SCRATCH_BASE + 0x1000
    mu.mem_write(card_ptr, b'\x00' * 0x100)
    
    # Boot function entry
    start = args.start
    
    print(f"[*] F286 Unicorn DSP Boot Emulator")
    print(f"[*] Kernel mapped: {kern_lo:#x} - {kern_lo + kern_sz:#x}")
    print(f"[*] Init data: {INIT_LO:#x} - {INIT_LO + INIT_SIZE:#x}")
    print(f"[*] Stack: {STACK_BASE:#x} + {STACK_SIZE:#x}")
    print(f"[*] Entry: {start:#x} (Thumb)")
    print(f"[*] OS stubs registered: {len(OS_STUBS)}")
    print("=" * 72)
    print()
    
    # Run
    try:
        mu.emu_start(start | 1, 0, count=args.max_insns, timeout=30 * 1000000)
    except UcError as e:
        pc = mu.reg_read(UC_ARM_REG_PC)
        print(f"\n[!] Emulation stopped: {e}")
        print(f"    PC = {pc:#x}")
        if pc:
            # Try to read the instruction at PC
            try:
                code = mu.mem_read(pc, 4)
                print(f"    Instruction: {code.hex()}")
            except:
                pass
    except Exception as e:
        print(f"\n[!] {e}")
    
    print(f"\n[*] Instructions executed: {mu.emu_count()}")
    print(f"[*] OS stub calls: {os_stub_count}")
    print(f"[*] MMIO writes logged: {len(trace_log)}")
    
    print(f"\n[*] Final hardware state:")
    for k in sorted(hw.keys()):
        print(f"    {k:08x} = {hw[k]:08x}")
    
    # Save trace
    if trace_log:
        with open(os.path.join(os.path.dirname(__file__), 'trace.log'), 'w') as f:
            f.write('\n'.join(trace_log))
        print(f"\n[*] Trace saved: {len(trace_log)} entries -> trace.log")

if __name__ == '__main__':
    main()
