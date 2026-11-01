"""fplinux_emu.py - run the FPLinux kernel (ramboot.bin) for the Ruio F286 in Unicorn.

Skips FPLinux stage 0 and enter the zImage the way
stage 0 does (ums9117_bootstrap_handoff_to_linux): zImage at FPLINUX_BOOT_LAYOUT_ZIMAGE_PHYS, DTB at
DTB_PHYS, r0 = 0, r1 = ~0 (DT boot), r2 = DTB, ARM state, SVC, MMU/caches off. Every MMIO access is
logged once per address (reads return 0 unless modelled). Progress is shown by scanning RAM for the
kernel's own log text, since the real console is the framebuffer (console=tty0).

  python fplinux_emu.py [--image PATH] [--insns 300000000] [--out runs/fplinux_<time>]
"""
import argparse, collections, json, os, re, struct, time
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import (ARM_OP_MEM, ARM_OP_REG, ARM_REG_R0, ARM_REG_R12, ARM_REG_SP, ARM_REG_LR, ARM_REG_PC,
                         ARM_SFT_LSL)
from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                     UC_HOOK_MEM_UNMAPPED, UC_HOOK_INTR, UC_HOOK_CODE, UC_MEM_WRITE, UC_ERR_INSN_INVALID,
                     UC_CTL_TLB_FLUSH, UC_CTL_IO_WRITE)
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_A7, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_PC, UC_ARM_REG_CPSR,
                                UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_SPSR, UC_ARM_REG_CP_REG,
                                UC_ARM_REG_FPEXC, UC_ARM_REG_C1_C0_2)

HERE = os.path.dirname(os.path.abspath(__file__))
import sys
sys.path.insert(0, HERE)
import fwpaths                                   # noqa: E402
IMAGE = fwpaths.FPLINUX_IMAGE                    # your own FPLinux build (ramboot.bin)

# Ruio 48 MB layout (FPLinux ums9117 platform bootstrap layout)
RAM_BASE, RAM_SIZE = 0x80000000, 0x03000000
ZIMAGE_PHYS = 0x81000000
DTB_PHYS = 0x82E00000
ZIMAGE_MAGIC = 0x016F2818

# MMIO windows mapped as plain memory with logging hooks (base, size, name); grown as the kernel asks.
MMIO = [
    (0x12000000, 0x10000, "GIC"),
    (0x20000000, 0x01000000, "AP_AHB"),
    (0x21000000, 0x01000000, "AP_AHB2"),
    (0x33000000, 0x00010000, "HWSPINLOCK"),
    (0x40000000, 0x00800000, "AON_APB"),
    (0x60000000, 0x01000000, "LCM_WHALE_APB"),             # LCM ports 0x60000000, whale APB 0x60830000
    (0x70000000, 0x02000000, "AP_APB"),
]
HW_INIT = os.path.join(HERE, "fplinux_hw_init.json")
HW_BASELINE = os.path.join(HERE, "fplinux_hw_baseline.json")
IRQ_SLICE = 500                        # insns per run slice while an IRQ is pending
NS_PER_INSN = 10                       # emulated time: 100 MIPS
TIMER_BASE, TIMER_HZ, TIMER_IRQ = 0x40050000, 32768, 32 + 28   # DT: sprd,pike2-timer, SPI 28
SYSCNT_BASE = 0x40230000               # FPLinux ums9117-timer.c: +0x0c = 1 kHz up-counter
GICD, GICC = 0x12001000, 0x12002000
ADI_BASE = 0x40600000                  # ADI controller; PMIC registers at +0x8000
KERNEL_PA = 0x80800000             # PA of PAGE_OFFSET (0xc0000000)
# Unisoc register blocks with SET (+0x1000) / CLEAR (+0x2000) aliases of the base registers (the
# FPLinux clock code sets a gate via the alias and reads the base back).
SETCLR_BANKS = (0x402E0000, 0x402B0000, 0x20E00000, 0x71300000)
# printk ring text (formatted, so these never match the format strings in the kernel image)
LOG_MARKERS = (b"Booting Linux on physical CPU 0x0", b"Linux version 6.", b"Linux version 5.", b"Machine model:",
               b"Kernel command line: console", b"Kernel panic - not syncing: ", b"Run /init as init process",
               b"Freeing unused kernel memory:", b"Unable to handle kernel NULL", b"Internal error: Oops")


def split_ramboot(data):
    """-> (zImage bytes, dtb bytes) located by their own headers inside ramboot.bin"""
    for o in range(0, len(data) - 0x30, 4):
        if struct.unpack_from("<I", data, o + 0x24)[0] == ZIMAGE_MAGIC:
            start, end = struct.unpack_from("<II", data, o + 0x28)
            zimg = data[o:o + (end - start)]
            break
    else:
        raise SystemExit("no zImage in the image")
    i = data.find(b"\xd0\x0d\xfe\xed", o + len(zimg))
    if i < 0:
        raise SystemExit("no DTB after the zImage")
    dtb = data[i:i + struct.unpack_from(">I", data, i + 4)[0]]
    return zimg, dtb


def kva_to_pa(va):
    """Kernel lowmem: PAGE_OFFSET 0xc0000000 = PA 0x80800000 (boot log: memory starts at 0x80800000)."""
    return va - 0xC0000000 + KERNEL_PA if va >= 0xC0000000 else va


def extract_klog(ram):
    """printk ring text records: each starts with a 4-byte block id ending in f0 ff 3f ('?') on this
    build. Returns the messages in order (best effort, read straight from RAM)."""
    m = re.search(rb"Booting Linux on physical CPU 0x[0-9a-f]", ram)   # formatted, not the "%x" template
    if not m:
        return []
    i = m.start()
    if ram[i - 15:i - 14] == b"[" and ram[i - 2:i] == b"] ":
        # plain-text log with "[    0.000000] " timestamps (current FPLinux build): read up to the NULs
        text = ram[i - 15:i - 15 + 0x40000].decode("latin-1")
        return re.findall(r"\[\s*\d+\.\d{6}\] [ -~]*", text)
    blk = ram[i - 8:i - 8 + 0x20000]
    out = []
    for r in re.split(rb"[\s\S]{1,2}\xf0\xff\?", blk):
        t = r.split(b"\n")[0].rstrip(b"\x00")
        if t and not t.startswith(b"\x00"):
            out.append(t.decode(errors="replace"))
    return out


def fix_initrd(dtb):
    """Stage 0 fills /chosen linux,initrd-{start,end} (placeholders 0xe5e5e5e5 / 0xf6f6f6f6) with the
    device-data blob; without one, make the range empty so the kernel ignores it."""
    b = bytearray(dtb)
    for ph in (b"\xe5\xe5\xe5\xe5", b"\xf6\xf6\xf6\xf6"):
        i = b.find(ph)
        if i >= 0:
            b[i:i + 4] = struct.pack(">I", DTB_PHYS)
    return bytes(b)


# Cosmetic bootargs that can give up their bytes to --params (the DTB is patched in place, same length)
SPARE_BOOTARGS = ("vt.global_cursor_default=1", "trace_buf_size=256K")


def set_bootargs(dtb, extra):
    """Append kernel parameters (e.g. 'f286_radio.autoint=1') to /chosen bootargs in place: the spare
    cosmetic options are dropped to make room and the rest is padded with spaces, so the DTB layout
    (property length) is unchanged."""
    if not extra:
        return dtb
    b = bytearray(dtb)
    i = b.find(b"console=tty0")
    end = b.index(b"\x00", i)
    old = b[i:end].decode()
    if extra.startswith("="):
        new = extra[1:]                     # "=<full command line>": replace it entirely
    else:
        words = [w for w in old.split() if w not in SPARE_BOOTARGS] + extra.split()
        new = " ".join(words)
    return dtb_resize_prop(bytes(b), i, end + 1, new.encode() + b"\x00")


def dtb_resize_prop(dtb, vstart, vend, value):
    """Replace a property value (bytes vstart..vend, NUL included) with `value`, growing or shrinking the
    FDT struct block: the FDT_PROP length word sits 8 bytes before the value, values are padded to 4,
    and the header's totalsize / size_dt_struct / off_dt_strings follow the size change."""
    b = bytearray(dtb)
    assert struct.unpack_from(">I", b, vstart - 12)[0] == 3, "not an FDT_PROP value"
    old_len = struct.unpack_from(">I", b, vstart - 8)[0]
    assert vstart + old_len == vend
    old_padded = (old_len + 3) & ~3
    new_padded = (len(value) + 3) & ~3
    delta = new_padded - old_padded
    b[vstart:vstart + old_padded] = value + bytes(new_padded - len(value))
    struct.pack_into(">I", b, vstart - 8, len(value))
    totalsize, off_struct, off_strings, off_rsv, version, lcv, boot_cpu, size_strings, size_struct = \
        struct.unpack_from(">9I", b, 4)
    assert off_struct < vstart < off_strings
    struct.pack_into(">I", b, 4, totalsize + delta)
    struct.pack_into(">I", b, 12, off_strings + delta)
    struct.pack_into(">I", b, 36, size_struct + delta)
    return bytes(b)


class Emu:
    def __init__(self, image, out, params=""):
        self.out = out
        os.makedirs(out, exist_ok=True)
        self.log_f = open(os.path.join(out, "run.log"), "w")
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        # The UMS9117 core is a Cortex-A7 (Unicorn's default model is a Cortex-A15, MIDR 412fc0f1).
        self.mu.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A7)
        # Unicorn starts the core Non-secure with NSACR = 0, which makes every Non-secure CPACR write
        # drop the CP10/CP11 bits (VFP stayed disabled and every VFP insn trapped). On the phone the
        # secure boot firmware grants Non-secure CP10/CP11 access before Linux; do the same here.
        self.cp15(1, 2, 0x00000C00, crm=1)                    # NSACR (c1, c1, 2): cp10, cp11
        self.mu.mem_map(RAM_BASE, RAM_SIZE)
        for base, size, _ in MMIO:
            self.mu.mem_map(base, size)
        self.seen = collections.OrderedDict()
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.on_mmio, begin=0x10000000, end=0x7FFFFFFF)
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.on_unmapped)
        self.mu.hook_add(UC_HOOK_INTR, self.on_intr)
        self.intr_counts = collections.Counter()
        self.abort_seen = {}
        self.syscalls = collections.Counter()
        self.irq_hook = None
        self.adi_rd = 0
        self.pending_exc = None
        self.trace_left, self.traced, self.trace_f = 0, False, None
        self.md_a, self.md_t = Cs(CS_ARCH_ARM, CS_MODE_ARM), Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.md_a.detail = self.md_t.detail = True
        # real register values read from the phone over the USB debug link (stock boot), e.g. the MPLL/CA7 clock
        # registers the inherited-clocks driver decodes (1 GHz) and the ADI controller mode
        # then the values FPLinux itself read on the phone (fplinux_hw_baseline.json, make_fplinux_baseline.py),
        # which win where both exist: they are the state the radio driver really starts from
        for path in (HW_INIT, HW_BASELINE):
            hw = json.load(open(path)) if os.path.exists(path) else {}
            for a, v in hw.items():
                self.mu.mem_write(int(a, 16), struct.pack("<I", int(v, 16)))
            self.log(f"{len(hw)} registers seeded from {os.path.basename(path)}")
        zimg, dtb = split_ramboot(open(image, "rb").read())
        self.mu.mem_write(ZIMAGE_PHYS, zimg)
        self.mu.mem_write(DTB_PHYS, set_bootargs(fix_initrd(dtb), params))
        if params:
            self.log(f"bootargs += {params}")
        self.log(f"zImage {len(zimg):#x} bytes -> {ZIMAGE_PHYS:#x}, DTB {len(dtb):#x} -> {DTB_PHYS:#x}")
        self.mu.reg_write(UC_ARM_REG_R0, 0)
        self.mu.reg_write(UC_ARM_REG_R1, 0xFFFFFFFF)
        self.mu.reg_write(UC_ARM_REG_R2, DTB_PHYS)
        self.mu.reg_write(UC_ARM_REG_CPSR, 0x1D3)        # SVC, IRQ/FIQ masked, ARM
        self.found = set()
        self.insns = 0
        self.t_load = self.t_ctl = self.t_int_en = self.t_raw = 0
        self.t_deadline = 0
        self.gicd_ctl = self.gicc_ctl = 0
        self.gic_enabled, self.gic_pending, self.gic_active = set(), set(), set()
        self.irqs = 0
        self.undefs = {}
        self.undef_repeat, self.last_undef, self.last_undef_insns = 0, None, 0

    def log(self, msg):
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        print(line, flush=True)
        self.log_f.write(line + "\n")
        self.log_f.flush()

    # ---- time: emulated from the instruction count (NS_PER_INSN), advanced between run chunks ----
    def now_ns(self):
        return self.insns * NS_PER_INSN

    # ---- sprd timer (upstream drivers/clocksource/timer-sprd.c, 32768 Hz) + syscounter (1 kHz) ----
    def timer_value(self):
        if not self.t_ctl & 2:
            return self.t_load
        left = self.t_deadline - self.now_ns()
        return max(0, left * TIMER_HZ // 1_000_000_000)

    def timer_write(self, off, value):
        if off == 0x00:
            self.t_load = (self.t_load & ~0xFFFFFFFF) | value
        elif off == 0x10:
            was = self.t_ctl & 2
            self.t_ctl = value
            if value & 2 and not was:
                self.t_deadline = self.now_ns() + max(1, self.t_load) * 1_000_000_000 // TIMER_HZ
        elif off == 0x14:
            self.t_int_en = value & 1
            if value & 8:
                self.t_raw = 0
                self.gic_pending.discard(TIMER_IRQ)

    def timer_tick(self):
        if self.t_ctl & 2 and self.now_ns() >= self.t_deadline:
            self.t_raw = 1
            if self.t_int_en:
                self.gic_pending.add(TIMER_IRQ)
            if self.t_ctl & 1:                                   # periodic: reload
                self.t_deadline += max(1, self.t_load) * 1_000_000_000 // TIMER_HZ
            else:
                self.t_ctl &= ~2

    # ---- GIC-400: distributor enables + CPU interface IAR/EOIR; IRQ entry done by take_irq ----
    def gic_write(self, addr, value):
        if addr == GICD + 0x000:
            self.gicd_ctl = value & 1
        elif GICD + 0x100 <= addr < GICD + 0x120:
            n = (addr - GICD - 0x100) * 8
            self.gic_enabled |= {n + b for b in range(32) if value >> b & 1}
        elif GICD + 0x180 <= addr < GICD + 0x1A0:
            n = (addr - GICD - 0x180) * 8
            self.gic_enabled -= {n + b for b in range(32) if value >> b & 1}
        elif addr == GICC + 0x000:
            self.gicc_ctl = value & 1
        elif addr == GICC + 0x010:                              # EOIR
            self.gic_active.discard(value & 0x3FF)

    def gic_iar(self):
        ready = sorted(i for i in self.gic_pending if i in self.gic_enabled and i not in self.gic_active)
        if not ready:
            return 1023
        irq = ready[0]
        self.gic_pending.discard(irq)
        self.gic_active.add(irq)
        return irq

    # ---- ADI controller (PMIC bus, 0x40600000; FPLinux f286-radio.c / spi-sprd-adi.c protocol). The PMIC
    # registers themselves are plain memory in the 0x40608000+ window: writes land there directly. ----
    def adi_access(self, uc, access, off, value):
        if off == 0x224 and access != UC_MEM_WRITE:          # user lock: free (driver polls for 0)
            uc.mem_write(ADI_BASE + 0x224, b"\0\0\0\0")
        elif off == 0x28 and access == UC_MEM_WRITE:         # RD_CMD: register offset in the window
            self.adi_rd = value & 0xFFFF
        elif off == 0x2C and access != UC_MEM_WRITE:         # RD_DATA: bit31 busy (never), addr | data
            v = struct.unpack("<H", uc.mem_read(ADI_BASE + (self.adi_rd & 0xFFFE), 2))[0]
            uc.mem_write(ADI_BASE + 0x2C, struct.pack("<I", (self.adi_rd & 0x7FFF) << 16 | v))
        elif off == 0x30 and access != UC_MEM_WRITE:         # ARM FIFO status: empty (bit10), not full
            uc.mem_write(ADI_BASE + 0x30, struct.pack("<I", 0x400))

    def on_irq_window(self, uc, addr, size, _):
        """Active only while an IRQ is pending: stop at the first instruction boundary with CPSR.I clear,
        where the CPU would take it (e.g. local_irq_enable after the idle loop's wfi)."""
        if not uc.reg_read(UC_ARM_REG_CPSR) & 0x80:
            uc.emu_stop()

    def irq_deliverable(self):
        return bool(self.gicd_ctl and self.gicc_ctl and
                    any(i in self.gic_enabled and i not in self.gic_active for i in self.gic_pending))

    def take_irq(self):
        """IRQ exception entry (high vectors, Thumb: SCTLR V and TE set, cr=50c53c7d in the boot log).
        CPSR first (banks SPSR/LR), then SPSR, LR = return + 4, PC = vector (unicorn #825 pattern)."""
        if not (self.gicd_ctl and self.gicc_ctl):
            return False
        if not any(i in self.gic_enabled and i not in self.gic_active for i in self.gic_pending):
            return False
        cpsr = self.mu.reg_read(UC_ARM_REG_CPSR)
        if cpsr & 0x80:
            return False
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        self.enter(0x12, 0x18, pc + 4)
        self.irqs += 1
        if self.irqs <= 3 or self.irqs % 1000 == 0:
            self.log(f"IRQ #{self.irqs} taken at pc={pc:#x} (pending {sorted(self.gic_pending)})")
        return True

    # ---- CPU exceptions Unicorn raises instead of delivering (QEMU EXCP_*: 2 SWI, 3 prefetch abort,
    # 4 data abort). Without delivery the same exception re-raises forever. Entry is done here like the
    # IRQ/UND paths, and the run loop restarts at the vector (emu_stop). ----
    def cp15(self, crn, opc2, value=None, crm=0, opc1=0):
        if value is None:
            return self.mu.reg_read(UC_ARM_REG_CP_REG, (15, 0, 0, crn, crm, opc1, opc2))
        self.mu.reg_write(UC_ARM_REG_CP_REG, (15, 0, 0, crn, crm, opc1, opc2, value & 0xFFFFFFFF))

    def walk(self, va, write=False, user=False):
        """Short-descriptor walk via TTBR0 (Linux classic MMU, TTBCR.N = 0, v6/v7 format) for one access.
        -> fault status: 0 = allowed, 5 section / 7 page translation, 0xd section / 0xf page permission.
        A push across a page boundary can fault on the second page only, so permissions must be checked,
        not just presence."""
        ttbr = self.cp15(2, 0) & ~0x3FFF
        try:
            l1 = struct.unpack("<I", self.mu.mem_read(ttbr + (va >> 20) * 4, 4))[0]
            if l1 & 3 == 0:
                return 0x5
            if l1 & 3 == 2:
                ap, apx, perm_fs = (l1 >> 10) & 3, (l1 >> 15) & 1, 0xD
                domain = (l1 >> 5) & 0xF
            else:
                l2 = struct.unpack("<I", self.mu.mem_read((l1 & ~0x3FF) + ((va >> 12) & 0xFF) * 4, 4))[0]
                if l2 & 3 == 0:
                    return 0x7
                ap, apx, perm_fs = (l2 >> 4) & 3, (l2 >> 9) & 1, 0xF
                domain = (l1 >> 5) & 0xF
        except UcError:
            return 0x5
        if (self.cp15(3, 0) >> (2 * domain)) & 3 == 3:          # manager domain: no permission check
            return 0
        ok_read = ap >= (2 if user else 1)
        ok_write = ok_read and not apx and (ap == 3 if user else ap >= 1)
        return 0 if (ok_write if write else ok_read) else perm_fs

    def fault_address(self, pc, thumb):
        """Data address(es) of the faulting load/store (capstone decode + current registers) and whether
        it writes. A multi-word access returns both ends so the one actually faulting can be picked."""
        md = self.md_t if thumb else self.md_a
        code = bytes(self.mu.mem_read(self.va_to_pa(pc), 4))
        insn = next(md.disasm(code, pc), None)
        if insn is None:
            return [], False
        write = insn.mnemonic.startswith(("st", "push", "vst", "swp", "strex"))
        regs = {r: self.mu.reg_read(UC_ARM_REG_R0 + r - ARM_REG_R0) for r in range(ARM_REG_R0, ARM_REG_R12 + 1)}
        regs[ARM_REG_SP] = self.mu.reg_read(UC_ARM_REG_SP)
        regs[ARM_REG_LR] = self.mu.reg_read(UC_ARM_REG_LR)
        regs[ARM_REG_PC] = pc + (4 if thumb else 8)
        mems = [op for op in insn.operands if op.type == ARM_OP_MEM]
        if mems:
            m = mems[0].mem
            base = regs.get(m.base, 0)
            if insn.post_index:
                ea = base
            else:
                ea = base + m.disp
                if m.index:
                    idx = regs.get(m.index, 0)
                    sh = mems[0].shift
                    if sh.type == ARM_SFT_LSL:
                        idx <<= sh.value
                    ea += -idx if mems[0].subtracted else idx
            ea &= 0xFFFFFFFF
            return [ea, (ea + 7) & 0xFFFFFFFF], write
        # ldm/stm/push/pop: first operand is the base register (implicit sp for push/pop)
        n = len([op for op in insn.operands if op.type == ARM_OP_REG])
        if insn.mnemonic.startswith(("push", "pop")):
            sp = regs[ARM_REG_SP]
            return ([sp - 4 * n, sp - 4] if insn.mnemonic.startswith("push") else [sp, sp + 4 * n - 4]), write
        base = regs.get(insn.operands[0].reg, 0)
        if "db" in insn.mnemonic:
            return [base - 4 * (n - 1), base - 4], write
        return [base, base + 4 * (n - 1)], write

    def va_to_pa(self, va):
        """Translate through the guest page tables (for reading code at a fault)."""
        if va >= 0xC0000000:
            return kva_to_pa(va)
        ttbr = self.cp15(2, 0) & ~0x3FFF
        l1 = struct.unpack("<I", self.mu.mem_read(ttbr + (va >> 20) * 4, 4))[0]
        if l1 & 3 == 2:
            return (l1 & 0xFFF00000) | (va & 0xFFFFF)
        l2 = struct.unpack("<I", self.mu.mem_read((l1 & ~0x3FF) + ((va >> 12) & 0xFF) * 4, 4))[0]
        return (l2 & 0xFFFFF000) | (va & 0xFFF)

    def enter(self, mode, offset, lr):
        """ARMv7 exception entry (Unicorn hands these back instead of taking them): new mode with IRQs
        masked (A also masked for IRQ/abort, ARM ARM B1.8.3), IT state cleared, T = SCTLR.TE, vector
        base = 0xffff0000 if SCTLR.V else VBAR. CPSR is written first so SPSR/LR land in the new bank."""
        sctlr = self.cp15(1, 0)
        base = 0xFFFF0000 if sctlr & (1 << 13) else self.cp15(12, 0) & ~0x1F
        thumb = bool(sctlr & (1 << 30))
        cpsr = self.mu.reg_read(UC_ARM_REG_CPSR)
        new = (cpsr & ~(0x1F | 0x20 | 0x0600FC00)) | mode | 0x80 | (0x100 if mode in (0x12, 0x17) else 0)
        new |= 0x20 if thumb else 0
        self.mu.reg_write(UC_ARM_REG_CPSR, new)
        self.mu.reg_write(UC_ARM_REG_SPSR, cpsr)
        self.mu.reg_write(UC_ARM_REG_LR, lr & 0xFFFFFFFF)
        self.mu.reg_write(UC_ARM_REG_PC, (base + offset) | (1 if thumb else 0))

    def on_intr(self, uc, intno, _):
        """Only record the exception and stop: registers changed from inside Unicorn's exception path
        did not stick (user SP read back as the ABT stack, a fixed fault re-raised forever). The run loop
        delivers it after emu_start returns, like the IRQ/UND paths, where register writes are reliable."""
        self.intr_counts[intno] += 1
        if self.pending_exc is None:
            self.pending_exc = intno
        uc.emu_stop()

    def deliver(self, intno):
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        cpsr = self.mu.reg_read(UC_ARM_REG_CPSR)
        thumb = bool(cpsr & 0x20)
        if intno == 2:                                          # SVC: PC already past the svc
            self.syscalls[(self.mu.reg_read(UC_ARM_REG_R0 + 7), pc)] += 1
            self.enter(0x13, 0x08, pc)
        elif intno == 3:                                        # prefetch abort at pc
            self.cp15(5, 1, self.walk(pc, False, (cpsr & 0x1F) == 0x10) or 0x7)   # IFSR
            self.cp15(6, 2, pc)                                 # IFAR
            self.enter(0x17, 0x0C, pc + 4)
        elif intno == 4:                                        # data abort
            try:
                addrs, write = self.fault_address(pc, thumb)
            except UcError:
                addrs, write = [], False
            user = (cpsr & 0x1F) == 0x10
            fs, far = 0, (addrs[0] if addrs else 0)
            for a in addrs:
                s = self.walk(a, write, user)
                if s:
                    fs, far = s, a
                    break
            if addrs and not fs:
                # The page tables allow this access, yet the CPU faulted: an emulator/decoder bug, not a
                # guest fault. Stop with the evidence instead of guessing.
                raise RuntimeError(f"data abort at pc={pc:#x} that the page tables allow (addrs "
                                   f"{[hex(x) for x in addrs]}, write={write}, user={user})")
            fs = fs or 0x5
            self.cp15(5, 0, fs | (0x800 if write else 0))       # DFSR (WnR bit 11)
            self.cp15(6, 0, far)                                # DFAR
            key = (pc, far)
            self.abort_seen[key] = self.abort_seen.get(key, 0) + 1
            n = self.abort_seen[key]
            if self.intr_counts[4] <= 3 or n in (20, 1000):
                self.log(f"data abort pc={pc:#x} far={far:#x} fs={fs:#x} write={write} (x{n}, mode {cpsr & 0x1f:#x}, "
                         f"sp={self.mu.reg_read(UC_ARM_REG_SP):#x})")
            self.enter(0x17, 0x10, pc + 8)
        else:
            self.log(f"INTR {intno} at pc={pc:#x}: not modelled")

    def on_trace(self, uc, addr, size, _):
        """Debug: disassembled trace of the next trace_left instructions (started at a repeated trap)."""
        if self.trace_left <= 0:
            return
        self.trace_left -= 1
        thumb = bool(uc.reg_read(UC_ARM_REG_CPSR) & 0x20)
        try:
            code = bytes(uc.mem_read(self.va_to_pa(addr), size))
            ins = next((self.md_t if thumb else self.md_a).disasm(code, addr), None)
            text = f"{ins.mnemonic} {ins.op_str}" if ins else code.hex()
        except (UcError, StopIteration):
            text = "?"
        extra = ""
        if "fpexc" in text:
            extra = "   ; " + " ".join(f"r{i}={uc.reg_read(UC_ARM_REG_R0 + i):#x}" for i in range(5)) + \
                    f" FPEXC={uc.reg_read(UC_ARM_REG_FPEXC):#x}"
        self.trace_f.write(f"{addr:08x} {uc.reg_read(UC_ARM_REG_CPSR) & 0x1f:02x} {text}{extra}\n")
        if self.trace_left == 0:
            self.trace_f.close()
            uc.hook_del(self.trace_hook)                 # a code hook on every insn is very slow

    def take_undef(self):
        """Undefined-instruction exception (Unicorn reports UC_ERR_INSN_INVALID instead). The Thumb-2
        kernel's WARN()/BUG() is `udf #2` (0xde02) and relies on this to print and continue. Entry:
        UND mode, vector +0x04, LR = faulting insn + 2 (Thumb) / + 4 (ARM)."""
        cpsr = self.mu.reg_read(UC_ARM_REG_CPSR)
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        thumb = bool(cpsr & 0x20)
        key = pc
        self.undefs[key] = self.undefs.get(key, 0) + 1
        # Loop guard: a trap that comes straight back with no progress in between means nothing handled
        # it. Identical state alone is legitimate (a task looping over a sleep re-traps its first VFP insn
        # every iteration: lazy VFP is switched off at each context switch), so measure progress as the
        # instructions run since the previous trap at this pc.
        state = (pc, self.mu.reg_read(UC_ARM_REG_SP), cpsr)
        stuck = state == self.last_undef and self.insns - self.last_undef_insns < 50_000
        self.undef_repeat = self.undef_repeat + 1 if stuck else 0
        self.last_undef, self.last_undef_insns = state, self.insns
        if self.undef_repeat >= 50:
            self.log(f"undefined insn at {pc:#x} re-trapped 50 times with no progress in between: giving up")
            return False
        try:                                     # mem_read is physical: kernel lowmem VA -> PA
            insn = bytes(self.mu.mem_read(self.va_to_pa(pc), 4))
        except UcError:
            insn = b"????"
        if self.undefs[key] == 3 and self.trace_left == 0 and not self.traced:
            self.traced = True
            self.trace_left = 4000
            self.trace_f = open(os.path.join(self.out, f"trace_undef_{pc:08x}.txt"), "w")
            self.trace_hook = self.mu.hook_add(UC_HOOK_CODE, self.on_trace)
            self.mu.ctl_flush_tb()                      # existing blocks were translated without the hook
        if self.undefs[key] in (3, 1000):
            self.log(f"  repeat UNDEF {pc:#x}: FPEXC={self.mu.reg_read(UC_ARM_REG_FPEXC):#x} "
                     f"CPACR={self.mu.reg_read(UC_ARM_REG_C1_C0_2):#x} insn={insn.hex()}")
        if self.undefs[key] <= 2:
            self.log(f"UNDEF at pc={pc:#x} {'thumb' if thumb else 'arm'} {insn.hex()} -> UND vector")
        self.enter(0x1B, 0x04, pc + (2 if thumb else 4))
        return True

    def on_mmio(self, uc, access, addr, size, value, _):
        if TIMER_BASE <= addr < TIMER_BASE + 0x20:
            off = addr - TIMER_BASE
            if access == UC_MEM_WRITE:
                self.timer_write(off, value)
            else:
                v = {0x08: self.timer_value(), 0x18: self.timer_value(), 0x10: self.t_ctl,
                     0x14: self.t_int_en | self.t_raw << 1 | (self.t_raw & self.t_int_en) << 2}.get(off)
                if v is not None:
                    uc.mem_write(addr & ~3, struct.pack("<I", v & 0xFFFFFFFF))
        elif addr == SYSCNT_BASE + 0x0C and access != UC_MEM_WRITE:
            uc.mem_write(addr, struct.pack("<I", (self.now_ns() // 1_000_000) & 0xFFFFFFFF))
        elif GICD <= addr < GICD + 0x2000:
            if access == UC_MEM_WRITE:
                self.gic_write(addr, value)
            elif addr == GICC + 0x00C:
                uc.mem_write(addr, struct.pack("<I", self.gic_iar()))
            elif addr == GICD + 0x004:
                uc.mem_write(addr, struct.pack("<I", 0x0000FC03))   # TYPER: 128 IRQs, 1 CPU
        elif ADI_BASE <= addr < ADI_BASE + 0x400:
            self.adi_access(uc, access, addr - ADI_BASE, value)
        if access == UC_MEM_WRITE:
            for bank in SETCLR_BANKS:
                off = addr - bank
                if 0x1000 <= off < 0x3000:
                    # 8/16/32-bit stores to the SET/CLEAR alias act on the matching lanes of the base word
                    word = bank + (off & 0xFFC)
                    lanes = ((1 << (8 * size)) - 1) << (8 * (addr & 3))
                    bits = (value << (8 * (addr & 3))) & lanes
                    cur = struct.unpack("<I", uc.mem_read(word, 4))[0]
                    new = cur | bits if off < 0x2000 else cur & ~bits
                    uc.mem_write(word, struct.pack("<I", new & 0xFFFFFFFF))
                    break
        key = (addr, access)
        if key not in self.seen:
            pc = uc.reg_read(UC_ARM_REG_PC)
            kind = "W" if access == UC_MEM_WRITE else "R"
            self.seen[key] = (pc, value)
            self.log(f"MMIO {kind} {addr:08x} sz{size} val={value:#x} pc={pc:#x}")

    def on_unmapped(self, uc, access, addr, size, value, _):
        self.log(f"UNMAPPED access {access} at {addr:#x} size {size} pc={uc.reg_read(UC_ARM_REG_PC):#x}")
        return False

    def scan_log(self):
        ram = bytes(self.mu.mem_read(RAM_BASE, RAM_SIZE))
        for m in LOG_MARKERS:
            if m in self.found:
                continue
            i = ram.find(m)
            if i >= 0:
                self.found.add(m)
                end = ram.find(b"\n", i, i + 300)
                self.log(f"KLOG @{RAM_BASE + i:#x}: {ram[i:end if end > 0 else i + 160].decode(errors='replace')}")

    def run(self, insns, chunk=200_000, report=100_000_000):
        pc = ZIMAGE_PHYS
        next_report = report
        while self.insns < insns:
            # A pending, enabled IRQ is taken by the CPU at the first instruction with CPSR.I clear. Runs
            # end at SVC/aborts and at the idle wfi, always with I set, so checking only between runs
            # starved the timer forever. While an IRQ is pending a code hook stops at the first boundary
            # with I clear (on_irq_window) and the IRQ is taken there.
            pending = self.irq_deliverable()
            if pending and self.irq_hook is None:
                self.irq_hook = self.mu.hook_add(UC_HOOK_CODE, self.on_irq_window)
                self.mu.ctl_flush_tb()                   # blocks translated earlier would skip the hook
            elif not pending and self.irq_hook is not None:
                self.mu.hook_del(self.irq_hook)
                self.irq_hook = None
            count = IRQ_SLICE if pending else chunk
            try:
                self.mu.emu_start(pc, 0xFFFFFFFF, count=count)
            except UcError as e:
                if not (e.errno == UC_ERR_INSN_INVALID and self.take_undef()):
                    self.log(f"STOP {e} pc={self.mu.reg_read(UC_ARM_REG_PC):#x} "
                             f"lr={self.mu.reg_read(UC_ARM_REG_LR):#x} cpsr={self.mu.reg_read(UC_ARM_REG_CPSR):#x}")
                    break
            self.insns += count
            if self.pending_exc is not None:
                exc, self.pending_exc = self.pending_exc, None
                self.deliver(exc)
            self.timer_tick()
            self.take_irq()
            pc = self.mu.reg_read(UC_ARM_REG_PC)
            if self.mu.reg_read(UC_ARM_REG_CPSR) & 0x20:
                pc |= 1
            if self.insns >= next_report:
                next_report += report
                self.log(f"{self.insns // 1_000_000}M insns ({self.now_ns() / 1e9:.2f} s), pc={pc:#x} "
                         f"irqs={self.irqs}")
                self.scan_log()
        self.scan_log()
        ram = bytes(self.mu.mem_read(RAM_BASE, RAM_SIZE))
        open(os.path.join(self.out, "ram.bin"), "wb").write(ram)
        klog = extract_klog(ram)
        open(os.path.join(self.out, "klog.txt"), "w", encoding="utf-8").write("\n".join(klog) + "\n")
        for line in klog[-12:]:
            self.log(f"klog| {line}")
        regs = " ".join(f"r{i}={self.mu.reg_read(UC_ARM_REG_R0 + i):#x}" for i in range(13))
        self.log(f"final {regs} sp={self.mu.reg_read(UC_ARM_REG_SP):#x} lr={self.mu.reg_read(UC_ARM_REG_LR):#x} "
                 f"pc={self.mu.reg_read(UC_ARM_REG_PC):#x}")
        self.log(f"timer: ctl={self.t_ctl:#x} load={self.t_load:#x} int_en={self.t_int_en} raw={self.t_raw} "
                 f"deadline={self.t_deadline / 1e9:.3f}s now={self.now_ns() / 1e9:.3f}s | gic: dctl={self.gicd_ctl} "
                 f"cctl={self.gicc_ctl} enabled60={TIMER_IRQ in self.gic_enabled} pending={sorted(self.gic_pending)} "
                 f"active={sorted(self.gic_active)} cpsr={self.mu.reg_read(UC_ARM_REG_CPSR):#x}")
        self.log("top syscalls (nr, return pc): " + ", ".join(f"{n}@{p:#x} x{c}" for (n, p), c in self.syscalls.most_common(12)))
        self.log(f"done: {len(self.seen)} distinct MMIO accesses; RAM saved to ram.bin (kernel VA 0xc0000000 = PA 0x80800000)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default=IMAGE, help="FPLinux ramboot.bin (default: $F286_FPLINUX_IMAGE or firmware/ramboot.bin)")
    ap.add_argument("--insns", type=int, default=300_000_000)
    ap.add_argument("--params", default="", help="kernel parameters to add, e.g. f286_radio.autoint=1")
    ap.add_argument("--out", default=os.path.join(fwpaths.RUNS_DIR, time.strftime("fplinux_%Y%m%d_%H%M%S")))
    a = ap.parse_args()
    if a.params.startswith("@"):                      # @file: avoids shell quoting of init scripts
        a.params = open(a.params[1:], encoding="utf-8").read().strip()
    Emu(a.image, a.out, a.params).run(a.insns)


if __name__ == "__main__":
    main()
