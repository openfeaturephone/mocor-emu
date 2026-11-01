#!/usr/bin/env python3
"""Emulate individual HAL functions from the F286 stock kernel.
Each function is pure MMIO (no OS calls). We trace every register access.

HAL functions in the LTE DSP boot chain:
  0x811d0d7c(r0) : AON_REG_PROT - r0=1 -> [0x402e006c] |= 0x9620
  0x811d0cc2(r0) : APB_RST2     - r0=1 -> [0x402e0130] |= 0x10000 (hold)
                              r0=0 -> [0x402e0130] &= ~0x10000 (release)
  0x811d0d30(r0) : LDSP_BOOT    - r0=1 -> [0x402e024c] |= 1 (start)
                              r0=0 -> [0x402e024c] &= ~1 (stop)
  0x811d0d0e(r0) : BOOT_VECTOR  - [0x402e0248] = r0 (verbatim)
  0x80d0fa7c(r0) : PMU pre-boot - r0=1 -> LDSP power release
  0x811d0d96(r0) : DSP power    - polls c0, writes 0x6083 gates
"""

from unicorn import *
from unicorn.arm_const import *
import struct

# Kernel file for extracting code
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import fwpaths  # noqa: E402
KERNEL = fwpaths.need(fwpaths.KERNEL, 'kernel partition')
# NOTE: BASE below is the early, wrong load base (0x70 below the real 0x80a05e38 for file
# offset 0x38, see mocor_emu.KBASE). Code runs from the right bytes only where the traced
# addresses were taken in this same frame; treat results as historical.
BASE = 0x80a05dc8

# MMIO space
MMIO_BASE = 0x40000000
MMIO_SIZE = 0x10000000

hw = {}
trace = []

def hw_read(addr):
    addr &= ~3
    defaults = {
        0x402B00C0: 0x00039CE0,
        0x402B0034: 0x01010402,
        0x402B0044: 0x00010105,
        0x402B00CC: 0x00000080,
        0x402E0130: 0x00030000,
        0x402E0248: 0x18000000,
        0x402E024C: 0x00000001,
        0x402E006C: 0x80000000,
        0x402E0140: 0x44160000,
    }
    return hw.get(addr, defaults.get(addr, 0))

def hook_read(uc, access, address, size, value, user_data):
    if access == UC_MEM_READ:
        addr = address & ~3
        val = hw_read(addr)
        uc.mem_write(address, val.to_bytes(4, 'little'))
        trace.append(f"  [R] {address:08x} -> {val:08x}")

def hook_write(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        addr = address & ~3
        hw[addr] = value
        trace.append(f"  [W] {address:08x} <- {value:08x}")

def hook_unmapped(uc, access, address, size, value, user_data):
    page = address & ~0xFFF
    try:
        uc.mem_map(page, 0x1000, UC_PROT_ALL)
        return True
    except:
        pass
    print(f"  [!] UNMAPPED {access} at {address:#x}")
    return False

def run_func(name, entry, r0, max_instrs=200):
    """Run one HAL function in Unicorn"""
    global hw, trace
    hw = {}
    trace = []
    
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    
    # Map code region (enough for the HAL block)
    code_base = 0x80a06000
    code_size = 0x800000  # 8 MB
    mu.mem_map(code_base & ~0xFFF, code_size + 0x1000, UC_PROT_ALL)
    
    # Write the kernel payload
    kern = open(KERNEL, 'rb').read()
    kern_off = code_base - BASE
    payload = kern[kern_off:kern_off + code_size]
    mu.mem_write(code_base & ~0xFFF, payload)
    
    # Map MMIO space
    mu.mem_map(MMIO_BASE, MMIO_SIZE, UC_PROT_ALL)
    
    # Map stack
    mu.mem_map(0xC0000000, 0x100000, UC_PROT_ALL)
    
    # Hooks
    mu.hook_add(UC_HOOK_MEM_READ, hook_read, begin=MMIO_BASE, end=MMIO_BASE + MMIO_SIZE)
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_write, begin=MMIO_BASE, end=MMIO_BASE + MMIO_SIZE)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                hook_unmapped)
    
    # Set up
    sp = 0xC0000000 + 0xF0000
    mu.reg_write(UC_ARM_REG_SP, sp)
    mu.reg_write(UC_ARM_REG_R0, r0)
    
    print(f"\n{'='*60}")
    print(f"Function: {name} @ {entry:#x} (r0={r0})")
    print(f"{'='*60}")
    
    try:
        mu.emu_start(entry | 1, entry + 0x800, count=max_instrs)
    except UcError as e:
        pc = mu.reg_read(UC_ARM_REG_PC)
        print(f"  [!] Stopped: {e} at PC={pc:#x}")
    except Exception as e:
        print(f"  [!] {e}")
    
    for t in trace:
        print(t)
    
    return hw

# ---- Extract and run each HAL function ----
kern = open(KERNEL, 'rb').read()

print("Unicorn HAL Function Emulator for F286/T107 LTE DSP boot")
print("=" * 60)

# 1. AON_REG_PROT: unlock protected registers
run_func("AON_REG_PROT(1) - unlock key 0x9620", 0x811d0d7c, 1)
print("  Expected: [0x402e006c] |= 0x9620")

# 2. APB_RST2 hold
run_func("APB_RST2(1) - LDSP hold", 0x811d0cc2, 1)
print("  Expected: [0x402e0130] |= 0x10000")

# 3. APB_RST2 release
run_func("APB_RST2(0) - LDSP release", 0x811d0cc2, 0)
print("  Expected: [0x402e0130] &= ~0x10000")

# 4. LDSP_BOOT start
run_func("LDSP_BOOT(1) - start", 0x811d0d30, 1)
print("  Expected: [0x402e024c] |= 1")

# 5. LDSP_BOOT stop
run_func("LDSP_BOOT(0) - stop", 0x811d0d30, 0)
print("  Expected: [0x402e024c] &= ~1")

# 6. BOOT_VECTOR
run_func("BOOT_VECTOR(0x40224200)", 0x811d0d0e, 0x40224200)
print("  Expected: [0x402e0248] = 0x40224200")

# 7. PMU pre-boot clears (the root-cause fix function)
run_func("PMU_PRE_BOOT(1) - LDSP power release", 0x80d0fa7c, 1)
print("  Expected: [0x402b2034] = 0x03000000, [0x402b2044] = 0x01000000 then 0x02000000, [0x402b20cc] = 0x20000")

print("\nDone.")
