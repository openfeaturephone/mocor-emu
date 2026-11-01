#!/usr/bin/env python3
"""F286 MocorOS emulator (Unicorn, Cortex-A7): boots the stock UMS9117 kernel and mmi_app.

Boots the stock Mocor kernel (ThreadX-based) in Unicorn (Cortex-A7).
Features:
  - Correct memory map + on-demand MMIO mapping
  - Hardware models: 16550 UART (console capture), chip-ID/PMU defaults,
    system-tick pump for known delay loops, generic poll unsticker
  - Automatic poll detection: tracks hot (PC, addr) read pairs, reports them
    with capstone disassembly of the polling instruction
  - Step debugger: breakpoints, watchpoints, step/continue/until, regs,
    disassemble, examine, patch, snapshots -- driven by command file or stdin
  - Per-run artifacts in runs/<ts>/: run.log, events.jsonl, uart.txt,
    snapshot.bin/.json, REPORT.md

Usage:
  python mocor_emu.py                       # boot, model ticks, auto-unstick, report
  python mocor_emu.py --mode report         # stop at first unknown poll (analysis)
  python mocor_emu.py --cmds dbg.txt        # boot then run debugger script
  python mocor_emu.py --restore runs/X/snapshot.json --cmds cont.txt
"""
import os, sys, json, time, base64, argparse, traceback, ctypes
import collections
from collections import OrderedDict, deque, Counter

from unicorn import *
from unicorn.arm_const import *
from capstone import *

# ---------------------------------------------------------------- paths
ROOT    = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import fwpaths                                   # noqa: E402  (firmware locations)
KERNEL  = fwpaths.KERNEL
MMI_APP = fwpaths.MMI_APP
MMI_BASE = 0x88000000        # mmi_app run VA = file offset 0 (DHTB hdr included)
MMI_PRELOAD = True           # load mmi_app.bin at MMI_BASE (see preload_modules)

# ---------------------------------------------------------------- kernel image layout
# REAL load mapping (checked against a RAM read of the loaded kernel): FDL2 loads
# the whole partition (DHTB header included) at 0x80a05e00, so file offset F
# lives at VA 0x80a05e00+F. The old base was 0x70 low, which broke every
# absolute pointer the SYSRAM blob holds (vector handler addresses).
KBASE = 0x80a05e38          # VA of kernel.bin file offset 0x38
KOFF  = 0x38
ENTRY = 0x80a061f0          # real absolute (file 0x3F0 = reset entry)
ENTRY_OS = 0x814c34a5       # OS main (Thumb, after chip init/scatter/decomp)

# Unicorn's ARM backend mishandles IT blocks when a backward branch targets
# the `ittt` itself (observed: condexec_bits stuck at block-start state, the
# conditional insns execute anyway, then the loop's b<cc>.w raises
# INSN_INVALID). The stock memset hot-loop uses exactly this pattern, inlined
# at many call sites. Load-time patch, semantically identical:
#   22 BF (ittt hs) 50 0C E8 A0 (stmhs) 50 0C E8 A0 (stmhs) -> 07 D3 (bcc tail) stms
# C=1: stores+subs+loop (subs/bhs below the pattern are untouched);
# C=0: branch to tail, skipping subs+branch exactly like the skipped IT block.
IT_PATCH_FROM = bytes.fromhex("22bfa0e80c50a0e80c50")
IT_PATCH_TO   = bytes.fromhex("07d3a0e80c50a0e80c50")

# functions neutered to `bx lr` via --nop-fn (identified blockers, see REPORT)
NOP_FNS = []
# raw byte patches via --patch VA=HEX (applied after load, before boot)
RAW_PATCHES = [
    # trace/int-lock depth saturation rings (see _setup_hooks comment):
    # depth A overflow-log at 0x8109997e-91 -> movs r0,#0x13; b 0x8109998e; nops
    (0x81099982, "132003e000bf00bf00bf"),
    # depth B overflow-log at 0x8109a52e-41 -> movs r0,#0x13;
    # str r0,[r4,#0xc]; b 0x8109a542; nops
    (0x8109a52e, "1320606006e000bf00bf00bf00bf00bf00bf00bf"),
    # RTOS param-check warn printer recurses with the log output path
    (0x80a09414, "7047"),
    # log port send = the CP-monitor interface; model instant consumption
    (0x811beeac, "00204770"),
    # blackbox trace logger: diagnostic ring with no consumer in our boot;
    # the svc-cascade's 153-iteration loop calls it per iteration
    (0x8120d654, "7047"),
    # NOTE: the old (0x80a0917c, "0020") fatal-logger patch is GONE - it
    # overwrote the second halfword of the runtime's own 4-byte `bl` that
    # the kernel installs at 0x80a0917a during early init (snapshot bytes
    # ba f2 xx xx), corrupting it into an undecodable insn and halting
    # every pre-park boot at 0x80a0917a. The snapshots carry the corrupted
    # halfword baked in, so restore the pristine pre-self-modification
    # pair here: `ldr r5,[pc,#0x358]; movs r0,#1` (file bytes d6 4d 01 20).
    # The logger's in-flight drain in _deliver_ticks handles the rest.
    (0x80a0917a, "d64d0120"),
    # the logger's in-flight counter: the tick
    # drain alone cannot keep count<=1 (two logs within one tick window
    # reach the reporter's shutdown at 0x80a0919c, and the defer range
    # covers the counter spin at 0x80a091a6). Make it structurally zero:
    # movs r0,#0 over `adds r0,r0,#1`, so `cmp r0,#1; bls` always takes the
    # fast path. Load-time patch, NOT a hook (hooks at 0x80a09184/88 wedge
    # this unicorn build).
    (0x80a09184, "0020"),
    # the channel RX drain thread waits forever on its semaphore (op=-1);
    # with no CP to signal it, make the wait non-blocking (op=0) so the
    # drain becomes a polling thread and processes CP replies every tick
    (0x8120d71c, "002100bf"),
    # LOG_CORE (0x80a0914c) never returns by design: its tail is the
    # diag RX daemon loop (0x80a09364-9412, `b .` idle spin) - every
    # assert tail-calls it (0x80a0b07a = `movs r3,#0; b.w 0x80a0914c`)
    # and the boot thread BECOMES the logger. On hardware the NV store
    # is factory-valid so no assert fires pre-display; in emulation the
    # NV-first-boot asserts would hang the boot here. Patch the assert
    # entry to return immediately - the assert text is already captured
    # by the emulator's own hooks.
    (0x80a0b07a, "7047"),

    # OS-object get-or-create slot fix: the finder at
    # 0x80e3e4c0 scans 128 static slots for [entry+4]==id; when the id
    # is missing (the display-init's dynamic objects 0x32/0x4f/0x51),
    # the not-found path leaves r1=0x80 (scan end) as the "new slot" -
    # the caller stores the object at slot 128 where the rescanning
    # finder can never see it -> infinite get-or-create loop. Patch the
    # not-found assert call to assign slot 12 (the first free slot after
    # the 12 static system entries): the caller's store then lands inside
    # the scanned range and the re-find matches.
    (0x80e3e4e2, "0c20bf00"),       # movs r1, #0xC; nop
    # Generic udelay/delay-loop: the tick-polling busy-wait at 0x8109c2c6
    # waits for the 0x4023000c counter to advance by a caller-supplied
    # delta. The deltas are calibrated for a 32kHz hardware timer (1
    # unit = 1ms = ~200K CPU instructions at 200MHz); in emulation the
    # counter advances 1 unit/instruction, but the DELTAS are still
    # calibrated for the hardware rate (millions of units = hours of
    # wall time). Patch the delay loop to return immediately - all
    # udelay/delay calls become no-ops, which is correct for emulation
    # (the hardware would have completed the delay by now).
    (0x8109c2c6, "10bd"),            # pop {r4, pc} - exit delay
    # Chan-mgr drain task neutralization: the drain task polls the diag
    # channel forever waiting for data that never comes (no CP, no diag
    # host in this boot). On hardware the scheduler preempts it and
    # other tasks run; in emulation the poll loop (0x8120d7a: bl
    # 0x811f6524 -> OS-object find) hogs CPU. Patch its loop body to
    # return immediately - the drain is diagnostic-only.
    (0x8120d71c, "7047"),            # bx lr at the drain loop head
    # NV_Init (0x80a1096a) loader bypass: the two NV backing
    # stores open through the FFS named-device registry ("A", "BML ...
    # NV Partition"), which no code populates in this boot - both loads
    # fail, NV_Init retries through its fallback forever (each retry
    # asserts via log-fn + display init), and every NV_Read then
    # short-circuits to error 7 ("not initialized"). Patch both loader
    # calls to return success: NV_Init takes its own success tail
    # (0x80a109b2: flag=1, r0=0) with an EMPTY cache, so item reads miss
    # the cache and take the guest's default-ROM filler (0x81491d0a) -
    # exactly a real first boot with an uninitialized NV partition.
    (0x80a10980, "0020bf00"),       # loader1 call -> movs r0,#0; nop
    (0x80a10990, "0020bf00"),       # loader2 call -> movs r0,#0; nop
]
# boot-parameter pre-seed via --init-va VA=HEX (word writes applied before boot;
# normally supplied by FDL2 -- e.g. main stack top at 0x814c5ba0)
INIT_VA = []


# ---------------------------------------------------------------- CP15 model
class CP15Model:
    """Cortex-A7 system-control coprocessor (trap-and-emulate model).

    Data registers are stored per (opc1, CRn, CRm, opc2) with ARMv7-A reset
    values; maintenance operations (cache/TLB, c7/c8) are modeled no-ops that
    report success, which is exact behaviour for a flat, cacheless emulation.
    """

    def __init__(self, run):
        self.run = run
        self.r = {
            # identity
            (0, 0, 0, 0): 0x410FC075,   # MIDR: Cortex-A7 r0p5
            (0, 0, 0, 1): 0x8444C004,   # CTR
            (0, 0, 0, 5): 0x80000F00,   # MPIDR: uniprocessor, U=1
            # ID registers (minimal plausible A7 values)
            (0, 0, 1, 0): 0x00000000,   # ID_PFR0
            (0, 0, 1, 1): 0x00000031,   # ID_PFR1 (generic timer present)
            (0, 0, 2, 0): 0x02101110,   # ID_ISAR0
            # caches
            (1, 0, 0, 1): 0x0F0123,     # CLIDR
            (2, 0, 0, 0): 0x00000000,   # CSSELR: level0 data cache selected
            (1, 0, 0, 2): 0x00000000,   # CTR-type level? A7: AIDR... keep 0
            (1, 0, 0, 0): 0x001FE01A,   # CCSIDR: 128 sets x 4-way x 64B lines
            # control
            (0, 1, 0, 0): 0x00C50078,   # SCTLR (ARMv7-A reset value)
            (0, 1, 0, 1): 0x00000000,   # ACTLR
            (0, 1, 0, 2): 0x00000000,   # CPACR
            (0, 2, 0, 2): 0x00000000,   # ...generic
        }
        self.served = 0
        self.unknown = collections.Counter()

    def read(self, opc1, crn, crm, opc2):
        key = (opc1, crn, crm, opc2)
        v = self.r.get(key, 0)
        if key not in self.r:
            self.unknown[("R",) + key] += 1
            self.r[key] = 0
        self.served += 1
        return v

    def write(self, opc1, crn, crm, opc2, val):
        key = (opc1, crn, crm, opc2)
        if key not in self.r:
            self.unknown[("W",) + key] += 1
        self.r[key] = val
        self.served += 1


def decode_cp15(word):
    """Return (L, opc1, CRn, Rt, CRm, opc2) for an ARM/Thumb32 coproc-15
    register transfer word, else None. Both encodings share the layout with
    cond=0xE / fixed 1110 prefix."""
    if (word & 0x0F000010) != 0x0E000010:
        return None
    if (word >> 8) & 0xF != 15:
        return None
    opc1 = (word >> 21) & 7
    l = (word >> 20) & 1
    crn = (word >> 16) & 0xF
    rt = (word >> 12) & 0xF
    opc2 = (word >> 5) & 7
    crm = word & 0xF
    return l, opc1, crn, rt, crm, opc2


def decode_mcrr(word):
    """MCRR/MRRC p15: cond 1100 0101(L)/0100 opc1 Rt2 Rt coproc CRm."""
    if (word & 0x0FF00000) != 0x0C400000:
        return None
    if (word >> 8) & 0xF != 15:
        return None
    l = (word >> 20) & 1 & 0x1 if False else (word >> 21) & 1
    opc1 = (word >> 4) & 0xF
    rt = (word >> 12) & 0xF
    rt2 = (word >> 16) & 0xF
    crm = word & 0xF
    return l, opc1, rt, rt2, crm


PROFILES = {
    # known-good boot recipe: regulator nop, FDL2 stack-top param, dispatch-walk
    # skip; CP15 remap shims are always applied by --cp15-shim (default on)
    "best": {
        "nop_fn": [0x80e191d0],
        "init_va": [(0x814c5ba4, 0x82000000)],
        "patch": [(0x81496cba, "7047bfbfbfbfbfbfbfbfbfbfbf")],
    },
}


def cp15_shim_payload(payload):
    """Patch ARM-encoded MRC/MCR p15,c10,c2 (PRRR/NMRR remap class) -- the
    class proven to raise at runtime. Other classes stay under the runtime
    skip backstop. Thumb32 shares the bit layout; kernel helpers are Thumb.
    The identical bit pattern decodes as the same MCR/MRC in Thumb32, but the
    kernel's remap helpers are ARM; runtime CP15 skip stays active as backstop."""
    n = 0
    for off in range(0, len(payload) - 3, 4):
        w = int.from_bytes(payload[off:off + 4], 'little')
        if (w & 0x0F000010) != 0x0E000010:      # ARM MCR/MRC shape (bit4 set)
            continue
        if (w >> 8) & 0xF != 15:                # coproc 15 only (system control)
            continue
        if (w >> 16) & 0xF != 10 or (w & 0xF) != 2:
            continue                            # PRRR/NMRR remap class only
        rd = (w >> 12) & 0xF
        # Thumb32 patches (early init executes these in Thumb):
        #   MRC -> MOV.W Rd, #0   (4F F0 00 Rd)
        #   MCR -> NOP.W NOP.W    (BF 00 BF 00)
        if (w >> 20) & 1:
            payload[off:off + 4] = bytes([0x4F, 0xF0, 0x00, rd])
        else:
            payload[off:off + 4] = bytes([0xBF, 0x00, 0xBF, 0x00])
        n += 1
    return n

# --- cellular capture switches (2026-10-30)
# CELL_CUTS: the early hooks that skip the LTE/DSP pre-boot / glue
# path (glue segment, task-loop exit, post-init, late-chain 0x80a48fac and
# veneer 0x80fc491c). False = let the stock code run so it can be observed.
CELL_CUTS = True
# STRICT: stop (with context) instead of skipping faulting instructions,
# returning from invalid insns, or continuing past native unicorn crashes.
STRICT = False
# CELL_TRACE: full, uncapped read+write trace (with pc/lr) of every
# cellular-relevant MMIO range -> runs/<dir>/cell_trace.tsv
CELL_TRACE = False
# per (rw,addr,value,pc) key: rows emitted before the key goes quiet
# (polls); suppressed counts are summarised at close
CELL_TRACE_KEY_CAP = 16
# NV_LEGACY_FILL: reproduce the pre-2026-10-30 NV_Read intercept, which
# filled buffers with 0x7047 (thumb "bx lr") instead of zeros
NV_LEGACY_FILL = False
# PMU_MODEL: PMU_APB 0x402b0000 / AON_APB 0x402e0000 +0x1000 SET / +0x2000
# CLEAR banks act on the base register, and the power-status registers
# 0x402b00c0/c4/d4 are derived from the domain request bits (see
# docs/hardware-models.md). False = old write-echo behaviour (status polls read 0 forever).
PMU_MODEL = True
# reset state = register values read on a live phone under FPLinux:
# whale die unpowered, every island status field 7 (OFF)
PMU_RESET = {
    0x402B0034: 0x03000000,   # XDSP-A (LTE core) request: b25|b24 held
    0x402B0038: 0x03000000,   # XDSP-B (GSM core) request: b25|b24 held
    0x402B003C: 0x01010303,   # live: b25 (WHu3g force-down) clear
    0x402B0044: 0x02010105,   # live: b24 (WTLCP force-down) clear
    0x402B00CC: 0x002200C2,   # live: b21 CM4 + b17 DSP deep-sleep force
}
PMU_SETCLR_BLOCKS = (0x402B0000, 0x402E0000)
# NV_REAL: serve NV_GetLength/NV_Read from this phone's own NV instead of
# zeros. Sources: nvcal.bin = DownloadedNV fixed stream
# (authoritative RF calibration, 243 ids), p_10000003.bin = RunningNV
# journal (checksummed copies; used for ids nvcal lacks). Misses keep the
# old zero-fill. False = zero-fill everything (pre-2026-10-30 model).
NV_REAL = True
# RF_MODEL: RFTI 0x40070000 = AP-side serial port to the SR3532 RF
# transceiver (stock accessors 0x812522d6 write / 0x812522fe read):
#   [0x240] = (reg<<16)|val (bit31 = read), [0x244] = 1 kicks, result in
#   [0x248]. Modelled as a transceiver register file; every transaction is
#   logged ([RFTI ] / RFTI events). RF_CHIP_ID answers reg 0x7f. NV 302
#   word +2 = 0xfffd ("auto-detect"), so the RFIC type comes from this ID:
#   0x810d1af0 accepts 0x6c0/0x6c1/0x740/0x742/0x743/0x744/0x746/0x747
#   (all -> g_rfic_type 0x17); anything else leaves it -1 -> fatal assert
#   drv_rf_iram.c:321. PLACEHOLDER: 0x6c0 picked as the first accepted id;
#   the real value has not been read from hardware (replay on the phone:
#   RFTI W 0x1001=1, W 0x1000=2, R 0x7f).
RF_MODEL = True
RF_CHIP_ID = 0x6C0
# WTL_TIMER: the LTE frame timer the AP reads at 0xe0020010/14 (stock
# 0x80cf4774 copies 8 bytes; base 0xe0020000 stored at 0x81714f84 by
# 0x8122fa54). Format (0x8106fb30/fb38): lo[18:0] = Ts within the frame,
# lo[31:19] = frame[12:0], hi[18:0] = frame[31:13]. Ts = 1/30.72 MHz,
# 307200 Ts per 10 ms frame (0x9600*8). Free-running off insn_total at
# WTL_TS_PER_INSN (~200 MIPS AP). Unmodelled it is auto-mapped zero RAM
# and every "wait until T" loop (0x80d1f832) spins forever.
HWSPINLOCK = True
# HWSPINLOCK: spinlock block 0x33000000 (stock 0x81125664 try-lock / 0x8112567a
# unlock): lock n at 0x33000800+4n. A read returns 0 and takes the lock when
# free, non-zero (1) while held; writing the key 0x55aa10c5 releases it.
# Write-echo left the key in RAM, so every second acquire timed out (eFuse
# block 0x18 read -> "Get_APCDAC_Slope_And_Intercept: Efuse read failed!").
# WFI_WAKE: unicorn ends emu_start at every WFI, so in the idle task's
# light-sleep loop (low page 0x9af -> 0x76c -> stub 0xf5c..0xfd4: IRQs
# masked, dsb, WFI, return, unmask) EVERY chunk boundary lands inside the
# masked window and _deliver_ticks never injects - the OS clock stops and
# the AP "sleeps" forever (seen: stuck from 33M to 1G). On hardware a pending IRQ
# wakes WFI regardless of the I bit. Model: a chunk that stopped right
# after a WFI counts as idle time (CHUNK already added) and the due tick
# is delivered at the WFI even if masked.
WFI_WAKE = True
# CP_STUB: scripted remote-core side of the hardware mailbox (SIPC smsg
# protocol). Every AP->CP doorbell is logged ([MBX-TX], MBX_TX events,
# runs/<dir>/cp_stub.tsv) with dst/w0/w1 decoded as smsg {ch,type,flag,
# value}. dst 1 = CM4 (WCN: ch4 "pipe" BT/FM/assert, ch5 "plog"): an AP
# OPEN {type 1, flag 0xBEEE} is answered with the peer OPEN, as the M4
# does on hardware. Replies go through a CP->AP FIFO model at 0x400a8000
# (+0/+4/+8 head = tag/w0/w1, +0xc=1 pops, +0x14 status wr<<0x10|rd<<0x18)
# and IRQ id 0x65 (table irq 0x45 TB_MBOX_TAR_AP_INT, ISR 0x811f63ff ->
# drain 0x811f630c). The 12-byte IPC ring sends (0x80ef1418) are logged
# too (IPC_TX). Extra replies: emu.cp_script = {(dst,w0): [(tag,w0,w1),..]}
CP_STUB = True
# SDHCI_MODEL: SD host controllers at 0x20300000 + slot<<20 (stock
# 0x81373c02: set CLK_CTRL +0x2c bit0 "internal clock enable", spin until
# bit1 "internal clock stable"). Auto-mapped RAM never sets bit1 -> the
# MMI T-card mount spun forever (seen: 37M to 1G). Model: bit1 follows
# bit0. Present-state (+0x24) stays 0 = no card inserted.
SDHCI_MODEL = True
# PMIC_ADC: PMIC aux ADC behind ADI (stock 0x811d08b0: select channel,
# start = ADI 0x8404 |= 2 (0x811d0a4e), poll 0x8460 bit0 done / 0x8404
# bit1 busy with a 6-tick timeout, result 0x8450[11:0]). Write-echo kept
# busy set forever, so every battery/temp sample ran to its timeout and
# the MMI thread lived in that loop. Model: conversion completes
# at once - busy clears, done sets, result = PMIC_ADC_RAW.
# PLACEHOLDER value (mid-scale), not a measured battery reading.
PMIC_ADC = True
PMIC_ADC_RAW = 0x800
# RTC_MODEL: PMIC RTC update/alarm completion + PMIC interrupt controller.
# The stock RTC driver (0x80c50528 set-time: write SEC/MIN/HOUR/DAY_UPD
# 0x40608210-0x4060821c, mark state 0x81704478 |= 0xf00) waits in
# 0x80c504ca (20 ms sleeps, forever) until its ISR 0x80c50306 clears the
# state bits from RTC INT_RAW 0x40608234 bits 8-11 (alarm regs 0x220-0x22c:
# bits 12-15). With a pure PMIC store the MMI task (P_APP) sat in that loop
# from 58.8M, so its queue filled and nothing after SIM-ready ran. Model:
# an update write completes at once (raw bit set), INT_CLR 0x40608238 is
# W1C; RTC = PMIC int 1 in the ANA int controller 0x406080c0 (+0 masked
# status, +4 raw, +8 enable); PMIC dispatcher 0x80a4f08a = table irq 0x26
# -> GIC id 0x46 (level).
RTC_MODEL = True
PMIC_GIC_ID = 0x46
# I2C_MODEL: AP I2C0/1/2 (driver 0x810f94ec, ISR 0x810f8fd8): CTL +0 (bit0
# START, bit3 read, bit11 int enable, bit20 stop), ADDR +4, COUNT +8, RX
# +0xc, TX +0x10, STATUS +0x14 (bit1 NACK, bit2 INT), RST +0x2c. The
# driver waits forever on its "i2c_wait" queue for the ISR; with no model
# the MMI task hung in the first transfer (62.2M, camera sensor probe).
# Model = empty bus: every transfer completes at once, writes are NACKed
# (driver returns -1), reads return 0x00. Every transfer is logged
# ([I2C  ] lines, runs/<dir>/i2c.txt).
I2C_MODEL = True
# LCDC_MODEL: AP display controller 0x20800000 frame-done interrupt. Driver:
# run = CTRL bit3 (0x810ba6ba), IRQ enable +0x110, clear +0x114 (W1C),
# masked status +0x118, raw +0x11c; ISR 0x810ba496 (TB_LCDC_INT, GIC 0x33)
# -> HISR sets event group "LCD_SYNC", which the MMI task waits on with no
# timeout for every refresh. Model: a run (bit3 0->1) completes the frame
# at once: raw bit0 (done) set, run bit self-clears; level IRQ while
# raw & enable. Raw bit1 (panel TE) reads as set (see _lcdc_read).
LCDC_MODEL = True
LCDC_GIC_ID = 0x33
# AP_TMR_MODEL: the OS tick is AP TMR0 at 0x40220000 (32768 Hz; HAL ops
# 0x817052f4: LOAD lo +0 / hi +4, CTRL +0x10 bit0 periodic, bit1 run,
# bit16 64-bit; INT +0x14 bit0 enable, bit3 clear; value +0x18), IRQ
# TB_AP_TMR0_INT (GIC 0x3d). The OS is tickless: when idle it programs a
# one-shot LOAD up to the next timer (seen: 0x10000 = 2 s) and on the IRQ
# credits the whole period. Firing TMR0 every 1 ms regardless made the OS
# clock run ~2000x fast while idle - the LTE AS power-on guard (20 s)
# expired ~10 ms after it was armed and EMM asserted. Model: run (bit1
# 0->1) arms the IRQ LOAD counts later (AP_TMR_INSN_PER_COUNT insns per
# count = tick_rate ms scale), periodic reloads, +0x18 reads the remaining
# count. Until the guest first starts TMR0 the old 1 ms cadence is used.
AP_TMR_MODEL = True
AP_TMR_BASE = 0x40220000
# CTR_REALTIME: the free-running counters run at their hardware rates in
# virtual time instead of 1 count per insn: SYST 0x40230000 +4/+0xc is the
# 1 kHz ms counter (spec ch6.9 "+1 per ms"; the OS timer list keeps
# absolute expiries in it: 0x80a323b2 rewrites a 20000 ms timer to
# [+0xc]+20000; 0x80a077ac = seconds), sysfrt 0x40040000 is 32768 Hz (udelay
# 0x80a0b63e: 30 us per count). At 1 count/insn every OS timer expired
# 200000x early (LTE AS power-on guard, 20 s, after ~0.1 ms).
CTR_REALTIME = True
# PMIC_EFUSE_READY: PMIC eFuse controller status 0x40608314 reads bit2
# (clear done) + bit4 (read done) set. Its waits (0x80aa7a50, 300 ms
# timeout on the SYST us clock) used to time out in ~1.5K insns while that
# clock ran 200x fast; at real rate each read cost 60M insns. Data
# (0x40608304) stays 0 - PLACEHOLDER eFuse contents, as before.
PMIC_EFUSE_READY = True
# LTE_ADX_STUB: the LTE DSP side of the ADX channel (layer1_adx_*.c).
# Release: 0x402e0248 = boot vector (0x80448400>>1), 0x402e024c bit0 run
# (0x80e2d9e6 dsp_init). LTE_adx_InitInterface (0x80b6c4f2) then blocks on
# "l1c_send_cmd_sema" (created at 0) until the DSP reports its version:
# response ring in AP IRAM 0xe478 (+0 u16 in, written by the DSP; entries
# at +4 + 8*i: u16 type, u16 len, u32 addr; data at addr + 0xfbec; 12
# entries), doorbell = DSP-side counter 0x11d08 changes + mailbox message
# from core 3 (handler 0x811f278e -> 0x813f1c04 drains the ring -> task
# LTE_layer1_adx 0x80c109a4: type 5 = version -> stores it, clears
# IsDspLoadingCode, posts the semaphore). Without it LCONTROL waited
# forever and EMM's 20 s AS power-on guard asserted. Payload values are
# PLACEHOLDERS (branch/svn 0, chip id from 0x80447e18).
LTE_ADX_STUB = True
# RES_MODEL: the "BML MMI Resource Partition" (mmi_res.bin, sres0001
# container: images, fonts, strings). Its only reader is the kernel's
# MMIRES read 0x80c370dc (r0=dst, r1=offset, r2=len; nonzero = ok), which
# opens the partition through the FFS named-device registry that nothing
# populates in emulation (see the NV_Init note), so every read failed and
# the MMI ran with an empty resource header: no wallpaper, icons or fonts
# (idle window painted black). Served from the partition image instead.
# Read at MMI init (~200M): a checkpoint taken before this flag existed
# keeps the empty header - re-boot fresh.
RES_MODEL = True
# Image: an ECC-corrected read of the mmi_res partition (e.g. through FDL2). A raw
# NAND main-area copy WITHOUT ECC correction has ~2.5k random 0->1
# bit flips (~1 per page; every difference vs the 9000 copy is an extra set bit).
# Flips in the vector-font glyph data drew some characters as solid cells or
# dropped them (k, m, d ...).
MMI_RES = fwpaths.MMI_RES
RES_LOG = int(os.environ.get('RES_LOG', '20'))   # [RES  ] lines logged per run
ADX_RESP_RING = 0xE478
ADX_RESP_N = 12
ADX_DATA_BASE = 0xFBEC
ADX_DOORBELL = 0x11D08
ADX_CORE = 3
ADX_BOOT_INSNS = 200_000        # "DSP boot" time before the first report (1 ms)
# AP->DSP command ring ([0x8175dde0] = 0xe400): +0 u16 wr (AP), +2 u16 rd
# (DSP), entries at +4 + 8*i (8): u16 cmd type, u16 len, u32 offset; data
# at 0xe4e0 + offset; doorbell = mailbox message to core 3. The stub
# consumes every entry (rd := wr) and logs it (adx_cmd.txt).
ADX_CMD_RING = 0xE400
ADX_CMD_N = 8
ADX_CMD_DATA = 0xE4E0
# L1 primitives travel as type-0 commands: u16 card, u16 0x5555, u32 msg id,
# payload (e.g. 0x94 CPHY_CARD_INFO_REQ). PAL (0x80e04244) dispatches the
# DSP's type-0 responses by id; confirms are request id + 1 (0x95 posts the
# PhyConfigReq semaphore via 0x80e04194). ADX_AUTO_CNF: answer every request
# with id+1 and a zeroed payload of the request's size - a PLACEHOLDER
# "success" until each confirm's real layout is known. DSP->AP data area:
# resp addr + 0xfbec, addr + len < 0x100c.
ADX_AUTO_CNF = True
ADX_CNF_DELAY = 40_000          # 0.2 ms
# Message direction table (0x8175d1ac, 12 bytes per id 0..0xad, used by the
# trace 0x811ade40): +4/+8 = src/dst task, 0xf7 = LTE L1 (LCONTROL) and
# 0x78 = DSP. The auto reply is the first id after the request whose
# direction is DSP->AP (0x94->0x95, 0x87->0x88, 0x70 CPHY_BAND_SWEEP_REQ
# -> 0x72; 0x71 is another AP->DSP id).
ADX_DIR_TABLE = 0x8175D1AC
# Reply payload sizes where the confirm is larger than the request.
# 0x72 band sweep result: PAL handler 0x80ee615a reads up to +0x46c
# (result count, <= 10). ADX_SCAN_RESULT: "no cell found" (count 0) -
# PLACEHOLDER until a phone capture gives real sweep results.
ADX_REPLY_LEN = {0x72: 0x480}
ADX_SCAN_RESULT = "cell"
# Synthesized LTE cell (SIM_CELL): band 3 EARFCN 1300 (1815 MHz DL), PCI 1,
# RSRP -80 dBm, RSRQ -10 dB (levels *16 as the PAL scales x100/16).
# PLACEHOLDER radio values; PLMN = the virtual SIM's HPLMN 001/01.
SIM_CELL = {"earfcn": 1300, "pci": 1, "rsrp": -80, "rsrq": -10}
# Scripted DSP reactions for the synthesized cell, beyond the generic reply
# (req id -> [(reply id, delay insns, filler)]). Requests 0x11..0x21 are
# answered in the low id range (req - 0x10: 0x13 -> 0x03, a confirm that
# carries a level at +0xa (x16) valid when +0xc != 0). 0x74 (sync/camp on
# earfcn+pci) -> generic 0x76, then MIB indication 0x02 (PAL 0x80ee39c2 ->
# pal_encode_mib 0x80c37c6a; fields u32 +0xc, u32 +0x10, u8 +0x14, u16
# +0x16 - values chosen valid under either mapping: bandwidth n50 / SFN).
ADX_SCRIPT = {
    0x13: [(0x03, 40_000, "sync_cnf")],
    # 0x74's own search/sync result id is not identified yet (0x01, 0x03,
    # 0x76 and the forwarded ids 0x00/0x07/0x08/0x09/0x0d/0x80 with
    # earfcn/pci did not advance RRC). MIB only.
    0x74: [(0x02, 2_000_000, "mib")],
}
if os.environ.get("ADX_TRY74"):                 # experiment: answer 0x74 with this id
    ADX_SCRIPT[0x74] = [(int(os.environ["ADX_TRY74"], 0), 200_000, "try"), (0x02, 2_000_000, "mib")]
I2C_CTLS = ((0x70500000, 0x2B), (0x70600000, 0x2C), (0x70700000, 0x2F))

# --- fast-turnaround tooling (2026-10-30) ---------------------------------
# Full-state checkpoints: ckpt_save()/MocorEmu.ckpt_load(). Captures every
# mapped region (incl. auto-mapped pages; zero 64K pages skipped), the
# native CPU context (banked regs included) and every picklable model
# attribute. The flags below + a source hash are recorded so a stale
# checkpoint is reported on load (warning only - loading a checkpoint
# taken before a model change is valid as long as the changed model was
# not exercised before the checkpoint's insn count).
CKPT_FLAGS = ("CELL_CUTS", "STRICT", "NV_LEGACY_FILL", "MMI_PRELOAD",
              "PMU_MODEL", "NV_REAL", "RF_MODEL", "RF_CHIP_ID",
              "HWSPINLOCK", "WFI_WAKE", "WTL_TIMER", "CP_STUB",
              "SDHCI_MODEL", "PMIC_ADC", "PMIC_ADC_RAW", "GIC_MODEL", "BLOCK_HOOKS", "CP15_INLINE", "MMU_GUARD", "INTR_HOOK", "CTR_POLL_SKIP", "TICK_EXACT_CHUNKS", "CTR_PAGES_UNHOOKED", "GIC_UNMASK_SITES", "NATIVE", "MMIO_NATIVE", "CONTINUOUS_TIME", "NATIVE_FAST", "NATIVE_BLOCK_DISPATCH", "LOG_TAP", "GATE_D_MODE", "DSP_STUB", "SIM_MODEL", "RTC_MODEL", "I2C_MODEL", "LCDC_MODEL", "AP_TMR_MODEL", "CTR_REALTIME", "PMIC_EFUSE_READY", "LTE_ADX_STUB", "RES_MODEL")
CKPT_SKIP = {"mu", "run", "_res_img", "deadline", "max_insns", "pump", "mode", "entry",
             "bps", "bps_armed", "tail_hook", "trace_tail", "wps",
             "stop_reason", "stop_detail", "stall_insns", "save_at",
             "_stall_hook", "_cp_tsv", "_gic_watch_h", "_gic_waiting",
             "_exact_code_hooks", "_raw_hook_add", "_native", "nst",
             "_native_lib", "_native_hooks", "_dev", "_py_mem_hooks",
             "_py_rd_cb", "_py_wr_cb", "_dev_bases", "_mmio_native", "_py_exc",
             "_uc_mem_read", "_uc_mem_write", "_py_blk", "_py_blk_cb", "_py_hook_cache", "_glog_f",
             "_sim_f", "_i2c_f", "_adx_f"}   # hook handles are per-process
CKPT_SKIP_PREFIX = ("_ct_",)
# Stall detector: stop when the run makes no progress for STALL_INSNS
# (no new radio-range MMIO write address, no new NV read, no new cell
# trace row, no new mailbox message, no new 64-byte PC bucket at chunk
# ends) and write stall_profile.txt (hot blocks, disassembly, stack code
# pointers) from a 1M-insn block profile. 0 = off.
STALL_INSNS = 0
# GIC_MODEL: GIC-400 distributor (0x12001000) + CPU interface (0x12002000)
# state instead of forced IRQ injection. Sources set PENDING (OS tick id
# from tick_irq_cycle on the tick cadence; mailbox CP->AP FIFO non-empty
# -> id 0x65, level). An IRQ is taken only when CPSR.I is clear; while
# masked a temporary block hook stops the chunk at the first unmasked
# block (so the guest's own cpsie/msr ends the wait) - WFI just wakes.
# GICC_IAR acks the lowest pending+enabled id (-> active), GICC_EOIR ends
# it. Before the kernel's GIC init ([0x817b1d38+4] == 0) the dispatcher
# reads the id from RAM 0x0c and enables are not yet programmed: every
# pending id is deliverable and is consumed on delivery (legacy path).
# The old forced injection is kept ONLY for the pre-OS park loops.
GIC_MODEL = True
# --- speed (2026-10-30) ---------------------------------------------------
# Unicorn checks EVERY address-specific UC_HOOK_CODE hook on EVERY executed
# instruction (measured on this firmware: 0 hooks 160 MIPS, 10 hooks 51,
# 200 hooks 3.9), while bounded UC_HOOK_BLOCK hooks are resolved at
# translation time (200 hooks: 138 MIPS). The emulator had 357 code hooks
# (190 CP15 inline sites, 130 unmask sites, 37 behaviour hooks) -> ~1.5 MIPS.
# BLOCK_HOOKS: register single-address code hooks as block hooks. Verified
# equivalent (hit counts, 20M-insn window) for function-entry hooks and for
# the unmask sites (QEMU ends the TB after cpsie/msr cpsr). Addresses in
# CODE_HOOK_EXACT are mid-block and stay true code hooks.
BLOCK_HOOKS = True
CODE_HOOK_EXACT = {0x80c2f1f2, 0x80c2f23e, 0x80c2f244, 0x80c2f30c,  # power-state wait heads
                   0x10A4}                                          # blob msr
# CP15_INLINE: the 190 inline CP15 site hooks. Off: unicorn executes CP15
# natively; the registers it cannot emulate raise and are serviced by the
# _loop backstop (as before for non-hooked classes), and class promotion
# (which re-adds code hooks) is disabled. Native values for the classes
# unicorn does implement are the real Cortex-A7 ones (e.g. CLIDR 0x0a200023
# - the Python model returned 0xf0123).
CP15_INLINE = False
# What the CP15 inline hooks really provided (found 2026-10-30): (1) the
# MMU stayed OFF - the Python model swallowed SCTLR writes, and the
# emulator depends on a flat map (mmi_app at 0x88000000 is preloaded, not
# mapped by the guest page tables -> native SCTLR.M=1 = prefetch abort at
# 0x880ac3bc); (2) precise servicing of raising CP15 ops. Without per-insn
# hooks:
# MMU_GUARD: SCTLR.M is cleared at every chunk boundary and on any
# prefetch/data abort (which is then retried).
# INTR_HOOK: one UC_HOOK_INTR (zero per-insn cost) services undefined-
# instruction exceptions precisely: CP15 ops via _cp15_service (user mode
# -> guest UND, as on hardware), anything else stops the run.
MMU_GUARD = True
INTR_HOOK = True
SCTLR_REG = (15, 0, 0, 1, 0, 0, 0)
# CTR_POLL_SKIP: the free-running counters (0x40040004/0x4023000c) are
# derived from insn_total, which only advances per chunk - inside a chunk
# they are frozen, so every busy-wait delay spun out the rest of the chunk
# (380K Python callbacks per 20M insns, 0x80a0b586/0x80a0b620). A counter
# read immediately following another counter read (no other MMIO read in
# between) is a busy-wait poll: advance virtual time by this many insn
# units per poll, like WFI does for idle. 0 = old behaviour.
CTR_POLL_SKIP = 0      # 1000 = 2x faster but breaks the boot path (timeout waits), see matrix 2026-10-30
# TICK_EXACT_CHUNKS: a chunk never runs past the next OS-tick due time, so
# ticks are not coalesced (with 40K-insn ticks and 200K chunks, 4 of every
# 5 ticks were silently dropped). Chunks that stop early are accounted by
# cause: WFI -> virtual time jumps to the next tick (idle fast-forward);
# busy-wait skip -> already advanced, capped at the next tick; unmask stop
# -> small fixed cost. Only full chunks add their exact count.
TICK_EXACT_CHUNKS = True
# CTR_PAGES_UNHOOKED: the free-running counter pages (0x40040000 sysfrt,
# 0x40230000 AP sys timer) are excluded from the Python read hook and their
# [+4]/[+0xc] cells are written with insn_total at every chunk start - the
# exact values the old per-read callback returned (insn_total only changes
# between chunks), without ~450K ctypes callbacks per 20M insns.
CTR_PAGES_UNHOOKED = True
# GIC_UNMASK_SITES: the 130 unmask-site block hooks cost ~20% (every bounded
# block hook is checked on every executed block). Off: a WFI exit with an
# IRQ pending and the guest masked single-steps (<= GIC_WFI_STEP_MAX insns)
# until the idle path unmasks and takes the IRQ there; other masked windows
# keep GIC_MASKED_CHUNK latency.
GIC_UNMASK_SITES = False
GIC_WFI_STEP_MAX = 2000
# NATIVE: hot paths in C (native/emu_native.c -> emu_native.dll, built with
# `python -m ziglang cc`), registered straight into unicorn with C function
# pointers - no Python frame / ctypes trampoline per event. Falls back to
# the Python paths if the DLL is missing.
#   blk_unmask_cb: one unbounded UC_HOOK_BLOCK; while an IRQ waits for the
#   guest to unmask it stops at the first block with CPSR.I clear. Replaces
#   the unmask-site hooks, the WFI single-stepping (142K emu_start calls per
#   40M insns) and the short masked chunks.
NATIVE = True
NATIVE_DLL = os.path.join(ROOT, "native", "emu_native.dll" if os.name == "nt" else "emu_native.so")


class NativeState(ctypes.Structure):
    """Mirror of NativeState in native/emu_native.c."""
    _fields_ = [("gic_waiting", ctypes.c_int32), ("stop_cause", ctypes.c_int32),
                ("unmask_stops", ctypes.c_uint64), ("insn_now", ctypes.c_uint64),
                ("mmio_c_reads", ctypes.c_uint64), ("mmio_c_writes", ctypes.c_uint64),
                ("mmio_py_reads", ctypes.c_uint64), ("mmio_py_writes", ctypes.c_uint64),
                ("est", ctypes.c_uint64)]


# CONTINUOUS_TIME (needs NATIVE): every timer model used to return a value
# derived from insn_total, which is frozen for a whole chunk - so device
# time depended on where chunks happened to end, and changing chunking
# (e.g. the native unmask stop) sent the boot down another path. The C
# block hook now accumulates an executed-insn estimate (block bytes * 2/5)
# and all timers read _now() = insn_total + estimate; early-stopped chunks
# are accounted with the estimate too.
# NATIVE_FAST: C device models for the hottest registers (emu_native.c
# fast_read/fast_write): ADI doorbell (0x40600020-0x40600033), LTE frame
# timer (0xE0020010/14, latch 0xE0020028), SDHCI CLK_CTRL (+0x2c). Same
# semantics as the Python models they bypass. Side effect: these accesses
# no longer reach the cell trace / ADI_BELL events (they were capture noise
# and are excluded from the CELL_CAPTURE files anyway).
NATIVE_FAST = True
# NATIVE_BLOCK_DISPATCH: single-address block hooks (incl. the converted
# code hooks) go into the C block hook's sorted address table instead of
# unicorn's hook list; Python runs only when such a block starts.
NATIVE_BLOCK_DISPATCH = True
# LOG_TAP: the guest's own debug trace, which the emulator otherwise drops
# (no diag host). printf-style SCI trace 0x8109e31e (r0 = format, varargs;
# 5573 call sites) is formatted; the ID trace 0x810994f2 (r0 module, r1 id,
# r2 nargs, r3/stack args; 9007 sites, no strings in the image) is logged
# raw. -> runs/<dir>/guest_log.txt
LOG_TAP = True
# DSP_STUB: stand-in for the GSM DSP firmware (no DSP core is emulated).
# Shared window 0x800e0000 (fw_modem); AP-staged param block at +0x19670
# (GSM L1 command block). The stock L1 (sharedmem_proc.c, wait loop
# 0x80ef4512) polls the DSP-written run word [win+0x19670+0x634] through
# the stable-read helper 0x80eeea92 and asserts "GSM DSP not Run after
# Mode Change!!" after 5000 tries. Model: the AP's GSM DSP release
# (AON 0x402e0254 = 1 with boot vector 0x402e0250) starts the "DSP"; while
# it runs, a poll of the run word reads DSP_RUN_VALUE. Every release and
# poll is logged ([DSP  ] lines / DSP_* events).
DSP_STUB = True
# SIM_MODEL: USIM controllers SIM0 0x70F00000 (virtual card inserted) and
# SIM1 0x71000000 (empty slot) + T=0 virtual UICC (vsim.py). Level IRQ:
# SIM0 table irq 10 -> GIC id 0x2a, SIM1 13 -> 0x2d. APDUs logged as
# [SIM  ] lines and runs/<dir>/sim_apdu.txt.
SIM_MODEL = True
SIM_CTLS = ((0x70F00000, 0x2A, True), (0x71000000, 0x2D, False))
DSP_GSM_WIN = 0x800E0000
DSP_GSM_RUN = DSP_GSM_WIN + 0x19670 + 0x634
DSP_RUN_VALUE = 1
# fields the GSM DSP firmware publishes in its param block once running
# ({offset from win+0x19670: (size, value)}). PLACEHOLDER values: only
# their non-zero-ness is checked so far (sharedmem_proc.c:7471,
# 0x80ef45a4: rf_open [+0x770] / rf_close [+0x772] -> 0x81712bac+8/+0xa);
# the real numbers come from the DSP (or a live dump of the window).
DSP_GSM_PUBLISH = {0x770: (2, 100), 0x772: (2, 40)}
# LTE XDSP boot (0x80d2d5f0): clear ready [0xe0419908], copy the boot image
# (0x815019b4, [0x81713f3c] words) to 0xe0400000, zero 0xe0440000/0xe0448000,
# pulse ctl 0xe047f000 = 0x1e,0,1,0,0x1e, spin until ready == 1. Model:
# the XDSP boot code runs once the pulse (1 then 0x1e) completes.
DSP_XDSP_CTLS = (0xE047F000, 0xE04FF000)
DSP_XDSP_CORES = ((0xE0400000, 0xE0419908), (0xE0480000, 0xE0499540))   # (window, ready word)
DSP_XDSP_BOOTLOADERS = {0x815019B4, 0x81517684}
# GATE_D_MODE: legacy (writes boot mode := 3 - wrong field), power (power
# state := 3), timer (only enable the AON tick timer). See _gate_d_seed.
GATE_D_MODE = "timer"   # legacy wrote the boot mode and blocked PS start
LOG_TAP_ID = True
LOG_TAP_MAX = 200000
CONTINUOUS_TIME = False  # True changes the boot path (fewer mailbox opens by the stall) - needs a calibrated rate first


# MMIO_NATIVE: device windows are uc_mmio_map regions with C shadow memory
# and C callbacks instead of RAM + memory hooks. With ANY memory hook
# installed unicorn routes every guest load/store through a slow helper
# that scans the hook list (measured: 30 mem hooks + block hooks = 22 MIPS
# vs 155 bare). Memory hooks whose range lies in a device region are kept
# in a Python dispatch list (registration order preserved) and run from
# one Python callback per access that actually needs a model; the
# free-running counters are answered in C; Python mem_read/mem_write on
# device addresses go to the shadow. py=1: every access runs the Python
# models (exact old semantics); py=0: pure echo in C.
MMIO_NATIVE = True
DEV_REGIONS = [
    (0x10000000, 0x00100000, 1, "periph ext"),
    (0x12000000, 0x00100000, 1, "GIC400"),
    (0x20100000, 0x00010000, 0, "AP DMA"),          # C: echo + CHN_PAUSE status bit
    (0x20300000, 0x00400000, 0, "SDHCI"),           # C: echo + CLK_CTRL stable bit
    (0x20800000, 0x00300000, 1, "LCDC/ROTA/LCM"),
    (0x20E00000, 0x00100000, 1, "AHB reg AP"),
    (0x21A00000, 0x00060000, 1, "NANDC (SNF)"),
    (0x30000000, 0x00100000, 1, "AON periph + PUB"),
    (0x33000000, 0x00001000, 1, "HW spinlock"),
    (0x40000000, 0x10000000, 1, "MMIO main 0x40-0x50"),
    (0x50800000, 0x00100000, 1, "CM4 IRAM/AHB/RF_MASTER"),
    (0x515C0000, 0x00040000, 1, "RF SPI 0x515x"),
    (0x60000000, 0x04000000, 1, "LCM ports + whale AHB"),
    (0x70000000, 0x01800000, 1, "APB periph 0x70"),
    (0xD15D0000, 0x00020000, 1, "whale AON"),
    (0xE0000000, 0x01000000, 1, "WTL window"),
]
CTR_PAGES = (0x40040000, 0x40230000)
EARLY_STOP_COST = 500
GIC_MASKED_CHUNK = 20000  # chunk size while an IRQ waits for the guest to unmask
# Unmask sites: every instruction that can clear CPSR.I (Thumb cpsie i/if,
# Thumb-2 msr cpsr, ARM msr cpsr_c/fsxc, ARM cpsie) found by a static scan
# of the kernel + low-page blob gets a code hook on the FOLLOWING
# instruction; while an IRQ waits for the guest to unmask, the hook stops
# the chunk there so the IRQ is taken right after the unmask (hardware
# timing). Short unmask windows (idle/sleep retry loops) were missed by
# chunk-boundary polling and livelocked the deep-sleep entry.
GIC_FORCED_RANGES = ((0x80a06e00, 0x80a06f00), (0x81608000, 0x81608200))
STALL_PROFILE_INSNS = 200_000   # profiling pass uses a Python block hook: keep it short
WTL_TIMER = True
WTL_TS_PER_INSN = 30.72 / 200.0
NV_FIXED = fwpaths.NVCAL
NV_JOURNAL = fwpaths.NV_JOURNAL


def load_nv_db():
    """id -> (bytes, source). Fixed stream first; journal-only ids take the
    most common checksum-valid payload (ties: highest offset)."""
    fwpaths.need(NV_FIXED, 'nvcal partition; or run with --no-real-nv')
    fwpaths.need(NV_JOURNAL, 'RunningNV journal partition; or run with --no-real-nv')
    from parse_nv import parse_fixed_stream, scan_journal_records
    db = {}
    _, recs, _, _ = parse_fixed_stream(open(NV_FIXED, 'rb').read(), verbose=False)
    for rid, rlen, off, payload, st in recs:
        if payload is not None:
            db[rid] = (payload, "nvcal")
    for rid, copies in scan_journal_records(open(NV_JOURNAL, 'rb').read()).items():
        if rid in db:
            continue
        valid = [c for c in copies if c[3]]
        if not valid:
            continue
        cnt = Counter(c[4] for c in valid)
        best = max(valid, key=lambda c: (cnt[c[4]], c[0]))
        db[rid] = (best[4], "journal")
    return db
CELL_TRACE_RANGES = [
    (0x400A0000, 0x400B0000, "MAILBOX"),
    (0x40220000, 0x40230000, "DSP_BOOT"),    # 0x40224200 DSP boot area
    (0x402B0000, 0x402C0000, "PMU"),         # +0x1000 set / +0x2000 clr
    (0x402D0000, 0x402E0000, "AON_CLK"),
    (0x402E0000, 0x402F0000, "AON_APB"),
    (0x403E0000, 0x40400000, "ANLG"),
    (0x404D0000, 0x40500000, "MBX_ABC"),
    (0x40600000, 0x40610000, "ADI"),
    (0x50800000, 0x50900000, "CM4_RF"),
    (0x515C0000, 0x51600000, "RF_SPI_515x"),
    (0x60830000, 0x60840000, "WHALE_AHB"),
    (0x70F00000, 0x71100000, "SIM"),
    (0x40070000, 0x40080000, "RFTI"),        # AP->RF transceiver serial port
    (0xD15D0000, 0xD15F0000, "WHALE_AON"),   # whale AON / PMU banks (auto-mapped RAM)
    (0xE0000000, 0xE0020000, "WTL_AP"),      # whale/WTLCP window seen from the AP
    (0xE0020018, 0xE1000000, "WTL_AP"),      # (frame timer 0xe0020010-17 excluded: hot)
]
# Entry points of interest: logged with r0-r3/lr on every call.
CELL_FUNCS = {
    0x80d0fa7c: "lte_preboot(doc VA)",
    0x80d0fab4: "lte_preboot(+0x38 VA)",
    0x80d0fad8: "lte_dsp_preboot_wrapper",
    0x80d0f944: "rf_hal_radio_on",
    0x80d0f4fa: "rf_hal_power_seq",
    0x80c5b6c0: "app_init_post_master",
    0x80c2eee6: "vbm_fw_load",
    0x811d0d96: "hal_dsp_power_poll",
}

# C assert handler: called as (expr, file, line) -- logged then force-returned
ASSERT_TRAP = 0x80a0b00a

# Mocor sprintf-class function: (r0=fmt, r1=buf, r2,r3,[sp..]=varargs).
# Trapped: formatted in Python, written to buf, force-return. This both
# unblocks the stack-smash overflow and yields the kernel's own log output.
SPRINTF_TRAP = 0x80dccd54   # console-out dispatcher: bx [global]; global=0 here
ITOA_TRAP    = 0x80dccd6c   # decimal itoa: (r0=value, r1=buf)

# Mocor sprintf-class function: (r0=fmt, r1=buf, r2,r3,[sp..]=varargs).
# Trapped: formatted in Python, written to buf, force-return. This both
# unblocks the stack-smash overflow and yields the kernel's own log output.
SPRINTF_TRAP = 0x80dccd54   # console-out dispatcher: bx [global]; global=0 here
ITOA_TRAP    = 0x80dccd6c   # decimal itoa: (r0=value, r1=buf)


def mini_printf(uc, fmt_addr, argregs, sp):
    """Format the NUL-terminated fmt string at fmt_addr (Thumb C variadic)."""
    def cstr(a):
        out = []
        for i in range(200):
            try:
                b = uc.mem_read(a + i, 1)[0]
            except UcError:
                break
            if b == 0:
                break
            out.append(b)
        return bytes(out).decode("ascii", "replace")

    def s32(v):
        return v - 0x100000000 if v & 0x80000000 else v

    fmt = cstr(fmt_addr)
    args = list(argregs)
    for i in range(16):
        try:
            args.append(int.from_bytes(uc.mem_read(sp + i * 4, 4), "little"))
        except UcError:
            break
    argi = 0

    def next_arg():
        nonlocal argi
        v = args[argi] if argi < len(args) else 0
        argi += 1
        return v

    out = []
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c != "%":
            out.append(c); i += 1; continue
        j = i + 1
        if j < len(fmt) and fmt[j] == "%":
            out.append("%"); i = j + 1; continue
        zero = False
        while j < len(fmt) and fmt[j] in "0-+ #":
            if fmt[j] == "0":
                zero = True
            j += 1
        w = 0
        while j < len(fmt) and fmt[j].isdigit():
            w = w * 10 + int(fmt[j]); j += 1
        while j < len(fmt) and fmt[j] in "lhz":
            j += 1
        if j >= len(fmt):
            break
        conv = fmt[j]; i = j + 1
        v = next_arg()
        if conv in "dib":
            s = str(s32(v))
        elif conv == "u":
            s = str(v & 0xFFFFFFFF)
        elif conv in "xX":
            s = format(v & 0xFFFFFFFF, conv)
        elif conv == "p":
            s = "0x%08x" % v
        elif conv == "c":
            s = chr(v & 0xFF)
        elif conv == "s":
            s = cstr(v)
        else:
            s = "%" + conv
        if w > len(s):
            s = s.rjust(w, "0" if zero else " ")
        out.append(s)
    return "".join(out)
def mini_printf(uc, fmt_addr, argregs, sp):
    """Format fmt at fmt_addr using regs r2,r3 then stack words. Returns str."""
    def cstr(a):
        out = []
        for i in range(200):
            try:
                b = uc.mem_read(a + i, 1)[0]
            except UcError:
                break
            if b == 0:
                break
            out.append(b)
        return bytes(out).decode('ascii', 'replace')

    def s32(v):
        return v - 0x100000000 if v & 0x80000000 else v

    fmt = cstr(fmt_addr)
    args = []
    for r in argregs:
        args.append(r)
    nstack = fmt.count('%')  # upper bound
    for i in range(min(nstack + 4, 16)):
        try:
            args.append(int.from_bytes(uc.mem_read(sp + i * 4, 4), 'little'))
        except UcError:
            break
    argi = 0

    def next_arg():
        nonlocal argi
        v = args[argi] if argi < len(args) else 0
        argi += 1
        return v

    out = []
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c != '%':
            out.append(c); i += 1; continue
        j = i + 1
        if j < len(fmt) and fmt[j] == '%':
            out.append('%'); i = j + 1; continue
        # flags
        zero = False
        while j < len(fmt) and fmt[j] in '0-+ #':
            if fmt[j] == '0':
                zero = True
            j += 1
        # width
        w = 0
        while j < len(fmt) and fmt[j].isdigit():
            w = w * 10 + int(fmt[j]); j += 1
        # length
        ln = ''
        while j < len(fmt) and fmt[j] in 'lhz':
            ln += fmt[j]; j += 1
        if j >= len(fmt):
            break
        conv = fmt[j]; i = j + 1
        v = next_arg()
        if conv in 'dib':
            s = str(s32(v))
        elif conv == 'u':
            s = str(v & 0xFFFFFFFF)
        elif conv in 'xX':
            s = f"{v & 0xFFFFFFFF:{conv}}"
        elif conv == 'p':
            s = f"0x{v:08x}"
        elif conv == 'c':
            s = chr(v & 0xFF)
        elif conv == 's':
            s = cstr(v)
        else:
            s = f"%{conv}"
        if w > len(s):
            s = s.rjust(w, '0' if zero else ' ')
        out.append(s)
    return ''.join(out)

# ---------------------------------------------------------------- memory layout
RAM_REGIONS = [
    (0x00000000, 0x01000000, "AP low RAM (module region)"),
    (0x00020000, 0x00001000, "AON RAM"),
    (0x30000000, 0x00100000, "AON Periph + PUB (DDR ctrl)"),
    (0x80000000, 0x40000000, "DDR (AP, 1GB full window)"),
    # fetches from 0x81605e00-0x88000000 still XFAULT via the check below
    (0xC0000000, 0x00100000, "Stack"),
]
MMIO_MAPS = [
    (0x12000000, 0x00100000, "CA7 GIC400"),
    (0x20E00000, 0x00010000, "AHB reg (AP)"),
    (0x40000000, 0x10000000, "MMIO main 0x40-0x50"),
    (0x50800000, 0x00100000, "CM4 IRAM/AHB/RF_MASTER"),
    (0x60830000, 0x00010000, "Whale AHB_reg"),
    (0x70000000, 0x01800000, "APB periph 0x70 (UART/SIM/pads/INTC)"),
    (0x88000000, 0x01000000, "mmi_app region (DDR wrap alias)"),
    (0xFFF00000, 0x00100000, "Top-of-memory (exception/init stacks @0xFFFFExxx)"),
]

BLOCK_NAMES = {
    0x402B0000: "PMU(AON)",  0x402D0000: "AON_CLK",   0x402E0000: "AON_APB",
    0x400A0000: "MAILBOX",   0x403E0000: "ANLG_TOP",  0x403F0000: "ANLG_G4",
    0x300E0000: "PUB/DDR",   0x404D0000: "MBX_A",     0x404E0000: "MBX_B",
    0x404F0000: "MBX_C",     0x60830000: "WHALE_AHB", 0x12000000: "GIC400",
    0x20E00000: "AHB_AP",    0x70000000: "UART0",     0x70F00000: "SIM0",
    0x71000000: "SIM1",      0x71300000: "PADS",      0x71400000: "INTC0",
    0x71500000: "INTC1",     0x71600000: "INTC2",     0x71700000: "INTC3",
    0x50800000: "CM4",       0x50820000: "CM4_AHB",   0x50830000: "RF_MASTER",
}
# ranges whose writes are radio-relevant (full trace kept for the report)
RADIO_WRITE_RANGES = [
    (0x402B0000, 0x402C0000), (0x402D0000, 0x402F0000),
    (0x60830000, 0x60840000), (0x404D0000, 0x40500000),
    (0x20E00000, 0x20E10000), (0x400A0000, 0x400B0000),
]

HW_DEFAULTS = {
    0x402E00FC: 0x98180001,   # chip ID
    # TGDSP boot vector reg; READ side = boot status (write=vector, read=status).
    # On HW the TGDSP boot ROM sets status=1 during whale power-on, before the
    # kernel runs. (LDSP side 0x402b0248/4C is driven at radio-on instead.)
    0x402B0250: 0x00000001,
}

# AP System Timer (spec ch6.9 pp1273-1277): 0x40230000, RTC-clocked,
# 32-bit free-running +1 per ms. Kernel waits on ThreadX tick advanced by IRQ31.
UNTIL_NEVER = 0x1_0000_0000  # unreachable stop address (0 would stop at PC=0!)
SYST_BASE = 0x40230000
AON_TMR_BASE = 0x40250000        # AON tick timer (ThreadX tick source)
INTC0_BASE = 0x71400000          # INTC0: SYST = channel 31
INTC_ENABLE = INTC0_BASE + 0x08  # bit31 = SYST line
INTC_STATUS31 = INTC0_BASE + 0xA0  # bank1 + 0x20: bit15 = SYST pending
SNF_BASE = 0x21A00000              # NANDC (SPI-NAND controller), spec ch 5.8
SNF_PAGE = 2112                    # 2048 main + 64 OOB
BOOT_MONO = time.monotonic()

# ---------------------------------------------------------------- tuning
CHUNK          = 200000      # instructions per emu_start chunk
# Real IRQ numbers (dispatch-table ids + 0x20) cycled into [0x0C] on each
# forced tick so the shared ISR dispatches each registered handler in turn.
TICK_IRQ_CYCLE = [0x3d]  # TEMP: real 61
TICK_IRQ_CYCLE_FULL = [0x22, 0x23, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
                 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
                 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3c, 0x3d, 0x3f,
                 0x42, 0x43, 0x44, 0x45, 0x46, 0x4d, 0x50, 0x51, 0x52,
                 0x54, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5d, 0x63, 0x64,
                 0x65, 0x66]
PROGRESS_EVERY = 2000000
HIT_PUMP       = 100000      # tick-loop hits between pumps
HIT_UNSTICK    = 300000      # generic hot-poll hits before unstick gen
MAX_UNSTICK_PER_KEY = 3
MAX_UNSTICK_TOTAL   = 8
TICK_PC        = 0x812f5ac2  # known Thumb delay loop: ldr r0,[r1,#0xc]; cmp; blo
                              # (0x812f5a58 is not the loop)
UART_LO, UART_HI = 0x70000000, 0x70100000
# UART0-2 occupy 0x70000000-0x702fffff. Everything else in the 0x70-0x72
# APB window (SIM0/1/2 0x70F0/0x7100/0x7110, pads 0x7130, INTC0-3
# 0x7140-0x7170) used to be routed to the UART handler and swallowed.
UART_END = 0x70300000

REG_LIST = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
            UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
            UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
            UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
            UC_ARM_REG_CPSR]
REG_NAMES = {}
for _i in range(13):
    REG_NAMES[REG_LIST[_i]] = f"r{_i}"
REG_NAMES[UC_ARM_REG_SP] = "sp"
REG_NAMES[UC_ARM_REG_LR] = "lr"
REG_NAMES[UC_ARM_REG_PC] = "pc"
REG_NAMES[UC_ARM_REG_CPSR] = "cpsr"
REG_NAMES[UC_ARM_REG_SPSR] = "spsr"
REG_BY_NAME = {v: k for k, v in REG_NAMES.items()}


def uc_pc(self):
    try:
        return self.mu.reg_read(UC_ARM_REG_PC)
    except Exception:
        return 0


def idx_uart_lsr(addr):
    return False


def now_s():
    return time.strftime("%H:%M:%S")


class Run:
    """Artifact sink for one emulation run."""
    def __init__(self, tag=None):
        ts = time.strftime("%Y%m%d_%H%M%S")
        self.dir = os.path.join(fwpaths.RUNS_DIR, f"{ts}" + (f"_{tag}" if tag else ""))
        os.makedirs(self.dir, exist_ok=True)
        self.log_f   = open(os.path.join(self.dir, "run.log"), "w", encoding="utf-8")
        self.ev_f    = open(os.path.join(self.dir, "events.jsonl"), "w", encoding="utf-8")
        self.uart_f  = open(os.path.join(self.dir, "uart.txt"), "wb")
        self.radio_w = []           # radio-relevant MMIO writes, ordered
        self.block_w = {}           # block base -> write count
        self.block_r = {}
        self.uart_bytes = 0
        self.n = 0                  # event counter

    def log(self, msg):
        line = f"[{now_s()}] {msg}"
        print(line, flush=True)
        self.log_f.write(line + "\n"); self.log_f.flush()

    def ev(self, etype, **kw):
        self.n += 1
        # batched writes: no per-event flush - close()
        # flushes; the <64KB tail on a hard kill is acceptable
        rec = {"i": self.n, "type": etype, **kw}
        self.ev_f.write(json.dumps(rec) + "\n")

    def uart(self, data: bytes):
        self.uart_f.write(data); self.uart_f.flush()
        self.uart_bytes += len(data)

    def close(self):
        for f in (self.log_f, self.ev_f, self.uart_f):
            try: f.close()
            except Exception: pass


class MocorEmu:
    def __init__(self, run, mode="unstick", entry=ENTRY, max_insns=20_000_000,
                 timeout_s=300, pump=True, trace_tail=0, cp15_shim=False):
        self.run = run
        self.mode = mode
        self.entry = entry
        self.max_insns = max_insns
        self.deadline = time.time() + timeout_s
        self.pump = pump

        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        if BLOCK_HOOKS:
            self._wrap_hook_add()
        if INTR_HOOK:
            self.mu.hook_add(UC_HOOK_INTR, self._on_intr)
        self._native = False
        if NATIVE:
            self._native_setup()
        self.insn_total = 0
        self.stop_reason = None
        self.stop_detail = None

        self.hw_regs = dict(HW_DEFAULTS)      # modeled MMIO word state
        if LCDC_MODEL:
            self.lcdc = {"ctrl": None, "raw": 0, "en": 0, "frames": 0}
        if I2C_MODEL:
            self.i2c = {base: {"ctl": 0, "st": 0, "addr": 0, "cnt": 0, "tx": [], "rx": [], "gid": gid}
                        for base, gid in I2C_CTLS}
        if SIM_MODEL:
            import vsim
            self.sim = {}
            for base, gid, has_card in SIM_CTLS:
                card = vsim.Card(log=self._sim_log) if has_card else None
                self.sim[base] = (vsim.SimCtl(base, card, self._sim_log), gid)
        if PMU_MODEL:
            self.hw_regs.update(PMU_RESET)
            self._pmu_state = None
            self._pmu_update()
        self.poll = {}                        # (pc,addr,size) -> [hits, gen, last_val, insn_str, first_pc]
        self.pump_count = 0
        self.unstick_count = 0
        self.wfi_count = 0
        self.tick_irq_cycle = TICK_IRQ_CYCLE
        self.pc_trace = deque(maxlen=48)   # sampled PC trail for runaway diagnosis
        self._rd_n = 0
        self.cp15_shim = cp15_shim
        self._cp_done = set()
        self.cp15 = CP15Model(run)
        self.mcrr = {}
        self.cp15_served = 0
        self.payload = None
        self.cp15_hook_classes = set(self.CP15_HOOK_CLASSES)
        self.cp15_sites = []
        self.snf_cfg = {0x04: 0, 0x08: 0, 0x0C: 0, 0x10: 0, 0x14: 0, 0x18: 0,
                        0x1C: 0, 0x30: 0, 0x34: 0, 0x38: 0x81000000, 0x3C: 0,
                        0x190: 0, 0x19C: 0, 0x1F0: 0, 0xD0: 0,
                        0x200: 0xFFFFFFFF, 0x204: 0, 0x208: 0xFFFFFFFF,
                        0x20C: 0, 0x210: 0xFFFFFFFF, 0x214: 0,
                        0x218: 0xFFFFFFFF, 0x21C: 0}
        self.snf_ins = [0] * 48
        self.snf_rbyt = 0
        self.snf_ecc = 0
        self._nand = None
        self._mmio_rd_hist = None
        self.tick_next = 1          # next virtual ms that raises the tick IRQ
        self.tick_pending = False
        self.tick_irq_cycle = TICK_IRQ_CYCLE
        self.cp15_skips = 0
        self.assert_count = 0
        self.trace_tail = trace_tail       # if >0: exact insn trace of last N insns
        self.insn_log = deque(maxlen=max(trace_tail, 1) if trace_tail else 64)
        self.tail_hook = None

        self.bps = OrderedDict()              # addr -> hook
        self.bps_armed = False
        self.wps = []                         # dicts: addr, kind, hook, stop
        self._setup_memory()
        self._pmic_static_init()
        self._setup_hooks()

    # ------------------------------------------------------------ memory
    def _map(self, base, size, name=""):
        page = base & ~0xFFF
        end = (base + size + 0xFFF) & ~0xFFF
        try:
            self.mu.mem_map(page, end - page, UC_PROT_ALL)
            self.run.log(f"  map {name or hex(page)}: {page:#x}+{end-page:#x}")
        except UcError:
            pass

    def _dev_covers(self, base, size):
        return any(b <= base and base + size <= b + n for b, n, _, _ in DEV_REGIONS)

    def _setup_memory(self):
        self._mmio_native = MMIO_NATIVE and getattr(self, '_native', False)
        if self._mmio_native:
            self._setup_dev_regions()
        for base, size, name in RAM_REGIONS:
            if not (self._mmio_native and self._dev_covers(base, size)):
                self._map(base, size, name)
        for base, size, name in MMIO_MAPS:
            if not (self._mmio_native and self._dev_covers(base, size)):
                self._map(base, size, name)
        # (map_full_space retired: 176 extra mappings caused unicorn
        # UC_ERR_RESOURCE exhaustion; the crash-resilient _loop handles
        # the firmware's native faults instead)
        data = open(fwpaths.need(KERNEL, 'kernel partition'), 'rb').read()
        payload = bytearray(data[KOFF:])
        n_patch = 0
        pos = 0
        while True:
            i = payload.find(IT_PATCH_FROM, pos)
            if i < 0:
                break
            payload[i:i+len(IT_PATCH_TO)] = IT_PATCH_TO
            n_patch += 1
            pos = i + len(IT_PATCH_TO)
        self.run.log(f"  IT-block patches applied: {n_patch}")
        self.run.ev("PATCH_IT", count=n_patch)
        if self.cp15_shim:
            n15 = cp15_shim_payload(payload)
            self.run.log(f"  CP15 remap shims applied: {n15}")
            self.run.ev("PATCH_CP15", count=n15)
        self.mu.mem_write(KBASE, bytes(payload))
        self.payload = bytes(payload)
        self.preload_modules()
        for fn in NOP_FNS:
            self.mu.mem_write(fn & ~1, bytes.fromhex("7047"))  # thumb bx lr
            self.run.log(f"  nop-fn: {fn:#x} (bx lr)")
            self.run.ev("NOP_FN", addr=hex(fn))
        for va, hx in RAW_PATCHES:
            self.mu.mem_write(va & ~1, bytes.fromhex(hx))
            self.run.log(f"  patch: {va:#x} <- {hx}")
            self.run.ev("PATCH_RAW", addr=hex(va), bytes=hx)
        for va, val in INIT_VA:
            self.mu.mem_write(va & ~3, val.to_bytes(4, 'little'))
            self.run.log(f"  init-va: {va:#x} = {val:#010x}")
            self.run.ev("INIT_VA", addr=hex(va), value=hex(val))
        self.run.log(f"  kernel: {len(payload):#x} bytes @ {KBASE:#x} (entry {ENTRY:#x})")

    def _auto_map(self, page):
        self._map(page, 0x1000, "auto")

    def map_full_space(self):
        """Map every remaining 16MB chunk of the 32-bit space (session
        32): the LTE/LCM glue firmware pre-loaded at 0x88-0x90xxxxxx
        wild-writes across its whole data area - per-page auto-mapping
        cannot serve writes that fault inside unicorn's native fast
        path (native host faults kill the process). With the full space
        mapped, firmware writes land in scratch RAM and execution
        continues. Modelled MMIO windows keep their hooks (hooks fire on
        access regardless of mapping)."""
        mapped = []
        for base, size, _n in list(RAM_REGIONS) + list(MMIO_MAPS):
            mapped.append((base, base + size))
        mapped.sort()
        merged = []
        for b, e in mapped:
            if merged and b <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((b, e))
        STEP = 0x1000000  # 16MB
        n = 0
        lo = 0
        for b, e in merged:
            hi = b
            while lo < hi:
                self._map(lo, min(STEP, hi - lo), "fullspace")
                n += 1
                lo = min(lo + STEP, hi)
            lo = max(lo, e)
        while lo < 0x100000000:
            self._map(lo, min(STEP, 0x100000000 - lo), "fullspace")
            n += 1
            lo += STEP
        self.run.log(f"  full-space mapping: {n} scratch chunks (firmware "
                     f"data areas live)")

    # ------------------------------------------------------------ hooks
    # ranges where Python must see accesses (device models); RAM runs native
    MMIO_HOOK_RANGES = [
        (0x10000000, 0x10100000),   # (reserved) periph window extensions
        (0x12000000, 0x12100000),   # GIC400
        (0x20800000, 0x20B00000),   # LCDC / ROTA / LCM
        (0x20E00000, 0x20F00000),   # AHB reg AP (clocks 0x20e01000/2000)
        (0x30000000, 0x30100000),   # AON periph + PUB
        (0x40000000, 0x50000000),   # MMIO main (PMU/CLK/AON_APB/AON tick/SYST)
        (0x50800000, 0x50900000),   # CM4 / RF master
        (0x60000000, 0x64000000),   # LCM data ports
        (0x70000000, 0x71800000),   # UART/SIM/pads/INTC0-3
        (0x21A00000, 0x21A60000),   # NANDC (SNF)
    ]

    def _setup_hooks(self):
        mu = self.mu
        for lo, hi in self.MMIO_HOOK_RANGES:
            rd = [(lo, hi)]
            if CTR_PAGES_UNHOOKED:
                for pg in CTR_PAGES:
                    nxt = []
                    for a, b in rd:
                        if a <= pg < b:
                            nxt += [(a, pg - 1), (pg + 0x1000, b)]
                        else:
                            nxt.append((a, b))
                    rd = nxt
            for a, b in rd:
                mu.hook_add(UC_HOOK_MEM_READ, self.on_read, begin=a, end=b)
            mu.hook_add(UC_HOOK_MEM_WRITE, self.on_write, begin=lo, end=hi)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                    UC_HOOK_MEM_FETCH_UNMAPPED, self.on_unmapped)
        if GIC_MODEL:
            self.gic = {"en": set(), "pend": set(), "active": [], "dctlr": 0,
                        "cctlr": 0, "acks": 0, "eois": 0, "taken": 0}
            mu.hook_add(UC_HOOK_MEM_READ, self._gic_read,
                        begin=0x12001000, end=0x12002FFF)
            mu.hook_add(UC_HOOK_MEM_WRITE, self._gic_write,
                        begin=0x12001000, end=0x12002FFF)
        else:
            mu.hook_add(UC_HOOK_MEM_READ, self._gicc_iar_read,
                        begin=0x1200200C, end=0x1200200F)
        if SDHCI_MODEL:
            mu.hook_add(UC_HOOK_MEM_READ, self._sdhci_read,
                        begin=0x20300000, end=0x206FFFFF)
        if HWSPINLOCK:
            self.hwlock_held = set()
            mu.hook_add(UC_HOOK_MEM_READ, self._hwlock_read,
                        begin=0x33000800, end=0x330008FF)
            mu.hook_add(UC_HOOK_MEM_WRITE, self._hwlock_write,
                        begin=0x33000800, end=0x330008FF)
        if WTL_TIMER:
            if not getattr(self, '_mmio_native', False):   # else: device region
                try:
                    mu.mem_map(0xE0020000, 0x1000, UC_PROT_ALL)
                except UcError:
                    pass
            mu.hook_add(UC_HOOK_MEM_READ, self._wtl_timer_read,
                        begin=0xE0020010, end=0xE0020017)
        # CP-side monitor: consumes AP log messages the instant they land.
        # The kernel logger's in-flight counter is the queue depth; on
        # hardware the modem-side monitor drains it continuously. Modeled
        # as a tick-driven drain in _deliver_ticks (counter cell
        # [logCB+0x20], logCB resolved from the logger's runtime pool
        # literal at 0x80a094D4) - NOT as the old movs r0,#1 image patch,
        # which forced every log down the output path and tripped the
        # log-tail state assert during the boot's early phase transitions.
        # (Hooks at 0x80a09184/88 wedge this unicorn build - do not use.)
        # Trace/int-lock depth saturation rings: the kernel's two trace
        # depths each log an overflow warning at >=20, and the log path
        # re-enters the locks -> unbounded recursion + stack flood. Clamp
        # both depths to the last table slot instead (diagnostic-only).
        # depth A: 0x81099982 = movs r0,#0x13; b 0x8109998e; nops
        mu.mem_write(0x81099982, b'\x13\x20\x03\xe0\x00\xbf\x00\xbf\x00\xbf')
        # depth B: 0x8109a52e = movs r0,#0x13; str r0,[r4,#0xc]; b 0x8109a542; nops
        mu.mem_write(0x8109a52e, b'\x13\x20\x60\x60\x06\xe0\x00\xbf\x00\xbf'
                                  b'\x00\xbf\x00\xbf\x00\xbf\x00\xbf\x00\xbf')
        # Channel acquirer (0x811f6554) descriptor seed: the descriptor
        # [0x81abc618] is BSS, filled by the channel-module init 0x811bef1c
        # which the init cascade dispatches only AFTER the scheduler starts.
        # The logger, though, sends every log message over channel 2 from a
        # pre-scheduler task (blob path 0x80a0704f -> ch2-open -> notify ->
        # wrapper -> acquire), and with desc[0]=0 its mask read lands on
        # [0x14] = the vector-table word 0xe59ff018 whose bit26 reads as
        # "slot busy" -> the cooperative single-core boot deadlocks in the
        # spin (3.2M iterations); failing the acquire instead
        # trips the log-tail state check straight into shutdown.
        # On hardware the boot ROM's IPC handshake has this area live
        # before the AP kernel runs, so seed the descriptor with exactly
        # the values the guest's own fill-init (0x811f670c) writes and let
        # the real acquire path proceed. Idempotent: the guest init later
        # rewrites the same words.
        mu.hook_add(UC_HOOK_CODE, self._chan_acquire_guard,
                    begin=0x811f6554, end=0x811f6554)
        # channel-module init (0x811bef1c): from here the AP channel
        # manager owns the mailbox (spawns the drain thread) and the
        # pre-init instant-consume model must switch off.
        mu.hook_add(UC_HOOK_CODE, self._chan_mgr_init_cb,
                    begin=0x811bef1c, end=0x811bef1d)
        # OSAL root-handle registration (bootloader handoff model): the
        # master-init OSAL phase (0x8120c4e2 -> 0x80a1096a) reads the
        # system-ctl root object handle at [0x817031c4] and passes it to
        # the OSAL create service as the owner. NOTHING in the AP kernel
        # image writes that field (single literal ref = the reader) - on
        # hardware the pre-kernel loader/CP-side handshake leaves a
        # registered root object there. With it 0 the create still
        # succeeds and returns a fresh object pointer, but the caller
        # (0x80a1096a, zero-means-done convention for this call shape)
        # classifies the pointer as an error, reports "Error 0x13 Invalid
        # caller", and the assert log's tail shuts the boot down. Model the handoff: the first successful
        # OSAL object create registers its handle as the root object.
        # Log-service early start (pre-kernel handoff model): the log
        # control object is STATIC at 0x817cc2e8 and its constructor
        # (0x811adf7c, called from master-init at 0x80c2f168 - after the
        # OSAL phase) initializes it: holder cell 0x81703a6c -> object,
        # 110 words (0x1b8 bytes) filled with 0x3bf, class byte +0x1b8 =
        # 0x35 (ctor default; the runtime log-port-open path later sets
        # 1, the only value LOG_CORE 0x80a0914c accepts as enabled).
        # Without a live object, routed logs read the class byte through
        # the NULL holder from low-RAM 0x1b8 and route FATAL. Seed the
        # real object with the handoff state (class=1, the routed/enabled
        # value); the guest's own ctor re-runs later and simply rewrites
        # the same fields.
        mu.mem_write(0x81703a6c, int(0x817cc2e8).to_bytes(4, 'little'))
        mu.mem_write(0x817cc2e8, b'\xbf\x03\x00\x00' * 110)
        mu.mem_write(0x817cc2e8 + 0x1b8, b'\x01')
        # Power-state + tick handoff: master-init's
        # tail wait loop (0x80c2f1f2) spins until the POWER state word
        # [0x81702030+4] enters the active set {3,9,d,e,f,10,11,14,15,16,
        # 18,19}; the state is only advanced by PM command interrupts
        # (charger/key/USB) that a UART-less emulation never receives.
        # SEEDING THESE AT BOOT WAS A REGRESSION: power=3
        # diverts the PRE-master-init blob into an early NV-assert loop
        # and the boot never reaches master-init. Instead the wait-loop
        # head hook below (0x80c2f1f2) seeds power state 3 (= "power-on
        # key held, active", routing the post-wait boot-cause switch to
        # the MAIN app chain) and enables the AON tick timer exactly when
        # the wait loop starts.
        # FS report-channel state (0x81102730 reads [0x818c0594 + idx],
        # 0xFF = channel initialized): the fs1 phase emits FS progress
        # events through the report helper 0x811beeac -> 0x81102faa, whose
        # first act is this channel check. The channel-init code never ran
        # in this boot (zero writers to the table), so the check fails and
        # the report's error path trips the stack tangle. On hardware the
        # state table is live by the time fs1 runs (pre-kernel FS
        # handoff). Seed the first table slots as initialized.
        mu.mem_write(0x818c0594, b'\xff' * 8)
        # FDL window state = "expired, no host" (9) from the start: the
        # cell is BSS-zero and nothing in-image writes it before LOG_CORE
        # checks it at 0x80a09300-12 (state 8 or 9 = skip the whole
        # diagnostic send pipeline; 0 makes log-fn hang on the pipeline's
        # un-built channel objects). The FDL window intercept below keeps
        # the same value consistent if the window itself is reached.
        mu.mem_write(0x8170400C, int(9).to_bytes(4, 'little'))
        # OS-object registry handoff: LOG_CORE's output
        # pipeline polls "find OS object 0x32/0x4f/0x51" via 0x80e3e512 -
        # objects that the log-fn display-init's get-or-create
        # (0x810f4c6e, called via 0x80e04a44) should create but whose
        # id-store doesn't stick in this boot. Seed them into the
        # registry (base 0x8170228c from the finder's pool literal at
        # 0x80e3e8c0): entries {name-ptr, id, 0, 1<<id, 0, 0, tail} - the
        # same layout as the 12 static system entries. Free slots start
        # at 12 (0x817023dc).
        mu.mem_write(0x82eac000, b'logch0/1/2 names')
        for _i, _oid in enumerate((0x32, 0x4F, 0x51)):
            _e = 0x8170228c + (12 + _i) * 28
            mu.mem_write(_e, (0x82eac000 + _i * 8).to_bytes(4, 'little') +
                         _oid.to_bytes(4, 'little') + bytes(4) +
                         (1 << (_oid & 31)).to_bytes(4, 'little') +
                         bytes(12) +
                         (0x80e3e817).to_bytes(4, 'little'))
        # OSAL "ensure" interception (pre-kernel handoff model): the
        # master-init OSAL phase 0x8120c4e2 performs two "ensure the
        # system object exists" calls (0x80a1096a and 0x81218758 - both
        # load an owner handle from a system ctl and call the OSAL create
        # service 0x8109cf18). On hardware the pre-kernel loader already
        # registered these objects, so the service finds them and returns
        # 0 ("done"). In emulation nothing pre-registered them: the
        # service CREATES and returns a fresh pointer, the ensure callers
        # classify nonzero as error and run their report path. That path
        # is fatal in emulation twice over: the reports route through
        # log-fn (whose control object the guest has not allocated - see
        # the log-service early start above), and the log formatter
        # (0x814c35a4, called from log-fn) leaves format-node pointers in
        # stack slots that the FS-layer reporter later pops as a return
        # address (wild fetch into the message text). Model
        # the handoff: when the create service is entered FROM either
        # ensure call site, return 0 immediately ("already done") without
        # running the report path. The RTOS port's own creates (different
        # call sites, real work) are untouched.
        # NOTE: the master-init OSAL phase's ensure
        # calls are EXPECTED to run their error-report path on hardware -
        # 0x80a1096a returns 0 ("handled") only after the report prints,
        # and the phase treats that as success. An earlier attempt to
        # intercept the create service for these sites (returning 0 =
        # "already done") made the ensure wrappers return their success
        # flag 1 instead, which the phase classifies as FAILURE - do not
        # re-add it. The report path is safe now that the log-control
        # object is seeded with its real static layout (0x817cc2e8).
        mu.hook_add(UC_HOOK_CODE, self._fs_report_intercept,
                    begin=0x81102faa, end=0x81102fab)
        # fs1's report helper (0x811beeac): intercepted one level up as
        # well - its push/pop frame lands exactly where log-fn's first
        # formatter pass left format-node pointers, and its `pop {...,pc}`
        # then loads a stale node instead of the return address (the
        # invalid-insn at the kernstate pointer 0x81701f94).
        # Returning at entry keeps fs1's caller frame intact.
        mu.hook_add(UC_HOOK_CODE, self._fs_report_intercept,
                    begin=0x811beeac, end=0x811beead)
        # Log-class keeper: the guest ctor
        # (0x811adf7c, called from master-init at 0x80c2f168) sets the
        # class byte to its 0x35 default, but LOG_CORE only treats 1 as
        # enabled - any other value routes to the fatal/wait machinery.
        # The in-image restorer (SET_1b8 via the port-open stub) is
        # reached only through indirect dispatch, so re-force 1 as soon
        # as the ctor returns (PC reaches 0x80c2f16c).
        mu.hook_add(UC_HOOK_CODE, self._log_class_keeper,
                    begin=0x80c2f16c, end=0x80c2f16d)
        # LcdDrvInit re-init guard: LcdDrvInit 0x8100457e checks
        # word [0x817020c8] at 0x810045b2 and returns in 2 instructions
        # when nonzero; the count only increments when the panel detect
        # (0x81246ab2, analog-pin reads) registers a panel, which never
        # succeeds in emulation, so EVERY call re-runs the full init
        # (~10M insns per routed log). Model the firmware's own guarantee
        # (init completed once): from the second call on, force the guard
        # so the call takes the instant exit. When the panel detect is
        # fixed this stays harmless (the guard would be set for real).
        mu.hook_add(UC_HOOK_CODE, self._lcd_init_guard,
                    begin=0x8100457e, end=0x8100457f)
        # NV init-done force: the master-init phase at
        # 0x8120c4e2 calls NV_Init (0x80a1096a) and 0x81218758 calls the
        # ref-NV init - both FAIL in emulation because the FFS named-
        # device registry is empty (the "A" / "BML ... NV Partition"
        # opens return 0x800A0000), leaving the init-done flags
        # [0x817031c1] / [0x81705fe1] at 0. Every NV_Read then
        # short-circuits to error 7 ("not initialized") - one item
        # (id=2, DOWNLOAD_PARAM) re-read 4175 times, each with a fatal-
        # routed assert + display init. On hardware a first boot has an
        # empty-but-valid NV container: reads fall through to the
        # default-ROM filler (0x81491d0a) and succeed with defaults.
        # Model exactly that: force both init-done flags after the two
        # init calls return; the empty cache then takes the default path.
        mu.hook_add(UC_HOOK_CODE, self._nv_init_flag,
                    begin=0x8120c4e8, end=0x8120c4e9)
        mu.hook_add(UC_HOOK_CODE, self._nv_init_flag,
                    begin=0x81218766, end=0x81218767)
        # NV_Read interpose: even with the init flags forced, the read
        # chain still fails downstream (the worker's cache is empty and
        # the flash/default fill path depends on the never-mounted NV
        # device). The callers only need the item bytes with a success
        # return; serve a zero-filled buffer ("first-boot defaults") and
        # return 0 at the NV_Read dispatcher (0x80a107e8: r0=id, r1=len,
        # r2=buf; covers normal and ref-NV ids alike).
        mu.hook_add(UC_HOOK_CODE, self._nv_read_intercept,
                    begin=0x80a107e8, end=0x80a107e9)
        # NV_GetLength (0x80a10b1e: r0=id -> u16 len, 0 = absent) and the
        # NV_Write dispatcher (0x80a107f8: r0=id, r1=len, r2=buf): answered
        # from / stored into the real NV DB when NV_REAL is on.
        if RES_MODEL:
            mu.hook_add(UC_HOOK_CODE, self._res_read_intercept,
                        begin=0x80c370dc, end=0x80c370dd)
        if NV_REAL:
            self.nv_db = load_nv_db()
            self.run.log("[NV   ] real NV DB: %d ids (%d nvcal, %d journal)" % (
                len(self.nv_db),
                sum(1 for v in self.nv_db.values() if v[1] == "nvcal"),
                sum(1 for v in self.nv_db.values() if v[1] == "journal")))
            mu.hook_add(UC_HOOK_CODE, self._nv_getlen_intercept,
                        begin=0x80a10b1e, end=0x80a10b1f)
            mu.hook_add(UC_HOOK_CODE, self._nv_write_intercept,
                        begin=0x80a107f8, end=0x80a107f9)
        # Power-state wait ("gate D"): the master-init tail wait loop spins on
        # the power state; seed it + enable the tick timer at the loop
        # head so the early boot is untouched. The loop has several heads
        # (0x80c2f1f2/23e/244/30c) - cover them all.
        for _gh in (0x80c2f1f2, 0x80c2f23e, 0x80c2f244, 0x80c2f30c):
            mu.hook_add(UC_HOOK_CODE, self._gate_d_seed,
                        begin=_gh, end=_gh | 1)
        # WHOLESALE GLUE SEGMENT SKIP: master-init's tail
        # between the boot-cause handling and the task spawn loop is
        # woven with LTE/DSP glue calls that dive into the pre-loaded
        # firmware with corrupted caller state. Jump from the first glue
        # call (0x8124ce64) straight to the task spawn loop head
        # (0x80c2f3ea: r4=0; count=...; spawn each entry) - everything
        # between is diagnostics and the LTE/DSP pre-boot.
        if CELL_CUTS:
            mu.hook_add(UC_HOOK_CODE, self._glue_segment_skip,
                        begin=0x8124ce64, end=0x8124ce65)
        # task-loop exit cut: the 4 post-loop spawn calls (0x80e179f2/ea/
        # ee/ec) each dive into the firmware glue - jump from the loop
        # exit straight to app-phase=4 + return (0x80c2f438)
        if CELL_CUTS:
            mu.hook_add(UC_HOOK_CODE, self._taskloop_exit_cut,
                        begin=0x80c2f418, end=0x80c2f419)
        # POST-INIT CUT: when master-init returns into the app-init
        # wrapper (PC reaches 0x80c2f456), the wrapper would continue
        # into 0x80c5b6c0 / 0x80d0fad8 (LTE/DSP pre-boot) - saturated
        # with firmware glue that dives into the loaded firmware image.
        # Return the app-init wrapper to kernel-enter instead (its own
        # saved lr at [sp+4] = 0x80a08835): kernel-enter finishes init
        # and starts the ThreadX scheduler on the already-spawned tasks.
        if CELL_CUTS:
            mu.hook_add(UC_HOOK_CODE, self._post_init_cut,
                        begin=0x80c2f456, end=0x80c2f457)
        # FDL/diag-host wait window skip: the loop at
        # 0x80a4f9cc (called from master-init 0x80c2f1ba) waits 15000
        # timer units for a download/AT host over the diag channel. Its
        # tick checks work with our 0x4023000c counter model, but the
        # window's diag channel depends on USB/DSP init that never
        # completes here - the TX-drain spin (0x80a077c2: channel-table
        # entry 1 lacks the 0x55 magic) wedges before any timeout. Model
        # "no host, channel went idle" (the hardware early-exit, state 6
        # at 0x8170400C): return at entry.
        mu.hook_add(UC_HOOK_CODE, self._fdl_window_skip,
                    begin=0x80a4f9cc, end=0x80a4f9cd)
        # twin build of the same window (0 BL xrefs, alternate build) -
        # the boot reaches THIS one first; same skip semantics
        mu.hook_add(UC_HOOK_CODE, self._fdl_window_skip,
                    begin=0x80a4f8d0, end=0x80a4f8d1)
        # Diag channel-1 fabrication: LOG_CORE's output pipeline
        # (blx r3 at 0x80a093c6/0x80a09400 through the callback table at
        # [0x81701ea8]) ends in the diag TX flush, whose drain
        # (0x80a077c2) spins forever while channel-table entry 1
        # (pointer table at 0x8170310C, getter [tbl+4+idx*4]) is NULL -
        # the diag channel was never created in this boot (its USB/DSP
        # dependencies don't exist here). Fabricate an open, empty
        # channel struct: [t+3]=0x55 (open magic), [t+4]=0 (mode < 0xC),
        # empty ring - the flush then completes instantly and log output
        # is dropped (no diag host to receive it).
        mu.hook_add(UC_HOOK_CODE, self._diag_chan_fix,
                    begin=0x80a077c2, end=0x80a077c3)
        # LOG_CORE output-pipeline skip: log-fn's send step (blx r3 at
        # 0x80a093c6/0x80a09400 through the 72-byte-stride callback table
        # at [0x81701ea8]+0x24) walks an object graph (diag channels,
        # format nodes) that the log service start never built in this
        # boot - each fabricated object only reveals the next missing
        # dependency. The send is DIAGNOSTIC OUTPUT: skipping it drops
        # the log bytes but preserves log-fn's control flow and its
        # display-init side effects, which is all the boot needs. Model:
        # "diag output dropped - no diag host".
        mu.hook_add(UC_HOOK_CODE, self._log_send_skip,
                    begin=0x80a093c6, end=0x80a093c7)
        mu.hook_add(UC_HOOK_CODE, self._log_send_skip,
                    begin=0x80a09400, end=0x80a09401)
        # Late-chain dispatch skip: master-init's late chain
        # step 0x80a48fac(1) makes an indirect call through an
        # uninitialized table - the emulator lands in the loaded
        # LTE/DSP firmware at 0x880ac3bc with a garbage lr, and the whole
        # post-chain (blx 0x80fc491c -> the 14-task spawn loop ->
        # app-phase=4 -> the scheduler) never runs. Skip the step: the
        # remaining chain is all direct calls down to the task spawn.
        if CELL_CUTS:
            mu.hook_add(UC_HOOK_CODE, self._late_chain_skip,
                        begin=0x80a48fac, end=0x80a48fad)
        # master-init early-phase get-or-create skip: 0x80baca68's
        # function calls the OS-object finder 9066 times in a loop that
        # never terminates in emulation (the three objects 0x32/0x4f/0x51
        # are seeded but the caller's post-find processing still loops).
        # Skip the call entirely - the objects are pre-seeded in the
        # registry and the caller's downstream code handles their absence.
        # 2026-10-30: this skips a whole driver-init chain (IRQ init
        # 0x8113e5c4, mmi_app veneer 0x80fc46ac, CLOCK FRAMEWORK init
        # 0x81118e82 -> every clock lookup NULL, e.g. "SDIO" -> NULL deref
        # crash at 132M). Like the other cuts it predates the mmi_app load;
        # now a CELL_CUTS cut too.
        if CELL_CUTS:
            mu.hook_add(UC_HOOK_CODE, self._late_chain_skip,
                        begin=0x80baca68, end=0x80baca69)
        # The LTE/DSP glue veneer right after it - same treatment (its
        # target firmware executes with corrupted caller state)
        if CELL_CUTS:
            mu.hook_add(UC_HOOK_CODE, self._late_chain_skip,
                        begin=0x80fc491c, end=0x80fc491d)
        # Firmware-region guard: the LTE/DSP firmware pre-loaded at
        # 0x86-0x90xxxxxx is entered through veneers whose caller state
        # is corrupt in this boot; executing it produces native host
        # faults that kill the process. The firmware belongs to the
        # modem cores, not the AP - any execution dive into it returns
        # to the caller immediately (r0=0).
        # (the fw_region_guard is RETIRED: with the full-space mapping
        # the firmware's wild writes land in scratch RAM and its glue
        # code runs - blocking it aborted LcdDrvInit mid-init)
        mu.hook_add(UC_HOOK_INSN_INVALID, self.on_invalid)
        if ASSERT_TRAP:
            mu.hook_add(UC_HOOK_CODE, self._assert_trap,
                        begin=ASSERT_TRAP & ~1, end=ASSERT_TRAP & ~1)
        if SPRINTF_TRAP:
            mu.hook_add(UC_HOOK_CODE, self._sprintf_trap,
                        begin=SPRINTF_TRAP & ~1, end=SPRINTF_TRAP & ~1)
        if ITOA_TRAP:
            mu.hook_add(UC_HOOK_CODE, self._itoa_trap,
                        begin=ITOA_TRAP & ~1, end=ITOA_TRAP & ~1)
        if SPRINTF_TRAP:
            mu.hook_add(UC_HOOK_CODE, self._sprintf_trap,
                        begin=SPRINTF_TRAP & ~1, end=SPRINTF_TRAP & ~1)
        if ITOA_TRAP:
            mu.hook_add(UC_HOOK_CODE, self._itoa_trap,
                        begin=ITOA_TRAP & ~1, end=ITOA_TRAP & ~1)
        # NOTE: WFI executes as a no-op in this unicorn build (verified) --
        # kernel "wait for interrupt" falls through; tick pump drives delays.
        if CELL_TRACE:
            self._setup_cell_trace()
        # LOG_CORE (0x80a0914c) is the never-returning fatal path (asserts
        # that bypass the 0x80a0b07a patch end here, and the boot thread
        # becomes the diag RX daemon). Log its (expr, file, line, msg).
        mu.hook_add(UC_HOOK_CODE, self._log_core_entry,
                    begin=0x80a0914c, end=0x80a0914d)
        if DSP_STUB:
            mu.hook_add(UC_HOOK_CODE, self._dsp_poll, begin=0x80eeea92, end=0x80eeea93)
            for ctl in DSP_XDSP_CTLS:
                mu.hook_add(UC_HOOK_MEM_WRITE,
                            lambda uc, acc, a, sz, v, ud: self._xdsp_ctl_write(uc, v),
                            begin=ctl, end=ctl + 3)
        if LOG_TAP:
            mu.hook_add(UC_HOOK_CODE, self._log_tap_printf, begin=0x8109e31e, end=0x8109e31f)
            if LOG_TAP_ID:
                mu.hook_add(UC_HOOK_CODE, self._log_tap_id, begin=0x810994f2, end=0x810994f3)

    def _sim_log(self, msg):
        n = getattr(self, '_sim_n', 0) + 1
        self._sim_n = n
        if n <= 300:
            self.run.log(f"[SIM  ] {msg}")
        f = getattr(self, '_sim_f', None)
        if f is None:
            f = self._sim_f = open(os.path.join(self.run.dir, "sim_apdu.txt"), "w")
        f.write(f"{self.insn_total}\t{msg}\n")
        f.flush()
        self.run.ev("SIM", msg=msg, insn=self.insn_total)

    def _pmic_static_init(self):
        if PMIC_EFUSE_READY:
            try:
                self.mu.mem_write(0x40608314, (0x14).to_bytes(4, 'little'))
            except UcError:
                pass

    # --------------------------------------------------------- AP TMR0
    def _aptmr_k(self):
        return getattr(self, 'tick_rate', 200_000) * 1000.0 / 32768.0

    def _aptmr_write(self, uc, a, value):
        T = self.__dict__.setdefault('aptmr', {"started": False, "ctrl": 0, "load": 0,
                                                "due": None, "period": 0, "n": 0})
        v = value & 0xFFFFFFFF
        if a == AP_TMR_BASE:
            T["load"] = v
            return
        if a == AP_TMR_BASE + 4:
            return                                  # 64-bit hi: unused (loads fit 32 bits)
        old = T["ctrl"]
        T["ctrl"] = v
        if (v & 2) and not (old & 2):               # run (CTRL reads are the model's, see on_read)
            n = max(1, T["load"])
            T["period"] = int(round(n * self._aptmr_k()))
            T["due"] = self.insn_total + T["period"]
            T["start"] = self.insn_total
            T["started"] = True
            T["n"] += 1
            k = T["n"]
            if k <= 10 or (n > 0x100 and k <= 200):
                self.run.log(f"[TMR0 ] start #{k} load={n:#x} ({n / 32.768:.1f} ms) "
                             f"{'periodic' if v & 1 else 'one-shot'} due={T['due']} insn={self.insn_total}")
        elif not (v & 2):
            T["due"] = None

    def _aptmr_remaining(self):
        T = getattr(self, 'aptmr', None)
        if not T or T.get("due") is None:
            return 0
        return max(0, int((T["due"] - self.insn_total) / self._aptmr_k()))

    # --------------------------------------------------------- LCDC
    def _lcdc_sync(self, uc):
        L = self.lcdc
        if L["ctrl"] is None:                       # pre-checkpoint state lives in the shadow
            rd = lambda a: int.from_bytes(uc.mem_read(a, 4), 'little')
            L["ctrl"], L["en"], L["raw"] = rd(0x20800000), rd(0x20800110), rd(0x2080011C)
        return L

    def _lcdc_read(self, uc, a):
        L = self._lcdc_sync(uc)
        if a == 0x20800000:
            return L["ctrl"]
        if a == 0x20800110:
            return L["en"]
        if a == 0x20800118:
            return L["raw"] & L["en"]
        # raw +0x11c: bit1 = panel TE / frame mark. The LCD ESD check
        # (esd_TASK, 0x810ba588 from 0x81005465) clears it and busy-polls
        # 120000x with the LCDC IRQ masked; it outranks the MMI task, so a
        # TE that never comes starved P_APP. TE is a free-running 60 Hz
        # panel signal: modelled as arriving during the poll.
        L["raw"] |= 2
        return L["raw"]

    def _lcdc_write(self, uc, a, value):
        L = self._lcdc_sync(uc)
        v = value & 0xFFFFFFFF
        if a == 0x20800110:
            L["en"] = v
        elif a == 0x20800114:
            L["raw"] &= ~v
        else:
            old = L["ctrl"]
            if (v & 8) and not (old & 8):           # run: frame done at once
                L["raw"] |= 1
                L["frames"] += 1
                v &= ~8
                n = L["frames"]
                if n <= 5 or n % 100 == 0:
                    self.run.log(f"[LCDC ] frame #{n} ctrl={value & 0xFFFFFFFF:#x} "
                                 f"pc={uc.reg_read(UC_ARM_REG_PC):#x} insn={self.insn_total}")
            L["ctrl"] = v
        self.hw_regs[a] = v

    # --------------------------------------------------------- I2C
    def _i2c_read(self, base, off):
        c = self.i2c[base]
        if off == 0x00:
            return c["ctl"]
        if off == 0x04:
            return c["addr"]
        if off == 0x08:
            return c["cnt"]
        if off == 0x0C:
            return c["rx"].pop(0) if c["rx"] else 0
        if off == 0x14:
            return c["st"] | (8 if not c["tx"] else 0)      # FIFO_EMPTY
        return self.hw_regs.get(base | off, 0)

    def _i2c_write(self, uc, base, off, value):
        c = self.i2c[base]
        v = value & 0xFFFFFFFF
        if off == 0x00:
            old = c["ctl"]
            c["ctl"] = v
            if (v & 1) and not (old & 1):
                rd = bool(v & 8)
                msg = (f"I2C {base:#x} {'R' if rd else 'W'} addr={c['addr'] >> 1:#04x} "
                       f"cnt={c['cnt']} tx={bytes(c['tx']).hex()} -> "
                       f"{'00' * c['cnt'] if rd else 'NACK'} "
                       f"pc={uc.reg_read(UC_ARM_REG_PC):#x} lr={uc.reg_read(UC_ARM_REG_LR):#x}")
                if rd:
                    c["rx"] = [0] * c["cnt"]
                    c["st"] = (c["st"] & ~2) | 4
                else:
                    c["st"] |= 4 | 2                         # INT + NACK: no device
                c["tx"] = []
                self._i2c_log(msg)
        elif off == 0x04:
            c["addr"] = v
        elif off == 0x08:
            c["cnt"] = v & 0xFFFF
        elif off == 0x10:
            c["tx"].append(v & 0xFF)
        elif off == 0x14:
            c["st"] = v
        elif off == 0x2C:
            c["tx"] = []
            c["rx"] = []
        else:
            self.hw_regs[base | off] = v

    def _i2c_log(self, msg):
        n = getattr(self, '_i2c_n', 0) + 1
        self._i2c_n = n
        if n <= 50:
            self.run.log(f"[I2C  ] {msg}")
        f = getattr(self, '_i2c_f', None)
        if f is None:
            f = self._i2c_f = open(os.path.join(self.run.dir, "i2c.txt"), "w")
        f.write(f"{self.insn_total}\t{msg}\n")
        f.flush()

    # --------------------------------------------------------- PMIC RTC
    def _pmic_rtc_write(self, uc, a, value):
        h = self.hw_regs
        v = value & 0xFFFFFFFF
        raw = h.get(0x40608234, 0)
        if 0x40608210 <= a <= 0x4060822C:          # time/alarm update -> done
            raw |= 1 << (8 + ((a - 0x40608210) >> 2))
        elif a == 0x40608238:                       # INT_CLR (W1C)
            raw &= ~v
        h[0x40608234] = raw & 0xFFFF

        # enables: a write here is the new value; otherwise the C shadow
        # (writes made before this model owned the range, e.g. pre-checkpoint)
        en_regs = getattr(self, '_rtc_en_regs', None)
        if en_regs is None:
            en_regs = self._rtc_en_regs = {}
        for ra in (0x40608230, 0x406080C8):
            if a == ra:
                en_regs[ra] = v
            elif ra not in en_regs:
                en_regs[ra] = int.from_bytes(uc.mem_read(ra, 4), 'little')
            h[ra] = en_regs[ra]
        # ANA int controller: RTC = int 1
        rtc = h[0x40608234] & h[0x40608230] & 0xFFFF
        ana_raw = (h.get(0x406080C4, 0) & ~2) | (2 if rtc else 0)
        h[0x406080C4] = ana_raw
        h[0x406080C0] = ana_raw & h[0x406080C8] & 0xFFFF
        for ra in (0x40608230, 0x40608234, 0x406080C0, 0x406080C4, 0x406080C8):   # shadow for C ADI reads
            uc.mem_write(ra, (h[ra] & 0xFFFFFFFF).to_bytes(4, 'little'))
        n = getattr(self, '_rtc_n', 0) + 1
        self._rtc_n = n
        if n <= 40:
            self.run.log(f"[RTC  ] w {a:#x}={v:#x} raw={h[0x40608234]:#x} en={h.get(0x40608230, 0):#x} "
                         f"ana={h[0x406080C0]:#x} pc={uc.reg_read(UC_ARM_REG_PC):#x} insn={self.insn_total}")

    # --------------------------------------------------------- LTE ADX stub
    def _adx_ctl_write(self, uc, a, value):
        v = value & 0xFFFFFFFF
        if a == 0x402E0248:
            self.adx_vector = v
            return
        run = bool(v & 1)
        was = getattr(self, 'adx_running', False)
        self.adx_running = run
        if run and not was:
            vec = getattr(self, 'adx_vector', 0)
            self.run.log(f"[ADX  ] LTE DSP released: vector {vec:#x} (entry {(vec << 1) & 0xFFFFFFFF:#x}) "
                         f"pc={uc.reg_read(UC_ARM_REG_PC):#x} insn={self.insn_total}")
            self.run.ev("ADX_DSP_RUN", vector=hex(vec), insn=self.insn_total)
            # VERSION as the stock DSP sends it: len 0x40, body+0..7 = branch 0x19a0,
            # svn 0xfc78, AON chip id 0, chip version 1 (read from the running stock
            # phone over the debug link). The AP only logs these; the rest of the
            # body is not read.
            ver = bytes.fromhex("a01978fc00000100").ljust(0x40, b"\0")
            self.__dict__.setdefault('_adx_pending', []).append(
                (self.insn_total + ADX_BOOT_INSNS, 5, ver, "version"))
        elif not run and was:
            self.run.log(f"[ADX  ] LTE DSP stopped insn={self.insn_total}")

    def _adx_cmds(self, uc):
        rd16 = lambda a: int.from_bytes(uc.mem_read(a, 2), 'little')
        wr, rd = rd16(ADX_CMD_RING) % ADX_CMD_N, rd16(ADX_CMD_RING + 2) % ADX_CMD_N
        if wr == rd:
            return
        f = getattr(self, '_adx_f', None)
        if f is None:
            f = self._adx_f = open(os.path.join(self.run.dir, "adx_cmd.txt"), "w")
        while rd != wr:
            ent = ADX_CMD_RING + 4 + 8 * rd
            ctype, clen = rd16(ent), rd16(ent + 2)
            off = int.from_bytes(uc.mem_read(ent + 4, 4), 'little')
            data = bytes(uc.mem_read(ADX_CMD_DATA + off, min(clen, 0x200))) if clen else b""
            n = getattr(self, '_adx_cmd_n', 0) + 1
            self._adx_cmd_n = n
            line = f"cmd #{n} slot {rd} type {ctype} len {clen} off {off:#x} data {data[:64].hex()}"
            if n <= 40:
                self.run.log(f"[ADX  ] AP->DSP {line} insn={self.insn_total}")
            line = f"cmd #{n} slot {rd} type {ctype} len {clen} off {off:#x} data {data.hex()}"
            f.write(f"{self.insn_total}\t{line}\n")
            f.flush()
            self.run.ev("ADX_CMD", type=ctype, len=clen, insn=self.insn_total)
            if ADX_AUTO_CNF and ctype == 0 and len(data) >= 8:
                card = int.from_bytes(data[0:2], 'little')
                mid = int.from_bytes(data[4:8], 'little')
                for sid, dly, kind in ADX_SCRIPT.get(mid, []) if ADX_SCAN_RESULT == "cell" else []:
                    m_ = bytearray(data[0:4] + sid.to_bytes(4, 'little') + bytes(0x78 - 8))
                    self._adx_fill_script(m_, kind)
                    self.__dict__.setdefault('_adx_pending', []).append(
                        (self.insn_total + dly, 0, bytes(m_), f"msg {sid:#x} {kind} for {mid:#x}"))
                rid = self._adx_reply_id(uc, mid)
                if rid is not None and not any(k == "sync_cnf" for _, _, k in ADX_SCRIPT.get(mid, [])):
                    n_ = max(ADX_REPLY_LEN.get(rid, 0), min(len(data), 0x78))
                    cnf = bytearray(data[0:4] + rid.to_bytes(4, 'little') + bytes(max(0, n_ - 8)))
                    if rid == 0x72 and ADX_SCAN_RESULT == "cell":
                        self._adx_fill_sweep(cnf)
                    cnf = bytes(cnf)
                    self.__dict__.setdefault('_adx_pending', []).append(
                        (self.insn_total + ADX_CNF_DELAY, 0, cnf, f"msg {rid:#x} reply to {mid:#x} card {card}"))
            rd = (rd + 1) % ADX_CMD_N
        uc.mem_write(ADX_CMD_RING + 2, rd.to_bytes(2, 'little'))

    def _adx_fill_sweep(self, m):
        """0x72 band sweep result (PAL 0x80ee615a): +0xa u16 mode (2 =
        sweep result list), entries of 0x70 bytes at +0xc (u32 earfcn,
        u16 pci at +8, s16 levels*16 at +0xa/+0xc/+0x16/+0x18, valid flag
        at +0x6c), u16 count at +0x46c."""
        c = SIM_CELL
        def put(off, v, n):
            m[off:off + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'little')
        put(0xA, 1, 2)
        e = 0xC
        put(e + 0x0, c["earfcn"], 4)
        put(e + 0x8, c["pci"], 2)
        put(e + 0xA, c["rsrp"] * 16, 2)
        put(e + 0xC, c["rsrq"] * 16, 2)
        put(e + 0x16, c["rsrp"] * 16, 2)
        put(e + 0x18, c["rsrq"] * 16, 2)
        put(e + 0x6C, 1, 4)
        put(0x46C, 1, 2)

    def _adx_fill_script(self, m, kind):
        c = SIM_CELL
        def put(off, v, n):
            m[off:off + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'little')
        if kind == "sync_cnf":
            put(0xA, c["rsrp"] * 16, 2)
            put(0xC, 1, 2)
        elif kind == "try":                      # earfcn/pci in the 0x74 request's spots
            put(0xC, c["earfcn"], 4)
            put(0x10, c["pci"], 2)
            put(0xA, c["rsrp"] * 16, 2)
        elif kind == "sync_ind":                 # 0x01 (PAL 0x80ee31de): +0xc == 1 -> found
            put(0xC, 1, 4)
        elif kind == "mib":
            put(0xC, 0, 4)
            put(0x10, 0, 4)
            put(0x14, 0, 1)
            put(0x16, 3, 2)

    def _adx_reply_id(self, uc, mid):
        """First id after mid that the direction table marks DSP->AP."""
        for rid in range(mid + 1, min(mid + 8, 0xAE)):
            try:
                src = int.from_bytes(uc.mem_read(ADX_DIR_TABLE + 12 * rid + 4, 4), 'little')
            except UcError:
                return mid + 1
            if src == 0x78:
                return rid
        return None

    def _adx_poll(self, mu):
        due = [x for x in self._adx_pending if x[0] <= self.insn_total]
        if not due:
            return
        self._adx_pending = [x for x in self._adx_pending if x[0] > self.insn_total]
        for _, rtype, payload, what in due:
            self._adx_resp(mu, rtype, payload, what)

    def _adx_resp(self, mu, rtype, payload, what=""):
        """Post one DSP->AP response the way the LTE DSP does."""
        rd16 = lambda a: int.from_bytes(mu.mem_read(a, 2), 'little')
        idx = rd16(ADX_RESP_RING) % ADX_RESP_N
        # payload area: circular over [0x100, 0x1000) (addr + len < 0x100c)
        cur = getattr(self, '_adx_data_cur', 0x100)
        if cur + len(payload) >= 0x1000:
            cur = 0x100
        addr = cur
        self._adx_data_cur = (cur + len(payload) + 7) & ~7
        mu.mem_write(ADX_DATA_BASE + addr, bytes(payload))
        ent = ADX_RESP_RING + 4 + 8 * idx
        mu.mem_write(ent, rtype.to_bytes(2, 'little') + len(payload).to_bytes(2, 'little')
                     + addr.to_bytes(4, 'little'))
        mu.mem_write(ADX_RESP_RING, ((idx + 1) % ADX_RESP_N).to_bytes(2, 'little'))
        n = int.from_bytes(mu.mem_read(ADX_DOORBELL, 4), 'little') + 1
        mu.mem_write(ADX_DOORBELL, (n & 0xFFFFFFFF).to_bytes(4, 'little'))
        self.run.log(f"[ADX  ] DSP->AP resp type {rtype} ({what}) len {len(payload)} slot {idx} "
                     f"data {payload.hex()} doorbell {n} insn={self.insn_total}")
        self.run.ev("ADX_RESP", type=rtype, what=what, slot=idx, insn=self.insn_total)
        self._cp_stub_rx(ADX_CORE, 0xADC00000 | rtype, n)

    # --------------------------------------------------------- DSP stub
    def _dsp_ctl_write(self, uc, a, value):
        """GSM DSP boot control (AON_APB, DSPBOOT_SEQ): 0x402e0250 boot
        vector (addr>>1), 0x402e0254 run (1) / stop (0), 0x402e0130 bit17
        hold."""
        v = value & 0xFFFFFFFF
        pc = uc.reg_read(UC_ARM_REG_PC)
        if a == 0x402E0250:
            self.dsp_gsm_vector = v
        elif a == 0x402E0254:
            run = bool(v & 1)
            if run and not getattr(self, 'dsp_gsm_running', False):
                vec = getattr(self, 'dsp_gsm_vector', 0)
                self.run.log(f"[DSP  ] GSM DSP released: vector {vec:#x} (entry {(vec & 0xFFFFFFF) << 1:#x}) "
                             f"pc={pc:#x} insn={self.insn_total}")
                self.run.ev("DSP_GSM_RUN", vector=hex(vec), pc=hex(pc), insn=self.insn_total)
                try:
                    uc.mem_write(DSP_GSM_RUN, int(DSP_RUN_VALUE).to_bytes(2, 'little'))
                    for off, (sz, val) in DSP_GSM_PUBLISH.items():
                        uc.mem_write(DSP_GSM_WIN + 0x19670 + off, int(val).to_bytes(sz, 'little'))
                except UcError:
                    pass
            elif not run and getattr(self, 'dsp_gsm_running', False):
                self.run.log(f"[DSP  ] GSM DSP stopped pc={pc:#x} insn={self.insn_total}")
                self.run.ev("DSP_GSM_STOP", pc=hex(pc), insn=self.insn_total)
            self.dsp_gsm_running = run

    def _xdsp_ctl_write(self, uc, value):
        """LTE XDSP boot pulses (0x80d2d5f0.., two cores): after each pulse
        (a 1 followed by 0x1e on a core ctl) the code now in each core's
        window reports its stage in that core's ready word - boot loader -> 1,
        any other (main) image -> 2. The code is identified by finding the
        window's first 64 bytes in the kernel image (logged with its VA)."""
        v = value & 0xFFFFFFFF
        seq = self.__dict__.setdefault('_xdsp_seq', [])
        seq.append(v)
        del seq[:-6]
        if not (v == 0x1E and 1 in seq[:-1]):
            return
        seq.clear()
        if not hasattr(self, '_kimg'):
            self._kimg = open(KERNEL, 'rb').read()
        pc = uc.reg_read(UC_ARM_REG_PC)
        for win, ready in DSP_XDSP_CORES:
            try:
                head = bytes(uc.mem_read(win, 64))
                cur = int.from_bytes(uc.mem_read(ready, 4), 'little')
            except UcError:
                continue
            if not head.strip(bytes(1)):
                continue
            off = self._kimg.find(head)
            if off < 0:
                self.run.log(f"[DSP  ] XDSP core {win:#x}: unknown code {head[:8].hex()} pc={pc:#x}")
                continue
            va = off + 0x80a05e00
            stage = 1 if va in DSP_XDSP_BOOTLOADERS else 2
            if cur == stage:
                continue
            uc.mem_write(ready, int(stage).to_bytes(4, 'little'))
            self.run.log(f"[DSP  ] XDSP core {win:#x}: image {va:#x} ({'boot loader' if stage == 1 else 'main'}) "
                         f"running -> ready[{ready:#x}]={stage} pc={pc:#x} insn={self.insn_total}")
            self.run.ev("DSP_XDSP_STAGE", core=hex(win), image=hex(va), stage=stage,
                        pc=hex(pc), insn=self.insn_total)

    def _dsp_poll(self, uc, address, size, user_data):
        """Stable-read helper 0x80eeea92(r0=cell): the DSP answers its run word."""
        cell = uc.reg_read(UC_ARM_REG_R0)
        if cell != DSP_GSM_RUN:
            return
        n = getattr(self, '_dsp_poll_n', 0) + 1
        self._dsp_poll_n = n
        running = getattr(self, 'dsp_gsm_running', False)
        if running:
            try:
                cur = int.from_bytes(uc.mem_read(cell, 2), 'little')
                if cur == 0:
                    uc.mem_write(cell, int(DSP_RUN_VALUE).to_bytes(2, 'little'))
            except UcError:
                pass
        if n <= 5:
            self.run.log(f"[DSP  ] run-word poll #{n} running={running} lr={uc.reg_read(UC_ARM_REG_LR):#x} "
                         f"insn={self.insn_total}")
        self.run.ev("DSP_POLL", n=n, running=running)

    # --------------------------------------------------------- log tap
    def _glog(self, line):
        n = getattr(self, '_glog_n', 0)
        if n >= LOG_TAP_MAX:
            return
        self._glog_n = n + 1
        f = getattr(self, '_glog_f', None)
        if f is None:
            f = self._glog_f = open(os.path.join(self.run.dir, "guest_log.txt"), "w",
                                    encoding="utf-8", errors="replace")
        f.write(line + chr(10))
        if n % 64 == 0:
            f.flush()

    def _gstr(self, uc, a, n=200):
        try:
            b = bytes(uc.mem_read(a, n)).split(bytes(1))[0]
            return b.decode('latin1')
        except Exception:
            return f"<{a:#x}>"

    def _cfmt(self, uc, fmt, args):
        out = []
        i = 0
        argi = 0
        import re as _re
        spec = _re.compile(r"%([-+ #0]*)(\d*)(?:\.(\d+))?(hh|h|ll|l|z)?([diuxXscp%])")
        for m in spec.finditer(fmt):
            out.append(fmt[i:m.start()])
            i = m.end()
            conv = m.group(5)
            if conv == '%':
                out.append('%')
                continue
            v = args[argi] if argi < len(args) else 0
            argi += 1
            if conv == 's':
                out.append(self._gstr(uc, v, 120))
            elif conv == 'c':
                out.append(chr(v & 0xFF))
            elif conv in 'di':
                vv = v - (1 << 32) if v & 0x80000000 else v
                out.append(('%' + m.group(1) + m.group(2) + 'd') % vv)
            elif conv == 'u':
                out.append(('%' + m.group(1) + m.group(2) + 'd') % v)
            elif conv in 'xX':
                out.append(('%' + m.group(1) + m.group(2) + conv) % v)
            elif conv == 'p':
                out.append(f"{v:#x}")
        out.append(fmt[i:])
        return ''.join(out)

    def _stack_args(self, uc, n, first_off):
        sp = uc.reg_read(UC_ARM_REG_SP)
        try:
            raw = bytes(uc.mem_read(sp + first_off, 4 * n))
            return [int.from_bytes(raw[4 * j:4 * j + 4], 'little') for j in range(n)]
        except Exception:
            return [0] * n

    def _log_tap_printf(self, uc, address, size, user_data):
        r = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        fmt = self._gstr(uc, r[0], 240)
        args = r[1:] + self._stack_args(uc, 8, 0)
        try:
            txt = self._cfmt(uc, fmt, args)
        except Exception:
            txt = fmt
        lr = uc.reg_read(UC_ARM_REG_LR)
        self._glog(f"{self.insn_total:>11} P lr={lr:#010x} {txt.rstrip()}")

    def _log_tap_id(self, uc, address, size, user_data):
        r = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        nargs = r[2] & 0xFF
        args = ([r[3]] + self._stack_args(uc, max(0, min(nargs, 8) - 1), 0))[:min(nargs, 8)]
        lr = uc.reg_read(UC_ARM_REG_LR)
        self._glog(f"{self.insn_total:>11} T lr={lr:#010x} mod={r[0]:#x} id={r[1]:#x} "
                   + " ".join(f"{a:#x}" for a in args))

    def _log_core_entry(self, uc, address, size, user_data):
        def cstr(a):
            try:
                b = bytes(uc.mem_read(a, 160)).split(b'\0')[0]
                return b.decode('latin1') if b and all(32 <= c < 127 for c in b) else None
            except UcError:
                return None
        r = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                      UC_ARM_REG_R2, UC_ARM_REG_R3)]
        lr = uc.reg_read(UC_ARM_REG_LR)
        parts = [cstr(r[0]), cstr(r[1]), r[2], cstr(r[3])]
        self.run.log(f"[FATAL] LOG_CORE expr={parts[0]!r} file={parts[1]!r} "
                     f"line={r[2]} msg={parts[3]!r} lr={lr:#x} insn={self.insn_total}")
        self.run.ev("FATAL_ASSERT", expr=parts[0], file=parts[1], line=r[2],
                    msg=parts[3], lr=hex(lr), insn=self.insn_total)
        if STRICT:
            self.stop_reason = "fatal-assert"
            self.stop_detail = f"{parts[1]}:{r[2]} {parts[0]}"
            uc.emu_stop()

    # ------------------------------------------------------- cell trace
    def _setup_cell_trace(self):
        """Full read+write trace of the cellular MMIO ranges. Registered
        after on_read/on_write (unicorn appends hooks), so a read's value
        is the one the models just published. Identical consecutive
        accesses (same rw/addr/value/pc) collapse into one row + count."""
        mu = self.mu
        self._ct_f = open(os.path.join(self.run.dir, "cell_trace.tsv"),
                          "w", encoding="utf-8")
        self._ct_f.write("insn\trw\taddr\tsize\tvalue\tpc\tlr\tblock\trepeat\n")
        self._ct_last = None
        self._ct_rep = 0
        self._ct_rows = 0
        self._ct_keys = {}
        for lo, hi, name in CELL_TRACE_RANGES:
            mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                        self._cell_trace_cb, user_data=name,
                        begin=lo, end=hi - 1)
        for va, name in CELL_FUNCS.items():
            mu.hook_add(UC_HOOK_CODE, self._cell_func_cb, user_data=name,
                        begin=va & ~1, end=va & ~1)
        self.run.log(f"[CELL ] trace armed: {len(CELL_TRACE_RANGES)} ranges, "
                     f"{len(CELL_FUNCS)} entry points")

    def _cell_trace_cb(self, uc, access, address, size, value, name):
        if access == UC_MEM_WRITE:
            rw = "W"
            v = value & ((1 << (8 * size)) - 1)
        else:
            rw = "R"
            try:
                v = int.from_bytes(uc.mem_read(address, size), 'little')
            except UcError:
                v = -1
        pc = uc.reg_read(UC_ARM_REG_PC)
        key = (rw, address, v, pc)
        if key == self._ct_last:
            self._ct_rep += 1
            return
        n = self._ct_keys.get(key, 0) + 1
        self._ct_keys[key] = n
        if n > CELL_TRACE_KEY_CAP:
            return
        self._ct_flush_rep()
        self._ct_last = key
        lr = uc.reg_read(UC_ARM_REG_LR)
        self._ct_f.write(f"{self.insn_total}\t{rw}\t{address:08x}\t{size}\t"
                         f"{v & 0xFFFFFFFF:08x}\t{pc:08x}\t{lr:08x}\t{name}\t")
        self._ct_pending = True
        self._ct_rows += 1

    def _ct_flush_rep(self):
        if getattr(self, '_ct_pending', False):
            self._ct_f.write(f"{self._ct_rep + 1}\n")
            self._ct_pending = False
        self._ct_rep = 0

    def _cell_func_cb(self, uc, address, size, name):
        regs = " ".join(f"r{i}={uc.reg_read(r):08x}" for i, r in enumerate(
            (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)))
        lr = uc.reg_read(UC_ARM_REG_LR)
        self.run.log(f"[CELLF] {address:08x} {name} {regs} lr={lr:08x} "
                     f"@{self.insn_total}")
        self.run.ev("CELL_FUNC", pc=hex(address), name=name, lr=hex(lr),
                    insn=self.insn_total)
        if CELL_TRACE:
            self._ct_flush_rep()
            self._ct_last = None
            self._ct_f.write(f"{self.insn_total}\tF\t{address:08x}\t0\t"
                             f"{uc.reg_read(UC_ARM_REG_R0):08x}\t{address:08x}\t"
                             f"{lr:08x}\t{name}\t1\n")

    def _strict_stop(self, mu, reason, detail):
        pc = mu.reg_read(UC_ARM_REG_PC)
        lr = mu.reg_read(UC_ARM_REG_LR)
        self.stop_reason = reason
        self.stop_detail = detail
        self.run.log(f"[STRICT] stop: {reason} {detail} lr={lr:#x}")
        self.run.log(f"[STRICT] ctx: {self._disasm_at(mu, pc & ~1, 4)}")
        self.run.log("[STRICT] pc-trail: " +
                     " ".join(f"{p:08x}" for p in self.pc_trace))
        self.run.ev("STRICT_STOP", reason=reason, detail=detail,
                    pc=hex(pc), lr=hex(lr))

    def close_cell_trace(self):
        if getattr(self, '_ct_f', None):
            self._ct_flush_rep()
            self._ct_f.close()
            hot = sorted(((n, k) for k, n in self._ct_keys.items()
                          if n > CELL_TRACE_KEY_CAP), reverse=True)
            with open(os.path.join(self.run.dir, "cell_trace_hot.tsv"), "w",
                      encoding="utf-8") as f:
                f.write("count\trw\taddr\tvalue\tpc\n")
                for n, (rw, a, v, pc) in hot:
                    f.write(f"{n}\t{rw}\t{a:08x}\t{v & 0xFFFFFFFF:08x}\t{pc:08x}\n")
            self.run.log(f"[CELL ] trace closed: {self._ct_rows} rows")
            self._ct_f = None

    @staticmethod
    def _is_mmio(addr):
        return 0x30000000 <= addr < 0x80000000

    def on_read(self, uc, access, address, size, value, user_data):
        a = address & ~3
        self._rd_n += 1
        # SNF model: 0x21A00000 sits BELOW _is_mmio's window, so it must be
        # dispatched explicitly (reads otherwise fall through to the generic
        # RAM poll-tracker and never see the model's published values).
        if SNF_BASE <= address < SNF_BASE + 0x600:
            self._snf_read(uc, address, size)
            return
        # HW free-running counters at 0x40040000 AND 0x40230000 (two timer
        # instances; the udelay helpers at 0x80a0b624/0x80a0b63e hold literal
        # 0x40230000, the x30 variant holds 0x40040000): the guest's
        # busy-wait delays read [+4]/[+0xc] twice and wait for the delta to
        # grow (elapsed*30 >= requested). A static zero MMIO read spins
        # forever (the pre-master-init wedge: 275K reads of 0x4023000c at
        # 0x80a0b620), so both cells advance with executed instructions
        # (~1 unit/4 insns).
        if (0x40040000 <= address < 0x40040010
                or 0x40230000 <= address < 0x40230010):
            if (address & 0xF) in (4, 0xC):
                if CTR_POLL_SKIP and self._rd_n == getattr(self, '_ctr_last_rd', -9) + 1:
                    step = CTR_POLL_SKIP
                    nd = self._next_tick_due() if TICK_EXACT_CHUNKS else None
                    if nd is not None and self.insn_total < nd <= self.insn_total + step:
                        step = max(0, nd - self.insn_total)
                        self._stop_cause = 'ctrskip'
                        uc.emu_stop()                  # deliver the tick now
                    self.insn_total += step
                    self.ctr_skipped = getattr(self, 'ctr_skipped', 0) + step
                self._ctr_last_rd = self._rd_n
                v = int(self._now() * self._ctr_scale(address & ~0xFFF, address & 0xC)) & 0xFFFFFFFF
                uc.mem_write(address & ~3,
                             int(v).to_bytes(4, 'little'))
                self.hw_regs[address & ~3] = v
            return
        # Mailbox read visibility (AP side + CP bank): map the guest's
        # polling/waiting pattern so the CP reply model can be built.
        if CP_STUB and 0x400A8000 <= address < 0x400A8018:
            q = self.__dict__.setdefault('cp_rxq', [])
            off = address - 0x400A8000
            if off == 0x14:
                v = ((len(q) & 0xFF) << 0x10)          # wr = n, rd = 0
            elif off < 0xC:
                v = q[0][off >> 2] if q else 0
            else:
                v = self.hw_regs.get(a, 0)
            uc.mem_write(a, int(v & 0xFFFFFFFF).to_bytes(4, 'little'))
            return
        if 0x400A0000 <= address < 0x400A0030 or 0x400A8000 <= address < 0x400A8030:
            self._mbx_rd = getattr(self, '_mbx_rd', 0) + 1
            if self._mbx_rd <= 200:
                self.run.log(f"[MBX-R] {address:08x} "
                             f"pc={uc.reg_read(UC_ARM_REG_PC):#x}")
            return
        if self._rd_n & 0x3FF == 0:
            pc_s = uc.reg_read(UC_ARM_REG_PC) & ~1
            self.pc_trace.append(pc_s)
            sp_s = uc.reg_read(UC_ARM_REG_SP)
            if sp_s >= 0xFFFFFFFC and self._rd_n > 0:
                self.sp_high = getattr(self, 'sp_high', 0) + 1
                if self.sp_high <= 8:
                    self.run.log(f"[SP-HI] sp={sp_s:#x} pc={pc_s:#x} "
                                 f"lr={uc.reg_read(UC_ARM_REG_LR):#x} n={self._rd_n}")
                self.run.ev("SP_HIGH", sp=hex(sp_s), pc=hex(pc_s),
                            lr=hex(uc.reg_read(UC_ARM_REG_LR)))
        # display engine block: display_model's layered read hook owns this
        # window (the 16550 LSR handling below used to
        # write 0x60 into engine byte reads)
        if 0x70B00000 <= address < 0x70B00100:
            return
        # UART access visibility: throttle reads per (port, off)
        if UART_LO <= address < UART_END:
            key = (address & 0xF0000, address & 0xFF)
            self.uart_rd = getattr(self, 'uart_rd', {})
            self.uart_rd[key] = self.uart_rd.get(key, 0) + 1
            if self.uart_rd[key] in (1, 2, 3, 10, 100, 1000, 10000, 100000):
                self.run.log(f"[UART-R] {address:08x} x{self.uart_rd[key]} "
                             f"pc={uc.reg_read(UC_ARM_REG_PC):#x}")
            if size == 1 and idx_uart_lsr(address):  # LSR handled below
                pass
        # 16550 UART: LSR=0x60 (THRE+TEMT, TX ready), RX empty
        if SIM_MODEL and (address & ~3) == 0x71300000:
            # APB SIM interrupt summary read by the ISR's per-card check
            # 0x80c5dcea: bit0 SIM0, bit23 SIM1, bit25 SIM2
            v = self.hw_regs.get(0x71300000, 0) & ~((1 << 0) | (1 << 23) | (1 << 25))
            for (base, _gid, _c), bit in zip(SIM_CTLS, (0, 23, 25)):
                if self.sim[base][0].irq():
                    v |= 1 << bit
            uc.mem_write(0x71300000, int(v).to_bytes(4, 'little'))
            return
        if AP_TMR_MODEL and AP_TMR_BASE <= address < AP_TMR_BASE + 0x20:
            a4 = address & ~3
            if a4 == AP_TMR_BASE + 0x18:
                v = self._aptmr_remaining()
            else:                                   # LOAD/CTRL/INT: last written value
                v = self.hw_regs.get(a4, 0) & ~(8 if a4 == AP_TMR_BASE + 0x14 else 0)
            uc.mem_write(address & ~3, int(v & 0xFFFFFFFF).to_bytes(4, 'little'))
            return
        if LCDC_MODEL and (address & ~3) in (0x20800000, 0x20800110, 0x20800118, 0x2080011C):
            v = self._lcdc_read(uc, address & ~3)
            uc.mem_write(address & ~3, int(v & 0xFFFFFFFF).to_bytes(4, 'little'))
            return
        if I2C_MODEL and (address & ~0xFFF) in self.i2c and (address & 0xFFF) < 0x40:
            v = self._i2c_read(address & ~0xFFF, address & 0xFFC)
            uc.mem_write(address & ~3, int(v & 0xFFFFFFFF).to_bytes(4, 'little'))
            return
        if SIM_MODEL and (address & ~0xFFF) in self.sim and (address & 0xFFF) < 0x100:
            ctl = self.sim[address & ~0xFFF][0]
            v = ctl.read(address & 0xFFC)
            uc.mem_write(address & ~3, int(v & 0xFFFFFFFF).to_bytes(4, 'little'))
            return
        if UART_LO <= address < UART_END and size == 1:
            idx = address & 7
            if idx == 5:
                uc.mem_write(address & ~3, 0x60)
                self.hw_regs[address & ~3] = 0x60
                return
            if idx == 2:      # IIR: no pending interrupt
                uc.mem_write(address & ~3, 0x01)
                self.hw_regs[address & ~3] = 0x01
                return
            if idx == 6:      # MSR: modem status, all clear
                uc.mem_write(address & ~3, 0x00)
                return
            if idx == 0:      # RX: no data
                return
        if self._is_mmio(address):
            if getattr(self, '_mmio_rd_hist', None) is not None:
                self._mmio_rd_hist[address & 0xFFFFFF] =                     self._mmio_rd_hist.get(address & 0xFFFFFF, 0) + 1
                if not hasattr(self, '_mmio_rd_pc'):
                    self._mmio_rd_pc = {}
                self._mmio_rd_pc[address & 0xFFFFFF] = uc.reg_read(UC_ARM_REG_PC) & ~1
            # ADI AON doorbell response registers (0x4060002c/0x40600030):
            # the pinmux helpers (read 0x81218546, write 0x81218598) poll
            # these from inside the trace spinlock. POLARITY (from the
            # disassembly of both poll loops): read helper `cmp r4,#0; blt poll`
            # -> bit31 SET = busy, CLEAR = data ready, and the ready echo
            # [31:16] must equal arg[16:2] exactly (no valid-bit set).
            # Write helper `lsls #0x14; bpl done` -> bit11 SET = engine
            # busy, CLEAR = idle (the write then stores directly). The
            # engine is modeled idle+instant: busy bits always clear, read
            # data = the emulated register file for the same offset.
            if 0x40600028 <= address < 0x40600034:
                rid = getattr(self, 'adi_req_id', 0) & 0x7FFF
                if address == 0x4060002c:
                    v = (rid << 16) | self.hw_regs.get(
                        0x40600000 | ((rid << 2) & 0xFFFF), 0)
                elif address == 0x40600030:
                    v = rid << 16
                else:
                    v = getattr(self, 'adi_req_id', 0) << 2
                if size == 4:
                    uc.mem_write(a, v.to_bytes(4, 'little'))
                    self.hw_regs[a] = v
                return
            # PMU(AON) power-state ready flags: the pre-OS blob and the clock
            # driver spin until [0x402b0250] == 1 (domain active).
            if 0x402b0250 <= address < 0x402b0254:
                if size == 4:
                    uc.mem_write(a, (1).to_bytes(4, 'little'))
                    self.hw_regs[a] = 1
                return
            # GP timer T0 value register (0x40400004): the RTOS tick path
            # polls it heavily; a free-running counter (instruction clock).
            if 0x40400004 <= address < 0x40400008:
                v = (self._now() // 100) & 0xFFFFFFFF
                if size == 4:
                    uc.mem_write(a, v.to_bytes(4, 'little'))
                    self.hw_regs[a] = v
                return
            # AON block 0x40220010/14: read by the real-IRQ-61 handler
            # (58x per service). Default: free-running counter. A probe can
            # pin pin-state via emu.pad_vals = {0x40220010: v, 0x40220014: v}.
            if 0x40220010 <= address < 0x40220018:
                pv = getattr(self, 'pad_vals', None)
                if pv is not None:
                    v = int(pv.get(address, 0)) & 0xFFFFFFFF
                else:
                    v = (self._now() // 50) & 0xFFFFFFFF
                if size == 4:
                    uc.mem_write(a, v.to_bytes(4, 'little'))
                    self.hw_regs[a] = v
                return
            # NOTE: the old "AP System Timer" virtual-ms model for this
            # range is gone - the free-running counter model at the top of
            # on_read (0x40230000 in the 0x40040000/0x40230000 group)
            # answers [+4]/[+0xc] first with an unconditional return, and
            # every executable guest consumer of this block reads only
            # those two cells (6 literals, all pool padding otherwise).
            blk = address & 0xFFFF0000
            br = self.run.block_r
            br[blk] = br.get(blk, 0) + 1
            if a in self.hw_regs:
                v = self.hw_regs[a]
                if size == 1:   v &= 0xFF
                elif size == 2: v &= 0xFFFF
                uc.mem_write(address, v.to_bytes(4, 'little'))
            return
        # RAM read: poll tracking (hot loop detection)
        if self.pump or self.mode == "report":
            pc = uc.reg_read(UC_ARM_REG_PC) & ~1
            key = (pc, a, size)
            e = self.poll.get(key)
            if e is None:
                if len(self.poll) > 300000:
                    self.poll.clear()
                self.poll[key] = [1, 0, None, None, pc]
            else:
                e[0] += 1
                hits = e[0]
                if hits == HIT_PUMP and self._is_tick_pc(pc):
                    self._tick_pump(uc, key)
                elif hits >= HIT_UNSTICK * (e[1] + 1) and e[1] < MAX_UNSTICK_PER_KEY:
                    self._generic_unstick(uc, key)

    def _is_tick_pc(self, pc):
        return pc in (TICK_PC, TICK_PC + 2, TICK_PC + 4)

    def _tick_pump(self, uc, key):
        """Known delay loop: ldr r0,[r1,#0xc]; cmp r0,r2; blo -- advance counter to r2."""
        pc, addr, size = key
        e = self.poll[key]
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)
        target_addr = (r1 + 0xC) & 0xFFFFFFFF
        try:
            cur = int.from_bytes(uc.mem_read(target_addr, 4), 'little')
        except UcError:
            return
        new = cur
        if r2 > cur:
            new = r2
        elif r2 == 0:
            new = cur + 1
        if new != cur:
            uc.mem_write(target_addr, new.to_bytes(4, 'little'))
        self.pump_count += 1
        e[0] = 0  # restart hit window so subsequent waits pump too
        self.run.log(f"[PUMP ] tick #{self.pump_count}: [{target_addr:#010x}] {cur} -> {new} (target r2={r2:#x}) at pc {pc:#x}")
        self.run.ev("TICKPUMP", pc=hex(pc), addr=hex(target_addr),
                    old=cur, new=new, target=hex(r2))

    def _chan_acquire_guard(self, uc, address, size, user_data):
        """See _setup_hooks: seed the channel-manager descriptor on first
        use (boot-ROM IPC handshake model) so the real acquire path runs."""
        try:
            base = int.from_bytes(self.mu.mem_read(0x81abc618, 4), 'little')
        except UcError:
            return
        if base:
            return
        # values from the guest's own fill-init 0x811f670c (review-verified
        # against the raw halfwords; [0x18] is guest-runtime-derived
        # ([0x400A8024]+1), seeded as 1 which is what the first init sees).
        w = {0x0: 0x400A0000, 0x4: 0x1000, 0x8: 1, 0xc: 0xFFFFFFFC,
             0x10: 0x400A8000, 0x14: 0x1000, 0x18: 1, 0x1c: 0xFFFFFFFE,
             0x20: 0x18, 0x24: 0xFF, 0x28: 0x10, 0x2c: 0xFF}
        for off, val in w.items():
            self.mu.mem_write(0x81abc618 + off, int(val).to_bytes(4, 'little'))
        n = getattr(self, '_chan_seed_n', 0) + 1
        self._chan_seed_n = n
        if n <= 3:
            self.run.log("[CHAN ] descriptor seeded on first acquire "
                         "(pre-init CP log path)")
        self.run.ev("CHAN_SEED")

    def _chan_mgr_init_cb(self, uc, address, size, user_data):
        self.chan_mgr_inited = True
        self.run.log("[CHAN ] channel-module init (0x811bef1c) running - "
                     "AP manager takes over")
        self.run.ev("CHAN_INIT")

    def _osal_root_register_cb(self, uc, address, size, user_data):
        """See _setup_hooks: at the OSAL create service's success tail
        (mov r0,r4; b tail) register the first created object as the
        system-ctl root handle - the pre-kernel loader handoff model."""
        if getattr(self, '_osal_root_done', False):
            return
        h = uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF
        if not (0x80000000 <= h < 0x83000000):
            return
        self._osal_root_done = True
        self.mu.mem_write(0x817031c4, int(h).to_bytes(4, 'little'))
        self.run.log("[OSAL ] root object handle %08x registered at "
                     "[0x817031c4] (bootloader handoff)" % h)
        self.run.ev("OSAL_ROOT", handle=hex(h))

    def _osal_ensure_intercept(self, uc, address, size, user_data):
        """See _setup_hooks: return 'already done' (0) when the OSAL
        create service is entered from either master-init ensure site."""
        lr = uc.reg_read(UC_ARM_REG_LR) & ~1
        if lr not in (0x80a10976, 0x81218766):
            return
        n = getattr(self, '_osal_ensure_n', 0) + 1
        self._osal_ensure_n = n
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        if n <= 4:
            self.run.log("[OSAL ] ensure call from %08x -> already done "
                         "(pre-kernel handoff)" % lr)
        self.run.ev("OSAL_ENSURE", site=hex(lr))

    def _fs_report_intercept(self, uc, address, size, user_data):
        """See _setup_hooks: accept FS report events at the dispatcher
        without running the (stack-tangling) format machinery. The event
        payload is logged for visibility: r0..r3 = the report helper's
        scalars, [sp] = the caller's stack argument."""
        n = getattr(self, '_fs_report_n', 0) + 1
        self._fs_report_n = n
        sp = uc.reg_read(UC_ARM_REG_SP)
        try:
            sarg = int.from_bytes(self.mu.mem_read(sp, 4), 'little')
        except Exception:
            sarg = 0
        if n <= 12:
            self.run.log("[FS   ] event r0=%08x r1=%08x r2=%08x r3=%08x "
                         "[sp]=%08x" % (uc.reg_read(UC_ARM_REG_R0),
                                        uc.reg_read(UC_ARM_REG_R1),
                                        uc.reg_read(UC_ARM_REG_R2),
                                        uc.reg_read(UC_ARM_REG_R3), sarg))
        self.run.ev("FS_EVENT", n=n, r0=uc.reg_read(UC_ARM_REG_R0),
                    r1=uc.reg_read(UC_ARM_REG_R1), sarg=hex(sarg))
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def _log_class_keeper(self, uc, address, size, user_data):
        """See _setup_hooks: re-force the log class byte to 1 (enabled)
        after the guest ctor sets its 0x35 default."""
        self.mu.mem_write(0x817cc2e8 + 0x1b8, b'\x01')
        n = getattr(self, '_log_class_n', 0) + 1
        self._log_class_n = n
        if n <= 3:
            self.run.log("[LOG  ] class byte re-forced to 1 after ctor")
        self.run.ev("LOG_CLASS_KEEP")

    def _lcd_init_guard(self, uc, address, size, user_data):
        """See _setup_hooks: from LcdDrvInit's second call on, force the
        init-completed guard so the call takes its 2-instruction exit."""
        n = getattr(self, '_lcd_init_n', 0) + 1
        self._lcd_init_n = n
        if n >= 2:
            self.mu.mem_write(0x817020c8, int(1).to_bytes(4, 'little'))
            if n == 2:
                self.run.log("[LCD ] init guard forced - re-inits skip")
                self.run.ev("LCD_GUARD")

    def _nv_init_flag(self, uc, address, size, user_data):
        """See _setup_hooks: force the NV init-done flags after the two
        init calls return (normal-NV ctrl 0x817031c0, ref-NV ctrl
        0x81705fe0; flag = byte at ctrl+1). The container stays empty, so
        item reads miss the cache and take the guest's default-ROM filler
        - a first-boot with defaults, like real hardware."""
        for ctrl in (0x817031c0, 0x81705fe0):
            if int.from_bytes(self.mu.mem_read(ctrl + 1, 1), 'little') == 0:
                self.mu.mem_write(ctrl + 1, b'\x01')
        n = getattr(self, '_nv_flag_n', 0) + 1
        self._nv_flag_n = n
        if n <= 4:
            self.run.log("[NV   ] init-done flags forced (first-boot "
                         "defaults model) #%d" % n)
        self.run.ev("NV_FLAG")

    def _glue_segment_skip(self, uc, address, size, user_data):
        """See _setup_hooks: jump from the LTE/DSP glue segment start
        straight to the task spawn loop head."""
        if getattr(self, '_glue_skip_done', False):
            return
        self._glue_skip_done = True
        uc.reg_write(UC_ARM_REG_PC, 0x80c2f3ea | 1)
        self.run.log("[CHAIN ] glue segment skipped -> task spawn loop")
        self.run.ev("GLUE_SKIP")

    def _taskloop_exit_cut(self, uc, address, size, user_data):
        """See _setup_hooks: at the task-loop exit jump to app-phase=4 +
        return, skipping the post-loop spawn calls that dive into the
        firmware glue."""
        uc.reg_write(UC_ARM_REG_PC, 0x80c2f438 | 1)
        n = getattr(self, '_tl_cut_n', 0) + 1
        self._tl_cut_n = n
        if n <= 3:
            self.run.log("[CHAIN ] task loop done -> app-phase=4, return "
                         "(post-loop spawns skipped)")
        self.run.ev("TASKLOOP_CUT")

    def _post_init_cut(self, uc, address, size, user_data):
        """See _setup_hooks: return the app-init wrapper to kernel-enter
        after master-init, skipping the LTE/DSP pre-boot glue."""
        if getattr(self, '_post_cut_done', False):
            return
        self._post_cut_done = True
        sp = uc.reg_read(UC_ARM_REG_SP)
        ret = int.from_bytes(self.mu.mem_read(sp + 4, 4), 'little')
        uc.reg_write(UC_ARM_REG_PC, ret)
        self.run.log("[CUT  ] app-init wrapper returned to kernel-enter "
                     "at %08x - scheduler path" % ret)
        self.run.ev("POST_INIT_CUT", ret=hex(ret))

    def _gate_d_seed(self, uc, address, size, user_data):
        """See _setup_hooks: at the master-init tail wait loop, seed the
        power state to active (3) and enable the AON tick timer so the
        wait exits and the task spawn / scheduler can proceed."""
        if getattr(self, '_gate_d_done', False):
            return
        self._gate_d_done = True
        # one-shot: drop the mid-block exact code hooks (each costs every insn)
        self._drop_exact_hooks((0x80c2f1f2, 0x80c2f23e, 0x80c2f244, 0x80c2f30c))
        # 0x81702030 struct: +4 BOOT MODE (0x80a4f156), +8 power state
        # (0x80a4f32e), +0xc phase, +0x14 boot cause. The original shim wrote
        # 3 to +4 believing it was the power state -> every boot ran in boot
        # mode 3, whose app-init branch (0x80c2f480) never starts the
        # protocol stack (2026-10-31). GATE_D_MODE selects the variant.
        if GATE_D_MODE == "legacy":
            self.mu.mem_write(0x81702034, int(3).to_bytes(4, 'little'))
        elif GATE_D_MODE == "power":
            self.mu.mem_write(0x81702038, int(3).to_bytes(4, 'little'))
        self.mu.mem_write(AON_TMR_BASE, int(1).to_bytes(4, 'little'))
        self.hw_regs[AON_TMR_BASE] = 1
        # Boot cause: 0x80a0d718 reads [0x81702030+0x14] (cached at
        # 0x80a4f140). Zero = normal power-key boot (NOT charger boot).
        # This routes the boot-cause switch to the main app chain
        # (0x80c56fe0) instead of the charge-only path (0x8124bebe(1)).
        self.mu.mem_write(0x81702044, int(0).to_bytes(4, 'little'))
        self.run.log("[GATE ] wait loop reached - power state := 3, AON "
                     "tick timer enabled")
        self.run.ev("GATE_D")

    def _nv_read_intercept(self, uc, address, size, user_data):
        """See _setup_hooks: serve NV_Read (r0=id, r1=len, r2=buf). With
        NV_REAL the item comes from the phone's NV (nvcal / RunningNV
        journal); misses and NV_REAL=False get a zero-filled buffer. Always
        returns success."""
        rid = uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF
        r1 = uc.reg_read(UC_ARM_REG_R1) & 0xFFFFFFFF
        r2 = uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF
        item = getattr(self, 'nv_db', {}).get(rid) if NV_REAL else None
        src = item[1] if item else "zero"
        if r1 and r1 < 0x10000 and 0x80000000 <= r2 < 0x83000000:
            n_ = min(r1, 0x10000)
            if item:
                buf = item[0][:n_].ljust(n_, b'\0')
            elif NV_LEGACY_FILL:
                buf = b'\x70\x47' * (n_ // 2)
            else:
                buf = bytes(n_)
            self.mu.mem_write(r2, buf)
        n = getattr(self, '_nv_read_n', 0) + 1
        self._nv_read_n = n
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        ilen = len(item[0]) if item else -1
        if n <= 200:
            self.run.log("[NV   ] read id=%d len=%d -> %s (item len %d) lr=%#x"
                         % (rid, r1, src, ilen, uc.reg_read(UC_ARM_REG_LR)))
        self.run.ev("NV_READ", id=rid, ln=r1, src=src, ilen=ilen, dst=hex(r2),
                    lr=hex(uc.reg_read(UC_ARM_REG_LR)))

    def _res_read_intercept(self, uc, address, size, user_data):
        """See RES_MODEL: MMIRES read (r0=dst, r1=offset, r2=len) served
        from mmi_res.bin; returns 1 (ok), 0 for an out-of-range request
        like the BML size check."""
        dst = uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF
        off = uc.reg_read(UC_ARM_REG_R1) & 0xFFFFFFFF
        n = uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF
        res = getattr(self, '_res_img', None)
        if res is None:
            res = self._res_img = open(fwpaths.need(MMI_RES, 'mmi_res partition, ECC-corrected'), 'rb').read()
        ok = dst != 0 and off + n <= len(res)
        if ok and n:
            self.mu.mem_write(dst, res[off:off + n])
        k = getattr(self, '_res_read_n', 0) + 1
        self._res_read_n = k
        if k <= RES_LOG or not ok:
            self.run.log("[RES  ] read #%d off=%#x len=%#x -> %#x %s lr=%#x"
                         % (k, off, n, dst, "ok" if ok else "FAIL",
                            uc.reg_read(UC_ARM_REG_LR)))
        uc.reg_write(UC_ARM_REG_R0, 1 if ok else 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def _nv_getlen_intercept(self, uc, address, size, user_data):
        """See _setup_hooks: NV_GetLength for ids present in the real NV DB;
        misses fall through to the guest (empty-cache default path)."""
        rid = uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF
        item = self.nv_db.get(rid)
        self.run.ev("NV_GETLEN", id=rid, ilen=len(item[0]) if item else -1,
                    lr=hex(uc.reg_read(UC_ARM_REG_LR)))
        if item is None:
            return
        uc.reg_write(UC_ARM_REG_R0, len(item[0]))
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def _nv_write_intercept(self, uc, address, size, user_data):
        """See _setup_hooks: NV_Write (r0=id, r1=len, r2=buf) updates the
        in-memory DB (no flash write-back) and returns success."""
        rid = uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF
        r1 = uc.reg_read(UC_ARM_REG_R1) & 0xFFFF
        r2 = uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF
        try:
            data = bytes(self.mu.mem_read(r2, r1))
        except UcError:
            return
        self.nv_db[rid] = (data, "written")
        self.run.log("[NV   ] write id=%d len=%d lr=%#x" % (rid, r1, uc.reg_read(UC_ARM_REG_LR)))
        self.run.ev("NV_WRITE", id=rid, ln=r1, lr=hex(uc.reg_read(UC_ARM_REG_LR)))
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def _fdl_window_skip(self, uc, address, size, user_data):
        """See _setup_hooks: skip the 15 s FDL/diag-host wait window with
        the hardware window-EXPIRED result: state 9 at 0x8170400C. State
        9 is in LOG_CORE's skip set (0x80a09306-12: state 8 or 9 jumps
        past the whole send pipeline); state 6 falls into the pipeline
        and hangs on its un-built object graph."""
        if getattr(self, '_fdl_skip_done', False):
            return
        self._fdl_skip_done = True
        self.mu.mem_write(0x8170400C, int(9).to_bytes(4, 'little'))
        self.mu.mem_write(0x81704020, int(0).to_bytes(4, 'little'))
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        self.run.log("[FDL  ] diag-host window skipped (expired, state 9)")
        self.run.ev("FDL_SKIP")

    def _diag_chan_fix(self, uc, address, size, user_data):
        """See _setup_hooks: fabricate diag channel 1 (open magic, empty
        ring) on the first TX-drain entry so the flush completes."""
        if getattr(self, '_diag_chan_done', False):
            return
        self._diag_chan_done = True
        ptr = 0x82eaa000
        st = bytearray(0x94)
        st[3] = 0x55
        self.mu.mem_write(ptr, bytes(st))
        self.mu.mem_write(0x81703114, int(ptr).to_bytes(4, 'little'))
        self.run.log("[DIAG ] channel 1 fabricated at %08x (open, empty)"
                     % ptr)
        self.run.ev("DIAG_CHAN")

    def _log_send_skip(self, uc, address, size, user_data):
        """See _setup_hooks: skip log-fn's diagnostic send callback; the
        blx would walk the un-built log output object graph."""
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        n = getattr(self, '_log_send_n', 0) + 1
        self._log_send_n = n
        if n <= 3:
            self.run.log("[LOG  ] send callback skipped (no diag host) #%d"
                         % n)
        self.run.ev("LOG_SEND_SKIP")

    def _late_chain_skip(self, uc, address, size, user_data):
        """See _setup_hooks: skip the master-init late-chain step whose
        indirect dispatch is uninitialized in this boot."""
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        n = getattr(self, '_late_skip_n', 0) + 1
        self._late_skip_n = n
        if n <= 3:
            self.run.log("[CHAIN] 0x80a48fac dispatch skipped (uninit "
                         "table)")
        self.run.ev("CHAIN_SKIP")

    def _fw_region_guard(self, uc, address, size, user_data):
        """See _setup_hooks: any AP execution dive into the pre-loaded
        LTE/DSP firmware region returns to the caller immediately."""
        n = getattr(self, '_fw_guard_n', 0) + 1
        self._fw_guard_n = n
        if n <= 8:
            self.run.log("[FW   ] execution dive blocked at pc=%08x lr=%08x"
                         % (address, uc.reg_read(UC_ARM_REG_LR)))
        self.run.ev("FW_GUARD", pc=hex(address))
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def _cp_log_drain_cb(self, uc, address, size, user_data):
        """Store-site model of the modem-core monitor: the log in-flight
        counter never leaves zero (fires at the logger's ADDS, 0x80a09184)."""
        if getattr(self, 'cp_log_drain', True):
            uc.reg_write(UC_ARM_REG_R0, 0)

    def _generic_unstick(self, uc, key):
        pc, addr, size = key
        e = self.poll[key]
        e[1] += 1
        gen = e[1]
        mask = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF}.get(size, 0xFFFFFFFF)
        if gen == 1: val = 1
        elif gen == 2: val = mask
        else: val = (mask >> 1) + 1  # 0x8000..: sign/status bit
        try:
            uc.mem_write(addr, (val & mask).to_bytes(size, 'little'))
        except UcError:
            self._auto_map(addr & ~0xFFF)
            uc.mem_write(addr, (val & mask).to_bytes(size, 'little'))
        self.unstick_count += 1
        insn = e[3] or self._disasm_at(uc, pc)
        e[3] = insn
        self.run.log(f"[UNSTK] gen{gen} [{addr:#010x}] <- {val & mask:#x} "
                     f"({size}B) pc={pc:#x} insn='{insn}' hits>={HIT_UNSTICK * gen}")
        self.run.ev("UNSTICK", pc=hex(pc), addr=hex(addr), size=size,
                    gen=gen, value=val & mask, insn=insn)
        if self.unstick_count >= MAX_UNSTICK_TOTAL:
            self.stop_reason = "unstick-budget"
            self.mu.emu_stop()

    def mmio_hist_on(self):
        self._mmio_rd_hist = {}

    def mmio_hist_dump(self):
        h = self._mmio_rd_hist
        if not h:
            return
        top = sorted(h.items(), key=lambda kv: -kv[1])[:40]
        pcl = getattr(self, '_mmio_rd_pc', {})
        self.run.log("[MMIOR] top reads: " +
                     " ".join("%06x=%d@%08x" % (a, n, pcl.get(a, 0)) for a, n in top))

    def _pmu_update(self):
        """Derive PMU power-status 0x402b00c0/c4/d4 from the request bits.
        Islands sit behind the whale die power request 0x60830044 bit6
        (live: requests released but c0/c4 stayed 7 until the die was
        powered). Field 0 = ON, 7 = OFF. Transitions are instant."""
        r = self.hw_regs.get
        whale = bool(r(0x60830044, 0) & 0x40)
        wtlcp_req = not (r(0x402B0044, 0) & 0x01000000)
        wtlcp = whale and wtlcp_req
        whu3g = whale and not (r(0x402B003C, 0) & 0x02000000)
        xdsp_lte = wtlcp and not (r(0x402B0034, 0) & 0x03000000)
        xdsp_gsm = whu3g and not (r(0x402B0038, 0) & 0x03000000)
        cm4 = not (r(0x402B00CC, 0) & 0x00200000)
        f = lambda on: 0 if on else 7
        c0 = (0x0E000000 | f(whu3g) | f(xdsp_lte) << 5 | f(xdsp_gsm) << 10
              | f(cm4) << 15)
        c4 = f(wtlcp)
        d4 = 0x60 if wtlcp_req else 0     # live: FSM reached 6 unpowered
        self.hw_regs[0x402B00C0] = c0
        self.hw_regs[0x402B00C4] = c4
        self.hw_regs[0x402B00D4] = d4
        st = (c0, c4, d4)
        if st != self._pmu_state:
            prev = self._pmu_state
            self._pmu_state = st
            if prev is not None and hasattr(self, 'run'):
                pc = self.mu.reg_read(UC_ARM_REG_PC)
                self.run.log(f"[PMU  ] c0={c0:08x} c4={c4:x} d4={d4:02x} "
                             f"(whale={int(whale)}) pc={pc:#x} insn={self.insn_total}")
                self.run.ev("PMU_STATE", c0=hex(c0), c4=hex(c4), d4=hex(d4),
                            pc=hex(pc), insn=self.insn_total)

    def _sdhci_read(self, uc, access, address, size, value, user_data):
        """See SDHCI_MODEL: CLK_CTRL bit1 (stable) mirrors bit0 (enable)."""
        a = address & ~3
        if a & 0xFFFFF != 0x2C:
            return
        try:
            v = int.from_bytes(uc.mem_read(a, 4), 'little')
        except UcError:
            return
        v = (v & ~2) | ((v & 1) << 1)
        uc.mem_write(a, v.to_bytes(4, 'little'))

    # ------------------------------------------------------------- GIC-400
    def _gic_set_pending(self, iid):
        g = self.gic
        if iid not in g["pend"]:
            g["pend"].add(iid)
            g.setdefault("pt", {})[iid] = self.insn_total

    def _gic_pick(self, d):
        """Oldest pending first (ties: lowest id). The real GIC picks by
        priority and retakes the next IRQ right after EOI; chunk-granular
        delivery plus a tick that re-pends every chunk would starve every
        higher id under lowest-id-first."""
        pt = self.gic.get("pt", {})
        return min(d, key=lambda i: (pt.get(i, 0), i))

    def _wrap_hook_add(self):
        """See BLOCK_HOOKS: route single-address code hooks to block hooks."""
        mu = self.mu
        raw = mu.hook_add
        self._raw_hook_add = raw
        self._exact_code_hooks = {}

        def hook_add(htype, cb, user_data=None, begin=1, end=0, *a, **k):
            if getattr(self, '_mmio_native', False) and \
                    htype & (UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE) and \
                    not htype & ~(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE):
                if begin <= end and self._dev_covers(begin, end - begin):   # end may be exclusive
                    self._py_mem_hooks.append((htype, begin, end, cb, user_data))
                    self._py_hook_cache = {}
                    return 0
                self.run.log(f"[MMIO ] memory hook outside device regions "
                             f"{begin:#x}-{end:#x} ({getattr(cb, '__name__', cb)}): "
                             f"forces unicorn's slow memory path")
            if htype == UC_HOOK_CODE and begin <= end and end - begin <= 4:
                if (begin & ~1) in CODE_HOOK_EXACT:
                    h = raw(htype, cb, user_data, begin, end, *a, **k)
                    self._exact_code_hooks.setdefault(begin & ~1, []).append(h)
                    return h
                return self._block_hook_at(begin, cb, user_data)
            if htype == UC_HOOK_BLOCK and begin == end:
                return self._block_hook_at(begin, cb, user_data)
            return raw(htype, cb, user_data, begin, end, *a, **k)
        mu.hook_add = hook_add

    def _native_setup(self):
        """See NATIVE: load emu_native.dll and register its C hooks."""
        if not os.path.exists(NATIVE_DLL):
            self.run.log(f"[NATIVE] {NATIVE_DLL} missing - Python paths "
                         f"(build: python -m ziglang cc -shared -O2 -o emu_native.dll emu_native.c)")
            return
        from unicorn.unicorn_py3 import unicorn as _ucmod
        uclib = _ucmod.uclib
        lib = ctypes.CDLL(NATIVE_DLL)
        vp = lambda f: ctypes.cast(f, ctypes.c_void_p)
        self.nst = NativeState()
        lib.native_init(vp(uclib.uc_reg_read), vp(uclib.uc_emu_stop),
                        ctypes.c_int(UC_ARM_REG_CPSR), ctypes.pointer(self.nst))
        self._native_lib = lib
        self._native_hooks = []
        h = _ucmod.uc_hook_h()
        err = uclib.uc_hook_add(self.mu._uch, ctypes.byref(h), UC_HOOK_BLOCK,
                                vp(lib.blk_unmask_cb),
                                ctypes.cast(ctypes.pointer(self.nst), ctypes.c_void_p),
                                ctypes.c_uint64(1), ctypes.c_uint64(0))
        if err:
            self.run.log(f"[NATIVE] uc_hook_add failed: {err}")
            return
        self._native_hooks.append(h)
        self._native = True
        self._py_blk = {}
        BLK = ctypes.CFUNCTYPE(None, ctypes.c_uint64, ctypes.c_uint32)
        self._py_blk_cb = BLK(self._py_block)
        lib.native_set_py_block(vp(self._py_blk_cb))
        self.run.log("[NATIVE] emu_native.dll loaded: blk_unmask_cb")

    # ---------------------------------------------------- native MMIO
    def _setup_dev_regions(self):
        """See MMIO_NATIVE: map device windows with C callbacks + shadows."""
        from unicorn.unicorn_py3 import unicorn as _ucmod
        uclib = _ucmod.uclib
        lib = self._native_lib
        vp = lambda f: ctypes.cast(f, ctypes.c_void_p)
        lib.native_region_mem.restype = ctypes.c_void_p
        self._dev = []
        for base, size, py, name in DEV_REGIONS:
            idx = lib.native_region_add(ctypes.c_uint64(base), ctypes.c_uint64(size), py)
            mem = lib.native_region_mem(idx)
            err = uclib.uc_mmio_map(self.mu._uch, ctypes.c_uint64(base), ctypes.c_size_t(size),
                                    vp(lib.mmio_read_cb), ctypes.c_void_p(idx),
                                    vp(lib.mmio_write_cb), ctypes.c_void_p(idx))
            if err:
                raise RuntimeError(f"uc_mmio_map {base:#x} failed: {err}")
            self._dev.append((base, size, mem, idx))
            self.run.log(f"  mmio {name}: {base:#x}+{size:#x} (py={py})")
        self._dev.sort()
        self._dev_bases = [d[0] for d in self._dev]
        for pg in CTR_PAGES:
            lib.native_add_ctr_page(ctypes.c_uint64(pg))
            if CTR_REALTIME:
                lib.native_set_ctr_scale(ctypes.c_uint64(pg), ctypes.c_double(self._ctr_scale(pg, 4)),
                                         ctypes.c_double(self._ctr_scale(pg, 0xC)))
        lib.native_set_ct(1 if CONTINUOUS_TIME else 0)
        lib.native_set_fast(1 if NATIVE_FAST else 0, ctypes.c_double(WTL_TS_PER_INSN))
        lib.native_get_adi_rid.restype = ctypes.c_uint32
        self._py_mem_hooks = []
        self._py_hook_cache = {}
        RD = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32)
        WR = ctypes.CFUNCTYPE(None, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint64)
        self._py_rd_cb = RD(self._py_mmio_read)
        self._py_wr_cb = WR(self._py_mmio_write)
        lib.native_set_py(vp(self._py_rd_cb), vp(self._py_wr_cb))
        # Python-side memory access to device addresses -> shadow
        mu = self.mu
        self._uc_mem_read = mu.mem_read
        self._uc_mem_write = mu.mem_write
        mu.mem_read = self._dev_mem_read
        mu.mem_write = self._dev_mem_write

    def _dev_find(self, addr, size):
        import bisect
        i = bisect.bisect_right(self._dev_bases, addr) - 1
        if i >= 0:
            b, n, mem, _ = self._dev[i]
            if b <= addr and addr + size <= b + n:
                return mem + (addr - b)
        return None

    def _dev_mem_read(self, address, size):
        p = self._dev_find(address, size)
        if p is None:
            return self._uc_mem_read(address, size)
        return bytearray(ctypes.string_at(p, size))

    def _dev_mem_write(self, address, data):
        p = self._dev_find(address, len(data))
        if p is None:
            return self._uc_mem_write(address, data)
        ctypes.memmove(p, bytes(data), len(data))

    def _py_hooks_for(self, addr, rw):
        """Registration-ordered hooks covering addr's 4K page (cached)."""
        key = (addr >> 12, rw)
        hl = self._py_hook_cache.get(key)
        if hl is None:
            pg = addr & ~0xFFF
            hl = [(lo, hi, cb, ud) for ht, lo, hi, cb, ud in self._py_mem_hooks
                  if ht & rw and lo <= pg + 0xFFF and hi >= pg]
            self._py_hook_cache[key] = hl
        return hl

    def _py_mmio_read(self, addr, size):
        try:
            for lo, hi, cb, ud in self._py_hooks_for(addr, UC_HOOK_MEM_READ):
                if lo <= addr <= hi:
                    cb(self.mu, UC_MEM_READ, addr, size, 0, ud)
            p = self._dev_find(addr, size)
            return int.from_bytes(ctypes.string_at(p, size), 'little') if p else 0
        except Exception as e:                     # never unwind through C
            self._py_exc = e
            self.mu.emu_stop()
            return 0

    def _py_mmio_write(self, addr, size, value):
        try:
            for lo, hi, cb, ud in self._py_hooks_for(addr, UC_HOOK_MEM_WRITE):
                if lo <= addr <= hi:
                    cb(self.mu, UC_MEM_WRITE, addr, size, value, ud)
            p = self._dev_find(addr, size)
            if p:
                ctypes.memmove(p, (value & ((1 << (8 * size)) - 1)).to_bytes(size, 'little'), size)
                if 0x40600000 <= addr < 0x40610000:
                    hv = self.hw_regs.get(addr & ~3)
                    if hv is not None:
                        ctypes.memmove(self._dev_find(addr & ~3, 4),
                                       (hv & 0xFFFFFFFF).to_bytes(4, 'little'), 4)
        except Exception as e:
            self._py_exc = e
            self.mu.emu_stop()

    def _py_block(self, addr, size):
        try:
            for cb, ud in self._py_blk.get(addr, ()):
                cb(self.mu, addr, size, ud)
        except Exception as e:                     # never unwind through C
            self._py_exc = e
            self.mu.emu_stop()

    def _mmu_off(self, uc, why):
        try:
            sc = uc.reg_read(UC_ARM_REG_CP_REG, SCTLR_REG)
        except UcError:
            return False
        if not sc & 1:
            return False
        uc.reg_write(UC_ARM_REG_CP_REG, SCTLR_REG + (sc & ~1,))
        n = getattr(self, '_mmu_off_n', 0) + 1
        self._mmu_off_n = n
        if n <= 5:
            self.run.log(f"[MMU  ] SCTLR.M cleared ({why}) sctlr={sc:#x} "
                         f"pc={uc.reg_read(UC_ARM_REG_PC):#x} #{n}")
        return True

    def _on_intr(self, uc, intno, user_data):
        """See INTR_HOOK. intno: 1 UDEF, 2 SWI, 3 prefetch abort,
        4 data abort, 5 IRQ, 7 BKPT."""
        pc = uc.reg_read(UC_ARM_REG_PC)
        if intno in (3, 4) and MMU_GUARD and self._mmu_off(uc, f"abort {intno}"):
            return                                   # retry with MMU off
        if intno == 1 and (pc & ~1) == 0x10A4:
            self._msr_cpsr_cb(uc, 0x10A4, 4, None)
            return
        if intno == 1:
            for delta in (0, -4, 4, -2, 2):
                w_pc = (pc + delta) & ~1
                try:
                    word = int.from_bytes(uc.mem_read(w_pc & ~3 if not (uc.reg_read(UC_ARM_REG_CPSR) & 0x20) else w_pc, 4), 'little')
                except UcError:
                    continue
                if (decode_cp15(word) or decode_mcrr(word)) and self._cp15_service(uc, w_pc, word):
                    self._advance(uc, w_pc)
                    self.cp15_served = getattr(self, 'cp15_served', 0) + 1
                    return
        n = getattr(self, '_intr_unh', 0) + 1
        self._intr_unh = n
        self.run.log(f"[INTR ] unhandled exception {intno} at pc={pc:#x} "
                     f"ctx: {self._disasm_at(uc, pc, 2)}")
        self.run.ev("INTR_UNHANDLED", intno=intno, pc=hex(pc))
        self.stop_reason = f"exception-{intno}"
        self.stop_detail = f"pc={pc:#x}"
        uc.emu_stop()

    def _block_hook_at(self, addr, cb, user_data):
        if NATIVE_BLOCK_DISPATCH and getattr(self, '_native', False):
            if addr not in self._py_blk:
                self._native_lib.native_add_block_addr(ctypes.c_uint64(addr))
            self._py_blk.setdefault(addr, []).append((cb, user_data))
            return 0
        return self._raw_hook_add(UC_HOOK_BLOCK, cb, user_data, addr, addr)

    def _drop_exact_hooks(self, addrs):
        for a in addrs:
            for h in self._exact_code_hooks.pop(a, []) if hasattr(self, '_exact_code_hooks') else []:
                try:
                    self.mu.hook_del(h)
                except (UcError, KeyError):
                    pass

    def _gic_ready(self, mu):
        try:
            return int.from_bytes(mu.mem_read(0x817B1D3C, 4), 'little') != 0
        except UcError:
            return False

    def _gic_deliverable(self, mu):
        g = self.gic
        if not self._gic_ready(mu):
            return set(g["pend"])
        if not (g["dctlr"] & 1 and g["cctlr"] & 1):
            return set()
        return g["pend"] & g["en"]

    def _gic_write(self, uc, access, address, size, value, user_data):
        g = self.gic
        v = value & 0xFFFFFFFF
        off = address - 0x12001000
        if off == 0:
            g["dctlr"] = v
        elif 0x100 <= off < 0x180 or 0x180 <= off < 0x200 or 0x200 <= off < 0x300:
            base = (off & 0x7F) * 8
            ids = {base + i for i in range(32) if v >> i & 1}
            if off < 0x180:
                g["en"] |= ids
            elif off < 0x200:
                g["en"] -= ids
            elif off < 0x280:
                for i in ids:
                    self._gic_set_pending(i)
            else:
                g["pend"] -= ids
        elif address == 0x12002000:
            g["cctlr"] = v
        elif address == 0x12002010:
            iid = v & 0x3FF
            if iid in g["active"]:
                g["active"].remove(iid)
            g["eois"] += 1

    def _gic_read(self, uc, access, address, size, value, user_data):
        g = self.gic
        off = address - 0x12001000
        a = address & ~3
        v = None
        if 0x100 <= off < 0x200:
            base = (off & 0x7F & ~3) * 8
            v = sum(1 << i for i in range(32) if base + i in g["en"])
        elif 0x200 <= off < 0x300:
            base = (off & 0x7F & ~3) * 8
            v = sum(1 << i for i in range(32) if base + i in g["pend"])
        elif a == 0x1200200C:                       # IAR: acknowledge
            d = self._gic_deliverable(uc)
            if d:
                v = self._gic_pick(d)
                g["pend"].discard(v)
                g["active"].append(v)
                g["acks"] += 1
            else:
                v = 0x3FF
        elif a == 0x12002018:                       # HPPIR
            d = self._gic_deliverable(uc)
            v = self._gic_pick(d) if d else 0x3FF
        if v is not None:
            uc.mem_write(a, int(v).to_bytes(4, 'little'))

    def _gic_tick_source(self, mu):
        """Same cadence/gating as _deliver_ticks, but only sets PENDING."""
        now = (self.insn_total // getattr(self, 'tick_rate', 200_000)) & 0xFFFFFFFF
        if not (self.hw_regs.get(AON_TMR_BASE, 0) & 1):
            return
        try:
            vec = int.from_bytes(mu.mem_read(0x38, 4), 'little')
        except UcError:
            vec = 0
        if not vec or vec < 0x1000:
            return
        due = False
        T = getattr(self, 'aptmr', None)
        if AP_TMR_MODEL and T and T.get("started"):
            if T["due"] is not None and self.insn_total >= T["due"]:
                due = True
                if T["ctrl"] & 1 and T["period"]:
                    while T["due"] <= self.insn_total:
                        T["due"] += T["period"]
                else:
                    T["due"] = None
        else:
            while now >= self.tick_next:
                self.tick_next = (self.tick_next + 1) & 0xFFFFFFFF
                due = True
        if due and not getattr(self, 'chain_hold', False):
            ids = getattr(self, 'tick_irq_cycle', None) or [0x3D]
            n = getattr(self, '_irq_cycle', 0)
            self._irq_cycle = n + 1
            self._gic_set_pending(ids[n % len(ids)])

    def _gic_hook_unmask_sites(self):
        sites = set()
        img = getattr(self, 'payload', None) or b""
        for off in range(0, len(img) - 3, 2):
            h1 = img[off] | img[off + 1] << 8
            h2 = img[off + 2] | img[off + 3] << 8
            if h1 in (0xB662, 0xB663):                        # cpsie i / if
                sites.add(KBASE + off + 2)
            elif (h1 & 0xFFF0) == 0xF380 and (h2 & 0xF0FF) == 0x8000 and h2 & 0x0100:
                sites.add(KBASE + off + 4)                    # msr cpsr_c.., Rn
            if off % 4 == 0:
                w = h1 | h2 << 16
                if (w & 0x0FFFFFF0) in (0x0121F000, 0x012FF000, 0x0123F000,
                                        0x0129F000) or w in (0xF1080080, 0xF10800C0):
                    sites.add(KBASE + off + 4)
        try:
            blob = bytes(self.mu.mem_read(0, 0x19A8))
        except UcError:
            blob = b""
        for off in range(0, len(blob) - 3, 4):
            w = int.from_bytes(blob[off:off + 4], 'little')
            if (w & 0x0FFFFFF0) in (0x0121F000, 0x012FF000, 0x0123F000,
                                    0x0129F000) or w in (0xF1080080, 0xF10800C0):
                sites.add(off + 4)
            for hh in (w & 0xFFFF, w >> 16):
                if hh in (0xB662, 0xB663):
                    sites.add(off + (2 if hh == (w & 0xFFFF) else 4))
        for a in sites:
            self.mu.hook_add(UC_HOOK_CODE, self._gic_unmask_site_cb, begin=a, end=a)
        self.run.log(f"[GIC  ] unmask sites hooked: {len(sites)}")
        return len(sites)

    def _gic_unmask_site_cb(self, uc, address, size, user_data):
        if getattr(self, '_gic_waiting', False) and \
                not (uc.reg_read(UC_ARM_REG_CPSR) & 0x80):
            self._gic_waiting = False
            self._stop_cause = 'unmask'
            uc.emu_stop()

    def _gic_unmask_cb(self, uc, address, size, user_data):
        if not (uc.reg_read(UC_ARM_REG_CPSR) & 0x80):
            self._gic_unmasked = True
            uc.emu_stop()

    def _gic_step(self, mu):
        g = self.gic
        h = getattr(self, '_gic_watch_h', None)
        if h is not None:
            mu.hook_del(h)
            self._gic_watch_h = None
        self._gic_tick_source(mu)
        if CP_STUB and getattr(self, 'cp_rxq', None) and 0x65 not in g["active"]:
            self._gic_set_pending(0x65)
        if SIM_MODEL:
            for ctl, gid in self.sim.values():
                if ctl.irq() and gid not in g["active"]:
                    self._gic_set_pending(gid)
        if LTE_ADX_STUB and getattr(self, 'adx_running', False):
            self._adx_cmds(mu)                  # the DSP polls its command ring every subframe
        if LTE_ADX_STUB and getattr(self, '_adx_pending', None):
            self._adx_poll(mu)
        if RTC_MODEL and self.hw_regs.get(0x406080C0, 0) and PMIC_GIC_ID not in g["active"]:
            self._gic_set_pending(PMIC_GIC_ID)
        if LCDC_MODEL and (self.lcdc["raw"] & self.lcdc["en"]) and LCDC_GIC_ID not in g["active"]:
            self._gic_set_pending(LCDC_GIC_ID)
        if I2C_MODEL:
            for c in self.i2c.values():
                if (c["st"] & 4) and (c["ctl"] & 0x800) and c["gid"] not in g["active"]:
                    self._gic_set_pending(c["gid"])
        d = self._gic_deliverable(mu)
        if not d:
            return
        if g["active"]:
            # an IRQ is still in service (no EOIR yet). Hardware would not
            # preempt at equal priority; if the CPU has left IRQ mode the
            # handler ended without EOIR - retire it so delivery resumes.
            if (mu.reg_read(UC_ARM_REG_CPSR) & 0x1F) == 0x12:
                return
            g["active"].clear()
            g["lost_eoi"] = g.get("lost_eoi", 0) + 1
        cpsr = mu.reg_read(UC_ARM_REG_CPSR)
        pc = mu.reg_read(UC_ARM_REG_PC)
        forced = any(lo <= pc <= hi for lo, hi in GIC_FORCED_RANGES)
        if (cpsr & 0x80) and not forced and self._native:
            self.nst.gic_waiting = 1           # C hook stops at the unmask
            return
        if (cpsr & 0x80) and not forced and not GIC_UNMASK_SITES and                 getattr(self, '_wfi_wake', False):
            # WFI woke on the pending IRQ: run the idle path to its unmask
            for n in range(GIC_WFI_STEP_MAX):
                try:
                    mu.emu_start(self._start_pc(), UNTIL_NEVER, count=1)
                except UcError:
                    break
                if not (mu.reg_read(UC_ARM_REG_CPSR) & 0x80):
                    break
            self.insn_total += n + 1
            self._wfi_wake = False
            cpsr = mu.reg_read(UC_ARM_REG_CPSR)
            pc = mu.reg_read(UC_ARM_REG_PC)
        if (cpsr & 0x80) and not forced:
            # wait for the guest to unmask: the unmask-site hooks stop the
            # chunk right after the unmasking instruction; the chunk is
            # also shortened to bound the time over-count of that stop
            self._gic_waiting = True
            self._chunk_override = GIC_MASKED_CHUNK
            return
        self._gic_waiting = False
        if self._native:
            self.nst.gic_waiting = 0
        iid = self._gic_pick(d)
        if not self._gic_ready(mu):
            g["pend"].discard(iid)              # legacy: no IAR ack
        self._inject_irq(mu, force=True, num=iid)
        g["taken"] += 1
        if iid == 0x65:
            n = getattr(self, '_mbx_irq_n', 0) + 1
            self._mbx_irq_n = n
            if n <= 20:
                self.run.log(f"[MBX-IRQ] id 0x65 -> AP at pc={pc:#x} "
                             f"({len(self.cp_rxq)} queued)")
            self.run.ev("MBX_IRQ", pc=hex(pc), n=len(self.cp_rxq))
        if g["taken"] in (1, 10, 100, 1000, 10000, 100000):
            self.run.log(f"[GIC  ] taken={g['taken']} acks={g['acks']} eois={g['eois']} "
                         f"en={[hex(x) for x in sorted(g['en']) if x >= 32]} ready={self._gic_ready(mu)} "
                         f"dctlr={g['dctlr']:#x} cctlr={g['cctlr']:#x} "
                         f"lost_eoi={g.get('lost_eoi', 0)}")

    def _gicc_iar_read(self, uc, access, address, size, value, user_data):
        """GICC_IAR: the injected interrupt id once, then 0x3ff (spurious)."""
        v = getattr(self, 'gic_iar', 0x3FF)
        self.gic_iar = 0x3FF
        uc.mem_write(0x1200200C, int(v).to_bytes(4, 'little'))

    def _hwlock_read(self, uc, access, address, size, value, user_data):
        """See HWSPINLOCK: test-and-set on read."""
        n = (address - 0x33000800) >> 2
        if n in self.hwlock_held:
            v = 1
        else:
            v = 0
            self.hwlock_held.add(n)
        uc.mem_write(address & ~3, v.to_bytes(4, 'little'))

    def _hwlock_write(self, uc, access, address, size, value, user_data):
        if (value & 0xFFFFFFFF) == 0x55AA10C5:
            self.hwlock_held.discard((address - 0x33000800) >> 2)

    def _wtl_timer_read(self, uc, access, address, size, value, user_data):
        """See WTL_TIMER: publish the frame timer before the read lands."""
        t = int(self._now() * WTL_TS_PER_INSN)
        frame, ts = divmod(t, 307200)
        lo = ((frame & 0x1FFF) << 19) | ts
        hi = (frame >> 13) & 0x7FFFF
        uc.mem_write(0xE0020010, lo.to_bytes(4, 'little') + hi.to_bytes(4, 'little'))

    def _rfti_xfer(self, uc):
        """See RF_MODEL: one RFTI transaction from the command word."""
        w = self.hw_regs.get(0x40070240, 0)
        reg = (w >> 16) & 0x7FFF
        rf = self.__dict__.setdefault('rf_regs', {})
        pc = uc.reg_read(UC_ARM_REG_PC)
        lr = uc.reg_read(UC_ARM_REG_LR)
        if w & 0x80000000:
            val = rf.get(reg, RF_CHIP_ID if reg == 0x7F else 0)
            self.hw_regs[0x40070248] = val
            uc.mem_write(0x40070248, val.to_bytes(4, 'little'))
            rw = "R"
        else:
            val = w & 0xFFFF
            rf[reg] = val
            rw = "W"
        n = getattr(self, '_rfti_n', 0) + 1
        self._rfti_n = n
        if n <= 400:
            self.run.log(f"[RFTI ] {rw} reg={reg:#06x} val={val:#06x} pc={pc:#x} lr={lr:#x}")
        self.run.ev("RFTI", rw=rw, reg=hex(reg), val=hex(val), pc=hex(pc),
                    lr=hex(lr), insn=self.insn_total)

    def on_write(self, uc, access, address, size, value, user_data):
        if 0x70B00000 <= address < 0x70B00100:
            # display engine block (the UART range check
            # below used to swallow this window - writes were lost and byte
            # writes leaked as UART chars). Record and let display_model's
            # layered hooks see the write too.
            self.hw_regs[address & ~3] = value & 0xFFFFFFFF
            self.run.ev("DISPENG_W", addr=hex(address), val=hex(value))
            return
        if UART_LO <= address < UART_END:
            self._uart_write(address, size, value)
            return
        if LCDC_MODEL and (address & ~3) in (0x20800000, 0x20800110, 0x20800114):
            self._lcdc_write(uc, address & ~3, value)
            return
        if I2C_MODEL and (address & ~0xFFF) in self.i2c and (address & 0xFFF) < 0x40:
            self._i2c_write(uc, address & ~0xFFF, address & 0xFFC, value)
            return
        if SIM_MODEL and (address & ~0xFFF) in self.sim and (address & 0xFFF) < 0x100:
            self.sim[address & ~0xFFF][0].write(address & 0xFFC, value)
            return
        if SNF_BASE <= address < SNF_BASE + 0x600:
            self._snf_write(uc, address, size, value)
            return
        if self._is_mmio(address):
            a = address & ~3
            self._n_mmio_w_since = getattr(self, '_n_mmio_w_since', 0) + 1
            if address == INTC_ENABLE:
                cur = self.hw_regs.get(a, 0)
                self.hw_regs[a] = cur | (value & 0xFFFFFFFF)
                return
            if address == INTC0_BASE + 0x0C:
                cur = self.hw_regs.get(INTC_ENABLE, 0)
                self.hw_regs[INTC_ENABLE] = cur & ~(value & 0xFFFFFFFF)
                return
            if address in (INTC0_BASE + 0x18, INTC0_BASE + 0x24,
                           INTC0_BASE + 0x98, INTC0_BASE + 0xA4):
                # dispatcher ack/mask writes for the SYST bank: drop pending
                self.tick_pending = False
                return
            if 0x40600020 <= address < 0x40600030:
                # ADI AON doorbell request (0x40600028): id lives in bits[16:2]
                self.adi_req_id = (value >> 2) & 0x7FFF
                if address == 0x40600028:
                    self.adi_ever_submitted = True
                # THROTTLED: this fires ~6 per 1000
                # instructions during pinmux passes (the poll helpers
                # re-submit constantly) - 5.5M events / 577MB in long
                # runs. Keep the state update unconditional, log the
                # first 100 + every 4096th.
                n = getattr(self, '_adi_bell_n', 0) + 1
                self._adi_bell_n = n
                if n <= 100 or n % 4096 == 0:
                    self.run.ev("ADI_BELL", addr=hex(address), val=hex(value),
                                req_id=self.adi_req_id)
            if CP_STUB and address == 0x400A800C and (value & 1):
                q = self.__dict__.setdefault('cp_rxq', [])
                if q:
                    m = q.pop(0)
                    self.run.log(f"[MBX-RX] AP popped tag={m[0]} w0={m[1]:#010x} w1={m[2]:#010x} "
                                 f"pc={uc.reg_read(UC_ARM_REG_PC):#x}")
                    self.run.ev("MBX_RX_POP", tag=m[0], w0=hex(m[1]), w1=hex(m[2]))
            if address == 0x400A0000:
                # mailbox cmd register: the chan-mgr writes the channel id
                # here when submitting a request (mgr-lite: str r4,[r0])
                self._mbx_ch = value & 0xFF
            if address == 0x400A000C:
                # AP mailbox doorbell: the chan
                # ctl 0x81abc618 is a DESCRIPTOR whose [+0] = 0x400a0000
                # (the AP mailbox MMIO base) - the acquirer (0x811f6554)
                # polls the HW register 0x400a0014, not RAM. Polarity:
                # bit(ch) SET = slot in use (acquire fails -1); bit(ch+24)
                # SET = spin-wait; BOTH CLEAR = acquire succeeds. Model:
                # doorbell sets bit(ch) (slot handed to the CP); the tick
                # drain clears it once the CP consumed. Never touch
                # bit(ch+24), never write the descriptor RAM.
                # ACK semantics: the doorbell sets
                # bit(ch) - the channel-open/slot-taken ACK the sender
                # waits for. The main loop's CP-consume model clears the
                # mask within one chunk (the modem core consumed the
                # slot), so an acquirer running later sees a clear mask.
                # (The old pre-init silent consume swallowed the ACK and
                # the sender timed out + retried forever.)
                ch = getattr(self, '_mbx_ch', 0)
                if CP_STUB:
                    self._cp_stub_tx(uc, ch)
                cur = self.hw_regs.get(0x400A0014, 0) | (1 << (ch & 31))
                self.hw_regs[0x400A0014] = cur
                uc.mem_write(0x400A0014, int(cur).to_bytes(4, 'little'))
                self.run.ev("MBX_ACK", ch=ch, mask=hex(cur))
            self.hw_regs[a] = (self.hw_regs.get(a, 0) & ~(0xFFFFFFFF >> (8 * (4 - size)))) | (value & 0xFFFFFFFF) if size < 4 else value & 0xFFFFFFFF
            if PMU_MODEL:
                blk_ = a & 0xFFFF0000
                off_ = a & 0xFFFF
                if blk_ in PMU_SETCLR_BLOCKS and 0x1000 <= off_ < 0x3000:
                    base = blk_ | (off_ & 0xFFF)
                    cur = self.hw_regs.get(base, 0)
                    v_ = value & 0xFFFFFFFF
                    self.hw_regs[base] = (cur | v_) if off_ < 0x2000 else (cur & ~v_)
                if blk_ == 0x402B0000 or a == 0x60830044:
                    self._pmu_update()
            if RF_MODEL and a == 0x40070244 and (value & 1):
                self._rfti_xfer(uc)
            if LTE_ADX_STUB and a in (0x402E0248, 0x402E024C):
                self._adx_ctl_write(uc, a, value)
            if DSP_STUB and a in (0x402E0250, 0x402E0254, 0x402E0130):
                self._dsp_ctl_write(uc, a, value)

            if AP_TMR_MODEL and a in (AP_TMR_BASE, AP_TMR_BASE + 4, AP_TMR_BASE + 0x10):
                self._aptmr_write(uc, a, value)
            if RTC_MODEL and (0x40608210 <= a < 0x40608240 or 0x406080C0 <= a < 0x406080D0):
                self._pmic_rtc_write(uc, a, value)
            if PMIC_ADC and a == 0x40608404 and (value & 2):
                self.hw_regs[0x40608404] = value & ~2 & 0xFFFFFFFF
                self.hw_regs[0x40608460] = self.hw_regs.get(0x40608460, 0) | 1
                self.hw_regs[0x40608450] = PMIC_ADC_RAW & 0xFFF
                for ra in (0x40608460, 0x40608450):       # shadow for C ADI reads
                    uc.mem_write(ra, (self.hw_regs[ra] & 0xFFFFFFFF).to_bytes(4, 'little'))
                n = getattr(self, '_adc_n', 0) + 1
                self._adc_n = n
                if n <= 5:
                    self.run.log(f"[ADC  ] PMIC aux ADC conversion #{n} -> {PMIC_ADC_RAW:#x} "
                                 f"pc={uc.reg_read(UC_ARM_REG_PC):#x}")
            blk = address & 0xFFFF0000
            bw = self.run.block_w
            bw[blk] = bw.get(blk, 0) + 1
            for lo, hi in RADIO_WRITE_RANGES:
                if lo <= address < hi:
                    self.run.radio_w.append((self.insn_total, address, size, value))
                    key = address
                    seen = getattr(self, '_mmio_w_seen', None)
                    if seen is None:
                        seen = self._mmio_w_seen = {}
                    n = seen.get(key, 0) + 1
                    seen[key] = n
                    if n <= 3 and len(seen) < 4000:
                        name = BLOCK_NAMES.get(blk, "")
                        self.run.log(f"[MMIO-W] {address:08x} = {value:08x} ({size}B)  {name} x{n}")
                    if n <= 40:
                        self.run.ev("MMIO_W", insn=self.insn_total, addr=hex(address),
                                    size=size, value=hex(value), block=BLOCK_NAMES.get(blk, hex(blk)))
                    break

    def _uart_write(self, address, size, value):
        key = (address & 0xF0000, address & 0xFF)
        self.uart_wr = getattr(self, 'uart_wr', {})
        self.uart_wr[key] = self.uart_wr.get(key, 0) + 1
        if self.uart_wr[key] in (1, 2, 3, 10, 100, 1000):
            self.run.log(f"[UART-W] {address:08x} = {value & 0xFF:02x} "
                         f"x{self.uart_wr[key]} pc={uc_pc(self)}")
        if size != 1:
            return
        idx = address & 7
        # byte-spaced 16550: 0=TX/RX, 5=LSR; also tolerate 4-byte stride
        if idx == 0:
            b = value & 0xFF
            if b == 0x0A or (32 <= b < 127):
                port = (address >> 16) & 0xF
                tag = "" if port == 0 else f"[U{port}]"
                self.run.uart(bytes([b]))
                sys.stdout.write((chr(b) if b != 0x0A else "\n"))
                sys.stdout.flush()

    def on_unmapped(self, uc, access, address, size, value, user_data):
        page = address & ~0xFFF
        pc = uc.reg_read(UC_ARM_REG_PC)
        ACC = {16: "R", 17: "W", 18: "F", 19: "R!", 20: "W!", 21: "F!"}

        if access in (UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT) and \
                not (0x80000000 <= address < 0x84000000 or address < 0x21000 or
                     0xFFF00000 <= address or 0x30000000 <= address < 0x30200000):
            lr = uc.reg_read(UC_ARM_REG_LR)
            sp = uc.reg_read(UC_ARM_REG_SP)
            stack = []
            for i in range(6):
                try:
                    stack.append(int.from_bytes(
                        uc.mem_read(sp + i * 4, 4), 'little'))
                except UcError:
                    stack.append(None)
            stk = " ".join(f"{v:08x}" if v is not None else "????????" for v in stack)
            self.run.log(f"[RUNAWAY] fetch {address:#010x} pc={pc:#x} lr={lr:#x} "
                         f"sp={sp:#x} stack=[{stk}]")
            self.run.log(f"[RUNAWAY] insn@lr: {self._disasm_at(uc, lr & ~1, 3)}")
            self.run.log("[RUNAWAY] pc-trail: " +
                         " ".join(f"{p:08x}" for p in self.pc_trace))
            self.run.ev("RUNAWAY", addr=hex(address), pc=hex(pc), lr=hex(lr),
                        sp=hex(sp), stack=[hex(v) if v is not None else None
                                           for v in stack])
            self.stop_reason = "runaway-fetch"
            self.stop_detail = f"pc={pc:#x} lr={lr:#x}"
            return False
        try:
            self.mu.mem_map(page, 0x1000, UC_PROT_ALL)
            self.run.log(f"[MAP  ] auto {page:#x} ({ACC.get(int(access),access)}) pc={pc:#x} lr={uc.reg_read(UC_ARM_REG_LR):#x}")
            self.run.ev("AUTOMAP", addr=hex(page), access=int(access), pc=hex(pc))
            return True
        except UcError:
            pass
        # map failed (overlapping/out of range): stop with full context
        self.run.log(f"[FAULT] unmapped {address:#010x} acc={ACC.get(int(access),access)} "
                     f"pc={pc:#x} insn='{self._disasm_at(uc, pc, 3)}'")
        self.run.ev("FAULT", kind="unmapped", addr=hex(address), pc=hex(pc))
        self.stop_reason = "unmapped-fatal"
        self.stop_detail = hex(address)
        return False

    def on_invalid(self, uc, user_data):
        pc = uc.reg_read(UC_ARM_REG_PC)
        code = b""
        try: code = bytes(uc.mem_read(pc & ~1, 4))
        except UcError: pass
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        itstate = (cpsr >> 25) & 0x3 | ((cpsr >> 8) & 0xFF)
        regs_s = " ".join(f"{REG_NAMES[r]}={uc.reg_read(r):08x}"
                          for r in REG_LIST if r != UC_ARM_REG_CPSR)
        self.run.log(f"[FAULT] invalid insn at {pc:#x}: {code.hex()} "
                     f"cpsr={cpsr:08x} itstate={itstate:#x}")
        self.run.log(f"[FAULT] {regs_s}")
        self.run.log(f"[FAULT] ctx: {self._disasm_at(uc, pc, 4)}")
        self.run.ev("FAULT", kind="invalid", pc=hex(pc), bytes=code.hex(),
                    cpsr=hex(cpsr), itstate=hex(itstate))
        # RESILIENCE: return to the caller (lr) instead of stopping -
        # the invalid insn is a corrupted function pointer from
        # zero-filled NV data; the caller can handle the error return
        lr = uc.reg_read(UC_ARM_REG_LR)
        if STRICT:
            self.stop_reason = "invalid-insn"
            self.stop_detail = f"{pc:#x} {code.hex()} lr={lr:#x}"
            self.run.log("[STRICT] stop on invalid insn; pc-trail: " +
                         " ".join(f"{p:08x}" for p in self.pc_trace))
            return False
        if 0x80a00000 <= lr < 0x83000000:
            self.run.log(f"[FAULT] returning to lr {lr:#010x}")
            uc.reg_write(UC_ARM_REG_PC, lr)
            return
        # fallback: skip the instruction (4B ARM, 2B Thumb)
        if cpsr & 0x20:
            uc.reg_write(UC_ARM_REG_PC, pc + 2)
        else:
            uc.reg_write(UC_ARM_REG_PC, pc + 4)
        self.stop_detail = f"{pc:#x} {code.hex()}"
        return False

    @staticmethod
    def _rd_cstr(uc, addr, n=120):
        try:
            b = bytes(uc.mem_read(addr, n))
            z = b.find(b'\x00')
            if z >= 0:
                b = b[:z]
            return b.decode('ascii', 'replace')
        except UcError:
            return "?"

    def _itoa_trap(self, uc, address, size, user_data):
        val = uc.reg_read(UC_ARM_REG_R0)
        buf = uc.reg_read(UC_ARM_REG_R1)
        s = str(val & 0xFFFFFFFF)
        try:
            uc.mem_write(buf, s.encode("ascii") + bytes([0]))
        except UcError:
            pass
        # trap fires before the push executes: plain force-return is balanced
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def _sprintf_trap(self, uc, address, size, user_data):
        buf = uc.reg_read(UC_ARM_REG_R0)
        txt = self._rd_cstr(uc, buf)
        self.sprintf_count = getattr(self, "sprintf_count", 0) + 1
        if self.sprintf_count <= 80:
            self.run.log("[KLOG  ] " + txt[:200])
        if self.sprintf_count <= 40:
            self.run.ev("KERNEL_LOG", n=self.sprintf_count, text=txt[:400])
        # trap fires before the push executes: plain force-return is balanced
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def _assert_trap(self, uc, address, size, user_data):
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)
        self.assert_count += 1
        if self.assert_count <= 40:
            self.run.log(f"[ASRT ] #{self.assert_count} "
                         f"{self._rd_cstr(uc, r1)}:{r2} {self._rd_cstr(uc, r0)}")
            self.run.ev("ASSERT", n=self.assert_count,
                        file=self._rd_cstr(uc, r1), line=r2,
                        expr=self._rd_cstr(uc, r0))
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    # ------------------------------------------------- SNF / NANDC model
    def _nand_img(self):
        if self._nand is None:
            try:
                self._nand = open(os.path.join(
                    fwpaths.NAND), 'rb').read()
                self.run.log(f"  nand image: {len(self._nand):#x} bytes")
            except OSError:
                self._nand = b''
        return self._nand

    def _snf_read(self, uc, address, size):
        self.snf_rd = getattr(self, 'snf_rd', 0) + 1
        if self.snf_rd <= 10:
            pc = uc.reg_read(UC_ARM_REG_PC)
            self.run.log(f"[SNF-R] {address:08x} pc={pc:#x}")
        a = address & 0x3FF
        s = self.snf_cfg
        if a == 0x00:                       # START: not busy, flash idle
            v = 0x40000000
        elif a == 0x10:                     # INT
            v = s[0x10]
        elif a == 0x19C:                    # SPI readback byte
            v = s[0x19C]
        elif a == 0xA4:                     # ECC status (2 B/sector)
            v = self.snf_ecc
        elif a == 0xD0:                     # instruction counter
            v = s[0xD0]
        elif 0x220 <= a < 0x27C:            # instruction FIFO readback: the
            # driver's queue helper does RMW per word, so reads must return
            # the packed halfword ops (two per 32-bit word)
            idx = (a - 0x220) >> 1
            if idx < len(self.snf_ins):
                if size == 4:
                    hi = self.snf_ins[idx + 1] if idx + 1 < len(self.snf_ins) else 0
                    v = (self.snf_ins[idx] & 0xFFFF) | (hi << 16)
                else:
                    v = self.snf_ins[idx] & 0xFFFF
            else:
                v = 0
        elif a in s:
            v = s[a]
        else:
            v = 0
        if size == 4:
            uc.mem_write(address & ~3, v.to_bytes(4, 'little'))
        elif size == 2:
            uc.mem_write(address, (v & 0xFFFF).to_bytes(2, 'little'))
        else:
            uc.mem_write(address, v & 0xFF)

    def _snf_write(self, uc, address, size, value):
        self.snf_wr = getattr(self, 'snf_wr', 0) + 1
        if self.snf_wr <= 20:
            pc = uc.reg_read(UC_ARM_REG_PC)
            self.run.log(f"[SNF-W] {address:08x} = {value & 0xFFFFFFFF:08x} pc={pc:#x}")
        a = address & 0x3FF
        s = self.snf_cfg
        if a == 0x00 and (value & 1):       # START -> run micro-op batch
            s[0x10] = 0                     # clear DONE while executing
            self._snf_run(uc)
            return
        if a == 0x10:                       # INT: EN store, [15:8] W1C
            en = value & 0xFF
            clr = (value >> 8) & 0xFF
            cur = s[0x10]
            s[0x10] = (cur & ~(clr << 16) & ~(clr << 24)) | en
            return
        if 0x220 <= a < 0x27C:              # INSTRUCTION slots (2 ops / word)
            idx = (a - 0x220) >> 1
            if size == 2:
                self.snf_ins[idx] = value & 0xFFFF
            elif size == 4:
                # driver's queue helper packs two halfword ops per 32-bit word
                self.snf_ins[idx] = value & 0xFFFF
                if idx + 1 < len(self.snf_ins):
                    self.snf_ins[idx + 1] = (value >> 16) & 0xFFFF
            else:
                cur = self.snf_ins[idx]
                if a & 1:
                    self.snf_ins[idx] = (cur & 0x00FF) | ((value & 0xFF) << 8)
                else:
                    self.snf_ins[idx] = (cur & 0xFF00) | (value & 0xFF)
            return
        if size == 4:
            s[a] = value & 0xFFFFFFFF
        elif size == 2:
            cur = s.get(a, 0)
            mask = 0xFFFF if (a & 1) == 0 else 0xFFFF00
            s[a] = (cur & ~mask & 0xFFFFFFFF) | ((value & 0xFFFF) << (8 if a & 1 else 0))
        else:
            s[a] = value & 0xFF

    def _snf_run(self, uc):
        """Interpret the micro-op batch the driver loaded into INSTRUCTION[]."""
        img = self._nand_img()
        s = self.snf_cfg
        main_sz = ((s[0x08] >> 0) & 0x3FF) + 1
        sec_num = ((s[0x04] >> 24) & 0xFF) + 1
        rep = ((s[0x04] >> 16) & 0xFF) + 1
        chunk = main_sz * sec_num
        cmd = None
        need = 0
        row = self.snf_row if hasattr(self, 'snf_row') else 0
        col = 0
        feat = getattr(self, 'snf_feat', {0xC0: 0, 0xB0: 9})
        self.snf_feat = feat
        nid = 0
        idb = []                             # READ ID bytes (packed into 0x19C)
        # batch length: controller counter (+0xD0) is authoritative; the
        # checkpointed driver-RAM counter can be stale from a previous phase
        ram_cnt = int(s.get(0xD0, 0)) & 0x1F
        if ram_cnt == 0:
            try:
                ram_cnt = int.from_bytes(uc.mem_read(0x81911640 + 0xD0, 4), 'little') & 0x1F
            except UcError:
                ram_cnt = 0
        self._snf_run_n = getattr(self, '_snf_run_n', 0) + 1
        if self._snf_run_n <= 40:
            ops = ['%04x' % self.snf_ins[i] for i in range(min(ram_cnt, len(self.snf_ins)))]
            self.run.log("[SNF-CMD] #%d row=%s main=%08x ops=%s" % (
                self._snf_run_n, getattr(self, 'snf_row', 0),
                s.get(0x200, 0) | (s.get(0x204, 0) << 16), ' '.join(ops)))
        main_addr = s.get(0x204, 0) | (s.get(0x200, 0) << 0)
        spar_addr = s.get(0x20C, 0) | (s.get(0x208, 0) << 0)
        ecc = 0
        for i in range(min(ram_cnt, len(self.snf_ins))):
            w = self.snf_ins[i]
            op = (w >> 12) & 0xF
            p = w & 0xFF
            if op == 0:                      # WBYT
                if cmd is None:
                    cmd = p; need = {0x13: 3, 0x0F: 1, 0x6B: 2}.get(p, 0)
                    col = 0
                else:
                    if cmd == 0x13:
                        row = (row << 8) | p; need -= 1
                    elif cmd == 0x0F:
                        col = p; need = 0
                    elif cmd == 0x6B:
                        col = (col << 8) | p; need -= 1
                    if need <= 0 and cmd != 0x13:
                        cmd = cmd  # keep cmd until next WBYT cmd or EXEC
            elif op == 4:                    # SWDT (feature write)
                if cmd == 0x1F:
                    feat[col] = p
                    cmd = None
            elif op == 1:                    # RBYT (readback)
                if cmd == 0x0F:
                    if col == 0xC0:
                        self.snf_rbyt = feat.get(0xC0, 0) & 0xFE
                    elif col == 0xB0:
                        self.snf_rbyt = feat.get(0xB0, 9)
                    else:
                        self.snf_rbyt = 0
                    cmd = None
                elif cmd == 0x9F:
                    # chip table entry0 (0x81524620) = {0x0000F8B1, 0}: the
                    # probe packs (b1|b0<<8) and matches entry word0, so the
                    # first two READ ID bytes must be F8 B1.
                    b = (0xF8, 0xB1, 0x00, 0x00)[nid % 4]; nid += 1
                    self.snf_rbyt = b
                    idb.append(b)
                else:
                    self.snf_rbyt = 0
            elif op in (2, 3):               # MWDT/MRDT: main data move
                coloff = col & 0x7FF
                if (col & 0x8000):
                    coloff |= 0x800
                dst = main_addr if op == 3 else main_addr
                page = row
                for r in range(rep):
                    src_off = page * SNF_PAGE + coloff
                    if img and src_off + chunk <= len(img):
                        page_data = img[src_off:src_off + chunk]
                        uc.mem_write(dst, page_data)
                        if 0x80000000 <= dst < 0x80800000 or dst < 0x13000:
                            # DSP/CM4-visible destination: these model writes bypass CPU store hooks
                            self.run.ev("NAND_DMA", dst=hex(dst), n=chunk, page=page,
                                        insn=self.insn_total)
                        if page_data == bytes([0xFF]) * chunk:
                            ecc |= 0x003F << (2 * (r % 2))
                    else:
                        uc.mem_write(dst, bytes([0xFF]) * chunk)
                        ecc |= 0x003F << (2 * (r % 2))
                    dst += chunk
                    page += 1
                self.snf_ecc = ecc
            elif op == 5:                    # SRDT: spare -> SPAR addr
                coloff = (col & 0x7FF) | 0x800
                sp_sz = ((s[0x08] >> 16) & 0xFF) + 1
                dst = spar_addr
                page = row
                for r in range(rep):
                    src_off = page * SNF_PAGE + coloff
                    if img and src_off + sp_sz <= len(img):
                        uc.mem_write(dst, img[src_off:src_off + sp_sz])
                    else:
                        uc.mem_write(dst, bytes([0xff]) * sp_sz)
                    dst += sp_sz
                    page += 1
            elif op == 6:                    # DUMY
                pass
            elif op == 0xE:                  # EXEC / read-status slot p
                if idb:
                    # READ ID: hardware packs the readback bytes big-endian
                    # into 0x19C (driver reads it as (b0<<8)|b1 halfword)
                    acc = 0
                    for b in idb[:2]:
                        acc = (acc << 8) | b
                    s[0x19C] = acc & 0xFFFF
                else:
                    s[0x19C] = getattr(self, 'snf_rbyt', 0) & 0xFF
                if cmd == 0x13:
                    pass                     # page read latched
                cmd = None if need <= 0 else cmd
            elif op == 0xF:                  # DONE
                break
        self.snf_row = row
        if idb:
            acc = 0
            for b in idb[:2]:
                acc = (acc << 8) | b
            s[0x19C] = acc & 0xFFFF
        else:
            s[0x19C] = getattr(self, 'snf_rbyt', 0) & 0xFF
        # completion: INT DONE raw + sts; driver polls +0x10 bit7/bit4
        s[0x10] = (s[0x10] | (1 << 24) | (1 << 25) | (1 << 26) | (1 << 28) | (1 << 16) | 0x80 | 0x10) & 0xFFFFFFFF
        self.snf_cfg[0xD0] = 0

    # ------------------------------------------------- scheduler tick
    def _deliver_ticks(self, mu):
        """AON tick timer -> IRQ. The live vector table routes IRQ through
        literal [0x38] (0x80a062d0 = the RTOS tick handler). Deliver as soon
        as the AON timer runs (bit0) - the parked 500ms delay polls a global
        that only the tick handler advances, and the INTC enable comes later
        in init. Deterministic: 1 tick per 200K instructions (the park loop
        does no MMIO, so read-count time starves there)."""
        now = (self.insn_total // getattr(self, 'tick_rate', 200_000)) & 0xFFFFFFFF
        # NOTE: the old und_count>0 gate is GONE: with the
        # msr mode-0 fix (_msr_cpsr_cb) no UND ever fires, so the gate starved every
        # pre-park checkpoint of ticks (the blob parked at 0x80a06e56 for
        # 1.2G insns). The vector[0x38] check below is the real gate - the
        # RTOS tick handler must be installed before ticks deliver.
        ctrl = self.hw_regs.get(AON_TMR_BASE, 0)
        running = ctrl & 1
        if not running:
            return
        try:
            vec = int.from_bytes(mu.mem_read(0x38, 4), 'little')
        except UcError:
            vec = 0
        if not vec or vec < 0x1000:
            # no live RTOS IRQ handler installed yet - hold ticks
            return
        while now >= self.tick_next:
            self.tick_next = (self.tick_next + 1) & 0xFFFFFFFF
            self.tick_pending = True
        if self.tick_pending:
            # chain_hold: the boot-init cascade runs atomically (no ticks)
            # exactly like real boot, where init completes before the
            # scheduler starts interleaving threads. Released by the script
            # once the chain parks.
            if getattr(self, 'chain_hold', False):
                return
            # Respect the guest's I-mask: a forced tick landing inside a
            # critical section (RTOS lock / ISR-tail mode-switch dance)
            # corrupts the nested return. Force ONLY in the park delay loop
            # (0x80a06exx) or the relocated park self-loop (trampoline
            # PARK at BASE+0x100), which spin with IRQs masked and need
            # ticks to progress.
            cpsr = mu.reg_read(UC_ARM_REG_CPSR)
            pc = mu.reg_read(UC_ARM_REG_PC)
            forced = ((0x80a06e00 <= pc <= 0x80a06f00)
                      or (0x81608000 <= pc <= 0x81608200)
                      or (0x8120d700 <= pc <= 0x8120d900)
                      or getattr(self, '_wfi_wake', False))
            if (cpsr & 0x80) and not forced:
                return
            # Even a FORCED tick must not land while the guest holds the
            # trace/int spinlock (trace-push 0x81099978, depth counter at
            # [tcb+8], tcb pointer cell 0x81099A1C - note
            # 0x81099A20 is string data, the real literal is at
            # 0x81099A1C = 0x81703238, counter = 0x81703240). Preempting a
            # lock holder leaves the lock taken forever and every later
            # acquire spins to the depth assert -> shutdown.
            try:
                tcb = int.from_bytes(mu.mem_read(0x81099A1C, 4), 'little')
                if 0x80000000 <= tcb < 0x83000000:
                    depth = int.from_bytes(mu.mem_read(tcb + 8, 4), 'little')
                    if depth:
                        return
            except UcError:
                pass
            # Defer ticks inside the service-walk / wait / lock regions:
            # a nested tick there re-enters the walk, contends its own lock,
            # and the contended lock's wait path recurses unboundedly.
            for lo, hi in ((0x81174000, 0x81176000), (0x80a09100, 0x80a09400),
                           (0x810b3130, 0x810b3200), (0x81099900, 0x81099b00)):
                if lo <= pc <= hi:
                    return
            self._inject_irq(mu, force=True)
            if getattr(self, '_wfi_wake', False):
                self._wfi_wake = False
                self.wfi_count += 1
                if self.wfi_count <= 5:
                    self.run.log(f"[WAKE ] WFI at {pc:#x} woken by tick #{self.wfi_count}")
            # CP-side monitor heartbeat: on hardware the modem core's monitor
            # drains the AP log queue every frame. The kernel logger suspends
            # any thread whose log lands while the in-flight counter is
            # nonzero, so without the drain every logging thread wedges.
            if getattr(self, 'cp_log_drain', True):
                try:
                    if int.from_bytes(mu.mem_read(0x81701ec8, 4), 'little'):
                        mu.mem_write(0x81701ec8, b'\x00\x00\x00\x00')
                    # the logger's in-flight counter is structurally zeroed
                    # by the RAW_PATCH at 0x80a09184; the
                    # tick drain additionally clears the drained-log count
                    # and releases the mailbox slot the CP consumed
                    # (bit(ch) set = slot busy; the CP frees
                    # it once the message is consumed).
                    mbx = int.from_bytes(mu.mem_read(0x400A0014, 4), 'little')
                    if mbx:
                        mu.mem_write(0x400A0014, b'\x00\x00\x00\x00')
                        self.hw_regs[0x400A0014] = 0
                except UcError:
                    pass

    def _inject_und(self, mu, pc):
        """Undefined-instruction entry (vector 0x04): bank SPSR, LR = pc+4,
        switch to UND mode ARM state, jump to the guest's vector-1 handler
        ([0x24] of the vector block at 0x0)."""
        cpsr = mu.reg_read(UC_ARM_REG_CPSR)
        try:
            handler = int.from_bytes(mu.mem_read(0x24, 4), 'little')
        except UcError:
            handler = 0
        entry = (handler if handler else 0x04) & ~1
        mu.reg_write(UC_ARM_REG_CPSR, (cpsr & ~0x3F) | 0x1B | 0x80)
        mu.reg_write(UC_ARM_REG_SPSR, cpsr)
        mu.reg_write(UC_ARM_REG_LR, (pc + 4) & 0xFFFFFFFF)   # was &~3: broke Thumb returns
        mu.reg_write(UC_ARM_REG_PC, entry)
        self.und_count = getattr(self, 'und_count', 0) + 1
        if self.und_count <= 10:
            self.run.log(f"[UND  ] user-mode CP15 fault at {pc:#x} -> "
                         f"{entry:#x} #{self.und_count}")
        self.run.ev("UND_DELIVER", pc=hex(pc), entry=hex(entry),
                    n=self.und_count)

    def _inject_irq(self, mu, force=False, num=None):
        """Validated virtual IRQ entry (unicorn #825/#1137 pattern):
        CPSR switch FIRST (banks SPSR), then SPSR, LR = pc+4, PC = vector."""
        cpsr = mu.reg_read(UC_ARM_REG_CPSR)
        if (cpsr & 0x80) and not force:
            # I-masked: hold pending (level behaviour)
            self._inj_masked = getattr(self, '_inj_masked', 0) + 1
            if self._inj_masked in (1, 100, 10000, 1000000):
                self.run.log(f"[IRQ-H] masked hold #{self._inj_masked} "
                             f"pc={mu.reg_read(UC_ARM_REG_PC):#x} cpsr={cpsr:#010x}")
            return
        # guest vector: the live vector block at 0x0 routes IRQ through the
        # literal at [0x38] (RTOS tick handler 0x80a062d0). Older layouts
        # kept the handler pointer at [0x0C]; fall back to it, then 0x18.
        try:
            handler = int.from_bytes(mu.mem_read(0x38, 4), 'little')
        except UcError:
            handler = 0
        if not handler or handler < 0x1000:
            try:
                handler = int.from_bytes(mu.mem_read(0x0C, 4), 'little')
            except UcError:
                handler = 0
        target = handler if (handler and handler >= 0x1000) else 0x18
        entry = target & ~1
        pc = mu.reg_read(UC_ARM_REG_PC)
        # The shared ISR reads the pending IRQ number from [[ctl+4]+0xC]
        # (ctl=0x817b1d38, [ctl+4]=0 -> falls back to RAM 0x0C). Cycle the
        # dispatch table's real IRQ numbers so every registered handler gets
        # serviced and the wake flags get a chance to set.
        n = getattr(self, '_irq_cycle', 0)
        irq_nums = getattr(self, 'tick_irq_cycle', None)
        if num is None and irq_nums:
            num_ = irq_nums[n % len(irq_nums)]
        else:
            num_ = num
        # GICC_IAR model: once the kernel's GIC init (0x8113e5c4, inside
        # the 0x80baca68 chain) has run, the dispatcher reads the id from
        # [[0x817b1d38+4]+0xc] = GICC_IAR 0x1200200c, not RAM 0x0c.
        self.gic_iar = num_ if num_ is not None else 0x3FF
        if num is not None:
            try:
                mu.mem_write(0x0C, int(num).to_bytes(4, 'little'))
            except UcError:
                pass
        elif irq_nums:
            num = irq_nums[n % len(irq_nums)]
            self._irq_cycle = n + 1
            try:
                mu.mem_write(0x0C, int(num).to_bytes(4, 'little'))
            except UcError:
                pass
            if self.tick_delivered if hasattr(self, 'tick_delivered') else True:
                pass
        mu.reg_write(UC_ARM_REG_CPSR, (cpsr & ~0x3F) | 0x12 | 0xC0)
        mu.reg_write(UC_ARM_REG_SPSR, cpsr)
        mu.reg_write(UC_ARM_REG_LR, (pc + 4) & 0xFFFFFFFF)   # was &~3: broke Thumb returns
        mu.reg_write(UC_ARM_REG_PC, entry)
        self.tick_delivered = getattr(self, 'tick_delivered', 0) + 1
        if self.tick_delivered <= 10:
            self.run.log(f"[IRQ  ] tick delivered -> {entry:#x} "
                         f"(from {pc:#x}) #{self.tick_delivered}")
        self.run.ev("IRQ_DELIVER", entry=hex(entry), pc=hex(pc))

    # ------------------------------------------------------------ disasm
    def _md(self, thumb):
        return Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)

    def _disasm_at(self, uc, addr, n=6):
        thumb = bool(uc.reg_read(UC_ARM_REG_CPSR) & 0x20)
        try:
            code = bytes(uc.mem_read(addr & ~1, 4 * n + 4))
            md = self._md(thumb)
            out = []
            for i, ins in enumerate(md.disasm(code, addr & ~1)):
                out.append(f"{ins.address:08x}: {ins.mnemonic} {ins.op_str}")
                if i + 1 >= n: break
            return " | ".join(out)
        except Exception:
            return "?"

    # ------------------------------------------------------------ run loop
    @staticmethod
    def _smsg_str(w0, w1):
        ch, ty, fl = w0 & 0xFF, (w0 >> 8) & 0xFF, (w0 >> 16) & 0xFFFF
        names = {1: "OPEN", 2: "OPEN_ACK", 3: "CLOSE", 4: "SBUF", 5: "CMD", 6: "DONE"}
        return f"ch={ch} type={ty}({names.get(ty, '?')}) flag={fl:#06x} value={w1:#010x}"

    def _cp_tsv_row(self, row):
        f = getattr(self, '_cp_tsv', None)
        if f is None:
            f = self._cp_tsv = open(os.path.join(self.run.dir, "cp_stub.tsv"), "w")
            f.write("\t".join(["insn", "dir", "dst", "w0", "w1", "decode", "pc", "lr"]) + "\n")
        f.write("\t".join(str(x) for x in row) + "\n")
        f.flush()

    def _cp_stub_tx(self, uc, dst):
        """AP->CP doorbell: log the message and queue any scripted reply."""
        w0 = self.hw_regs.get(0x400A0004, 0)
        w1 = self.hw_regs.get(0x400A0008, 0)
        pc = uc.reg_read(UC_ARM_REG_PC)
        lr = uc.reg_read(UC_ARM_REG_LR)
        d = self._smsg_str(w0, w1)
        self._mbx_tx_n = getattr(self, '_mbx_tx_n', 0) + 1
        self.run.log(f"[MBX-TX] dst={dst} w0={w0:#010x} w1={w1:#010x} {d} pc={pc:#x} lr={lr:#x}")
        self.run.ev("MBX_TX", dst=dst, w0=hex(w0), w1=hex(w1), pc=hex(pc), lr=hex(lr),
                    insn=self.insn_total)
        self._cp_tsv_row([self.insn_total, "TX", dst, f"{w0:08x}", f"{w1:08x}", d,
                          f"{pc:x}", f"{lr:x}"])
        if LTE_ADX_STUB and dst == ADX_CORE:
            self._adx_cmds(uc)
        replies = list(getattr(self, 'cp_script', {}).get((dst, w0), []))
        ch, ty = w0 & 0xFF, (w0 >> 8) & 0xFF
        if not replies and dst == 1 and ty == 1 and (w0 >> 16) == 0xBEEE:
            replies = [(1, w0, 0)]                     # peer OPEN
            if ch in (4, 5):
                # sbuf attach request (WCN SIPC handshake): CMD {ch,
                # type 5, flag 1}; the AP answers DONE with the descriptor.
                # ch4 "pipe" and ch5 "plog" both wait for it.
                replies.append((1, 0x00010500 | ch, 0))
        if dst == 1 and ty == 6 and ch in (4, 5) and 0x80000000 <= w1 < 0x80020000:
            # DONE: CM4 attaches - overwrite the AP's ring0 tx_rd witness
            # (0xFFFFFFFF) with tx_wr. desc: +0 ringnr, ring0 @+4:
            # tx_addr, tx_size, tx_rd(+0xc), tx_wr(+0x10)
            try:
                wr = int.from_bytes(self.mu.mem_read(w1 + 0x10, 4), 'little')
                self.mu.mem_write(w1 + 0x0C, wr.to_bytes(4, 'little'))
                self.run.log(f"[MBX-CP] CM4 attached ch{ch} desc {w1:#x}: ring0 tx_rd := {wr:#x}")
                self.run.ev("CM4_ATTACH", desc=hex(w1))
            except UcError:
                pass
        for r in replies:
            self._cp_stub_rx(*r)

    def _cp_stub_rx(self, tag, w0, w1):
        q = self.__dict__.setdefault('cp_rxq', [])
        q.append((tag, w0 & 0xFFFFFFFF, w1 & 0xFFFFFFFF))
        d = self._smsg_str(w0, w1)
        self.run.log(f"[MBX-RX] queue tag={tag} w0={w0:#010x} w1={w1:#010x} {d}")
        self.run.ev("MBX_RX", tag=tag, w0=hex(w0), w1=hex(w1), insn=self.insn_total)
        self._cp_tsv_row([self.insn_total, "RX", tag, f"{w0:08x}", f"{w1:08x}", d, "", ""])

    def _deliver_mbx_irq(self, mu):
        """CP->AP FIFO non-empty -> TB_MBOX_TAR_AP_INT (id 0x65), same
        safety gates as the tick."""
        if not getattr(self, 'cp_rxq', None):
            return False
        if getattr(self, '_mbx_irq_insn', -1) == self.insn_total:
            return False
        cpsr = mu.reg_read(UC_ARM_REG_CPSR)
        if (cpsr & 0x80) and not getattr(self, '_wfi_wake', False):
            return False
        try:
            tcb = int.from_bytes(mu.mem_read(0x81099A1C, 4), 'little')
            if 0x80000000 <= tcb < 0x83000000 and \
                    int.from_bytes(mu.mem_read(tcb + 8, 4), 'little'):
                return False
        except UcError:
            pass
        pc = mu.reg_read(UC_ARM_REG_PC)
        for lo, hi in ((0x81174000, 0x81176000), (0x80a09100, 0x80a09400),
                       (0x810b3130, 0x810b3200), (0x81099900, 0x81099b00)):
            if lo <= pc <= hi:
                return False
        self._mbx_irq_insn = self.insn_total
        self._wfi_wake = False
        self._inject_irq(mu, force=True, num=0x65)
        n = getattr(self, '_mbx_irq_n', 0) + 1
        self._mbx_irq_n = n
        if n <= 20:
            self.run.log(f"[MBX-IRQ] id 0x65 -> AP at pc={pc:#x} ({len(self.cp_rxq)} queued)")
        self.run.ev("MBX_IRQ", pc=hex(pc), n=len(self.cp_rxq))
        return True

    # ------------------------------------------------------- checkpoints
    def ckpt_save(self, path):
        import pickle, zlib, hashlib
        mu = self.mu
        regions = []
        STEP = 0x1000000
        for b, e, perm in mu.mem_regions():
            size = e - b + 1
            pages = {}
            for o in range(0, size, STEP):
                blk = bytes(mu.mem_read(b + o, min(STEP, size - o)))
                if not blk.strip(b"\x00"):
                    continue
                for po in range(0, len(blk), 0x10000):
                    pg = blk[po:po + 0x10000]
                    if pg.strip(b"\x00"):
                        pages[o + po] = zlib.compress(pg, 1)
            regions.append((b, size, perm, pages))
        state = {}
        dropped = []
        for k, v in self.__dict__.items():
            if k in CKPT_SKIP or k.startswith(CKPT_SKIP_PREFIX):
                continue
            try:
                pickle.dumps(v)
            except Exception:
                dropped.append(k)
                continue
            state[k] = v
        meta = {"insn": self.insn_total,
                "flags": {n: globals()[n] for n in CKPT_FLAGS if n in globals()},
                "src_md5": hashlib.md5(open(__file__, "rb").read()).hexdigest(),
                "saved": now_s()}
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({"meta": meta, "ctx": mu.context_save(),
                         "regions": regions, "state": state}, f, protocol=5)
        if dropped:
            self.run.log(f"[CKPT ] not picklable, NOT saved: {', '.join(sorted(dropped))}")
        npg = sum(len(r[3]) for r in regions)
        self.run.log(f"[CKPT ] saved {path} at insn {self.insn_total} "
                     f"({npg} pages, {os.path.getsize(path) >> 20} MB)")
        self.run.ev("CKPT_SAVE", path=path, insn=self.insn_total)
        return path

    @classmethod
    def ckpt_load(cls, run, path, **kw):
        import pickle, zlib, hashlib
        with open(path, "rb") as f:
            d = pickle.load(f)
        emu = cls(run, **kw)
        mu = emu.mu
        meta = d["meta"]
        have = {(b, e - b + 1) for b, e, _ in mu.mem_regions()}
        Z = bytes(0x10000)
        for b, size, perm, pages in d["regions"]:
            if (b, size) not in have:
                try:
                    mu.mem_map(b, size, perm)
                except UcError:
                    pass
            for po in range(0, size, 0x10000):
                pg = pages.get(po)
                n = min(0x10000, size - po)
                mu.mem_write(b + po, zlib.decompress(pg) if pg else Z[:n])
        mu.context_restore(d["ctx"])
        # boot_run-time setup that a resumed run skips: static CP15 site
        # hooks (the Python CP15 model) + MMIO histogram
        if emu.payload:
            emu.cp15_register_static_sites()
            if GIC_MODEL and GIC_UNMASK_SITES:
                emu._gic_hook_unmask_sites()
        emu.mmio_hist_on()
        emu._pmic_static_init()
        fresh_cp15 = set(emu.cp15_hook_classes)
        for k, v in d["state"].items():
            setattr(emu, k, v)
        if SIM_MODEL and isinstance(getattr(emu, 'sim', None), dict):
            for ctl, _gid in emu.sim.values():      # vsim log callbacks are not pickled
                ctl.log = emu._sim_log
                if ctl.card is not None:
                    ctl.card.log = emu._sim_log
        # hooks registered at runtime are not state: re-register the CP15
        # classes promoted to inline hooks after __init__
        if not CP15_INLINE:
            emu.cp15_hook_classes = set()
        if getattr(emu, '_gate_d_done', False):
            emu._drop_exact_hooks((0x80c2f1f2, 0x80c2f23e, 0x80c2f244, 0x80c2f30c))
        extra = set(emu.cp15_hook_classes) - fresh_cp15
        if extra:
            full = emu.cp15_hook_classes
            emu.cp15_hook_classes = extra
            n = emu._hook_cp15_class_set()
            emu.cp15_hook_classes = full
            run.log(f"[CKPT ] re-hooked promoted CP15 classes {sorted(extra)} (+{n} sites)")
        emu.stop_reason = None
        emu.stop_detail = None
        now = {n: globals()[n] for n in CKPT_FLAGS if n in globals()}
        diff = {n: (meta["flags"].get(n), now[n]) for n in now
                if meta["flags"].get(n) != now[n]}
        md5 = hashlib.md5(open(__file__, "rb").read()).hexdigest()
        run.log(f"[CKPT ] loaded {path}: insn {meta['insn']} saved {meta['saved']}"
                + (f" | FLAGS DIFFER {diff}" if diff else "")
                + (" | source changed since save" if md5 != meta["src_md5"] else ""))
        run.ev("CKPT_LOAD", path=path, insn=meta["insn"], flag_diff=str(diff),
               src_changed=md5 != meta["src_md5"])
        return emu

    # ----------------------------------------------------- stall detector
    def _stall_check(self, mu, pc):
        b = self.__dict__.setdefault("_stall_pcs", set())
        b.add(pc >> 6)
        sig = (len(getattr(self, "_mmio_w_seen", {}) or {}), len(b),
               getattr(self, "_nv_read_n", 0),
               len(getattr(self, "cp_rxq", []) or []),
               getattr(self, "_mbx_tx_n", 0), getattr(self, "_sim_n", 0),
               getattr(self, "_glog_n", 0))
        if sig != getattr(self, "_stall_sig", None):
            self._stall_sig = sig
            self._stall_last = self.insn_total
            return False
        return self.insn_total - getattr(self, "_stall_last", 0) >= self.stall_insns

    def stall_profile(self, n_insns=None):
        """Block-profile the next n_insns and write stall_profile.txt."""
        mu = self.mu
        n_insns = n_insns or STALL_PROFILE_INSNS
        cnt = Counter()

        def bh(uc, addr, size, ud):
            cnt[addr] += 1
        h = mu.hook_add(UC_HOOK_BLOCK, bh)
        mu.ctl_flush_tb()     # hooks added mid-run skip already-translated blocks
        target = self.insn_total + n_insns
        prev_max = self.max_insns
        self.max_insns = target
        self.stall_insns = 0
        try:
            self._loop(mu.reg_read(UC_ARM_REG_PC))
        finally:
            mu.hook_del(h)
            mu.ctl_flush_tb()
            self.max_insns = prev_max
        L = [f"stall profile at insn {self.insn_total} ({n_insns} insns, "
             f"{len(cnt)} distinct blocks)", ""]
        for a, n in cnt.most_common(30):
            L.append(f"  {a:#010x} {n}")
        if cnt:
            L.append("")
            L.append("hot block disassembly:")
            for a, _ in cnt.most_common(4):
                L.append(f"  -- {a:#x}")
                thumb = True
                try:
                    code = bytes(mu.mem_read(a & ~1, 0x40))
                    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
                    for i in md.disasm(code, a & ~1):
                        L.append(f"     {i.address:#x} {i.mnemonic} {i.op_str}")
                        if i.mnemonic in ("bx", "pop", "b") and "lr" in i.op_str + i.mnemonic:
                            break
                except UcError:
                    pass
        sp = mu.reg_read(UC_ARM_REG_SP)
        L.append("")
        L.append(self.regs())
        L.append("stack code pointers (sp..sp+0x200):")
        try:
            for i in range(0x80):
                w = int.from_bytes(mu.mem_read(sp + 4 * i, 4), "little")
                if (0x80a06000 <= w < 0x81800000 or 0x88000000 <= w < 0x89000000) and w & 1:
                    L.append(f"  [sp+{4 * i:#x}] {w:#x}")
        except UcError:
            pass
        txt = chr(10).join(L)
        with open(os.path.join(self.run.dir, "stall_profile.txt"), "w") as f:
            f.write(txt)
        self.run.log("[STALL] profile written: top " + ", ".join(
            f"{a:#x}x{n}" for a, n in cnt.most_common(6)))
        return txt

    def _ctr_scale(self, page, off):
        """Counter ticks per insn for a free-running counter cell."""
        if not CTR_REALTIME:
            return 1.0
        per_us = getattr(self, 'tick_rate', 200_000) / 1000.0     # insns per us
        if page == 0x40230000:
            return 1.0 / (per_us * 1000.0)                          # ms
        return 32768.0 / (per_us * 1e6)

    def _now(self):
        """Device-visible time in insn units (see CONTINUOUS_TIME)."""
        if CONTINUOUS_TIME and getattr(self, '_native', False):
            return self.insn_total + min(self.nst.est, getattr(self, '_last_chunk', CHUNK))
        return self.insn_total

    def _next_tick_due(self):
        """insn_total at which the next OS tick becomes due (None if the
        tick source is not running yet)."""
        if not (self.hw_regs.get(AON_TMR_BASE, 0) & 1):
            return None
        T = getattr(self, 'aptmr', None)
        if AP_TMR_MODEL and T and T.get("started"):
            return T["due"]
        return self.tick_next * getattr(self, 'tick_rate', 200_000)

    def _after_wfi(self, mu, pc):
        """True when the chunk stopped on the instruction after a WFI."""
        try:
            if mu.reg_read(UC_ARM_REG_CPSR) & 0x20:
                return (int.from_bytes(mu.mem_read(pc - 2, 2), 'little') == 0xBF30 or
                        int.from_bytes(mu.mem_read(pc - 4, 4), 'little') == 0x8003F3AF)
            return int.from_bytes(mu.mem_read(pc - 4, 4), 'little') & 0x0FFFFFFF == 0x0320F003
        except UcError:
            return False

    def _start_pc(self):
        """PC for emu_start: bit0 must be set when CPU is in Thumb mode
        (unicorn takes initial decode mode from the address, not CPSR)."""
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        if self.mu.reg_read(UC_ARM_REG_CPSR) & 0x20:
            pc |= 1
        return pc

    def boot_state(self):
        self.mu.reg_write(UC_ARM_REG_CPSR, 0x000000D3)  # SVC, ARM, IRQ/FIQ masked
        self.mu.reg_write(UC_ARM_REG_SP, 0x80010000)
        self.mu.reg_write(UC_ARM_REG_R0, 0)
        # VFP enable: without CPACR CP10/CP11 access and
        # FPEXC.EN, VFP instructions cause UND exceptions. The kernel's
        # own UND handler normally does this dance, but in the emulated
        # boot the UND path leads to the log daemon spin.
        self.mu.reg_write(UC_ARM_REG_C1_C0_2, 0xF00000)   # CPACR: CP10/CP11 full access
        self.mu.reg_write(UC_ARM_REG_FPEXC, 0x40000000)   # FPEXC.EN = 1

    def preload_modules(self):
        """Execute the image-load scatter table in Python (normally done by
        FDL2 + the kernel's own init). Table at 0x815A937C, 10 records of
        {src_va, dst_va, size, handler}. Handlers: 0x81496d48 = LZ decompress
        (out size = size), 0x81496dac = memcpy, 0x81496dc8 = zero-fill.
        Re-run after restore."""
        from decomp_lz import decomp
        ker = open(KERNEL, 'rb').read()
        LOADED_AT = 0x80a05e00   # FDL2 base for the kernel partition
        # scatter table read directly from the image at 0x815A937C
        import struct
        tva = 0x815A937C
        toff = tva - LOADED_AT
        DECOMP_H, COPY_H, ZERO_H = 0x81496d48, 0x81496dac, 0x81496dc8
        n_decomp = 0
        for i in range(10):
            src_va, dst_va, sz, hnd = struct.unpack_from('<4I', ker, toff + i * 16)
            src_off = src_va - LOADED_AT
            chunk = ker[src_off:src_off + sz]
            if hnd == DECOMP_H:
                out, used = decomp(ker[src_off:], sz)
                if len(out) != sz:
                    self.run.log(f"  scatter[{i}]: DECOMP size mismatch "
                                 f"{len(out):#x} != {sz:#x}")
                self.mu.mem_write(dst_va, out)
                n_decomp += 1
                self.run.log(f"  scatter[{i}]: decomp {src_va:#x} -> {dst_va:#x} "
                             f"({sz:#x} out, {used:#x} in)")
            elif hnd == COPY_H:
                if len(chunk) < sz:
                    chunk = chunk + bytes(sz - len(chunk))
                self.mu.mem_write(dst_va, chunk)
                self.run.log(f"  scatter[{i}]: copy   {src_va:#x} -> {dst_va:#x} "
                             f"({sz:#x})")
            else:
                self.mu.mem_write(dst_va, bytes(sz))
                self.run.log(f"  scatter[{i}]: zero   {dst_va:#x} ({sz:#x})")
        # mmi_app.bin (the OSAL-client app image the kernel's PLT veneers
        # 0x80FC46DC-0x80FC4BFC jump into). Base check 2026-10-30: the
        # WHOLE file incl. the 0x200 DHTB header sits at 0x88000000 - 42/59
        # PLT targets land on push under that base, 0/59 with the header
        # stripped. Before this it was never loaded: every veneer ran
        # zeros, which is what the early "LTE/DSP glue" cuts and the
        # low-page wild-write restore were working around.
        if MMI_PRELOAD:
            mmi = open(fwpaths.need(MMI_APP, 'mmi_app partition'), 'rb').read()
            self.mu.mem_write(MMI_BASE, mmi)
            self.run.log(f"  mmi_app.bin -> {MMI_BASE:#x} ({len(mmi):#x})")
        # NOP the walker entry so the kernel skips the scatter re-execution
        self.mu.mem_write(0x81496d14, bytes([0x00, 0xbf, 0x00, 0xbf]))
        self.run.log("  walker NOPed at 0x81496d14")
        # Context table (RAM 0x18dc-0x19a8): the LIVE DEVICE dump shows it is
        # ALL ZEROS at stub time too - by design. The restore loads CPSR=0
        # (USER mode) and the next privileged instruction (mcr p15 at
        # 0x10b4) takes the UNDEFINED exception -> RTOS scheduler start
        # (see _inject_und). Unicorn silently ignores the guest's MSR
        # switch to USER mode, so hook the msr at blob 0x10a4 and perform
        # the full CPSR write ourselves.
        if INTR_HOOK:
            # zero-cost form: the msr becomes a permanently-undefined
            # instruction; _on_intr performs the CPSR write precisely
            # (a code hook would tax every executed instruction)
            self.mu.mem_write(0x10A4, (0xE7F000F0).to_bytes(4, 'little'))
        else:
            self.mu.hook_add(UC_HOOK_CODE, self._msr_cpsr_cb, begin=0x10A4, end=0x10A4)
        # CP channel-message consumption: fs1 queues messages into the
        # per-channel rings (chan table 0x8170e300: +0xc+ch = sent count,
        # +0x10+ch = processed count) and waits until the CP drains them
        # (the wrapper at 0x8120d80e compares the two bytes). The store at
        # 0x8120d70c bumps the sent count - mirror it into the processed
        # count so the CP consumes each message instantly.
        self.mu.hook_add(UC_HOOK_CODE, self._chan_send_cb,
                    begin=0x8120D70C, end=0x8120D70E)
        # CP slot-ring consumption (second inter-core transport): the AP's
        # IPC send (0x80ef1418) writes 12-byte messages into an 8-slot ring
        # at [[0x81712bac]+0x28]+0x70c with write/read halfword indices at
        # +0x76e/+0x76c, then tail-calls the ch2-open best-effort. With no
        # real CP the read index never advances, the second send takes the
        # queue-full path (0x80ef139e/0x80ef12a2), its assert log hits the
        # log-tail state assert (0x80a092d2 -> shutdown veneer) and the boot
        # dies. Hook the send path right before the fullness compare
        # (0x80ef146e) and model the CP having consumed every queued msg.
        self.mu.hook_add(UC_HOOK_CODE, self._ipc_drain_cb,
                    begin=0x80EF1464, end=0x80EF1468)
        # self.mu.hook_add(UC_HOOK_CODE, self._ctx_fill_cb, begin=0x1004, end=0x1004)
        # NOTE: the LZ decompressor (0x81496d48) stays INTACT - module config
        # and images decompress through it for real. The Python preload above
        # reproduces its rec[0] output byte-identically (verified vs device).

    def _msr_cpsr_cb(self, uc, address, size, user_data):
        """blob 0x10a4: `msr cpsr_fsxc, r1` - unicorn drops the privileged->
        user transition, so apply it here and skip the instruction.
        A mode field of 0 means KEEP THE CURRENT
        MODE on hardware (ARMv7 treats the all-zero encoding as
        unpredictable-but-current on real cores; the blob's context-restore
        dance relies on staying privileged so its CPACR/VFP/ACTLR sequence
        executes without faulting). Mapping 0 to USER made every one of
        those privileged ops fault UND into the kernel's hardwired
        assert-stub handler (threadx_assert.c:0x146b) - the panic loop."""
        r1 = uc.reg_read(UC_ARM_REG_R1)
        if r1 & 0x1F:
            val = r1
        else:
            val = (r1 & ~0x1F) | (uc.reg_read(UC_ARM_REG_CPSR) & 0x1F)
        uc.reg_write(UC_ARM_REG_CPSR, val)
        uc.reg_write(UC_ARM_REG_PC, address + 4)
        n = getattr(self, '_msr_log_n', 0) + 1
        self._msr_log_n = n
        if n <= 24 or n % 5000 == 0:
            self.run.log(f"[MSR  ] CPSR <- {val:#010x} (mode {val & 0x1F:#x}) "
                         f"at {address:#x} #{n}")
        self.run.ev("MSR_CPSR", val=hex(val))

    def _chan_send_cb(self, uc, address, size, user_data):
        """0x8120d70c: the AP queues a signal message into a channel ring
        (sent count byte at table+0xc+ch). Model the CP consuming it
        instantly (processed count at +0x10+ch catches up). Do NOT bump
        the sent count again for a 'reply' - the module's local counter
        only advances 1 per send, and a desync makes the ring capacity
        check in 0x811034b4 fail (sent >= local+1 reads as 'full')."""
        ch = uc.reg_read(UC_ARM_REG_R4) & 0xFF
        sent = int.from_bytes(uc.mem_read(0x8170E30C + ch, 1), 'little')
        uc.mem_write(0x8170E310 + ch, bytes([sent & 0xFF]))
        self.run.ev("CHAN_CONSUMED", ch=ch, sent=sent)

    def _ipc_drain_cb(self, uc, address, size, user_data):
        """0x80ef1464: the AP's IPC send is about to compare the slot-ring
        read index against its next write slot. Model the CP draining every
        queued message at this point: read idx = write idx, and the paired
        depth counters at [0x81712bac]+0xc/+0xe equalized."""
        try:
            ipc = int.from_bytes(uc.mem_read(0x81712BAC, 4), 'little')
            base = int.from_bytes(uc.mem_read(ipc + 0x28, 4), 'little')
            if not base or base < 0x1000:
                return
            wr = int.from_bytes(uc.mem_read(base + 0x76E, 2), 'little')
            if CP_STUB:
                rd = int.from_bytes(uc.mem_read(base + 0x76C, 2), 'little')
                i = rd
                while i != wr and (i - rd) & 0xFFFF < 16:
                    m = bytes(uc.mem_read(base + 0x70C + (i % 8) * 12, 12))
                    self.run.log(f"[IPC-TX] slot {i % 8} {m.hex()} lr={uc.reg_read(UC_ARM_REG_LR):#x}")
                    self.run.ev("IPC_TX", slot=i % 8, msg=m.hex(), insn=self.insn_total)
                    i = (i + 1) & 0xFFFF
            uc.mem_write(base + 0x76C, int(wr & 0xFFFF).to_bytes(2, 'little'))
            d0 = int.from_bytes(uc.mem_read(ipc + 0xC, 2), 'little')
            uc.mem_write(ipc + 0xE, int(d0 & 0xFFFF).to_bytes(2, 'little'))
            self.run.ev("IPC_DRAIN", wr=wr)
        except UcError:
            pass

    def _ctx_fill_cb(self, uc, address, size, user_data):
        if getattr(self, '_ctx_filled', False):
            return
        self._ctx_filled = True
        def wr(a, v):
            uc.mem_write(a, int(v & 0xFFFFFFFF).to_bytes(4, 'little'))
        # The table is FDL2's runtime save area (zero in flash). Restore into
        # the natural boot's captured state at the OS-main call site inside
        # early init (checkpoints/main): return to 0x80a06244 (Thumb) with
        # the exact register file the natural boot had there.
        RET_LR = 0x814C34A5          # land ON the OS-main dispatcher call,
        RET_SP = 0x81FFFFF8          # with the checkpoint's exact args
        RET_CPSR = 0x000000D3
        RET_REGS = {0: 0x000000D3, 1: 0x82000000, 2: 0x814C5BA4}
        for base in (0x194C, 0x1958, 0x1960, 0x196C, 0x1978, 0x1984):
            wr(base, RET_SP)
            wr(base + 4, 0)
            wr(base + 8, 0xD3)
        wr(0x1948, RET_CPSR)
        for i in range(1, 13):
            wr(0x1910 + (i - 1) * 4, RET_REGS.get(i, 0))
        wr(0x1940, RET_SP)
        wr(0x1944, RET_LR)
        self.run.log(f"[CTXF ] context table filled: lr={RET_LR:#x} "
                     f"sp={RET_SP:#x} cpsr={RET_CPSR:#x}")
        self.run.ev("CTX_FILL", lr=hex(RET_LR), sp=hex(RET_SP))

    # ---------------------------------------------- low-blob WFI wake    # ---------------------------------------------- low-blob WFI wake
    def _blob_wfi_cb(self, uc, address, size, user_data):
        """WFI in the low SYSRAM blob = the pre-OS sleep wait. A pending
        AON tick wakes WFI even with I-masked; deliver the IRQ inline."""
        if not (self.hw_regs.get(AON_TMR_BASE, 0) & 1):
            return
        self.tick_pending = True
        pc = uc.reg_read(UC_ARM_REG_PC)
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        uc.reg_write(UC_ARM_REG_CPSR, (cpsr & ~0x1F) | 0x12 | 0xC0)
        uc.reg_write(UC_ARM_REG_SPSR, cpsr)
        uc.reg_write(UC_ARM_REG_LR, (pc + 4) & 0xFFFFFFFC)
        try:
            handler = int.from_bytes(uc.mem_read(0x0C, 4), 'little')
        except UcError:
            handler = 0
        entry = (handler if handler else 0x18) & ~1
        uc.reg_write(UC_ARM_REG_PC, entry)
        self.tick_wakes = getattr(self, 'tick_wakes', 0) + 1
        if self.tick_wakes <= 10:
            self.run.log("[WAKE ] tick WFI at {:#x} -> IRQ {:#x} #{}".format(
                pc, entry, self.tick_wakes))
        self.run.ev("TICK_WAKE", pc=hex(pc), entry=hex(entry), n=self.tick_wakes)

    def blob_wfi_hooks(self):
        if getattr(self, '_wfi_hooked', False):
            return
        self._wfi_hooked = True
        try:
            data = open(KERNEL, 'rb').read()
            blob = data[0xBFBC28:0xBFBC28 + 0x19A8]
        except OSError:
            return
        n = 0
        for i in range(0, len(blob) - 3, 4):
            w = int.from_bytes(blob[i:i + 4], 'little')
            if w == 0xE320F003:                      # ARM WFI
                self.mu.hook_add(UC_HOOK_CODE, self._blob_wfi_cb,
                                 begin=i, end=i)
                n += 1
        self.run.log("  blob WFI hooks: %d" % n)
        self.run.ev("WFI_HOOKS", count=n)

    def boot_run(self, start=None):
        start = start or self.entry
        self.boot_state()
        if self.payload:
            self.cp15_register_static_sites()
            if GIC_MODEL and GIC_UNMASK_SITES:
                self._gic_hook_unmask_sites()
        self.mmio_hist_on()
        self.mu.reg_write(UC_ARM_REG_PC, start)
        self.run.log(f"[BOOT ] start {start:#x} cpsr={self.mu.reg_read(UC_ARM_REG_CPSR):#x} "
                     f"sp={self.mu.reg_read(UC_ARM_REG_SP):#x}")
        self.run.ev("BOOT", entry=hex(start))
        try:
            self._loop(start)
        finally:
            self.close_cell_trace()

    def _tail_insn(self, uc, address, size, user_data):
        self.insn_log.append((address & ~1, uc.reg_read(UC_ARM_REG_CPSR),
                              uc.reg_read(UC_ARM_REG_SP)))

    def _loop(self, pc):
        mu = self.mu
        last_prog = 0
        last_prog_pc = -1
        self._n_mmio_w_since = 0
        while self.insn_total < self.max_insns:
            if time.time() > self.deadline:
                self.stop_reason = self.stop_reason or "timeout"
                break
            if self.trace_tail and self.tail_hook is None:
                self.tail_hook = mu.hook_add(UC_HOOK_CODE, self._tail_insn,
                                             begin=1, end=0)
                self.run.log(f"[TRACE] tracer armed (logging last {self.trace_tail})")
            # one injection per chunk: the mailbox IRQ goes first (ticks
            # are pending every chunk and would otherwise always leave
            # the CPU in IRQ mode, masked), but never twice in a row
            if MMU_GUARD:
                self._mmu_off(mu, "boundary")
            if GIC_MODEL:
                self._gic_step(mu)
            else:
                mbx_done = False
                if CP_STUB and not getattr(self, '_mbx_last', False):
                    mbx_done = self._deliver_mbx_irq(mu)
                self._mbx_last = mbx_done
                if not mbx_done:
                    self._deliver_ticks(mu)
            # CP-side mailbox consume (model): the modem core drains AP
            # mailbox slots asynchronously on its own clock. The old model
            # ran this inside _deliver_ticks, which is gated on the AON
            # timer being enabled - a gate that never fires before the
            # scheduler starts, so the acquirer's spin on bit(ch+24) of
            # 0x400A0014 waited forever (bisect_long). Consume within one
            # chunk whenever a slot is pending: the pre-init doorbell path
            # never sets bits (silent consume), so a nonzero mask always
            # means a real handoff awaiting the CP.
            mbx = self.hw_regs.get(0x400A0014, 0)
            if mbx:
                self.hw_regs[0x400A0014] = 0
                try:
                    mu.mem_write(0x400A0014, b'\x00\x00\x00\x00')
                    self.run.ev("MBX_CP_CONSUME", mask=hex(mbx))
                except UcError:
                    pass
            # Pin the ENTIRE low-page (0x0-0x1000): firmware wild writes
            # fill it with 0x0F bytes (diag channel fill pattern), which
            # corrupts the vector table AND the UND/VFP handler code.
            # Save the original at boot and restore when corrupted.
            if not hasattr(self, '_lowpage_saved'):
                self._lowpage_saved = bytes(mu.mem_read(0x0, 0x1000))
            if mu.mem_read(0x600, 4) != self._lowpage_saved[0x600:0x604]:
                mu.mem_write(0x0, self._lowpage_saved)
                self.run.ev("LOWPAGE_RESTORED")
            try:
                try:
                    # NO wall-clock chunk timeout in practice: count=CHUNK
                    # (a hard instruction budget) is what guarantees each
                    # chunk returns - Unicorn's timeout is a cooperative
                    # stop flag that cannot break a hung Python hook, and
                    # the wall-clock deadline check at the loop top only
                    # runs between chunks. The large value exists purely so
                    # a pathological never-returning-chunk cannot wedge the
                    # watchdog silently; a host-load-dependent SMALL timeout
                    # here was the run-to-run nondeterminism root (it
                    # truncated chunks mid-flight under load, shifting every
                    # later tick-delivery point).
                    chunk = getattr(self, '_chunk_override', 0) or CHUNK
                    self._chunk_override = 0
                    if TICK_EXACT_CHUNKS:
                        nd = self._next_tick_due()
                        if nd is not None and nd > self.insn_total:
                            chunk = max(256, min(chunk, nd - self.insn_total))
                    self._last_chunk = chunk
                    self._stop_cause = None
                    if getattr(self, '_native', False):
                        self.nst.est = 0
                    if getattr(self, '_mmio_native', False):
                        self.nst.insn_now = self.insn_total
                    elif CTR_PAGES_UNHOOKED:
                        for pg in CTR_PAGES:
                            for off in (4, 0xC):
                                cv = int(self.insn_total * self._ctr_scale(pg, off)) & 0xFFFFFFFF
                                mu.mem_write(pg + off, cv.to_bytes(4, 'little'))
                    mu.emu_start(self._start_pc(), UNTIL_NEVER, count=chunk,
                                 timeout=3_600_000_000)
                finally:
                    if self.insn_total < 5_000_000:
                        self.run.log(f"[CHUNK] @{self.insn_total} "
                                     f"pc={mu.reg_read(UC_ARM_REG_PC):#x}")
            except OSError as e:
                # native unicorn crash (host access violation inside
                # uc_emu_start - seen executing loaded LTE/DSP firmware
                # whose wild writes outrun the auto-mapped pages). Skip
                # the faulting instruction and continue; re-executing the
                # same pc crashes forever and exhausts unicorn's internal
                # resources (UC_ERR_RESOURCE).
                pc = mu.reg_read(UC_ARM_REG_PC)
                if STRICT:
                    self._strict_stop(mu, "native-crash", f"{e} pc={pc:#x}")
                    break
                self.insn_total += CHUNK
                self.run.log(f"[CRASH] native uc_emu_start fault: {e}; "
                             f"skipping at pc={pc:#010x}")
                self.run.ev("UC_CRASH", pc=hex(pc))
                mu.reg_write(UC_ARM_REG_PC, self._start_pc() + 4)
                continue
            except UcError as e:
                pc = mu.reg_read(UC_ARM_REG_PC)
                # unhandled CP15 / system instruction: log and skip (4 bytes
                # in both ARM and Thumb-2 MCR/MRC encodings)
                if 'Unhandled CPU exception' in str(e):
                    # trap-and-emulate: the reported pc can be off by the
                    # pipeline offset; scan a small window for the coproc word
                    serviced = False
                    for delta in (0, -4, 4):
                        try:
                            w_pc = (pc + delta) & ~3
                            word = int.from_bytes(mu.mem_read(w_pc, 4), 'little')
                        except UcError:
                            continue
                        if self._cp15_service(mu, w_pc, word):
                            self._skips_since_progress = 0
                            d = decode_cp15(word)
                            if d:
                                key = (d[2], d[4])
                                self.cp15_backstop_counts = getattr(
                                    self, 'cp15_backstop_counts', {})
                                self.cp15_backstop_counts[key] =                                     self.cp15_backstop_counts.get(key, 0) + 1
                                if self.cp15_backstop_counts[key] == 8:
                                    if CP15_INLINE:
                                        self.cp15_promote_class(*key)
                            if self.cp15_served <= 20:
                                self.run.log(f"[CP15 ] served at {w_pc:#x} "
                                             f"({word:08x})")
                            self.run.ev("CP15_SERVED", pc=hex(w_pc))
                            self._advance(mu, w_pc)
                            serviced = True
                            break
                    if serviced:
                        continue
                    self._skips_since_progress = getattr(
                        self, '_skips_since_progress', 0) + 1
                    if self._skips_since_progress > 10000:
                        self.stop_reason = "skip-storm"
                        self.stop_detail = f"pc={pc:#x}"
                        self.run.log(f"[STORM] 200+ consecutive unhandled "
                                     f"exceptions at {pc:#x} -- stopping")
                        self.run.ev("SKIP_STORM", pc=hex(pc))
                        break
                if STRICT:
                    self._strict_stop(mu, "uc-error", f"{e} pc={pc:#x}")
                    break
                # RESILIENCE: don't stop on ANY UcError -
                # log it, skip the faulting instruction, and continue.
                # The CPU state is usually recoverable; stopping here
                # loses the entire boot for a single bad instruction.
                self.insn_total += CHUNK
                _skip = 4 if not (mu.reg_read(UC_ARM_REG_CPSR) & 0x20) else 2
                self.run.log(f"[SKIP ] {e} at {pc:#x} -> {pc + _skip:#010x}")
                self.run.ev("UC_SKIP", err=str(e), pc=hex(pc))
                mu.reg_write(UC_ARM_REG_PC, self._start_pc() + _skip)
                continue
            self._skips_since_progress = 0
            pc = mu.reg_read(UC_ARM_REG_PC)
            pe = getattr(self, '_py_exc', None)
            if pe is not None:
                self._py_exc = None
                raise pe
            cause = getattr(self, '_stop_cause', None)
            if self._native and self.nst.stop_cause:
                self.nst.stop_cause = 0
                cause = 'unmask'
            wfi = self._after_wfi(mu, pc) if (WFI_WAKE or TICK_EXACT_CHUNKS) else False
            if not TICK_EXACT_CHUNKS:
                self.insn_total += getattr(self, '_last_chunk', CHUNK)
            elif cause == 'ctrskip':
                pass                                    # already advanced
            elif cause == 'unmask':
                self.insn_total += (min(self.nst.est, self._last_chunk)
                                    if CONTINUOUS_TIME and self._native else EARLY_STOP_COST)
            elif wfi:
                nd = self._next_tick_due()
                ran = (min(self.nst.est, self._last_chunk)
                       if CONTINUOUS_TIME and self._native else EARLY_STOP_COST)
                self.insn_total = max(self.insn_total + ran,
                                      nd if nd is not None else
                                      self.insn_total + getattr(self, '_last_chunk', CHUNK))
            else:
                self.insn_total += getattr(self, '_last_chunk', CHUNK)
            if WFI_WAKE:
                self._wfi_wake = wfi
            sa = getattr(self, 'save_at', None)
            if sa and self.insn_total >= sa[0][0]:
                at, path = sa.pop(0)
                self.ckpt_save(path)
            if getattr(self, 'stall_insns', 0) and self._stall_check(mu, pc):
                self.run.log(f"[STALL] no progress for {self.stall_insns} insns "
                             f"(pc={pc:#x}) - profiling")
                self.stall_profile()
                self.stop_reason = "stall"
                self.stop_detail = f"pc={pc:#x}"
                self.run.ev("STALL", pc=hex(pc), insn=self.insn_total)
                break
            if self.insn_total - last_prog >= PROGRESS_EVERY:
                sp = mu.reg_read(UC_ARM_REG_SP)
                self.run.log(f"[.... ] {self.insn_total/1e6:.1f}M insns pc={pc:#010x} sp={sp:#010x}")
                if pc == last_prog_pc and self._n_mmio_w_since == 0:
                    # NOTE: the NV/charge task legitimately cycles through
                    # int_lock/int_unlock pairs during bulk NV reads - this
                    # is compute-intensive but NOT stuck. The
                    # deadloop detector is DISABLED for this case.
                    pass
                last_prog_pc = pc
                self._n_mmio_w_since = 0
                last_prog = self.insn_total
            if self.stop_reason:
                self.run.ev("STOP", reason=self.stop_reason, detail=self.stop_detail)
                break
        else:
            self.stop_reason = self.stop_reason or "max-insns"
        self.mmio_hist_dump()
        self.run.log(f"[HALT ] {self.stop_reason} after {self.insn_total} insns, "
                     f"pc={mu.reg_read(UC_ARM_REG_PC):#x}")
        if self.tail_hook is not None:
            entries = list(self.insn_log)
            self.run.log(f"[TRACE] {len(entries)} insns logged")
            with open(os.path.join(self.run.dir, "trace.txt"), "w") as tf:
                for addr, cpsr, sp in entries:
                    mode = "T" if cpsr & 0x20 else "A"
                    tf.write("%08x:%s sp=%08x" % (addr, mode, sp) + chr(10))
            # find transition into low-RAM sled: last insn with pc >= 0x21000
            cut = 0
            for k, (addr, cpsr, sp) in enumerate(entries):
                if addr >= 0x21000 or 0x80000000 <= addr < 0x84000000 or addr >= 0xFFF00000:
                    cut = k
            lo = max(0, cut - 20)
            for addr, cpsr, sp in entries[lo:cut + 40]:
                t = "T" if cpsr & 0x20 else "A"
                self.run.log(f"  {addr:08x}:{t} sp={sp:08x}")

    # ------------------------------------------------------------ debugger
    def dbg_break(self, uc, address, size, user_data):
        if not self.bps_armed:
            return
        self.stop_reason = "breakpoint"
        self.stop_detail = hex(address)
        self.run.log(f"[BRK  ] hit {address:#x}")
        self.run.ev("BREAK", addr=hex(address))
        uc.emu_stop()

    def bp_add(self, addr):
        addr &= ~1
        if addr in self.bps:
            return
        h = self.mu.hook_add(UC_HOOK_CODE, self.dbg_break, begin=addr, end=addr)
        self.bps[addr] = h
        self.bps_armed = True

    def bp_del(self, addr):
        addr &= ~1
        h = self.bps.pop(addr, None)
        if h:
            self.mu.hook_del(h)

    def _logbp_cb(self, uc, address, size, user_data):
        sp = uc.reg_read(UC_ARM_REG_SP)
        try:
            m0 = int.from_bytes(uc.mem_read(sp, 4), 'little')
            m1 = int.from_bytes(uc.mem_read(sp + 4, 4), 'little')
        except UcError:
            m0 = m1 = -1
        self.logbp_n = getattr(self, 'logbp_n', 0) + 1
        if self.logbp_n <= 60:
            self.run.log(f"[LBP  ] #{self.logbp_n} pc={address:#x} sp={sp:#x} "
                         f"[sp]={m0:08x} [sp+4]={m1:08x} lr={uc.reg_read(UC_ARM_REG_LR):#x}")
        self.run.ev("LOGBP", n=self.logbp_n, pc=hex(address), sp=hex(sp),
                    m0=hex(m0), m1=hex(m1))

    def ftrace_arm(self, addr, n):
        """Log the first n instructions executed from addr (forward trace)."""
        state = {"left": n, "on": False}
        def cb(uc, address, size, ud):
            if not state["on"]:
                if (address & ~1) == (addr & ~1):
                    state["on"] = True
                else:
                    return
            if state["left"] <= 0:
                return
            state["left"] -= 1
            cpsr = uc.reg_read(UC_ARM_REG_CPSR)
            sp = uc.reg_read(UC_ARM_REG_SP)
            self.run.log("[FTR  ] %08x:%s sp=%08x"
                         % (address & ~1, "T" if cpsr & 0x20 else "A", sp))
            if state["left"] == 0:
                self.stop_reason = "ftrace-done"
                self.mu.emu_stop()
        self.mu.hook_add(UC_HOOK_CODE, cb, begin=1, end=0)
        self.run.log(f"[FTR  ] armed at {addr:#x} for {n} insns")

    def logbp_add(self, addr):
        addr &= ~1
        self.mu.hook_add(UC_HOOK_CODE, self._logbp_cb, begin=addr, end=addr)

    def _regbp_cb(self, uc, address, size, user_data):
        self.logbp_n = getattr(self, 'logbp_n', 0) + 1
        if self.logbp_n > 80:
            return
        sp = uc.reg_read(UC_ARM_REG_SP)
        try:
            m = int.from_bytes(uc.mem_read(sp, 16), 'little')
        except UcError:
            m = 0
        vals = [uc.reg_read(UC_ARM_REG_R0 + i) for i in range(4)]
        self.run.log(
            "[RBP  ] #%d pc=%08x r0-r3=%08x %08x %08x %08x lr=%08x sp=%08x "
            "[sp]=%08x [sp+4]=%08x [sp+8]=%08x [sp+12]=%08x"
            % (self.logbp_n, address, vals[0], vals[1], vals[2], vals[3],
               uc.reg_read(UC_ARM_REG_LR), sp,
               m & 0xFFFFFFFF, (m >> 32) & 0xFFFFFFFF,
               (m >> 64) & 0xFFFFFFFF, (m >> 96) & 0xFFFFFFFF))
        self.run.ev("REGBP", n=self.logbp_n, pc=hex(address),
                    r0=hex(vals[0]), r1=hex(vals[1]), r2=hex(vals[2]),
                    r3=hex(vals[3]), lr=hex(uc.reg_read(UC_ARM_REG_LR)),
                    sp=hex(sp))

    def regbp_add(self, addr):
        addr &= ~1
        self.mu.hook_add(UC_HOOK_CODE, self._regbp_cb, begin=addr, end=addr)

    # -------- CP15 trap-and-emulate (proper model, no shims) --------
    def _cp15_service(self, uc, pc, word):
        """Service one coproc-15 instruction at pc from the model. Returns
        True if handled (pc advanced), False if not a coproc-15 op.
        USER-mode CP15 access = UNDEFINED per ARMv7-A: raise the guest UND
        exception (vector 0x04) instead of emulating - the boot relies on
        this privilege fault to enter the RTOS scheduler. The zeroed restore
        table leaves the mode field at 0 (user-equivalent)."""
        if (uc.reg_read(UC_ARM_REG_CPSR) & 0x1F) in (0x10, 0x00):
            self._inject_und(uc, pc)
            self._und_injected = True
            return True
        d = decode_cp15(word)
        if d:
            l, opc1, crn, rt, crm, opc2 = d
            if l:
                val = self.cp15.read(opc1, crn, crm, opc2)
                if rt != 15:
                    uc.reg_write(UC_ARM_REG_R0 + rt, val)
            else:
                val = uc.reg_read(UC_ARM_REG_R0 + rt) if rt != 15 else 0
                self.cp15.write(opc1, crn, crm, opc2, val)
            self.cp15_served += 1
            return True
        m = decode_mcrr(word)
        if m:
            l, opc1, rt, rt2, crm = m
            key = ("mcrr", opc1, crm)
            if l:   # MRRC
                a, b = self.mcrr.get(key, (0, 0))
                uc.reg_write(UC_ARM_REG_R0 + rt, a)
                uc.reg_write(UC_ARM_REG_R0 + rt2, b)
            else:   # MCRR
                a = uc.reg_read(UC_ARM_REG_R0 + rt)
                b = uc.reg_read(UC_ARM_REG_R0 + rt2)
                self.mcrr[key] = (a, b)
            self.cp15_served += 1
            return True
        return False

    def _advance(self, uc, pc):
        if getattr(self, '_und_injected', False):
            self._und_injected = False      # exception entry set PC already
            return
        thumb = uc.reg_read(UC_ARM_REG_CPSR) & 0x20
        uc.reg_write(UC_ARM_REG_PC, (pc + 4) | (1 if thumb else 0))

    def _cp15_inline_cb(self, uc, address, size, user_data):
        """Inline hook at a statically known CP15 site: service and skip."""
        if (uc.reg_read(UC_ARM_REG_CPSR) & 0x1F) in (0x10, 0x00):
            self._inject_und(uc, address & ~3)
            self._und_injected = True
            return
        try:
            word = int.from_bytes(uc.mem_read(address & ~3, 4), 'little')
            pc = uc.reg_read(UC_ARM_REG_PC) & ~3
            if self._cp15_service(uc, pc, word):
                self._advance(uc, pc)
        except UcError:
            pass

    # classes (CRn, CRm) known to raise in unicorn -> inline-hooked up front
    CP15_HOOK_CLASSES = {(10, 2), (0, 0), (1, 0), (0, 1), (2, 0), (1, 0, 0, 0)}

    def cp15_register_static_sites(self):
        """Scan the loaded kernel image for coproc-15 words; register inline
        hooks ONLY for raising classes (every hook costs unicorn per-block
        checking). Other classes start on the runtime backstop and get
        promoted to inline hooks after repeated service.
        The SYSRAM blob (RAM 0x0-0x19a8) is scanned too: its ARM restore code
        issues CP15 writes that MUST fault in user mode."""
        self.cp15_sites = []
        if not CP15_INLINE:
            self.cp15_hook_classes = set()
        for off in range(0, len(self.payload) - 3, 2):   # 2-byte: catches
            w = int.from_bytes(self.payload[off:off + 4], 'little')  # unaligned Thumb32
            d = decode_cp15(w) or decode_mcrr(w)
            if d:
                self.cp15_sites.append((KBASE + off, d))
        blob = bytes(self.mu.mem_read(0, 0x19A8))
        for off in range(0, len(blob) - 3, 4):           # ARM: 4-byte aligned
            w = int.from_bytes(blob[off:off + 4], 'little')
            d = decode_cp15(w) or decode_mcrr(w)
            if d:
                self.cp15_sites.append((off, d))
        n = self._hook_cp15_class_set()
        self.run.log(f"  CP15: {len(self.cp15_sites)} static sites "
                     f"(incl. blob), {n} inline hooks "
                     f"(classes {sorted(self.cp15_hook_classes)})")
        self.run.ev("CP15_HOOKS", count=n)

    def _hook_cp15_class_set(self):
        n = 0
        for va, d in self.cp15_sites:
            if d[0] == 0 or d[0] == 1:      # MRC/MCR: (L, opc1, CRn, Rt, CRm, opc2)
                crn, crm = d[2], d[4]
            else:                            # MRRC/MCRR: (L, opc1, Rt, Rt2, CRm)
                crn, crm = 14, d[4]
            if (crn, crm) in self.cp15_hook_classes:
                self.mu.hook_add(UC_HOOK_CODE, self._cp15_inline_cb,
                                 begin=va & ~1, end=va & ~1)
                n += 1
        return n

    def cp15_promote_class(self, crn, crm):
        if (crn, crm) in self.cp15_hook_classes:
            return
        self.cp15_hook_classes.add((crn, crm))
        n = self._hook_cp15_class_set()
        self.run.log(f"[CP15 ] class (c{crn},c{crm}) promoted to inline hooks "
                     f"(+{n} sites)")

    def checkpoint_add(self, name, addr, outdir):
        addr &= ~1
        def cb(uc, address, size, user_data, _name=name):
            if _name in self._cp_done:
                return
            self._cp_done.add(_name)
            self.run.log(f"[CPSNP] checkpoint '{_name}' at {address:#x} -- saving")
            self.snapshot("snapshot", outdir=outdir)
            self.run.ev("CHECKPOINT", name=_name, pc=hex(address))
        self.mu.hook_add(UC_HOOK_CODE, cb, begin=addr, end=addr)

    def wp_add(self, addr, kind, stop=False):
        kinds = {"r": UC_HOOK_MEM_READ, "w": UC_HOOK_MEM_WRITE}
        hts = []
        for k in kind:
            ht = kinds.get(k)
            if ht:
                h = self.mu.hook_add(ht, self._wp_cb, begin=addr, end=addr)
                hts.append((ht, h))
        self.wps.append({"addr": addr, "kind": kind, "hooks": hts, "stop": stop})

    def _wp_cb(self, uc, access, address, size, value, user_data):
        for w in self.wps:
            if w["addr"] <= address < w["addr"] + 8:
                pc = uc.reg_read(UC_ARM_REG_PC)
                acc = "R" if access == UC_MEM_READ else "W"
                val = value if access == UC_MEM_WRITE else \
                    int.from_bytes(uc.mem_read(address, size), 'little')
                self.run.log(f"[WP   ] {acc} [{address:#x}] = {val:#x} pc={pc:#x}")
                self.run.ev("WATCH", rw=acc, addr=hex(address), value=hex(val), pc=hex(pc))
                if w["stop"]:
                    self.stop_reason = "watchpoint"
                    uc.emu_stop()

    def cont(self, budget=None):
        """Continue from current PC, managing breakpoint re-arm dance."""
        mu = self.mu
        pc = mu.reg_read(UC_ARM_REG_PC)
        self.stop_reason = None
        # step over current insn with bps disarmed so we don't re-hit
        if self.bps_armed and (pc & ~1) in self.bps:
            self.bps_armed = False
            try:
                mu.emu_start(self._start_pc(), UNTIL_NEVER, count=1)
            except UcError:
                pass
            self.insn_total += 1
            pc = mu.reg_read(UC_ARM_REG_PC)
            self.bps_armed = True
        limit = budget if budget is not None else self.max_insns
        prev = self.max_insns
        self.max_insns = self.insn_total + (limit or 10_000_000)
        self._loop(pc)
        self.max_insns = prev

    def step(self, n=1):
        mu = self.mu
        self.stop_reason = None
        for _ in range(n):
            if self.stop_reason:
                break
            pc = mu.reg_read(UC_ARM_REG_PC)
            thumb = bool(mu.reg_read(UC_ARM_REG_CPSR) & 0x20)
            ins = self._disasm_at(mu, pc, 1)
            self.run.log(f"[STEP ] {ins}")
            try:
                mu.emu_start(self._start_pc(), UNTIL_NEVER, count=1)
            except UcError as e:
                self.run.log(f"[STOP ] {e}")
                break
            self.insn_total += 1
        self.run.log(f"[PC   ] {mu.reg_read(UC_ARM_REG_PC):#010x}")

    def regs(self):
        mu = self.mu
        vals = []
        for r in REG_LIST:
            try:
                vals.append((REG_NAMES[r], mu.reg_read(r)))
            except UcError:
                vals.append((REG_NAMES[r], -1))
        cpsr = mu.reg_read(UC_ARM_REG_CPSR)
        mode = {0x10: "usr", 0x12: "irq", 0x13: "svc", 0x17: "abt",
                0x1A: "hyp", 0x1B: "und", 0x1F: "sys"}.get(cpsr & 0x1F, "?")
        s = " ".join(f"{n}={v:08x}" for n, v in vals[:13])
        t = "thumb" if cpsr & 0x20 else "arm"
        return (f"{s}\nsp={vals[13][1]:08x} lr={vals[14][1]:08x} pc={vals[15][1]:08x} "
                f"cpsr={cpsr:08x} ({mode}, {t}, irq{'off' if cpsr & 0x80 else 'on'}, "
                f"fiq{'off' if cpsr & 0x40 else 'on'})")

    # ------------------------------------------------------------ snapshot
    def snapshot(self, tag="snap", outdir=None):
        mu = self.mu
        outdir = outdir or self.run.dir
        base = os.path.join(outdir, tag)
        # --- CPU state as plain values (portable across processes) ---
        saved_cpsr = mu.reg_read(UC_ARM_REG_CPSR)
        regs = {REG_NAMES[r]: mu.reg_read(r)
                for r in REG_LIST if r != UC_ARM_REG_CPSR}
        regs["cpsr"] = saved_cpsr
        banked = {}
        base_cpsr = saved_cpsr & ~0x1F
        for mname, mode in (("irq", 0x12), ("fiq", 0x11), ("abt", 0x17),
                            ("und", 0x1B), ("svc", 0x13), ("sys", 0x1F)):
            mu.reg_write(UC_ARM_REG_CPSR, base_cpsr | mode)
            e = {}
            for rn, rr in (("sp", UC_ARM_REG_SP), ("lr", UC_ARM_REG_LR)):
                e[rn] = mu.reg_read(rr)
            if mname == "fiq":
                for i in range(8, 14):
                    e[f"r{i}"] = mu.reg_read(UC_ARM_REG_R0 + i)
            e["spsr"] = mu.reg_read(UC_ARM_REG_SPSR)
            banked[mname] = e
        mu.reg_write(UC_ARM_REG_CPSR, saved_cpsr)
        regions = []
        dump_regions = [r for r in RAM_REGIONS + MMIO_MAPS
                        if not (0x40000000 <= r[0] < 0x50000000)]  # MMIO state = hw_regs
        for idx, (b, sz, name) in enumerate(dump_regions):
            fn = f"{tag}.r{idx}.bin"
            try:
                data = bytes(mu.mem_read(b, sz))
                open(os.path.join(outdir, fn), "wb").write(data)
                regions.append({"base": b, "size": sz, "name": name, "file": fn})
            except UcError:
                pass
        meta = {
            "insn": self.insn_total, "regs": regs, "banked": banked,
            "hw_regs": {hex(k): v for k, v in self.hw_regs.items()},
            "regions": regions, "stop_reason": self.stop_reason,
            "und_count": getattr(self, 'und_count', 0),
            # modeled-device live state (review bug-2): without these a
            # snapshot taken after the channel-module init silently resumes
            # with doorbells taking the pre-init silent-consume path, and
            # the first _deliver_ticks injects an immediate tick.
            "chan_mgr_inited": getattr(self, 'chan_mgr_inited', False),
            "adi_req_id": getattr(self, 'adi_req_id', 0),
            "mbx_ch": getattr(self, '_mbx_ch', 0),
            "tick_next": getattr(self, 'tick_next', 1),
        }
        with open(base + ".json", "w") as f:
            json.dump(meta, f, indent=1)
        self.run.log(f"[SNAP ] saved {base}.json (+{len(regions)} region files)")
        self.run.ev("SNAPSHOT", file=base + ".json")
        return base + ".json"

    @classmethod
    def restore(cls, run, path, **kw):
        with open(path) as f:
            meta = json.load(f)
        emu = cls(run, **kw)
        for r in meta["regions"]:
            data = open(os.path.join(os.path.dirname(path), r["file"]), "rb").read()
            emu._map(r["base"], r["size"], r["name"])
            emu.mu.mem_write(r["base"], data)
        emu.hw_regs = {int(k, 16): v for k, v in meta["hw_regs"].items()}
        # modeled-device live state (defaults match a pre-init snapshot)
        emu.chan_mgr_inited = bool(meta.get("chan_mgr_inited", False))
        emu.adi_req_id = int(meta.get("adi_req_id", 0))
        emu._mbx_ch = int(meta.get("mbx_ch", 0))
        emu.tick_next = int(meta.get("tick_next", 1))
        mu = emu.mu
        # banked-mode register restore (mode switch reveals banked banks)
        for mname, mode in (("irq", 0x12), ("fiq", 0x11), ("abt", 0x17),
                            ("und", 0x1B), ("svc", 0x13), ("sys", 0x1F)):
            e = meta["banked"].get(mname, {})
            cur = mu.reg_read(UC_ARM_REG_CPSR)
            mu.reg_write(UC_ARM_REG_CPSR, (cur & ~0x1F) | mode)
            for rn, rr in (("sp", UC_ARM_REG_SP), ("lr", UC_ARM_REG_LR)):
                if rn in e:
                    mu.reg_write(rr, e[rn])
            if mname == "fiq":
                for i in range(8, 14):
                    if f"r{i}" in e:
                        mu.reg_write(UC_ARM_REG_R0 + i, e[f"r{i}"])
            if "spsr" in e:
                mu.reg_write(UC_ARM_REG_SPSR, e["spsr"])
        # restore CPSR first (sets Thumb/mode), then GPRs, then PC last
        if "cpsr" in meta["regs"]:
            mu.reg_write(UC_ARM_REG_CPSR, meta["regs"]["cpsr"])
        for rn, rv in meta["regs"].items():
            if rn == "cpsr":
                continue
            mu.reg_write(REG_BY_NAME[rn], rv)
        if "pc" in meta["regs"]:
            # PC writes re-derive Thumb state from bit0 - keep CPSR.T consistent
            t = (meta["regs"].get("cpsr", 0) >> 5) & 1
            mu.reg_write(UC_ARM_REG_PC, meta["regs"]["pc"] | t)
        emu.insn_total = meta.get("insn", 0)
        emu.und_count = meta.get("und_count", 0)
        emu.cp15_register_static_sites()
        # snapshot RAM just overwrote __init__'s image patches - re-apply
        # RAW_PATCHES + the log-counter increment patch (see _setup_hooks)
        for va, hx in RAW_PATCHES:
            emu.mu.mem_write(va & ~1, bytes.fromhex(hx))
        emu.mu.mem_write(0x80a09184, b'\x01\x20')
        # NOTE: do NOT re-run preload_modules() here - __init__ already loaded
        # the image, and re-running the scatter would wipe runtime state
        # (e.g. TCBs in the zero-filled BSS) from mid-run snapshots.
        emu.run.log(f"[RSTR ] {path}: pc={meta['regs'].get('pc', 0):#x} "
                    f"insn={emu.insn_total}")
        emu.run.ev("RESTORE", file=path)
        return emu

    # ------------------------------------------------------------ report
    def report(self):
        L = []
        L.append(f"# Mocor EMU run report -- {now_s()}\n")
        L.append(f"- mode: {self.mode}   entry: {self.entry:#x}")
        L.append(f"- instructions: {self.insn_total}   stop: {self.stop_reason} {self.stop_detail or ''}")
        L.append(f"- SNF accesses: rd={getattr(self, 'snf_rd', 0)} "
                 f"wr={getattr(self, 'snf_wr', 0)}")
        L.append(f"- tick pumps: {self.pump_count}   unsticks: {self.unstick_count}   "
                 f"WFI skips: {self.wfi_count}")
        L.append(f"- UART bytes: {self.run.uart_bytes}")
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        L.append(f"- final PC: {pc:#x} (thumb={bool(self.mu.reg_read(UC_ARM_REG_CPSR)&0x20)})")
        L.append(f"- context: {self._disasm_at(self.mu, pc)}\n")
        L.append("## Radio-relevant MMIO writes (stock radio-on trace)")
        if self.run.radio_w:
            seen = {}
            for insn, addr, size, val in self.run.radio_w:
                blk = BLOCK_NAMES.get(addr & 0xFFFF0000, "")
                seen.setdefault((addr & ~3, val), insn)
                L.append(f"- insn#{insn}  {addr:08x} = {val:08x}  {blk}")
            L.append(f"\n({len(self.run.radio_w)} writes, {len(seen)} unique addr=value)")
        else:
            L.append("- none")
        L.append("\n## Top poll loops (pc, addr -> value being waited on)")
        top = sorted(self.poll.items(), key=lambda kv: -kv[1][0])[:15]
        for (pc_k, addr, size), (hits, gen, last, ins, fp) in top:
            if hits < 1000:
                continue
            L.append(f"- pc={pc_k:#x} [{addr:#010x}] x{size}B hits={hits} gen={gen} "
                     f"insn='{ins or '?'}'")
        L.append("\n## MMIO write histogram")
        for blk, n in sorted(self.run.block_w.items(), key=lambda kv: -kv[1])[:15]:
            L.append(f"- {blk:08x} {BLOCK_NAMES.get(blk,''):12s} {n}")
        L.append("\n## Next-step suggestions")
        if self.stop_reason == "invalid-insn":
            L.append("- invalid instruction: check if it is an unsupported coproc/NEON; "
                     "add an INSN hook or fix mode (Thumb?) at the previous branch.")
        elif self.stop_reason == "timeout":
            L.append("- timeout: likely a poll that detection missed (writes? DMA?) -- "
                     "inspect top poll loops and final PC context.")
        elif self.stop_reason and self.stop_reason.startswith("unstick-budget"):
            L.append("- unstick budget hit: a modeled value let the kernel proceed but it "
                     "looped again elsewhere; check UNSTICK events in events.jsonl and "
                     "model that device properly in HW_DEFAULTS/on_read.")
        else:
            L.append("- inspect events.jsonl MMIO_W/WFI/POLL sequences for the next blocker.")
        txt = "\n".join(L)
        with open(os.path.join(self.run.dir, "REPORT.md"), "w", encoding="utf-8") as f:
            f.write(txt)
        return txt


# ---------------------------------------------------------------- debugger command loop
def px(s):
    """Parse int accepting 0x-hex, bare hex, or decimal."""
    try:
        return int(s, 0)
    except ValueError:
        return int(s, 16)


def dbg_shell(emu, cmds, one_shot=False):
    """Execute debugger commands. cmds: iterable of strings, or None = stdin REPL."""
    def do(line):
        line = line.strip()
        if not line or line.startswith("#"):
            return True
        parts = line.split()
        c, a = parts[0].lower(), parts[1:]
        emu.run.log(f"[DBG  ] > {line}")
        try:
            if c in ("q", "quit", "exit"):
                return False
            elif c == "info":
                emu.run.log("[DBG  ] " + emu.regs())
            elif c in ("r", "regs"):
                emu.run.log("[DBG  ] " + emu.regs())
            elif c == "s":
                emu.step(int(a[0]) if a else 1)
            elif c in ("c", "cont"):
                emu.cont(int(a[0]) if a else None)
            elif c == "until":
                tgt = px(a[0])
                mu = emu.mu
                try:
                    mu.emu_start(emu._start_pc(), tgt & ~1 or UNTIL_NEVER, count=emu.max_insns)
                except UcError as e:
                    emu.run.log(f"[DBG  ] {e}")
                emu.run.log(f"[DBG  ] at {mu.reg_read(UC_ARM_REG_PC):#x}")
            elif c == "b":
                if a[0] == "list":
                    emu.run.log(f"[DBG  ] bps: {[hex(x) for x in emu.bps]}")
                elif a[0] == "del":
                    emu.bp_del(px(a[1]))
                else:
                    emu.bp_add(px(a[0]))
            elif c == "wa":
                if a[0] == "list":
                    emu.run.log(f"[DBG  ] wps: {[(hex(w['addr']), w['kind']) for w in emu.wps]}")
                else:
                    emu.wp_add(px(a[0]), a[1], stop=(len(a) > 2 and a[2] == "stop"))
            elif c in ("x", "xw"):
                if a and a[0].lower() in REG_BY_NAME:
                    addr = emu.mu.reg_read(REG_BY_NAME[a[0].lower()])
                else:
                    addr = px(a[0])
                n = px(a[1]) if len(a) > 1 else 4
                if c == "xw":
                    for i in range(n):
                        off = addr + i * 4
                        v = int.from_bytes(emu.mu.mem_read(off, 4), 'little')
                        emu.run.log(f"[DBG  ] {off:08x}: {v:08x}")
                else:
                    data = bytes(emu.mu.mem_read(addr, n))
                    for i in range(0, len(data), 16):
                        chunk = data[i:i+16]
                        hx = " ".join(f"{b:02x}" for b in chunk)
                        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                        emu.run.log(f"[DBG  ] {addr+i:08x}: {hx:<32s} {asc}")
            elif c == "d":
                if a and a[0].lower() in ("pc", "lr"):
                    r = emu.mu.reg_read(REG_BY_NAME[a[0].lower()])
                    addr = r - 4 if a[0].lower() == "lr" else r
                    emu.run.log(f"[DBG  ] {a[0].lower()}={r:#x}")
                else:
                    addr = px(a[0]) if a else emu.mu.reg_read(UC_ARM_REG_PC)
                n = px(a[1]) if len(a) > 1 else 10
                emu.run.log("[DBG  ] " + emu._disasm_at(emu.mu, addr, n))
            elif c == "setpc":
                emu.mu.reg_write(UC_ARM_REG_PC, px(a[0]))
                emu.run.log(f"[DBG  ] pc={emu.mu.reg_read(UC_ARM_REG_PC):#x}")
            elif c == "setreg":
                rn, rv = a[0].lower(), px(a[1])
                emu.mu.reg_write(REG_BY_NAME[rn], rv)
                emu.run.log(f"[DBG  ] {rn}={rv:#x}")
            elif c in ("w8", "w16", "w32"):
                addr, val = px(a[0]), px(a[1])
                sz = int(c[1:]) // 8
                emu.mu.mem_write(addr, val.to_bytes(sz, 'little'))
                emu.run.log(f"[DBG  ] wrote {val:#x} ({sz}B) to {addr:#x}")
            elif c == "poll":
                top = sorted(emu.poll.items(), key=lambda kv: -kv[1][0])[:int(a[0]) if a else 10]
                for (pc_k, addr, size), (hits, gen, last, ins, fp) in top:
                    emu.run.log(f"[DBG  ] pc={pc_k:#x} [{addr:#010x}] x{size} hits={hits} "
                                f"gen={gen} '{ins or '?'}'")
            elif c == "snap":
                emu.snapshot(a[0] if a else "snap")
            elif c == "ev":
                emu.run.log("[DBG  ] (see events.jsonl)")
            elif c == "help":
                emu.run.log("[DBG  ] regs|s[n]|c[budget]|until A|b add/del/list A|wa A r|w [stop]|"
                            "x A[n]|xw A[n]|d A[n]|setpc A|setreg r v|w8/w16/w32 A v|poll[n]|snap tag|quit")
            else:
                emu.run.log(f"[DBG  ] ? {c}")
        except Exception as e:
            emu.run.log(f"[DBG  ] ERR {e}: {traceback.format_exc(limit=1)}")
        return True

    if cmds is None:
        print("dbg> interactive (one command per line, 'quit' to exit)")
        for line in sys.stdin:
            if not do(line):
                break
    else:
        for line in cmds:
            if not do(line):
                break


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="F286 Mocor OS Unicorn emulator v2")
    ap.add_argument("--mode", choices=["unstick", "report"], default="unstick",
                    help="unstick: auto-pump ticks + unstick polls; report: stop at 1st unknown poll")
    ap.add_argument("--max-insns", type=px, default=20_000_000)
    ap.add_argument("--timeout", type=float, default=300)
    ap.add_argument("--entry", type=px, default=ENTRY)
    ap.add_argument("--entry-os", action="store_true",
                    help="boot at OS main (0x814c34a4) skipping early init")
    ap.add_argument("--no-pump", action="store_true", help="disable tick pump")
    ap.add_argument("--no-cell-cuts", action="store_true",
                    help="do not skip the LTE/DSP pre-boot / glue path")
    ap.add_argument("--strict", action="store_true",
                    help="stop on faults instead of skipping/returning")
    ap.add_argument("--no-pmu-model", action="store_true",
                    help="old write-echo PMU (no set/clr banks, no status)")
    ap.add_argument("--no-real-nv", action="store_true",
                    help="zero-fill every NV read (no nvcal/journal DB)")
    ap.add_argument("--cell-trace", action="store_true",
                    help="full cellular MMIO r/w trace -> cell_trace.tsv")
    ap.add_argument("--cmds", help="debugger command file ('-' = stdin)")
    ap.add_argument("--restore", help="snapshot.json to resume from")
    ap.add_argument("--tag", help="run directory tag")
    ap.add_argument("--vector-bp", action="store_true",
                    help="breakpoint all 7 ARM exception vectors")
    ap.add_argument("--trace-tail", type=px, default=0, metavar="N",
                    help="exact instruction trace of the last N insns (slower)")
    ap.add_argument("--profile", choices=sorted(PROFILES.keys()),
                    help="apply a named boot-recipe (nop-fn/init-va/patch set)")
    ap.add_argument("--checkpoint", action="append", default=[], metavar="NAME=ADDR",
                    help="snapshot to checkpoints/NAME/ when PC reaches ADDR (repeatable)")
    ap.add_argument("--cp15-shim", action="store_true",
                    help="LEGACY: binary-patch p15,c10,c2 sites (proper CP15 model is default)")
    ap.add_argument("--logbp", type=px, action="append", default=[], metavar="ADDR",
                    help="non-stopping breakpoint: log pc/sp/[sp] and continue")
    ap.add_argument("--regbp", type=px, action="append", default=[], metavar="ADDR",
                    help="non-stopping breakpoint: log r0-r3/lr/sp/[sp..] and continue")
    ap.add_argument("--ftrace", action="append", default=[], metavar="ADDR=N",
                    help="forward-trace the first N insns from ADDR then stop")
    ap.add_argument("--wp", action="append", default=[], metavar="ADDR=r|w[rw][:stop]",
                    help="watchpoint pre-armed before boot, e.g. --wp FFFFFFF4=w:stop")
    ap.add_argument("--init-va", action="append", default=[], metavar="VA=HEX",
                    help="pre-seed a 32-bit boot param word, e.g. --init-va 814c5ba0=82000000")
    ap.add_argument("--patch", action="append", default=[], metavar="VA=HEX",
                    help="raw byte patch, e.g. --patch 81496dea=bf00bf00 (repeatable)")
    ap.add_argument("--nop-fn", type=px, action="append", default=[], metavar="ADDR",
                    help="neuter function at ADDR to 'bx lr' (repeatable)")
    ap.add_argument("--bp", type=px, action="append", default=[],
                    help="breakpoint (repeatable), set before boot")
    ap.add_argument("--until", type=px,
                    help="run to address (pre-boot)")
    args = ap.parse_args()
    global CELL_CUTS, STRICT, CELL_TRACE, PMU_MODEL, NV_REAL
    NV_REAL = not args.no_real_nv
    PMU_MODEL = not args.no_pmu_model
    CELL_CUTS = not args.no_cell_cuts
    STRICT = args.strict
    CELL_TRACE = args.cell_trace

    run = Run(tag=args.tag)
    run.log(f"=== mocor_emu v2 mode={args.mode} ===")
    try:
        if args.restore:
            emu = MocorEmu.restore(run, args.restore, mode=args.mode,
                                   pump=not args.no_pump, timeout_s=args.timeout,
                                   max_insns=args.max_insns,
                                   trace_tail=args.trace_tail)
        else:
            prof = PROFILES.get(args.profile or "")
            if prof:
                NOP_FNS.extend(prof.get("nop_fn", []))
                RAW_PATCHES.extend(prof.get("patch", []))
                INIT_VA.extend(prof.get("init_va", []))
            NOP_FNS.extend(args.nop_fn)
            for spec in args.patch:
                va, _, hx = spec.partition("=")
                RAW_PATCHES.append((px(va), hx))
            for spec in args.init_va:
                va, _, hx = spec.partition("=")
                INIT_VA.append((px(va), int(hx, 0) if hx.lower().startswith('0x') else int(hx, 16)))
            entry = ENTRY_OS if args.entry_os else args.entry
            emu = MocorEmu(run, mode=args.mode, entry=entry,
                           max_insns=args.max_insns, timeout_s=args.timeout,
                           pump=not args.no_pump, trace_tail=args.trace_tail,
                           cp15_shim=False)
        for b in args.bp:
            emu.bp_add(b)
        if args.vector_bp:
            for v in (0x0, 0x4, 0x8, 0xC, 0x10, 0x18, 0x1C):
                emu.bp_add(v)
        cp_dir = os.path.join(fwpaths.RUNS_DIR, "checkpoints")
        os.makedirs(cp_dir, exist_ok=True)
        for spec in args.checkpoint:
            name, _, addr = spec.partition("=")
            outdir = os.path.join(cp_dir, name)
            os.makedirs(outdir, exist_ok=True)
            emu.checkpoint_add(name, px(addr), outdir)
        for a in args.logbp:
            emu.logbp_add(a)
        for a in args.regbp:
            emu.regbp_add(a)
        for spec in args.ftrace:
            a, _, n = spec.partition("=")
            emu.ftrace_arm(px(a), int(n or 200))
        for spec in args.wp:
            addr, _, kind = spec.partition("=")
            kind, _, stop = kind.partition(":")
            emu.wp_add(px(addr), kind or "w", stop=stop == "stop")
        if args.cmds:
            # pre-boot bps armed; run boots first, then commands execute
            if not args.restore:
                emu.boot_run()
            else:
                emu.mmio_hist_on()
            dbg_shell(emu, open(args.cmds, encoding="utf-8") if args.cmds != "-" else None)
        else:
            if args.until:
                if not args.restore:
                    emu.boot_state()
                mu = emu.mu
                while emu.insn_total < args.max_insns:
                    try:
                        mu.emu_start(emu._start_pc(), args.until & ~1,
                                     count=CHUNK, timeout=3_600_000_000)
                    except UcError as e:
                        run.log(f"[STOP ] {e} pc={mu.reg_read(UC_ARM_REG_PC):#x}")
                        break
                    emu.insn_total += CHUNK
                    if ((mu.reg_read(UC_ARM_REG_PC) & ~1) == (args.until & ~1)
                            or emu.stop_reason):
                        break
                run.log(f"[HALT ] --until pc={mu.reg_read(UC_ARM_REG_PC):#x} "
                        f"insns={emu.insn_total}")
            elif args.restore:
                # continue from the restored state (do NOT reboot over it)
                emu.mmio_hist_on()
                emu._loop(emu.mu.reg_read(UC_ARM_REG_PC))
                emu.mmio_hist_dump()
            else:
                emu.boot_run()
    except Exception:
        run.log("[FATAL] " + traceback.format_exc())
        emu = None

    try:
        emu.snapshot("final")
    except Exception:
        pass
    if emu:
        rep = emu.report()
        print("\n" + rep)
    run.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
