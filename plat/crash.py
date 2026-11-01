"""plat.crash -- one clear report for every firmware assert / CPU fault.

  plat_run.py TAG --plugin crash[:stop=1,max=200,dabt=0]

Report = kind, expr/file/line/msg, thread, pc/lr/sp/cpsr, r0-r12, heuristic backtrace.
Written to run.log, <run.dir>/crash_reports.txt and ev("CRASH", ...).
Options: stop=1 stop the run at the first report (default 0: log and continue);
         max=N  cap on reports (default 200); dabt=0 silences data-abort (automap) reports.

Where asserts really go (found 2026-10-31; mocor_emu's ASSERT_TRAP 0x80a0b00a is
mid-instruction (a `bl` operand), so its [ASRT ] log has never fired in any run):
  0x80a0b07a  kernel assert entry `movs r3,#0; b.w LOG_CORE` (r0 expr, r1 file, r2 line).
              The emulator patches it to `bx lr`, so it never reaches LOG_CORE.
  0x80a0914c  LOG_CORE (expr,file,line,msg): PS/driver macros call it directly.
  0x80a09414  target of the mmi_app "assert" veneer 0x880a9be0 (ARM `ldr pc,[pc,#-4]`).
              Original body: `movs r3..r0,#0; b LOG_CORE` - it zeroes the args, so the
              mmi side reaches LOG_CORE with no text; also patched to `bx lr`. The caller's
              r0-r2 are still intact at entry, so they are reported when they look like strings.
Faults: undefined insn (on_invalid), unmapped fetch = prefetch abort and unmapped data
access = data abort (on_unmapped; the emulator auto-maps and continues), and the guest's
own UND/PABT/DABT vector handlers ([0x24]/[0x2c]/[0x30]) if the guest ever reaches them.
"""
import os
import struct
from unicorn import UC_HOOK_CODE, UcError
import unicorn.arm_const as A

CURRENT_THREAD = 0x81701f78          # _tx_thread_current_ptr
TCB_NAME = 0x28
KERNEL = (0x80a06000, 0x81600000)
MMI = (0x88000000, 0x88f00000)
FETCH_FAULTS = (21, 24)              # UC_MEM_FETCH_UNMAPPED / FETCH_PROT
_S = {}                              # plugin state (not on emu: checkpoints pickle emu attrs)


def _cstr(uc, a, n=200):
    try:
        b = bytes(uc.mem_read(a, n)).split(b"\0")[0]
    except (UcError, OverflowError):
        return None
    return b.decode("latin1") if len(b) >= 1 and all(32 <= c < 127 for c in b) else None


def _u32(uc, a):
    try:
        return struct.unpack("<I", bytes(uc.mem_read(a, 4)))[0]
    except (UcError, OverflowError):
        return None


def _in_code(v):
    return KERNEL[0] <= v < KERNEL[1] or MMI[0] <= v < MMI[1]


def _bl_before(uc, ret):
    """Describe the call insn just before Thumb return address `ret`, or None."""
    a = ret & ~1
    try:
        h0, h1 = struct.unpack("<HH", bytes(uc.mem_read(a - 4, 4)))
    except UcError:
        return None
    if (h0 & 0xF800) == 0xF000 and (h1 & 0xC000) == 0xC000:     # BL / BLX imm
        s, i10 = (h0 >> 10) & 1, h0 & 0x3FF
        j1, j2, i11 = (h1 >> 13) & 1, (h1 >> 11) & 1, h1 & 0x7FF
        i1, i2 = (~(j1 ^ s)) & 1, (~(j2 ^ s)) & 1
        off = (s << 24) | (i1 << 23) | (i2 << 22) | (i10 << 12) | (i11 << 1)
        if s:
            off -= 1 << 25
        if h1 & 0x1000:
            return f"bl {(a + off) & 0xFFFFFFFF:#x}"
        return f"blx {((a & ~3) + off) & 0xFFFFFFFF:#x} (arm)"
    if (h1 & 0xFF87) == 0x4780:                                 # blx rN
        return f"blx r{(h1 >> 3) & 15}"
    return None


def backtrace(uc, sp, n=0x400):
    out = []
    try:
        st = bytes(uc.mem_read(sp, n))
    except UcError:
        return out
    for i in range(0, len(st) - 3, 4):
        v = struct.unpack_from("<I", st, i)[0]
        if v & 1 and _in_code(v):
            d = _bl_before(uc, v)
            if d:
                out.append((i, v, d))
    return out


def thread_name(uc):
    t = _u32(uc, CURRENT_THREAD)
    if not t:
        return "none"
    p = _u32(uc, t + TCB_NAME)
    nm = _cstr(uc, p, 32) if p else None
    return f"{nm or '?'} (tcb {t:#x})"


def report(emu, kind, pc, **info):
    if _S.get("done", 0) >= _S["max"]:
        return
    uc, run = emu.mu, emu.run
    insn = emu.insn_total
    key = (info.get("file"), info.get("line"))
    if key[0] and _S.get("last") and _S["last"][0] == key and insn - _S["last"][1] < 64:
        return                                                  # same assert via two entries
    _S["last"] = (key, insn)
    _S["done"] = _S.get("done", 0) + 1
    r = [uc.reg_read(getattr(A, f"UC_ARM_REG_R{i}")) for i in range(13)]
    sp, lr = uc.reg_read(A.UC_ARM_REG_SP), uc.reg_read(A.UC_ARM_REG_LR)
    cpsr = uc.reg_read(A.UC_ARM_REG_CPSR)
    mode = {0x10: "usr", 0x11: "fiq", 0x12: "irq", 0x13: "svc", 0x17: "abt",
            0x1b: "und", 0x1f: "sys"}.get(cpsr & 0x1f, "?")
    th = thread_name(uc)
    L = [f"=== CRASH #{_S['done']} {kind} insn={insn} t={insn / 2e8:.3f}s thread={th}",
         "  " + " ".join(f"{k}={v!r}" for k, v in info.items() if v is not None),
         f"  pc={pc:#010x} lr={lr:#010x} sp={sp:#010x} cpsr={cpsr:#010x} "
         f"({mode}{',thumb' if cpsr & 0x20 else ''})",
         "  " + " ".join(f"r{i}={r[i]:08x}" for i in range(13))]
    bt = backtrace(uc, sp)
    L.append(f"  backtrace (heuristic, {len(bt)} frames; lr={lr:#x}):")
    for off, v, d in bt[:24]:
        L.append(f"    [sp+{off:#05x}] {v:#010x}  after {d}")
    for ln in L:
        run.log("[CRASH] " + ln)
    with open(_S["path"], "a", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n\n")
    run.ev("CRASH", kind=kind, pc=hex(pc), lr=hex(lr), sp=hex(sp), thread=th, insn=insn,
           bt=[hex(v) for _, v, _ in bt[:24]], **{k: v for k, v in info.items() if v is not None})
    if _S["stop"]:
        emu.stop_reason = "crash"
        emu.stop_detail = f"{kind} {info.get('file')}:{info.get('line')} pc={pc:#x}"
        uc.emu_stop()


def pre(run, opts):
    """Class-level wraps of the two fault callbacks (hook_add binds the method when
    MocorEmu is built, so this must run first; plat_run calls it)."""
    from mocor_emu import MocorEmu
    if getattr(MocorEmu, "_plat_crash_wrapped", False):
        return
    MocorEmu._plat_crash_wrapped = True
    o_inv, o_unm = MocorEmu.on_invalid, MocorEmu.on_unmapped

    def on_invalid(self, uc, ud):
        if _S:
            pc = uc.reg_read(A.UC_ARM_REG_PC)
            try:
                code = bytes(uc.mem_read(pc & ~1, 4)).hex()
            except UcError:
                code = ""
            report(self, "UNDEF", pc, bytes=code)
        return o_inv(self, uc, ud)

    def on_unmapped(self, uc, access, address, size, value, ud):
        if _S:
            pc = uc.reg_read(A.UC_ARM_REG_PC)
            if int(access) in FETCH_FAULTS:
                report(self, "PREFETCH_ABORT", pc, addr=hex(address))
            elif _S["dabt"]:
                report(self, "DATA_ABORT", pc, addr=hex(address),
                       access="write" if int(access) in (17, 20, 22) else "read")
        return o_unm(self, uc, access, address, size, value, ud)
    MocorEmu.on_invalid, MocorEmu.on_unmapped = on_invalid, on_unmapped


def install(emu, run, opts):
    _S.clear()
    _S.update(stop=opts.get("stop", "0") == "1", max=int(opts.get("max", 200)),
              dabt=opts.get("dabt", "1") != "0", path=os.path.join(run.dir, "crash_reports.txt"))
    uc = emu.mu

    def args4(uc):
        return [uc.reg_read(getattr(A, f"UC_ARM_REG_R{i}")) for i in range(4)]

    def kernel_assert(uc, a, sz, ud):                            # 0x80a0b07a
        r = args4(uc)
        report(emu, "ASSERT", a, expr=_cstr(uc, r[0]), file=_cstr(uc, r[1]), line=r[2],
               msg=_cstr(uc, r[3]), caller=hex(uc.reg_read(A.UC_ARM_REG_LR)))

    def log_core(uc, a, sz, ud):                                 # 0x80a0914c
        r = args4(uc)
        report(emu, "FATAL_ASSERT", a, expr=_cstr(uc, r[0]), file=_cstr(uc, r[1]), line=r[2],
               msg=_cstr(uc, r[3]), caller=hex(uc.reg_read(A.UC_ARM_REG_LR)))

    def mmi_assert(uc, a, sz, ud):                               # 0x80a09414 via 0x880a9be0
        r = args4(uc)
        lr = uc.reg_read(A.UC_ARM_REG_LR)
        e, f = _cstr(uc, r[0]), _cstr(uc, r[1])
        report(emu, "ASSERT_MMI" if MMI[0] <= lr < MMI[1] else "ASSERT_VENEER", a,
               expr=e, file=f, line=r[2] if f else None, caller=hex(lr))

    for addr, fn in ((0x80a0b07a, kernel_assert), (0x80a0914c, log_core), (0x80a09414, mmi_assert)):
        uc.hook_add(UC_HOOK_CODE, fn, begin=addr, end=addr + 1)

    # guest exception vectors: literal pool at 0x20.. (und 0x24, pabt 0x2c, dabt 0x30)
    for vec, kind in ((0x24, "VEC_UND"), (0x2c, "VEC_PABT"), (0x30, "VEC_DABT")):
        h = _u32(uc, vec)
        if h and h >= 0x1000:
            def vh(uc, a, sz, ud, kind=kind):
                report(emu, kind, a, lr=hex(uc.reg_read(A.UC_ARM_REG_LR)))
            uc.hook_add(UC_HOOK_CODE, vh, begin=h & ~1, end=(h & ~1) + 1)
    run.log(f"[CRASH] reporter armed stop={_S['stop']} -> {_S['path']}")
