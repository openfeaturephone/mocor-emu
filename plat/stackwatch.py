"""stackwatch.py - track the lowest SP the current thread reaches (per thread name) and
report it against the ThreadX TCB stack bounds. opts: after=<insn> (start tracking)."""
from unicorn import UC_HOOK_BLOCK
from unicorn.arm_const import UC_ARM_REG_SP

TX_CURRENT = 0x81701f78


def _rd(uc, a):
    return int.from_bytes(uc.mem_read(a, 4), "little")


def install(emu, run, opts):
    after = int(float(opts.get("after", 0)))
    lo = {}

    def blk(uc, addr, size, ud):
        if emu.insn_total < after:
            return
        tcb = _rd(uc, TX_CURRENT)
        if not tcb:
            return
        sp = uc.reg_read(UC_ARM_REG_SP)
        cur = lo.get(tcb)
        if cur is None or sp < cur[0]:
            lo[tcb] = (sp, addr, emu.insn_total)
    emu.mu.hook_add(UC_HOOK_BLOCK, blk, begin=0x88000000, end=0x8f000000)
    emu._stackwatch = lo


def finish(emu, run, opts):
    uc = emu.mu
    for tcb, (sp, addr, n) in emu._stackwatch.items():
        name = bytes(uc.mem_read(_rd(uc, tcb + 0x28), 24)).split(b"\0")[0].decode("latin1")
        start, end = _rd(uc, tcb + 0xc), _rd(uc, tcb + 0x10)
        run.log(f"[STACK] {name} stack {start:#x}-{end:#x} ({end - start + 1} B) "
                f"min sp {sp:#x} = {sp - start} B free, at pc {addr:#x} insn {n}")
