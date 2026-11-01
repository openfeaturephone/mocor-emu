"""plat.timeline -- when does each hook address run, with a deep call stack (timing studies).

  plat_run.py TAG --plugin "timeline:addrs=0x88425b64+0x883f989e,max=3,depth=0x1800"

Block hooks (not per-insn) at each address (function entries only: a block hook fires only when
a translated block STARTS there). Logs `[TLINE]` rows: insn count, virtual ms (insn/200k), r0-r3,
lr and every stack word in the next `depth` bytes that looks like a Thumb return address in
kernel/mmi code (heuristic, includes stale words). First `max` hits per address.
"""
from unicorn import UC_HOOK_BLOCK, UcError
import unicorn.arm_const as A

IPMS = 200_000                    # insns per virtual ms (WTL_TS_PER_INSN model)


def install(emu, run, opts):
    addrs = [int(x, 0) for x in opts.get("addrs", "").split("+") if x]
    mx = int(opts.get("max", "3"), 0)
    depth = int(opts.get("depth", "0x800"), 0)
    cnt = {}

    def cb(uc, a, size, ud):
        n = cnt[a] = cnt.get(a, 0) + 1
        if n > mx:
            return
        r = [uc.reg_read(x) for x in (A.UC_ARM_REG_R0, A.UC_ARM_REG_R1, A.UC_ARM_REG_R2, A.UC_ARM_REG_R3,
                                      A.UC_ARM_REG_LR, A.UC_ARM_REG_SP)]
        try:
            st = bytes(uc.mem_read(r[5], depth))
        except UcError:
            st = b""
        ws = [int.from_bytes(st[i:i + 4], "little") for i in range(0, len(st) - 3, 4)]
        cs = [hex(w) for w in ws if (0x80a00000 <= w < 0x82000000 or 0x88000000 <= w < 0x89000000) and w & 1]
        d0 = ""
        if 0x80000000 <= r[0] < 0x90000000:
            try:
                d0 = " [r0]=" + bytes(uc.mem_read(r[0], 16)).hex(" ", 4)
            except UcError:
                pass
        run.log(f"[TLINE] {a:#x} #{n} insn={emu.insn_total} ms={emu.insn_total / IPMS:.1f} "
                f"r0={r[0]:#x} r1={r[1]:#x} r2={r[2]:#x} r3={r[3]:#x} lr={r[4]:#x}{d0}")
        run.log(f"[TLINE]   stack: {' '.join(cs)}")
    for a in addrs:
        emu.mu.hook_add(UC_HOOK_BLOCK, cb, begin=a, end=a)
