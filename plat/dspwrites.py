"""plat.dspwrites -- log every AP write that a DSP / CM4 can see, with the code that made it.

  plat_run.py TAG --plugin "dspwrites:stop_after=0x400000000"

Ranges (UC_HOOK_MEM_WRITE): register space 0x20000000-0x7fffffff and 0xd0000000-0xefffffff
(PMU, AON, ADI, whale, XDSP windows, INTCs), on-chip share RAM 0x0-0x12c00 and its AON mirror
0x20000000-0x20012c00 (inside the first range), and the DSP-visible DRAM 0x80000000-0x807fffff
(CM4 code, GSM window/image, LTE window/handshake/image/calibration, slots, DlDataMem).

Output runs/<tag>/dspwrites.jsonl, one record per run of writes: consecutive writes by the same PC
to adjacent addresses are merged ({"i": first insn, "pc", "lr", "a": start, "n": bytes, "w": count,
"v": first value (hex) and, for single writes, the value}). Register-space writes are never merged.
"""
import json
import os

import unicorn.arm_const as A
from unicorn import UC_HOOK_MEM_WRITE

RANGES = [(0x00000000, 0x00012FFF), (0x20000000, 0x7FFFFFFF), (0x80000000, 0x807FFFFF),
          (0xD0000000, 0xEFFFFFFF)]


def install(emu, run, opts):
    path = os.path.join(run.dir, "dspwrites.jsonl")
    out = open(path, "w")
    stop_after = int(opts.get("stop_after", "0"), 0)
    cur = {}                                   # the open merged run (RAM only)

    def flush():
        if cur:
            out.write(json.dumps(cur) + "\n")
            cur.clear()

    def cb(uc, access, addr, size, value, ud):
        pc = uc.reg_read(A.UC_ARM_REG_PC)
        is_reg = not (addr < 0x13000 or 0x20000000 <= addr < 0x20013000 or 0x80000000 <= addr < 0x80800000)
        v = value & ((1 << (8 * size)) - 1)
        if not is_reg and cur and cur["pc"] == pc and addr == cur["a"] + cur["n"]:
            cur["n"] += size
            cur["w"] += 1
            return
        flush()
        rec = {"i": emu.insn_total, "pc": pc, "lr": uc.reg_read(A.UC_ARM_REG_LR), "a": addr,
               "n": size, "w": 1, "v": f"{v:x}"}
        if is_reg:
            out.write(json.dumps(rec) + "\n")
        else:
            cur.update(rec)
        if stop_after and emu.insn_total > stop_after:
            flush()
            out.flush()
            uc.emu_stop()

    for lo, hi in RANGES:
        emu.mu.hook_add(UC_HOOK_MEM_WRITE, cb, begin=lo, end=hi)
    run.log(f"[DSPW ] logging AP writes to {', '.join(f'{lo:#x}-{hi:#x}' for lo, hi in RANGES)} -> {path}")

    old = getattr(run, "close", None)
    if callable(old):
        def close(*a, **k):
            flush()
            out.close()
            return old(*a, **k)
        run.close = close
