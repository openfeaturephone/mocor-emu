"""plat.mmu -- flag the accesses the phone's MMU would fault on (the emulator runs MMU-off).

  plat_run.py TAG ... --plugin "mmu:after=5.53G,thread=P_APP,stop=1"
  app_test.py usbprobe --plugin "mmu:after=5.53G"

The guest's own tables are walked at install: TTBR0/TTBR1/TTBCR/DACR/SCTLR come from the
unicorn CPU context (checkpoints keep it: mu.context_save holds cp15), so no hard-coding is
needed; `ttb=0x81600000` overrides. Found (IDLE2_5500M): TTBR0 0x81600049, TTBCR 0, DACR
0x55555555 (all client), SCTLR 0xc5107e = M (cleared by MMU_GUARD) + **A (alignment check)**
+ C + I, TRE=AFE=0. Region table: docs/hardware-models.md, "MMU".

mmi_app 0x88000000..+0xF00000 is demand paged (mmu_vm.c, fault handler 0x80a0cb82): L2
entries stay "fault" in the emulator, so they are taken as what the pager installs:
0x811b6c8c type 2 -> desc = pa|0x27e = small page, AP[2:0]=111 (read-only, all modes),
XN=0, TEX1 C B. So the paged image is readable + executable, never writable.

Checks (opts `checks=wxa` = the default):
  w  write to a page the phone maps read-only or not at all: mem_protect + WRITE_PROT hook
  x  block fetched from an XN or unmapped page (block hook)        -> prefetch abort
  a  every load/store executed in `code=lo-hi;..` (default the heap 0x82000000-0x83000000
     where apps load, + mmi_app 0x88000000-0x88f00000) is decoded with capstone (IT-aware,
     per block) and its address computed from the registers: unaligned while SCTLR.A=1
     (`align=0|1` overrides), read of unmapped/no-access VA, write to read-only (if no w).
     Code + block hooks only; costs a Python call per insn in range.
  R, W  (opt-in, debugging only) global UC_HOOK_MEM_READ / _WRITE. They PERTURB the guest
     (unicorn IT-block bug, see _hooks): trust only the first report, with stop=1.
Window: hooks are added at install (see _hooks); reports only for after <= insn < until;
`thread=NAME` reports only while that ThreadX thread is current (checked per report).
`ignore=lo-hi;lo-hi` VA ranges never reported (default: emulator scratch 0x8b000000-0x90000000).
Report = crash.py format (thread, regs, heuristic backtrace) -> run.log + mmu_reports.txt;
each (kind, pc) is reported once, totals at finish. stop=1 stops at the first one.
"""
import os
import struct
from unicorn import (UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_BLOCK, UC_HOOK_MEM_WRITE_PROT, UC_HOOK_CODE,
                     UC_PROT_ALL, UC_PROT_READ, UC_PROT_EXEC, UcError)
import unicorn.arm_const as A
from . import crash, keypad

CP = lambda crn, crm, op1, op2: (15, 0, 0, crn, crm, op1, op2)
PAGER = (0x88000000, 0x88F00000)
PAGER_DESC = 0x27E                       # small page, AP=111 RO, XN=0 (0x811b6c8c type 2)
F_MAP, F_PR, F_PW, F_UR, F_UW, F_X = 1, 2, 4, 8, 16, 32
# AP[2:0] (AFE=0) -> priv R/W, user R/W
AP_PERM = {0: 0, 1: F_PR | F_PW, 2: F_PR | F_PW | F_UR, 3: F_PR | F_PW | F_UR | F_UW,
           4: 0, 5: F_PR, 6: F_PR | F_UR, 7: F_PR | F_UR}
_S = {}


def _cp(uc, reg):
    try:
        return uc.reg_read(A.UC_ARM_REG_CP_REG, reg)
    except (UcError, Exception):
        return 0


def _flags(ap, xn, dom, dacr):
    d = (dacr >> (2 * dom)) & 3
    if d == 0:
        return F_MAP                     # domain no-access: every access faults
    f = F_MAP | (F_PR | F_PW | F_UR | F_UW if d == 3 else AP_PERM[ap])
    return f | (0 if xn else F_X)


def walk(uc, ttb=None):
    """-> (flags bytearray per 4 KB page, list of region rows, cp15 dict)."""
    regs = {n: _cp(uc, CP(*r)) for n, r in (("SCTLR", (1, 0, 0, 0)), ("TTBR0", (2, 0, 0, 0)),
            ("TTBR1", (2, 0, 0, 1)), ("TTBCR", (2, 0, 0, 2)), ("DACR", (3, 0, 0, 0)))}
    n = regs["TTBCR"] & 7
    base0 = ttb or (regs["TTBR0"] & ~((1 << (14 - n)) - 1)) or 0x81600000
    base1 = regs["TTBR1"] & ~0x3FFF
    dacr = regs["DACR"]
    fl = bytearray(1 << 20)
    rows = []
    rd = lambda a: struct.unpack("<I", bytes(uc.mem_read(a, 4)))[0]
    for i in range(4096):
        tb = base1 if n and i >= (4096 >> n) and base1 else base0
        d = rd(tb + 4 * (i if tb == base0 else i))
        va = i << 20
        t = d & 3
        if t == 2:                                        # section / supersection
            ap = ((d >> 15) & 1) << 2 | (d >> 10) & 3
            f = _flags(ap, (d >> 4) & 1, (d >> 5) & 15, dacr)
            fl[i << 8:(i + 1) << 8] = bytes([f]) * 256
            rows.append((va, va + 0x100000, f"sect AP{ap} XN{(d >> 4) & 1} D{(d >> 5) & 15} "
                         f"TEX{(d >> 12) & 7}C{(d >> 3) & 1}B{(d >> 2) & 1}", (d & 0xFFF00000) - va))
        elif t == 1:                                      # coarse page table
            dom, l2 = (d >> 5) & 15, d & ~0x3FF
            for j in range(256):
                e = rd(l2 + 4 * j)
                pva = va | j << 12
                if e & 3 == 0 and PAGER[0] <= pva < PAGER[1]:
                    e, tag = PAGER_DESC | pva, "pager"
                else:
                    tag = "page"
                if e & 3 == 0:
                    f, desc = 0, "fault"
                elif e & 2:
                    ap = ((e >> 9) & 1) << 2 | (e >> 4) & 3
                    f, desc = _flags(ap, e & 1, dom, dacr), f"{tag} AP{ap} XN{e & 1} D{dom}"
                else:
                    ap = ((e >> 9) & 1) << 2 | (e >> 4) & 3
                    f, desc = _flags(ap, (e >> 15) & 1, dom, dacr), f"large AP{ap} XN{(e >> 15) & 1} D{dom}"
                fl[(i << 8) | j] = f
                rows.append((pva, pva + 0x1000, desc, 0 if not f else (e & 0xFFFFF000) - pva))
        else:
            rows.append((va, va + 0x100000, "fault", 0))
    merged = []                                           # coalesce equal neighbours
    for r in rows:
        if merged and merged[-1][1] == r[0] and merged[-1][2:] == r[2:]:
            merged[-1] = (merged[-1][0], r[1]) + r[2:]
        else:
            merged.append(r)
    regs["ttb"] = base0
    return fl, merged, regs


def _ignored(a):
    return any(lo <= a < hi for lo, hi in _S["ignore"])


def _report(emu, kind, pc, addr, **info):
    S = _S
    key = (kind, pc)
    if _ignored(addr) or _ignored(pc):
        return
    S["counts"][kind] = S["counts"].get(kind, 0) + 1
    if key in S["seen"] or key in S["other"]:
        return
    uc = emu.mu
    th = crash.thread_name(uc)
    if S["thread"] and S["thread"] not in th:
        S["other"].add(key)                               # (kind, pc) seen in another thread
        return
    S["seen"].add(key)
    if len(S["seen"]) > S["max"]:
        return
    r = [uc.reg_read(getattr(A, f"UC_ARM_REG_R{i}")) for i in range(13)]
    sp, lr, cpsr = (uc.reg_read(x) for x in (A.UC_ARM_REG_SP, A.UC_ARM_REG_LR, A.UC_ARM_REG_CPSR))
    pf = S["fl"][addr >> 12]
    L = [f"=== MMU #{len(S['seen'])} {kind} addr={addr:#010x} insn={emu.insn_total} "
         f"t={emu.insn_total / 2e8:.3f}s thread={th}",
         "  " + " ".join(f"{k}={v}" for k, v in info.items()) + f" page_flags={_fdesc(pf)}"
         + f" region={region_of(addr)}",
         f"  pc={pc:#010x} lr={lr:#010x} sp={sp:#010x} cpsr={cpsr:#010x} mode={cpsr & 0x1f:#x}",
         "  " + " ".join(f"r{i}={r[i]:08x}" for i in range(13))]
    bt = crash.backtrace(uc, sp)
    L.append(f"  backtrace (heuristic, {len(bt)} frames):")
    for off, v, d in bt[:16]:
        L.append(f"    [sp+{off:#05x}] {v:#010x}  after {d}")
    for ln in L:
        emu.run.log("[MMU  ] " + ln)
    with open(S["path"], "a", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n\n")
    emu.run.ev("MMU", kind=kind, pc=hex(pc), addr=hex(addr), lr=hex(lr), thread=th,
               insn=emu.insn_total, bt=[hex(v) for _, v, _ in bt[:16]], **info)
    if S["stop"]:
        emu.stop_reason = "mmu"
        emu.stop_detail = f"{kind} addr={addr:#x} pc={pc:#x}"
        uc.emu_stop()


def _fdesc(f):
    if not f & F_MAP:
        return "unmapped"
    return "".join(c for b, c in ((F_PR, "R"), (F_PW, "W"), (F_UR, "r"), (F_UW, "w"), (F_X, "x")) if f & b) or "none"


def region_of(a):
    for lo, hi, desc, off in _S.get("rows", ()):
        if lo <= a < hi:
            return f"{lo:#x}-{hi - 1:#x}:{desc}"
    return "?"


def _user(uc):
    return uc.reg_read(A.UC_ARM_REG_CPSR) & 0x1F == 0x10


def _on_write(uc, access, addr, size, value, emu):     # checks=W only (perturbs, see _hooks)
    if not _live(emu):
        return
    f = _S["fl"][addr >> 12]
    if not f & F_UW and not (f & F_PW and not _user(uc)):
        _report(emu, "WRITE_FAULT" if f & F_MAP else "WRITE_UNMAPPED", uc.reg_read(A.UC_ARM_REG_PC),
                addr, size=size, value=f"{value & 0xFFFFFFFF:#x}")
    if _S["align"] and size in (2, 4, 8) and addr & (min(size, 4) - 1):
        _report(emu, "ALIGN_WRITE", uc.reg_read(A.UC_ARM_REG_PC), addr, size=size)


def _on_prot(uc, access, addr, size, value, emu):        # checks=w: write to a protected page
    if _live(emu):
        f = _S["fl"][addr >> 12]
        _report(emu, "WRITE_FAULT" if f & F_MAP else "WRITE_UNMAPPED", uc.reg_read(A.UC_ARM_REG_PC),
                addr, size=size, value=f"{value & 0xFFFFFFFF:#x}", note="later execution may diverge")
    try:
        uc.mem_protect(addr & ~0xFFF, 0x1000, UC_PROT_ALL)   # let the store retry and go through
    except UcError:
        return False
    _S["unprot"] += 1
    return True


def _protect(emu):
    """mem_protect (read+exec) every unicorn-mapped page the phone cannot write (privileged view),
    except `ignore` ranges. -> number of ranges."""
    uc, fl, n = emu.mu, _S["fl"], 0
    for b, e, perm in list(uc.mem_regions()):
        p = b >> 12
        while p <= e >> 12:
            if fl[p] & F_PW or _ignored(p << 12):
                p += 1
                continue
            q = p
            while q <= e >> 12 and not fl[q] & F_PW and not _ignored(q << 12):
                q += 1
            try:
                uc.mem_protect(p << 12, (q - p) << 12, UC_PROT_READ | UC_PROT_EXEC)
                n += 1
                _S["prot"].append((p << 12, q << 12))
            except UcError as ex:
                emu.run.log(f"[MMU  ] mem_protect {p << 12:#x}-{q << 12:#x} failed: {ex}")
            p = q
    return n


def _on_read(uc, access, addr, size, value, emu):
    if not _live(emu):
        return
    f = _S["fl"][addr >> 12]
    if not f & F_UR and not (f & F_PR and not _user(uc)):
        _report(emu, "READ_FAULT" if f & F_MAP else "READ_UNMAPPED", uc.reg_read(A.UC_ARM_REG_PC),
                addr, size=size)
    if _S["align"] and size in (2, 4, 8) and addr & (min(size, 4) - 1):
        _report(emu, "ALIGN_READ", uc.reg_read(A.UC_ARM_REG_PC), addr, size=size)


def _on_block(uc, addr, size, emu):
    if not _live(emu):
        return
    if not _S["fl"][addr >> 12] & F_X:
        _report(emu, "EXEC_XN" if _S["fl"][addr >> 12] & F_MAP else "EXEC_UNMAPPED", addr, addr, size=size)


# ---- checks=a: decode every load/store in the `code` ranges (code + block hooks: safe) ----
_W4 = ("ldr", "str", "ldrex", "strex", "ldrt", "strt", "vldr", "vstr", "ldrd", "strd")
_W2 = ("ldrh", "strh", "ldrsh", "ldrht", "strht", "ldrsht", "ldrexh", "strexh")
_MULTI = ("ldm", "stm", "push", "pop", "vldm", "vstm", "vpush", "vpop")


def _cs():
    if "cs" not in _S:
        import capstone
        from capstone import arm as CA
        md = {}
        for t, m in ((1, capstone.CS_MODE_THUMB), (0, capstone.CS_MODE_ARM)):
            md[t] = capstone.Cs(capstone.CS_ARCH_ARM, m)
            md[t].detail = True
        regs = {f"r{i}": getattr(A, f"UC_ARM_REG_R{i}") for i in range(13)}
        regs.update(sb=A.UC_ARM_REG_R9, sl=A.UC_ARM_REG_R10, fp=A.UC_ARM_REG_R11, ip=A.UC_ARM_REG_R12,
                    sp=A.UC_ARM_REG_SP, lr=A.UC_ARM_REG_LR, pc=A.UC_ARM_REG_PC)
        _S["cs"] = (md, CA, regs)
    return _S["cs"]


def _decode_block(uc, addr, size):
    md, CA, regs = _cs()
    thumb = 1 if uc.reg_read(A.UC_ARM_REG_CPSR) & 0x20 else 0
    try:
        code = bytes(uc.mem_read(addr, size))
    except UcError:
        return
    dec = _S["dec"]
    for i in md[thumb].disasm(code, addr):
        m = i.mnemonic.split(".")[0]
        if i.cc != CA.ARM_CC_AL and len(m) > 2 and m not in ("pop", "push", "vpop"):
            m = m[:-2] if m[-2:] in ("eq", "ne", "hs", "cs", "lo", "cc", "mi", "pl", "vs", "vc",
                                     "hi", "ls", "ge", "lt", "gt", "le") else m
        need = 4 if m.startswith(_MULTI) or m in _W4 else 2 if m in _W2 else \
            1 if m in ("ldrb", "strb", "ldrsb", "ldrexb", "strexb") else 0
        st = m.startswith(("st", "push", "vst", "vpush"))
        if not need:
            dec[i.address] = None
            continue
        name = lambda r: md[thumb].reg_name(r)
        if m.startswith(_MULTI):
            base = "sp" if m in ("push", "pop", "vpush", "vpop") else name(i.operands[0].reg)
            dec[i.address] = (need, regs[base], 0, (0, 0), -4 if m in ("push", "vpush") or
                              m.endswith("db") else 0, i.cc, i.mnemonic, thumb, st)
            continue
        mem = [o for o in i.operands if o.type == CA.ARM_OP_MEM]
        if not mem:
            dec[i.address] = None
            continue
        o = mem[0]
        idx = regs.get(name(o.mem.index)) if o.mem.index else 0
        sh = o.shift.value if o.mem.index else 0
        disp = 0 if i.post_index else o.mem.disp
        dec[i.address] = (need, regs[name(o.mem.base)], (-1 if o.subtracted else 1) * (idx and 1),
                          (idx, sh), disp, i.cc, i.mnemonic, thumb, st)


def _cond(cpsr, cc, CA):
    n, z, c, v = (cpsr >> 31) & 1, (cpsr >> 30) & 1, (cpsr >> 29) & 1, (cpsr >> 28) & 1
    return {CA.ARM_CC_EQ: z, CA.ARM_CC_NE: not z, CA.ARM_CC_HS: c, CA.ARM_CC_LO: not c,
            CA.ARM_CC_MI: n, CA.ARM_CC_PL: not n, CA.ARM_CC_VS: v, CA.ARM_CC_VC: not v,
            CA.ARM_CC_HI: c and not z, CA.ARM_CC_LS: not c or z, CA.ARM_CC_GE: n == v,
            CA.ARM_CC_LT: n != v, CA.ARM_CC_GT: not z and n == v, CA.ARM_CC_LE: z or n != v
            }.get(cc, True)


def _on_ablock(uc, addr, size, emu):
    if addr not in _S["dec"] and _live(emu):
        _decode_block(uc, addr, size)


def _on_acode(uc, addr, size, emu):
    d = _S["dec"].get(addr)
    if not d or not _live(emu):
        return
    need, base, sign, (idx, sh), disp, cc, mn, thumb, st = d
    _, CA, _ = _S["cs"]
    if cc != CA.ARM_CC_AL and not _cond(uc.reg_read(A.UC_ARM_REG_CPSR), cc, CA):
        return
    b = ((addr + (4 if thumb else 8)) & ~3) if base == A.UC_ARM_REG_PC else uc.reg_read(base)
    ea = (b + disp + (sign * (uc.reg_read(idx) << sh) if sign else 0)) & 0xFFFFFFFF
    if ea & (need - 1) and _S["align"]:
        _report(emu, "ALIGN_WRITE" if st else "ALIGN_READ", addr, ea, op=mn.replace(" ", "_"), need=need)
    f = _S["fl"][ea >> 12]
    ok = (F_PW | F_UW) if st else (F_PR | F_UR)
    if not f & ok or (_user(uc) and not f & ok & (F_UW | F_UR)):
        if st and "w" in _S["checks"]:
            return                                        # the mem_protect path reports it
        _report(emu, ("WRITE_" if st else "READ_") + ("FAULT" if f & F_MAP else "UNMAPPED"),
                addr, ea, op=mn.replace(" ", "_"))


def _hooks(emu):
    """Add the hooks once, at install. Two unicorn 2.1.4 traps found 2026-10-31:
    - Hooks added between chunks of a running emulator (tried first, from _gic_step) changed
      guest behaviour (misaligned heap pointers, an UNDEF at 0x10a4), so the window is an
      insn_total compare in each callback instead.
    - A UC_HOOK_MEM_WRITE covering the store address breaks Thumb IT blocks: after
      `it hs; strhs ..; it eq; bxeq lr` (the stock memset tail 0x810a0884) the IT state leaks
      to the return site and the caller's next instruction is skipped (memset callers then
      return dst+len: misaligned "heap" pointers). Repro: docs/gotchas.md.
      A write-protect fault on such a store misbehaves the same way. Read, block and code
      hooks are fine. So writes are checked by mem_protect (no cost, nothing changes until
      the first real violation) and the write hook is opt-in (checks=W)."""
    uc, c = emu.mu, _S["checks"]
    raw = getattr(emu, "_raw_hook_add", uc.hook_add)        # bypass the MMIO-native rerouting
    if "w" in c:
        emu.run.log(f"[MMU  ] write-protected {_protect(emu)} ranges")
        _S["h"].append(raw(UC_HOOK_MEM_WRITE_PROT, _on_prot, emu, 1, 0))
    if "W" in c:
        _S["h"].append(raw(UC_HOOK_MEM_WRITE, _on_write, emu, 1, 0))
    if "R" in c:
        _S["h"].append(raw(UC_HOOK_MEM_READ, _on_read, emu, 1, 0))
    if "x" in c:
        _S["h"].append(raw(UC_HOOK_BLOCK, _on_block, emu, 1, 0))
    if "a" in c:
        for lo, hi in _S["code"]:
            _S["h"].append(raw(UC_HOOK_BLOCK, _on_ablock, emu, lo, hi - 1))
            _S["h"].append(raw(UC_HOOK_CODE, _on_acode, emu, lo, hi - 1))


def _live(emu):
    t = emu.insn_total
    return t >= _S["after"] and (_S["until"] is None or t < _S["until"])


def _ranges(spec):
    return [tuple(int(x, 0) for x in r.split("-")) for r in spec.replace("|", ";").split(";") if r]


def install(emu, run, opts):
    _S.clear()
    ttb = int(opts["ttb"], 0) if opts.get("ttb") else None
    fl, rows, regs = walk(emu.mu, ttb)
    ign = opts.get("ignore", "0x8b000000-0x90000000")
    _S.update(fl=fl, rows=rows, seen=set(), other=set(), counts={}, h=[], prot=[], unprot=0, dec={},
              code=_ranges(opts.get("code", "0x82000000-0x83000000;0x88000000-0x88f00000")), max=int(opts.get("max", 50)),
              stop=opts.get("stop", "0") == "1", thread=opts.get("thread", ""),
              checks=opts.get("checks", "wxa"),
              ignore=_ranges(ign),
              after=keypad.parse_time(opts["after"]) if opts.get("after") else 0,
              until=keypad.parse_time(opts["until"]) if opts.get("until") else None,
              path=os.path.join(run.dir, "mmu_reports.txt"))
    _S["align"] = bool(regs["SCTLR"] & 2) if opts.get("align") is None else opts["align"] == "1"
    run.log("[MMU  ] cp15 " + " ".join(f"{k}={v:#x}" for k, v in regs.items())
            + f" align_check={_S['align']}")
    with open(os.path.join(run.dir, "mmu_regions.txt"), "w") as f:
        for lo, hi, desc, off in rows:
            f.write(f"{lo:#010x}-{hi - 1:#010x} {desc}" + (f" pa_off={off:#x}" if off else "") + "\n")
    _hooks(emu)
    run.log(f"[MMU  ] {len(rows)} regions -> mmu_regions.txt; after={_S['after']} until={_S['until']} "
            f"thread={_S['thread'] or '*'} -> {_S['path']}")


def finish(emu, run, opts):
    run.log(f"[MMU  ] totals {_S.get('counts')} unique={len(_S.get('seen', ()))} "
            f"pages_unprotected={_S.get('unprot')}")
