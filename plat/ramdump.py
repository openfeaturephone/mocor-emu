"""plat.ramdump -- at each LCDC frame start, dump layer registers + kernel/GUI RAM windows to <run.dir>/rd/f<n>.npz
  --plugin ramdump[:every=1]   (analysis helper for screenshot-from-RAM work)"""
import os
import struct
import numpy as np
from . import fb

WIN = [(0x817ce000, 0x2000), (0x817af000, 0x2000), (0x818fcf00, 0x700), (0x818ac600, 0x2a00)]
_S = {}


def pre(run, opts):
    from mocor_emu import MocorEmu
    if getattr(MocorEmu, "_plat_rd_wrapped", False):
        return
    MocorEmu._plat_rd_wrapped = True
    orig = MocorEmu._lcdc_write

    def w(self, uc, a, value):
        start = (a == fb.LCDC and (value & 8) and not (self._lcdc_sync(uc)["ctrl"] & 8))
        if _S and _S.get('rdw') and fb.LCDC <= a < fb.LCDC + 0x100 and (a & 3) == 0 and (a - fb.LCDC) in (0, 0x24, 0x54, 0x84, 0xb4, 0xe4, 0x20, 0x50, 0xe0):
            from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP
            sp = uc.reg_read(UC_ARM_REG_SP)
            st = struct.unpack("<48I", bytes(uc.mem_read(sp, 192)))
            cs = [hex(x) for x in st if 0x80a05e00 <= x < 0x80f00000 or 0x88000000 <= x < 0x88400000 or 0x814c0000 <= x < 0x81500000]
            self.run.log("[RDW  ] w %#x=%#x pc=%#x lr=%#x stack=%s" % (a, value, uc.reg_read(UC_ARM_REG_PC), uc.reg_read(UC_ARM_REG_LR), " ".join(cs[:14])))
        orig(self, uc, a, value)
        if start and _S:
            dump(self, value)
    MocorEmu._lcdc_write = w


def dump(emu, ctrl):
    n = emu.lcdc["frames"]
    ls = fb.layers(emu)
    d = {"ctrl": np.array([ctrl]), "insn": np.array([emu.insn_total])}
    d["regs"] = np.frombuffer(bytes(emu.mu.mem_read(fb.LCDC, 0x100)), np.uint8)
    for a, l in WIN:
        d[f"w{a:x}"] = np.frombuffer(bytes(emu.mu.mem_read(a, l)), np.uint8)
    for L in ls:
        if L["en"]:
            d["buf_" + L["name"]] = np.frombuffer(bytes(emu.mu.mem_read(L["addr"], max(L["pitch"], L["w"]) * L["h"] * 4)), np.uint8)
    np.savez_compressed(os.path.join(_S["dir"], f"f{n:04d}.npz"), **d)
    if _S.get("cmp") and not (ctrl & 0x10):
        for L in ls:
            L["alpha"] = fb._reg(emu, {"IMG": 0, "OSD1": 0x38, "OSD2": 0x68, "OSD3": 0x98, "OSD4": 0xb0 + 0x18}[L["name"]]) & 255
        _, _, ref, _ = fb.compose(emu, ls)
        if ref.shape[0] == 320 and ref.shape[1] == 240:
            try:
                cmp_ram(emu, emu.run, "f%d" % n, ref)
            except Exception as e:
                emu.run.log("[RDV  ] cmp err %r" % e)
    emu.run.log("[RD   ] frame %d ctrl=%#x " % (n, ctrl) + " ".join(f"{L['name']}:{L['addr']:#x},{L['w']}x{L['h']}@{L['x']},{L['y']}f{L['fmt']}" for L in ls if L["en"]))


def install(emu, run, opts):
    pre(run, opts)
    _S.clear()
    _S["dir"] = os.path.join(run.dir, "rd")
    _S["cmp"] = bool(opts.get("cmp"))
    _S["rdw"] = bool(opts.get("rdw"))
    if opts.get("tick"):
        step = int(float(opts["tick"]))
        orig = emu._gic_step
        _S["next"] = int(float(opts.get("t0", "5.6e9")))

        def gic_step(mu):
            if emu.insn_total >= _S["next"]:
                _S["next"] += step
                try:
                    cmp_ram(emu, run, "t%d" % (emu.insn_total // 1000000))
                except Exception as e:
                    run.log("[RDV  ] tick err %r" % e)
            return orig(mu)
        emu._gic_step = gic_step
    os.makedirs(_S["dir"], exist_ok=True)
    if opts.get("blend2"):
        install_blend2(emu, run, opts)
    if opts.get("blend3"):
        install_blend3(emu, run, opts)
    if opts.get("cpy"):
        install_cpy(emu, run, opts)
    if opts.get("blend"):
        install_blend(emu, run, opts)
    if opts.get("trace"):
        install_trace(emu, run, opts)


def scan(emu, targets, lo=0x80000000, hi=0x83000000, step=0x100000):
    out = {}
    for a in range(lo, hi, step):
        try:
            b = bytes(emu.mu.mem_read(a, step))
        except Exception:
            continue
        arr = np.frombuffer(b, "<u4")
        for t in targets:
            for i in np.nonzero(arr == t)[0]:
                out.setdefault(t, []).append(a + int(i) * 4)
    return out


def finish(emu, run, opts):
    if opts.get('cmp'):
        cmp_ram(emu, run, 'final')
    finish2(emu, run)
    ls = fb._S.get("cfg") or []
    ts = [0x82d77300, 0x82930d00, 0x82876600] + [L["addr"] for L in ls if L["addr"]]
    r = scan(emu, sorted(set(ts)))
    for t, v in r.items():
        run.log("[RDS  ] ptr %#x at %s" % (t, " ".join(hex(x) for x in v)))
    for a, l in WIN:
        np.save(os.path.join(_S["dir"], f"final_w{a:x}.npy"), np.frombuffer(bytes(emu.mu.mem_read(a, l)), np.uint8))


def finish2(emu, run):
    import pickle
    d = {}
    for a, l in [(0x82779000, 0x1000), (0x8292b000, 0x2000)]:
        d[a] = bytes(emu.mu.mem_read(a, l))
    # pointers into those ranges
    ptrs = {}
    for a in range(0x80a00000, 0x83000000, 0x100000):
        try:
            b = bytes(emu.mu.mem_read(a, 0x100000))
        except Exception:
            continue
        arr = np.frombuffer(b, "<u4")
        m = ((arr >= 0x82779000) & (arr < 0x8277a000)) | ((arr >= 0x8292b000) & (arr < 0x8292d000))
        for i in np.nonzero(m)[0]:
            ptrs[a + int(i) * 4] = int(arr[i])
    d["ptrs"] = ptrs
    pickle.dump(d, open(os.path.join(_S["dir"], "final.pkl"), "wb"))
    run.log("[RDS  ] saved final.pkl, %d ptrs" % len(ptrs))


def install_trace(emu, run, opts):
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR
    lo, hi = int(opts.get("tlo", "0x80a46000"), 0), int(opts.get("thi", "0x80a47400"), 0)
    t0 = int(float(opts.get("tfrom", "5.69e9")))
    fns = set()
    import fwpaths
    for l in open(os.path.join(fwpaths.FUNCS_DIR, "kernel_funcs.tsv")):
        p = l.split()
        if len(p) > 2 and p[0] == "F":
            a = int(p[1], 16)
            if lo <= a < hi:
                fns.add(a | int(p[4]))
    def cb(uc, addr, size, ud):
        if emu.insn_total < t0:
            return
        r = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        run.log("[RDT  ] %#x(%s) lr=%#x insn=%d" % (addr, ",".join("%#x" % x for x in r), uc.reg_read(UC_ARM_REG_LR), emu.insn_total))
    for f in fns:
        a = f & ~1
        emu.mu.hook_add(UC_HOOK_CODE, cb, None, a, a + 1)
    run.log("[RDT  ] hooked %d fns" % len(fns))


def install_blend(emu, run, opts):
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR
    def cb(uc, addr, size, ud):
        r = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        lr = uc.reg_read(UC_ARM_REG_LR)
        run.log("[RDB  ] FUN_811f3000(%s) lr=%#x" % (",".join("%#x" % x for x in r), lr))
        try:
            arr = bytes(uc.mem_read(r[1], 12 * min(r[3], 8)))
            for i in range(min(r[3], 8)):
                p, a2, a3 = struct.unpack_from("<3I", arr, i * 12)
                run.log("[RDB  ]   [%d] ptr=%#x %#x %#x" % (i, p, a2, a3))
                if p:
                    s = bytes(uc.mem_read(p, 0x50))
                    run.log("[RDB  ]     " + " ".join("%08x" % x for x in struct.unpack("<20I", s)))
        except Exception as e:
            run.log("[RDB  ] err %s" % e)
    emu.mu.hook_add(UC_HOOK_CODE, cb, None, 0x811f3000, 0x811f3001)


def install_blend2(emu, run, opts):
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR, UC_ARM_REG_SP
    def cb(uc, addr, size, ud):
        r = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        sp = uc.reg_read(UC_ARM_REG_SP)
        st = struct.unpack("<24I", bytes(uc.mem_read(sp, 96)))
        run.log("[RDC  ] FUN_811f3c58(%s) lr=%#x sp=%#x stack=%s" % (",".join("%#x" % x for x in r), uc.reg_read(UC_ARM_REG_LR), sp, " ".join("%x" % x for x in st)))
        n = st[0]
        try:
            for i in range(min(st[0] if 0 else 6, 6)):
                arr = bytes(uc.mem_read(r[2] + 12 * i, 12))
                run.log("[RDC  ]    r2[%d] %s" % (i, " ".join("%08x" % x for x in struct.unpack("<3I", arr))))
        except Exception as e:
            pass
    emu.mu.hook_add(UC_HOOK_CODE, cb, None, 0x811f3c58, 0x811f3c59)


def install_blend3(emu, run, opts):
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR, UC_ARM_REG_SP
    def cb(uc, addr, size, ud):
        r = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        sp = uc.reg_read(UC_ARM_REG_SP)
        st = struct.unpack("<80I", bytes(uc.mem_read(sp, 320)))
        cs = [hex(x) for x in st if 0x80a05e00 <= x < 0x81f00000 or 0x88000000 <= x < 0x88400000]
        run.log("[RDD  ] FUN_811f35f6(%s) lr=%#x callstack=%s" % (",".join("%#x" % x for x in r), uc.reg_read(UC_ARM_REG_LR), " ".join(cs[:12])))
        try:
            ptrs = struct.unpack("<%dI" % min(r[3], 8), bytes(uc.mem_read(r[2], 4 * min(r[3], 8))))
            run.log("[RDD  ]    ptrs=%s" % " ".join("%#x" % p for p in ptrs))
            if r[1]:
                run.log("[RDD  ]    base info=%#x" % r[1])
        except Exception as e:
            run.log("[RDD  ] err %s" % e)
    emu.mu.hook_add(UC_HOOK_CODE, cb, None, 0x811f35f6, 0x811f35f7)


def install_cpy(emu, run, opts):
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_LR, UC_ARM_REG_SP
    def cb(uc, addr, size, ud):
        d, s, n = (uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        if 0x818fd100 <= d < 0x818fd500:
            sp = uc.reg_read(UC_ARM_REG_SP)
            st = struct.unpack("<120I", bytes(uc.mem_read(sp, 480)))
            cs = [hex(x) for x in st if 0x80a05e00 <= x < 0x81f00000 or 0x88000000 <= x < 0x88400000]
            run.log("[RDM  ] memcpy(%#x,%#x,%#x) lr=%#x cs=%s" % (d, s, n, uc.reg_read(UC_ARM_REG_LR), " ".join(cs[:16])))
    emu.mu.hook_add(UC_HOOK_CODE, cb, None, 0x810992d4, 0x810992d5)


def cmp_ram(emu, run, tag, ref=None):
    """compose from RAM layers (ram_layers/ram_compose of the phone-side f286.py client, which
    must be importable, e.g. via PYTHONPATH) and diff against ref (default: fb panel)"""
    try:
        import f286
    except ImportError:
        run.log("[RDV  ] f286.py (USB debug client) not on sys.path: RAM compose skipped")
        return
    rd = lambda a, n: bytes(emu.mu.mem_read(a, n))
    ls = f286.ram_layers(rd)
    img = f286.ram_compose(rd, ls)
    if ref is None:
        ref = fb._S.get("panel")
    d = np.abs(img.astype(int) - ref.astype(int)).max(-1)
    run.log("[RDV  ] %s: ram layers %s | diff px>0: %d  >8: %d  max %d" % (
        tag, " ".join("id%d@%#x/%dx%d+%d,%d/f%d/%s" % (L["id"], L["src"], L["w"], L["h"], L["x"], L["y"], L["fmt"], "V" if L["vis"] else "-") for L in ls),
        int((d > 0).sum()), int((d > 8).sum()), int(d.max())))
    try:
        from PIL import Image
        Image.fromarray(img).save(os.path.join(_S["dir"], "ram_%s.png" % tag))
        Image.fromarray(ref).save(os.path.join(_S["dir"], "ref_%s.png" % tag))
    except Exception:
        pass
