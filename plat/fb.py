"""plat.fb -- framebuffer PNG capture from the LCDC layer registers.

  plat_run.py TAG --plugin fb[:every=N,panel=1,dump=1,snaps=insn;insn]
  from plat import fb;  fb.snapshot(emu, "x.png")  # on demand, returns (w, h, info)

On every LCDC frame start (write of ctrl bit3 at 0x20800000 - the same event mocor_emu's
_lcdc_write logs as "[LCDC ] frame #n") the enabled layers are composed and written to
<run.dir>/fb/frame_<n>_<insn>M.png. every=N keeps every Nth frame; a frame identical to the
previous written one is skipped. panel=1 also installs display_model.DisplayModel (the i80
panel-push path) and writes fb/panel_<insn>M.png at the end of the run if it received pixels.

LCDC register layout (UMS9117/sc88xx-style "lcdc", derived from the firmware driver writes
seen with --mmio-watch 20800000-20800400 from CV_4220M, and from the Linux sprd lcdc layout):
  0x000 CTRL      bit3 = start frame (the emulator completes it at once and clears the bit)
  0x004 SIZE_XY   (height << 16) | width       0x014000f0 = 240x320
  0x008 BG color  0x00c DISP_SIZE
  Layers (offset of each block; every register is 32 bit):
        OSD1 0x20   OSD2 0x50   OSD3 0x80   OSD4 0xb0   IMG 0xe0
     +0x00 CTRL    bit0 = layer enable; bits[7:4] = data format (5 = RGB565 in all writes seen)
     +0x04 BASE    buffer address >> 2 (0x20a4b840 -> 0x8292e100)
     +0x08 BASE2   alpha-plane / UV base (unused here)
     +0x0c SIZE_XY (height << 16) | width of the source window
     +0x10 PITCH   line pitch in pixels (0xf0 = 240)
     +0x14 DISP_XY screen position: x = [11:0], y = [27:16]
     +0x18 = global alpha (0xff on OSD2). Format 3 = ARGB8888 (4 bytes/pixel, pitch in pixels,
     alpha blended; all-zero pixel = transparent), 5 = RGB565 (opaque).
  Z order, bottom to top: IMG, OSD1, OSD2, OSD3, OSD4 (assumed; the stock MMI draws one
  layer at a time). 0x110 INT_EN, 0x114 INT_CLR, 0x118 INT_STATUS, 0x11c INT_RAW.
Observed (IDLE_5500M, 2026-10-31): display frames start with ctrl 0x0b: IMG (RGB565) + OSD1
(RGB565 full-screen UI) + OSD2 (240x18 ARGB8888 status overlay, all-zero = transparent; the
status bar itself is in OSD1). The in-between frames start with ctrl 0x19 (bit4) and only enable
OSD2 on a full-screen scratch buffer: they are logged but not composed. The last display
frame's layer set is remembered (_S["cfg"]) and used by snapshot().
"""
import hashlib
import os
import struct
import numpy as np
from unicorn import UcError

LCDC = 0x20800000
LAYERS = (("IMG", 0xe0), ("OSD1", 0x20), ("OSD2", 0x50), ("OSD3", 0x80), ("OSD4", 0xb0))
RECT = 0x817ce248 + 0x15c                  # kernel: u16 left, top, width, height of the pending update
_S = {}                                   # plugin state (kept off emu: checkpoints pickle emu attrs)


def _reg(emu, off):
    try:
        return struct.unpack("<I", bytes(emu.mu.mem_read(LCDC + off, 4)))[0]
    except UcError:
        return emu.hw_regs.get(LCDC + off, 0)


def layers(emu):
    """Decode the five layer blocks -> list of dicts (enabled or not)."""
    out = []
    for name, o in LAYERS:
        ctrl, base, size, pitch, xy = (_reg(emu, o + d) for d in (0, 4, 0xc, 0x10, 0x14))
        out.append(dict(name=name, en=bool(ctrl & 1), ctrl=ctrl, fmt=(ctrl >> 4) & 0xF,
                        addr=(base << 2) & 0xFFFFFFFF, w=size & 0xFFFF, h=size >> 16,
                        pitch=pitch & 0xFFFF, x=xy & 0xFFF, y=(xy >> 16) & 0xFFF))
    return out


def _seed(emu):
    """Layer set for a snapshot with no frame history (fresh checkpoint load): the driver
    disables OSD1 after each frame but leaves its base/size, and the next-pass OSD2 is a
    full-screen scratch buffer, so use OSD1 as-is and ignore OSD2."""
    ls = layers(emu)
    for L in ls:
        L["en"] = L["name"] == "OSD1" and bool(L["addr"]) and L["fmt"] == 5
    return ls


def _decode(raw, L, h, w, pitch):
    """-> (rgb uint8 HxWx3, alpha uint8 HxW or None)."""
    if L["fmt"] == 3:                       # ARGB8888 (0xAARRGGBB LE); all-zero = transparent
        px = np.frombuffer(raw, "<u4").reshape(h, pitch)[:, :w]
        rgb = np.stack([(px >> 16) & 255, (px >> 8) & 255, px & 255], -1).astype(np.uint8)
        return rgb, (px >> 24).astype(np.uint8)
    px = np.frombuffer(raw, "<u2").reshape(h, pitch)[:, :w].astype(np.uint16)
    r, g, b = (px >> 11) & 31, (px >> 5) & 63, px & 31
    return np.stack([(r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2)], -1).astype(np.uint8), None


def compose(emu, ls=None, base=None):
    """-> (w, h, rgb888 HxWx3 ndarray, layer list). Black if nothing is enabled.
    ls = layer configs to use (default: the remembered last display frame, else _seed)."""
    size = _reg(emu, 0x04)
    W, H = (size & 0xFFFF) or 240, (size >> 16) or 320
    W, H = min(W, 1024), min(H, 1024)
    canvas = np.zeros((H, W, 3), np.float32)
    ls = ls or _S.get("cfg") or _seed(emu)
    if base is not None:                    # overlay-only pass: start from the panel image
        bh, bw = min(H, base.shape[0]), min(W, base.shape[1])
        canvas[:bh, :bw] = base[:bh, :bw]
    for L in ls:
        if not L["en"] or not L["w"] or not L["h"]:
            continue
        if base is not None and L["name"] in ("IMG", "OSD1"):
            continue
        w, h = min(L["w"], 1024), min(L["h"], 1024)
        pitch = max(L["pitch"], w)
        bpp = 4 if L["fmt"] == 3 else 2
        try:
            raw = bytes(emu.mu.mem_read(L["addr"], pitch * h * bpp))
        except (UcError, OverflowError):
            L["err"] = "unmapped"
            continue
        if L["fmt"] not in (3, 5) and (L["name"], L["fmt"]) not in _S.setdefault("warned", set()):
            _S["warned"].add((L["name"], L["fmt"]))
            emu.run.log(f"[FB   ] {L['name']} format nibble {L['fmt']} (ctrl {L['ctrl']:#x}) drawn as RGB565")
        rgb, al = _decode(raw, L, h, w, pitch)
        x0, y0 = L["x"], L["y"]
        cw, ch = min(w, W - x0), min(h, H - y0)
        if cw <= 0 or ch <= 0:
            continue
        src = rgb[:ch, :cw].astype(np.float32)
        if al is None:
            canvas[y0:y0 + ch, x0:x0 + cw] = src
        else:                               # pixel alpha x layer alpha (+0x18)
            a = al[:ch, :cw, None].astype(np.float32) / 255 * (L.get("alpha", 255) / 255)
            dst = canvas[y0:y0 + ch, x0:x0 + cw]
            canvas[y0:y0 + ch, x0:x0 + cw] = src * a + dst * (1 - a)
    return W, H, np.clip(canvas + 0.5, 0, 255).astype(np.uint8), ls


def _png(rgb, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    import lcd_render
    h, w = rgb.shape[:2]
    if lcd_render.HAVE_PIL:
        lcd_render.Image.fromarray(rgb, "RGB").save(path)
    else:
        lcd_render._write_png_manual(rgb.tobytes(), w, h, path)


def snapshot(emu, path):
    """Compose the last display frame (or the live OSD1 buffer) and write a PNG.
    Returns (w, h, layers)."""
    rgb = _S.get("panel")
    ls = _S.get("cfg") or []
    if rgb is None:
        _, _, rgb, ls = compose(emu)
    _png(rgb, path)
    return rgb.shape[1], rgb.shape[0], ls


def on_frame(emu, ctrl=0x8):
    n = emu.lcdc["frames"]
    ls = layers(emu)
    for L in ls:
        L["alpha"] = _reg(emu, {"IMG": 0, "OSD1": 0x38, "OSD2": 0x68, "OSD3": 0x98, "OSD4": 0xc8}[L["name"]]) & 255
    en = ",".join(f"{L['name']}@{L['addr']:#x}" for L in ls if L["en"]) or "none"
    if ctrl & 0x10:
        # start value 0x19 (bit4) vs 0x0b: the odd frames only enable OSD2 on a full-screen
        # scratch buffer (0x82876600, mostly junk). Not a display frame; keep the last one.
        emu.run.log(f"[FB   ] frame #{n} ctrl={ctrl:#x} (bit4) not composed (layers {en})")
        return
    emu.run.log("[FB   ]   " + " ".join(f"{L['name']}:ctrl={L['ctrl']:#x},{L['w']}x{L['h']}@{L['x']},{L['y']}" for L in ls if L["en"])
                + f" lcdc={_reg(emu, 4):#x} start={ctrl:#x}")
    _S["cfg"] = ls
    _S["seen"] = _S.get("seen", 0) + 1
    if _S["dump"]:
        for L in ls:
            if L["en"]:
                open(os.path.join(_S["dir"], f"raw_{n}_{L['name']}.bin"), "wb").write(
                    bytes(emu.mu.mem_read(L["addr"], max(L["pitch"], L["w"]) * L["h"] * 4)))
    by = {L["name"]: L for L in ls}
    # Overlay-only pass: OSD1 points at the IMG layer's own buffer (the stale boot logo / black
    # scratch) while OSD2 carries the status bar. It is the status-strip refresh, not a new UI
    # image: draw OSD2 over the existing panel instead of replacing the panel with the scratch.
    overlay = by["OSD1"]["en"] and by["OSD1"]["addr"] == by["IMG"]["addr"] and by["OSD2"]["en"]
    if overlay and _S.get("panel") is not None:
        rx, ry = struct.unpack("<2H", bytes(emu.mu.mem_read(RECT, 4)))
        size = _reg(emu, 4)
        h0, w0 = min((size >> 16) or 320, 320 - ry), min((size & 0xFFFF) or 240, 240 - rx)
        w, h, rgb, ls = compose(emu, ls, base=_S["panel"][ry:ry + h0, rx:rx + w0])
        _S["panel"][ry:ry + h, rx:rx + w] = rgb[:h, :w]
        _S["rect"] = (rx, ry, w, h)
        emu.run.log("[FB   ]   overlay-only pass (OSD1 == IMG buffer): OSD2 blended on the panel")
        return _frame_out(emu, n, ls, w, h, en)
    w, h, rgb, ls = compose(emu, ls)
    # partial updates (LCDC size < panel): blit into the persistent panel image at the window
    # origin the kernel LCD driver keeps at RECT (last block-invalidate: left, top, w, h).
    panel = _S.get("panel")
    if panel is None:
        panel = _S["panel"] = np.zeros((320, 240, 3), np.uint8)
    rx, ry, rw, rh = struct.unpack("<4H", bytes(emu.mu.mem_read(RECT, 8)))
    if rx >= panel.shape[1] or ry >= panel.shape[0]:
        rx = ry = 0
    ph, pw = min(h, panel.shape[0] - ry), min(w, panel.shape[1] - rx)
    panel[ry:ry + ph, rx:rx + pw] = rgb[:ph, :pw]
    _S["rect"] = (rx, ry, rw, rh)
    return _frame_out(emu, n, ls, w, h, en)


def _frame_out(emu, n, ls, w, h, en):
    rgb = _S["panel"]
    if _S["seen"] % _S["every"]:
        return
    dg = hashlib.md5(rgb.tobytes()).digest()
    if dg == _S.get("last"):
        emu.run.log(f"[FB   ] frame #{n} identical, skipped (layers {en})")
        return
    _S["last"] = dg
    p = os.path.join(_S["dir"], f"frame_{n}_{emu.insn_total // 1_000_000}M.png")
    _png(rgb, p)
    nz = int((rgb.sum(-1) > 0).sum())
    emu.run.log(f"[FB   ] frame #{n} {w}x{h} layers {en} nonblack_px={nz} rect={_S['rect']} -> {os.path.basename(p)}")
    emu.run.ev("FB_FRAME", n=n, path=p, layers=en, nonblack=nz, insn=emu.insn_total)


def pre(run, opts):
    from mocor_emu import MocorEmu
    if getattr(MocorEmu, "_plat_fb_wrapped", False):
        return
    MocorEmu._plat_fb_wrapped = True
    orig = MocorEmu._lcdc_write

    def _lcdc_write(self, uc, a, value):
        start = (a == LCDC and (value & 8) and not (self._lcdc_sync(uc)["ctrl"] & 8))
        orig(self, uc, a, value)
        if start and _S:
            on_frame(self, value)
    MocorEmu._lcdc_write = _lcdc_write


def install(emu, run, opts):
    pre(run, opts)

    _S.clear()
    _S.update(dump=opts.get("dump") == "1", every=max(1, int(opts.get("every", 1))), dir=os.path.join(run.dir, "fb"))
    os.makedirs(_S["dir"], exist_ok=True)
    try:                                    # panel memory is not in checkpoints: seed from OSD1
        _S["panel"] = compose(emu)[2].copy()
    except Exception:
        pass
    if opts.get("panel", "0") == "1":
        from display_model import DisplayModel
        _S["dm"] = DisplayModel(emu)
        _S["dm"].install()
    snaps = sorted(int(float(x)) for x in opts.get("snaps", "").split(";") if x)
    if snaps:                               # snaps=<insn>;<insn>: panel PNG at each, snap_<insn>M.png
        orig = emu._gic_step
        _S["snaps"] = snaps

        def gic_step(mu):
            while _S["snaps"] and emu.insn_total >= _S["snaps"][0]:
                t = _S["snaps"].pop(0)
                snapshot(emu, os.path.join(_S["dir"], f"snap_{t // 1_000_000}M.png"))
            return orig(mu)
        emu._gic_step = gic_step
    run.log(f"[FB   ] armed every={_S['every']} -> {_S['dir']}")


def finish(emu, run, opts):
    try:
        snapshot(emu, os.path.join(_S["dir"], "final.png"))
    except Exception as e:                  # never lose the run's stop report to a render error
        run.log(f"[FB   ] final snapshot failed: {e}")
    dm = _S.get("dm")
    if dm is not None and any(dm.lcd_frame):
        import lcd_render
        p = os.path.join(_S["dir"], f"panel_{emu.insn_total // 1_000_000}M.png")
        lcd_render.render_png(bytes(dm.lcd_frame), p, 240, 320)
        run.log(f"[FB   ] panel-push frame -> {p}")
