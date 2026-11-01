"""fplinux_lcd.py - AP display path model (LCDC 0x20800000, LCM 0x20A00000, panel bus 0x60000000).

Enough for FPLinux's ums9117 DRM driver: the LCM never reports busy,
every CTRL.RUN produces a frame (RGB565 IMG layer copied into a 240x320 panel buffer at the DCS 2A/2B
window) and raises frame-done on GIC SPI 19 (ID 51, level), and the panel bus window is mapped.

Wiring into fplinux_emu.py:

    from fplinux_lcd import LcdModel
    # Emu.__init__, after the MMIO windows are mapped and gic_pending exists:
    self.lcd = LcdModel(self)          # needs self.mu, self.gic_pending, self.log, self.out
    self.lcd.map_window()              # maps 0x60000000 (0x40000); FPLinux's first DCS write faults without it
    # Emu.on_mmio, first thing:
    if self.lcd.on_mmio(uc, access, addr, size, value):
        pass                           # (still fall through to the seen-log if wanted)
    # end of Emu.run():
    self.lcd.save_png(os.path.join(self.out, "panel.png"))

Hook semantics assumed (unicorn): a read hook runs before the load, so writing the register value from
the hook is what the guest reads; a write hook runs before the store, so the guest's raw value lands in
memory afterwards and every register whose read-back differs is overridden on read.

  python fplinux_lcd.py --selftest [--png out.png]
"""
import os
import struct
import zlib

LCDC_BASE, LCDC_SPAN = 0x20800000, 0x120
LCM_BASE = 0x20A00000
LCM_STS0 = LCM_BASE + 0x08              # b1 smem_busy, b0 wbuf busy: always 0 here
PANEL_BUS, PANEL_SPAN = 0x60000000, 0x40000
PANEL_DATA = PANEL_BUS + 0x20000        # D/C = HADDR17: 0x60000000 command, 0x60020000 data
AHB_RST = 0x20E01004                    # SET alias of AHB_RST 0x20E00004; bit1 = LCDC soft reset
LCDC_IRQ = 32 + 19                      # int_req_lcdc = SPI 19 -> GIC ID 51, level-high
PANEL_W, PANEL_H = 240, 320

# LCDC register offsets (TRM 5.10 + stock setters)
CTRL, LCM_SIZE, FIFO_STATUS = 0x000, 0x00C, 0x014
IMG_CTRL, IMG_Y_BASE, IMG_SIZE_XY, IMG_PITCH = 0x020, 0x024, 0x02C, 0x030
CAP_CTRL, CAP_BASE = 0x0E0, 0x0E4
IRQ_EN, IRQ_CLR, IRQ_STATUS, IRQ_RAW = 0x110, 0x114, 0x118, 0x11C
CTRL_EN, CTRL_RUN = 1 << 0, 1 << 3
IRQ_DONE = 1 << 0


def png565(buf, w, h, path):
    """RGB565 little-endian buffer -> PNG (no PIL)."""
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        row = buf[y * w * 2:(y + 1) * w * 2]
        for x in range(w):
            p = row[2 * x] | row[2 * x + 1] << 8
            raw += bytes((((p >> 11) & 31) * 255 // 31, ((p >> 5) & 63) * 255 // 63, (p & 31) * 255 // 31))
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(bytes(raw))) + chunk(b"IEND", b""))


class LcdModel:
    def __init__(self, emu):
        self.emu = emu
        self.panel = bytearray(PANEL_W * PANEL_H * 2)
        self.frames = 0
        self.cmd, self.params = None, []
        self.col, self.row = (0, PANEL_W - 1), (0, PANEL_H - 1)
        self.dcs_log = 0
        self.reset()

    # ---- hook 1: the panel bus window ----
    def map_window(self):
        self.emu.mu.mem_map(PANEL_BUS, PANEL_SPAN)
        self.emu.log(f"[LCD ] panel bus {PANEL_BUS:#x}+{PANEL_SPAN:#x} mapped (cmd {PANEL_BUS:#x}, data {PANEL_DATA:#x})")

    def reset(self):
        """LCDC soft reset: registers back to 0 (FIFO_STATUS reads 0x5555), no pending done."""
        self.ctrl = self.en = self.raw = 0
        self._sync_irq()

    def _reg(self, off):
        return struct.unpack("<I", self.emu.mu.mem_read(LCDC_BASE + off, 4))[0]

    # ---- hook 3: frame-done interrupt (level: pending while raw & en) ----
    def _sync_irq(self):
        if self.raw & self.en & IRQ_DONE:
            self.emu.gic_pending.add(LCDC_IRQ)
        else:
            self.emu.gic_pending.discard(LCDC_IRQ)

    def raise_frame_done(self):
        self.raw |= IRQ_DONE
        self._sync_irq()

    def on_mmio(self, uc, access, addr, size, value):
        """Called from the emulator's MMIO hook for every access; returns True for addresses it models."""
        write = access == 17          # UC_MEM_WRITE (avoid importing unicorn constants here)
        if LCDC_BASE <= addr < LCDC_BASE + LCDC_SPAN:
            off = (addr - LCDC_BASE) & ~3
            if write:
                self._lcdc_write(off, value & 0xFFFFFFFF)
            else:
                v = {CTRL: self.ctrl, FIFO_STATUS: 0x5555, IRQ_EN: self.en, IRQ_CLR: 0,
                     IRQ_STATUS: self.raw & self.en, IRQ_RAW: self.raw}.get(off)
                if v is not None:
                    uc.mem_write(LCDC_BASE + off, struct.pack("<I", v))
            return True
        # ---- hook 2: LCM status never busy ----
        if addr & ~3 == LCM_STS0:
            if not write:
                uc.mem_write(LCM_STS0, b"\0\0\0\0")
            return True
        if PANEL_BUS <= addr < PANEL_BUS + PANEL_SPAN:
            if write:
                self._panel_write(addr, value)
            return True
        if write and addr == AHB_RST and value & 2:
            self.reset()
        return False

    def _lcdc_write(self, off, v):
        if off == CTRL:
            run = v & CTRL_RUN and not self.ctrl & CTRL_RUN
            self.ctrl = v & ~CTRL_RUN                    # RUN self-clears
            if run:
                self.frame()
        elif off == IRQ_EN:
            self.en = v & 3
        elif off == IRQ_CLR:
            self.raw &= ~v
        self._sync_irq()

    def _panel_write(self, addr, v):
        if not addr & 0x20000:                            # command phase
            self.cmd, self.params = v & 0xFF, []
            if self.dcs_log < 40:
                self.dcs_log += 1
                self.emu.log(f"[LCD ] DCS {self.cmd:02x}")
            return
        self.params.append(v & 0xFF)
        p = self.params
        if len(p) == 4 and self.cmd in (0x2A, 0x2B):
            win = (p[0] << 8 | p[1], p[2] << 8 | p[3])
            if self.cmd == 0x2A:
                self.col = win
            else:
                self.row = win

    def frame(self):
        img, cap, capb = self._reg(IMG_CTRL), self._reg(CAP_CTRL), self._reg(CAP_BASE) << 2
        size = self._reg(LCM_SIZE)
        w, h = size & 0xFFF, (size >> 16) & 0xFFF
        if not self.ctrl & CTRL_EN or capb != PANEL_DATA or not cap & 0x20:
            self.emu.log(f"[LCD ] frame with ctrl={self.ctrl:#x} cap={cap:#x} capbase={capb:#x} (not routed to the panel?)")
        if img & 1 and (img >> 4) & 0xF == 5:             # RGB565 (FPLinux fbdev)
            base = (self._reg(IMG_Y_BASE) & 0x3FFFFFFF) << 2
            pitch = self._reg(IMG_PITCH) & 0xFFF
            x0, y0 = self.col[0], self.row[0]
            n = max(0, min(w, PANEL_W - x0)) * 2
            for y in range(max(0, min(h, PANEL_H - y0))):
                o = ((y0 + y) * PANEL_W + x0) * 2
                self.panel[o:o + n] = self.emu.mu.mem_read(base + y * pitch * 2, n)
        else:
            self.emu.log(f"[LCD ] IMG_CTRL={img:#x} not RGB565, not drawn")
        self.frames += 1
        self.raise_frame_done()                           # done at once; taken at the next IRQ check
        if self.frames <= 3 or self.frames % 50 == 0:
            self.emu.log(f"[LCD ] frame #{self.frames} {w}x{h} at col={self.col} row={self.row}")
            self.save_png(os.path.join(self.emu.out, "panel.png"))

    def save_png(self, path):
        png565(self.panel, PANEL_W, PANEL_H, path)


def selftest(png=None):
    """Drive one FPLinux-style frame through on_mmio with unicorn's hook ordering emulated."""
    import tempfile
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MEM_WRITE, UC_MEM_READ
    assert UC_MEM_WRITE == 17

    class FakeEmu:
        def __init__(self):
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            self.mu.mem_map(0x20000000, 0x01000000)
            self.mu.mem_map(0x80000000, 0x00100000)
            self.gic_pending, self.out, self.lines = set(), tempfile.mkdtemp(), []

        def log(self, m):
            self.lines.append(m)

    e = FakeEmu()
    lcd = LcdModel(e)
    lcd.map_window()

    def wr(a, v, sz=4):
        lcd.on_mmio(e.mu, UC_MEM_WRITE, a, sz, v)        # hook first, then the store
        e.mu.mem_write(a, (v & (1 << 8 * sz) - 1).to_bytes(sz, "little"))

    def rd(a):
        lcd.on_mmio(e.mu, UC_MEM_READ, a, 4, 0)
        return struct.unpack("<I", e.mu.mem_read(a, 4))[0]

    # framebuffer: 240x320 RGB565 gradient at 0x80000000, pitch 240 px
    fb = bytearray()
    for y in range(PANEL_H):
        for x in range(PANEL_W):
            fb += struct.pack("<H", ((x * 31 // PANEL_W) << 11) | ((y * 63 // PANEL_H) << 5) | 0x1F // 2)
    e.mu.mem_write(0x80000000, bytes(fb))

    assert rd(LCM_STS0) == 0, "LCM busy"
    assert rd(LCDC_BASE + FIFO_STATUS) == 0x5555
    for cmd, params in ((0x2A, (0, 0, 0, 239)), (0x2B, (0, 0, 1, 63))):
        wr(PANEL_BUS, cmd, 2)
        for b in params:
            wr(PANEL_DATA, b, 2)
    wr(PANEL_BUS, 0x2C, 2)
    assert lcd.col == (0, 239) and lcd.row == (0, 319), (lcd.col, lcd.row)
    L = LCDC_BASE
    wr(L + LCM_SIZE, PANEL_W | PANEL_H << 16)
    wr(L + IMG_CTRL, 0x251)
    wr(L + IMG_Y_BASE, 0x80000000 >> 2)
    wr(L + IMG_SIZE_XY, PANEL_W | PANEL_H << 16)
    wr(L + IMG_PITCH, PANEL_W)
    wr(L + CAP_CTRL, 0x20 | 2 << 6)
    wr(L + CAP_BASE, PANEL_DATA >> 2)
    wr(L + IRQ_CLR, 1)
    wr(L + IRQ_EN, 1)
    assert LCDC_IRQ not in e.gic_pending
    wr(L + CTRL, CTRL_EN | 2)
    wr(L + CTRL, rd(L + CTRL) | CTRL_RUN)
    assert rd(L + CTRL) & CTRL_RUN == 0, "RUN did not self-clear"
    assert LCDC_IRQ in e.gic_pending, "no frame-done IRQ"
    assert rd(L + IRQ_STATUS) & 1 and rd(L + IRQ_RAW) & 1
    assert lcd.panel == fb, "panel content differs from the framebuffer"
    wr(L + IRQ_CLR, 1)
    assert LCDC_IRQ not in e.gic_pending and rd(L + IRQ_STATUS) == 0 and rd(L + IRQ_CLR) == 0
    wr(L + IRQ_EN, 0)
    wr(AHB_RST, 2)
    assert rd(L + CTRL) == 0
    if png:
        lcd.save_png(png)
    print(f"selftest OK: {lcd.frames} frame, IRQ {LCDC_IRQ} raised and cleared, panel matches; "
          f"{len(e.lines)} log lines" + (f", PNG {png}" if png else ""))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--png")
    a = ap.parse_args()
    if a.selftest:
        selftest(a.png)
    else:
        ap.print_help()
