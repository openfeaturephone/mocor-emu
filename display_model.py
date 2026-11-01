"""LCD / display device model for the UMS9117 Unicorn emulator (mocor_emu).

Patch class applied ON TOP of a restored MocorEmu instance -- NO edits to
mocor_emu.py. Extra unicorn hooks are layered over the emulator's existing
MMIO hooks (mu.hook_add supports multiple registrations; the model is written
so that callback ordering vs MocorEmu.on_read/on_write cannot change the
observable result: any value we publish is mirrored into emu.hw_regs).

Models (from a static read of the kernel display driver):

* Panel i80 CPU-push ports (primary render path):
    CMD  window = 0x60000000 + (slot << 26)      (0x20000 wide, slot<4)
    DATA window = CMD + 0x20000                  (bit17 of addr selects DATA)
  Every store to 0x60000000..0x63FFFFFF lands in the DCS state machine:
  CMD write sets the current command; DATA writes append params / pixels.

* LCM top block 0x20A00000: +0x00 clock cfg, +0x10 mode, +0x14 timing,
  +0x20/+0x30/+0x40 bus-type regs -- all writes accepted+recorded; +0x08
  status bit1 = busy: pulses after a block write and self-clears after a
  couple of reads (firmware polls `while (0x20A00008 & 2)`).

* LCM low-level engine 0x70B00000: +0x34 status kept idle (bit25 = 0 on
  reads), +0x00 read-FIFO answers the ST7789 panel ID pattern 0x8552 so a
  natural panel-detect can pick the QVGA ST7789 driver (driver table entry 7).

* Clock gates 0x402E260C / 0x402E160C and pinmux 0x20E01000: recorded only.

* DCS protocol decode: 0x2A set_column, 0x2B set_row, 0x2C RAMWR (RGB565
  pixel stream, window-clipped into self.lcd_frame 240x320x2), 0x11 SLPOUT,
  0x29 DISPON, 0x28 DISPOFF, 0x43/0x44 internal rect-queue opcodes.

Usage:
    from display_model import DisplayModel
    dm = DisplayModel(emu); dm.install()
    ... run ...
    import lcd_render; lcd_render.render_png(dm.lcd_frame, "lcd.png")
"""
from collections import Counter

from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_PC

# ---- hook ranges (exact) -------------------------------------------------
PANEL_LO = 0x60000000            # CMD/DATA windows, all 4 slots
PANEL_HI = 0x63FFFFFF            # inclusive end (slot = (addr >> 26) & 3)
LCM_BASE = 0x20A00000            # LCM i80 top block
LCM_END = 0x20A000FF             # +0x00..+0xFF (covers +0x08/+0x10/+0x14/+0x20..40)
ENG_BASE = 0x70B00000            # LCM low-level engine
ENG_END = 0x70B000FF
GATE_ADDRS = (0x402E260C, 0x402E160C, 0x20E01000)   # recorded only

WIDTH, HEIGHT = 240, 320

# DCS commands
DCS_SWRESET = 0x01
DCS_SLPIN = 0x10
DCS_SLPOUT = 0x11
DCS_DISPOFF = 0x28
DCS_DISPON = 0x29
DCS_SET_COL = 0x2A
DCS_SET_ROW = 0x2B
DCS_RAMWR = 0x2C
DCS_RAMRD = 0x2E
DCS_MADCTL = 0x36
DCS_COLMOD = 0x3A
# internal rect-queue opcodes (dispatcher 0x80a4c25c; NOT panel commands --
# they may still appear in a capture, so we just count them)
OP_SET_COL = 0x43
OP_SET_ROW = 0x44

CMD_NAMES = {
    0x01: "SWRESET", 0x10: "SLPIN", 0x11: "SLPOUT", 0x28: "DISPOFF",
    0x29: "DISPON", 0x2A: "SETCOL", 0x2B: "SETROW", 0x2C: "RAMWR",
    0x2E: "RAMRD", 0x36: "MADCTL", 0x37: "VSCRDEF", 0x38: "IDMOFF",
    0x39: "IDMON", 0x3A: "COLMOD", 0x43: "OP43-SETCOL", 0x44: "OP44-SETROW",
    0xB2: "PORCTRL", 0xB7: "GCTRL", 0xBB: "VCOMS", 0xC0: "LCMCTRL",
    0xC2: "VDVVRHEN", 0xC3: "VRHS", 0xC4: "VDVS", 0xC5: "FRCTRL1",
    0xC6: "FRCTRL2", 0xD0: "PWCTRL1", 0xD6: "GATECTRL", 0xE0: "GAMP+",
    0xE1: "GAMP-", 0xE4: "GATECTRL2", 0x55: "WRCtrl", 0x21: "INVON",
}

PANEL_ID_WORD = 0x85528552       # ST7789 ID pattern for engine read-FIFO


class DisplayModel:
    """Layered display/panel device model. See module docstring."""

    def __init__(self, emu, width=WIDTH, height=HEIGHT):
        self.emu = emu
        self.mu = emu.mu
        self.width = width
        self.height = height

        # ---- deliverables -------------------------------------------------
        self.lcd_frame = bytearray(width * height * 2)   # RGB565, row-major
        self.lcd_cmd_log = []        # (pc, value16) of CMD-window writes

        # ---- counters -----------------------------------------------------
        self.cmd_writes = 0
        self.data_writes = 0
        self.pixels_written = 0
        self.ramwr_cmds = 0
        self.ramwr_bursts = 0        # completed 0x2C bursts (frame or rect)
        self.frames_completed = 0    # bursts that filled their full window
        self.dispon_seen = 0
        self.dispoff_seen = 0
        self.slpout_seen = 0
        self.slpin_seen = 0
        self.op43_seen = 0
        self.op44_seen = 0
        self.lcm_reads = 0
        self.lcm_writes = 0
        self.eng_reads = 0
        self.gate_writes = Counter()          # addr -> count
        self.cmd_hist = Counter()             # cmd byte -> count
        self.size_hist = Counter()            # store size -> count
        self.cmd_by_slot = Counter()
        self.data_by_slot = Counter()

        # ---- DCS state ----------------------------------------------------
        self.cur_cmd = None
        self.params = []
        self.col_start, self.col_end = 0, width - 1
        self.row_start, self.row_end = 0, height - 1
        self.px_x, self.px_y = 0, 0
        self._burst_px = 0
        self._burst_exp = width * height

        # ---- misc device state -------------------------------------------
        self.lcm_regs = {}           # offset -> last written value
        self._busy_left = 0          # 0x20A00008 bit1 pulses this many reads
        self.installed = False
        self._hooks = []
        self._ev_budget = 48         # throttled run.ev budget
        self._log_budget = 96        # throttled run.log budget

    # ------------------------------------------------------------------ install
    def install(self):
        if self.installed:
            return self
        mu = self.mu
        hs = self._hooks
        # 1. panel i80 ports: every store into any CMD/DATA window
        hs.append(mu.hook_add(UC_HOOK_MEM_WRITE, self._panel_write,
                              begin=PANEL_LO, end=PANEL_HI))
        # 1b. panel DATA-window reads: the panel-ID autodetect sends
        # RDDID (CMD 0x04) then reads 4 bytes here; with nothing served
        # the mapped-RAM zeros fail every driver match and the panel
        # count stays 0 forever (the display never starts). Serve the
        # real ST7789 RDDID response 85 85 52 85 (the value the ST7789 entry matches): id16 =
        # b2|b3<<8 = 0x8552 -> the ST7789 descriptor matches and
        # LcdDrvInit runs the full panel init in the same call.
        self.rddid_idx = 0
        hs.append(mu.hook_add(UC_HOOK_MEM_READ, self._panel_data_read,
                              begin=0x60020000, end=0x60020003))
        # 2. LCM top block 0x20A00000 (+0x08 busy model, rest accept+record)
        hs.append(mu.hook_add(UC_HOOK_MEM_READ, self._lcm_read,
                              begin=LCM_BASE, end=LCM_END))
        hs.append(mu.hook_add(UC_HOOK_MEM_WRITE, self._lcm_write,
                              begin=LCM_BASE, end=LCM_END))
        # 3. LCM low-level engine 0x70B00000 (status idle, read-FIFO = ID)
        hs.append(mu.hook_add(UC_HOOK_MEM_READ, self._eng_read,
                              begin=ENG_BASE, end=ENG_END))
        # 4. clock gates / pinmux: record only
        for a in GATE_ADDRS:
            hs.append(mu.hook_add(UC_HOOK_MEM_WRITE, self._gate_write,
                                  begin=a, end=a + 3))
        self.installed = True
        self.emu.run.log("[DISP] DisplayModel installed: panel %08x-%08x, "
                         "lcm %08x-%08x, eng %08x-%08x, gates %s" %
                         (PANEL_LO, PANEL_HI, LCM_BASE, LCM_END,
                          ENG_BASE, ENG_END,
                          [hex(a) for a in GATE_ADDRS]))
        self.emu.run.ev("DISP_MODEL_INSTALLED")
        return self

    def uninstall(self):
        for h in self._hooks:
            try:
                self.mu.hook_del(h)
            except Exception:
                pass
        self._hooks = []
        self.installed = False

    # ------------------------------------------------------------- hook helpers
    def _ev(self, etype, **kw):
        if self._ev_budget > 0:
            self._ev_budget -= 1
            try:
                self.emu.run.ev(etype, **kw)
            except Exception:
                pass

    def _log(self, msg):
        if self._log_budget > 0:
            self._log_budget -= 1
            try:
                self.emu.run.log(msg)
            except Exception:
                pass

    # ------------------------------------------------------------- panel i80
    RDDID_BYTES = (0x85, 0x85, 0x52, 0x85)

    def _panel_data_read(self, uc, access, address, size, user_data):
        """Serve the RDDID response on the slot-0 DATA window after the
        guest sends CMD 0x04 (see install)."""
        if self.cur_cmd != 0x04:
            return
        b = self.RDDID_BYTES[self.rddid_idx % 4]
        self.rddid_idx += 1
        uc.mem_write(address, bytes([b]) * size)

    def _panel_write(self, uc, access, address, size, value, user_data):
        slot = (address >> 26) & 3
        is_data = bool((address >> 17) & 1)
        v = value & {1: 0xFF, 2: 0xFFFF}.get(size, 0xFFFFFFFF)
        self.size_hist[size] += 1
        pc = uc.reg_read(UC_ARM_REG_PC) & ~1
        if is_data:
            self.data_writes += 1
            self.data_by_slot[slot] += 1
            self._data(v)
        else:
            self.cmd_writes += 1
            self.cmd_by_slot[slot] += 1
            self._cmd(uc, v, pc)

    def _cmd(self, uc, v, pc):
        # a new command terminates any open 0x2C pixel burst
        self._end_burst()
        c = v & 0xFF
        self.cur_cmd = c
        self.params = []
        if c == 0x04:
            self.rddid_idx = 0
        if len(self.lcd_cmd_log) < 200000:
            self.lcd_cmd_log.append((pc, v & 0xFFFF))
        self.cmd_hist[c] += 1
        if self.cmd_writes <= self._log_budget:
            name = CMD_NAMES.get(c, "")
            self._log("[DISP-CMD] #%d %02x%s @%08x" %
                      (self.cmd_writes, c, " " + name if name else "", pc))
        if c == DCS_SLPOUT:
            self.slpout_seen += 1
            self._ev("LCD_SLPOUT", n=self.slpout_seen, pc=hex(pc))
        elif c == DCS_DISPON:
            self.dispon_seen += 1
            self._ev("LCD_DISPON", n=self.dispon_seen, pc=hex(pc))
        elif c == DCS_DISPOFF:
            self.dispoff_seen += 1
        elif c == DCS_SLPIN:
            self.slpin_seen += 1
        elif c == DCS_RAMWR:
            self.ramwr_cmds += 1
            self._decode_window()
            self.px_x, self.px_y = self.col_start, self.row_start
            self._burst_exp = max(
                1, (self.col_end - self.col_start + 1) *
                   (self.row_end - self.row_start + 1))
            self._burst_px = 0
            self._ev("LCD_RAMWR", n=self.ramwr_cmds,
                     win="%d,%d-%d,%d" % (self.col_start, self.row_start,
                                          self.col_end, self.row_end))
        elif c == OP_SET_COL:
            self.op43_seen += 1
        elif c == OP_SET_ROW:
            self.op44_seen += 1

    def _data(self, v):
        c = self.cur_cmd
        if c == DCS_RAMWR:
            self._pixel(v & 0xFFFF)
        else:
            self.params.append(v & 0xFFFF)
            if c in (DCS_SET_COL, DCS_SET_ROW):
                self._decode_window()

    def _decode_window(self):
        """Decode 0x2A/0x2B params into the pixel window. The panel API sends
        one param per DATA write (byte values on the low lane); a 2-write
        halfword form (start, end) is also accepted when a value exceeds the
        byte lane. Byte form: [SC_hi, SC_lo, EC_hi, EC_lo]."""
        p = self.params
        if not p or self.cur_cmd not in (DCS_SET_COL, DCS_SET_ROW):
            return
        if len(p) == 2 and (p[0] > 0xFF or p[1] > 0xFF):
            s, e = p[0] & 0xFFFF, p[1] & 0xFFFF        # halfword form
        else:
            b = [x & 0xFF for x in p]                  # byte-lane form
            s = (b[0] << 8) | (b[1] if len(b) > 1 else 0)
            e = ((b[2] << 8) | b[3]) if len(b) >= 4 else s
        if e < s:
            e = s
        if self.cur_cmd == DCS_SET_COL:
            self.col_start, self.col_end = s, e
        else:
            self.row_start, self.row_end = s, e

    def _pixel(self, v):
        w, h = self.width, self.height
        x, y = self.px_x, self.px_y
        if x <= self.col_end and y <= self.row_end and 0 <= x < w and 0 <= y < h:
            o = (y * w + x) * 2
            self.lcd_frame[o] = v & 0xFF
            self.lcd_frame[o + 1] = (v >> 8) & 0xFF
        self.pixels_written += 1
        self._burst_px += 1
        x += 1
        if x > self.col_end:
            x = self.col_start
            y += 1
            if y > self.row_end:
                # window exhausted: the burst is logically complete even if
                # more pixels keep streaming (they wrap and re-count)
                self._end_burst()
                y = self.row_start
        self.px_x, self.px_y = x, y

    def _end_burst(self):
        if self._burst_px > 0:
            self.ramwr_bursts += 1
            if self._burst_px >= self._burst_exp:
                self.frames_completed += 1
            self._burst_px = 0

    # ------------------------------------------------------------- LCM 0x20A00000
    def _lcm_read(self, uc, access, address, size, value, user_data):
        self.lcm_reads += 1
        if (address & ~3) == LCM_BASE + 0x08:
            st = 2 if self._busy_left > 0 else 0
            if self._busy_left > 0:
                self._busy_left -= 1
            try:
                uc.mem_write(address & ~3, st.to_bytes(4, 'little'))
            except Exception:
                pass
            # mirror into hw_regs so MocorEmu.on_read (which republishes
            # hw_regs into memory) writes the same value in any hook order
            self.emu.hw_regs[address & ~3] = st

    def _lcm_write(self, uc, access, address, size, value, user_data):
        self.lcm_writes += 1
        mask = {1: 0xFF, 2: 0xFFFF}.get(size, 0xFFFFFFFF)
        self.lcm_regs[address - LCM_BASE] = value & mask
        self._busy_left = 3            # status bit1 busy, clears after ~3 reads

    # ------------------------------------------------------------- engine 0x70B00000
    def _eng_read(self, uc, access, address, size, value, user_data):
        self.eng_reads += 1
        a = address & ~3
        if a == ENG_BASE + 0x34:
            # status: keep bit25 (busy) idle
            try:
                uc.mem_write(a, b"\x00\x00\x00\x00")
            except Exception:
                pass
            self.emu.hw_regs[a] = 0
        elif a == ENG_BASE:
            # read-data FIFO: answer the ST7789 panel-ID pattern so a natural
            # detect (0x81246c98) can identify the QVGA ST7789 driver
            try:
                uc.mem_write(a, PANEL_ID_WORD.to_bytes(4, 'little'))
            except Exception:
                pass
            self.emu.hw_regs[a] = PANEL_ID_WORD

    # ------------------------------------------------------------- gates
    def _gate_write(self, uc, access, address, size, value, user_data):
        self.gate_writes[address & ~3] += 1

    # ------------------------------------------------------------------ reporting
    def stats(self):
        return {
            "cmd_writes": self.cmd_writes, "data_writes": self.data_writes,
            "pixels": self.pixels_written, "ramwr_cmds": self.ramwr_cmds,
            "bursts": self.ramwr_bursts, "frames": self.frames_completed,
            "slpout": self.slpout_seen, "dispon": self.dispon_seen,
            "lcm_rd": self.lcm_reads, "lcm_wr": self.lcm_writes,
            "eng_rd": self.eng_reads,
            "gates": {hex(k): v for k, v in self.gate_writes.items()},
            "cmds_logged": len(self.lcd_cmd_log),
        }

    def summary(self):
        top = " ".join("%02x:%d" % kv for kv in
                       self.cmd_hist.most_common(16))
        return ("lcd: cmd_w=%d data_w=%d pixels=%d ramwr_cmds=%d bursts=%d "
                "frames=%d slpout=%d dispon=%d op43/44=%d/%d lcm_rd=%d "
                "lcm_wr=%d eng_rd=%d gates=%s | top cmds: %s" %
                (self.cmd_writes, self.data_writes, self.pixels_written,
                 self.ramwr_cmds, self.ramwr_bursts, self.frames_completed,
                 self.slpout_seen, self.dispon_seen, self.op43_seen,
                 self.op44_seen, self.lcm_reads, self.lcm_writes,
                 self.eng_reads,
                 {hex(k): v for k, v in self.gate_writes.items()}, top))
