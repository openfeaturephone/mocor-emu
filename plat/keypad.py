"""plat/keypad.py -- model of the KPD matrix controller (0x40250000, GIC 0x44).

Kernel driver (ours, mapped at VA = file + 0x80a05e00):
  init 0x81179f2a  (registers table-irq 0x24 -> GIC 0x44 = SPI 36)
  ISR  0x81179eae  reads int_raw (+8), ORs 0xfff into int_clr (+0x10),
                   enqueues one code per raw bit (bit0..3 -> 1..4 press slots,
                   bit4..7 -> 5..8 release slots) into a ring at 0x81704420
  0x81179da2(slot) reads key_status (+0x2c): slot s = byte s,
                   index = (b & 7) << 3 | (b >> 4) & 7
  0x8117a0f4(index) -> SCI_VK from the 64-entry ROM keymap at 0x814ccb74
  0x81179d7e sends the key signal (0x80 = up, 0x81 = down) to the KPD server.
Registers: ctrl 00 (bit0 enable; shared with the emulator's tick gate, left alone),
int_en 04, int_raw 08, int_clr 10, polarity 18, debounce 1c, clk_div 28, key_status 2c.

API: install(emu, run, opts) -> Keypad; press(emu, key, hold_ms=100);
opts: keys="OK@4.40G/150,DOWN@+100ms" (see parse_keys), keyfile=path, hold=ms.
"""
import re
import struct
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE

KPD_BASE = 0x40250000
KPD_GIC = 0x44                       # table irq 0x24 + 0x20
KEYMAP_PTR_LIT = 0x812189dc          # literal pool word holding the keymap pointer
INSN_PER_MS = 200_000                # 200M insns = 1 s virtual
R_CTRL, R_EN, R_RAW, R_CLR, R_STATUS = 0x00, 0x04, 0x08, 0x10, 0x2c

# app API key name -> SCI_VK (keymap ROM table 0x814ccb74). RED (VK 2) is not
# in the matrix (power button, EIC), so it can't be injected here.
VK = {"UP": 4, "DOWN": 5, "LEFT": 6, "RIGHT": 7, "GREEN": 1, "CALL": 1,
      "LSOFT": 8, "RSOFT": 9, "OK": 0x0d, "STAR": 0x2a, "*": 0x2a,
      "HASH": 0x23, "#": 0x23}
VK.update({str(d): 0x30 + d for d in range(10)})
# MMI KEY code (press msg = 0xfa00 | KEY), for reference/verification
KEYCODE = {"UP": 1, "DOWN": 2, "LEFT": 3, "RIGHT": 4, "GREEN": 5, "CALL": 5,
           "1": 8, "2": 9, "3": 10, "4": 11, "5": 12, "6": 13, "7": 14, "8": 15,
           "9": 16, "STAR": 0x11, "*": 0x11, "0": 0x12, "HASH": 0x13, "#": 0x13,
           "LSOFT": 0x16, "RSOFT": 0x17, "OK": 0x1b}


def parse_time(s, base=0):
    """'4.40G' '4220M' '1.5s' '+100ms' (relative to `base`) or a plain insn count."""
    s = s.strip().lower()
    rel = s.startswith("+")
    s = s.lstrip("+")
    m = re.fullmatch(r"([0-9.]+)\s*(ms|s|g|m|k)?", s)
    if not m:
        raise ValueError(f"bad time {s!r}")
    v = float(m.group(1)) * {"ms": INSN_PER_MS, "s": 200e6, "g": 1e9, "m": 1e6,
                             "k": 1e3, None: 1}[m.group(2)]
    return int(v) + (base if rel else 0)


def parse_keys(spec, default_hold=100):
    """'OK@4.40G/150,DOWN@+100ms' -> [(key, t, hold_ms)]. Entries split on , ; |
    or newlines. '+t' is relative to the previous key's release. '/N' = hold in ms."""
    out, prev = [], 0
    for ent in re.split(r"[,;|\n]", spec):
        ent = ent.strip()
        if not ent or ent.startswith("#"):
            continue
        name, _, rest = ent.partition("@")
        when, _, hold = rest.partition("/")
        hold = int(hold) if hold else default_hold
        t = parse_time(when, prev)
        out.append((name.strip().upper(), t, hold))
        prev = t + hold * INSN_PER_MS
    return out


class Keypad:
    def __init__(self, emu, run, hold=100):
        self.emu, self.run, self.hold = emu, run, hold
        self.q = []                  # (insn, kind, slot), kind 'dn'/'up'
        self.slot = 0
        self.log = []                # (insn, event) for tests
        self.idx = self._load_keymap()
        self.raw = 0
        if self._get(R_STATUS) == 0:
            self._set(R_STATUS, 0x77777777)  # phone rest value: no key in any slot (see _step)

    def _load_keymap(self):
        mu = self.emu.mu
        ptr = struct.unpack("<I", bytes(mu.mem_read(KEYMAP_PTR_LIT, 4)))[0]
        tab = struct.unpack("<64H", bytes(mu.mem_read(ptr, 128)))
        idx = {vk: i for i, vk in enumerate(tab) if vk != 0xffff}
        self.run.log(f"[KPD] keymap at {ptr:#x}: {len(idx)} keys")
        return idx

    def scan_byte(self, key):
        """key_status byte for a key: index (A = idx>>3, B = idx&7) -> B<<4 | A."""
        i = self.idx[VK[key.upper()]]
        return ((i & 7) << 4) | (i >> 3)

    def press(self, key, hold_ms=None, at=None):
        key = key.upper()
        if key not in VK or VK[key] not in self.idx:
            raise ValueError(f"key {key} is not in the keypad matrix")
        t = self.emu.insn_total if at is None else at
        s = self.slot
        self.slot = (s + 1) % 4
        self.q.append((t, "dn", s, key))
        self.q.append((t + int((self.hold if hold_ms is None else hold_ms) * INSN_PER_MS), "up", s, key))
        self.q.sort(key=lambda e: e[0])

    def _set(self, off, v):
        self.emu.mu.mem_write(KPD_BASE + off, struct.pack("<I", v & 0xffffffff))

    def _get(self, off):
        return struct.unpack("<I", bytes(self.emu.mu.mem_read(KPD_BASE + off, 4)))[0]

    def _step(self, mu):
        e = self.emu
        while self.q and self.q[0][0] <= e.insn_total:
            t, kind, s, key = self.q.pop(0)
            # key_status as read on the phone (2026-10-31): unused slots 0x77, a slot keeps its
            # last key's scan byte, bit 7 is set only while that key is down (rest 0x77777731,
            # held 0x777777b4, released 0x77777734). The kernel decode masks bit 7 off.
            st = self._get(R_STATUS)
            if st == 0:
                st = 0x77777777
            if kind == "dn":
                st = st & ~(0xff << (8 * s)) | (self.scan_byte(key) | 0x80) << (8 * s)
                self.raw |= 1 << s
            else:
                st &= ~(0x80 << (8 * s))
                self.raw |= 1 << (4 + s)
            self._set(R_STATUS, st)
            self._set(R_RAW, self.raw)
            self.log.append((e.insn_total, kind, key))
            self.run.log(f"[KPD] {key} {kind} slot{s} raw={self.raw:#x} insn={e.insn_total}")
        if self.raw and (self.raw & self._get(R_EN)):
            e._gic_set_pending(KPD_GIC)      # level IRQ: stays until int_clr

    def _on_write(self, uc, access, addr, size, value, ud):
        if addr & ~3 == KPD_BASE + R_CLR:
            self.raw &= ~(value & 0xfff)
            self._set(R_RAW, self.raw)
            self.emu.gic["pend"].discard(KPD_GIC) if self.raw == 0 else None

    def _on_read(self, uc, access, addr, size, value, ud):
        if addr & ~3 == KPD_BASE + R_RAW:
            self._set(R_RAW, self.raw)


def install(emu, run, opts):
    kp = Keypad(emu, run, hold=int(opts.get("hold", 100)))
    emu.keypad = kp
    emu.mu.hook_add(UC_HOOK_MEM_WRITE, kp._on_write, begin=KPD_BASE, end=KPD_BASE + 0xff)
    emu.mu.hook_add(UC_HOOK_MEM_READ, kp._on_read, begin=KPD_BASE, end=KPD_BASE + 0xff)
    orig = emu._gic_step

    def gic_step(mu):
        kp._step(mu)
        return orig(mu)
    emu._gic_step = gic_step
    # plat_run splits opts on commas: later entries of keys= arrive as bare keys
    spec = ",".join([opts.get("keys", "")] + [k for k in opts if "@" in k])
    if opts.get("keyfile"):
        spec += "\n" + open(opts["keyfile"]).read()
    for key, t, hold in parse_keys(spec, kp.hold):
        kp.press(key, hold, at=t)
        run.log(f"[KPD] scheduled {key} at {t} hold {hold}ms")
    return kp


def press(emu, key, hold_ms=100):
    emu.keypad.press(key, hold_ms)
