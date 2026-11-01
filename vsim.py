"""vsim.py -- virtual SIM for mocor_emu: USIM controller model + T=0 UICC.

Controller (stock driver usim_drv.c; ISR 0x80c62fae):
  +0x00 TX byte   +0x04 RX byte (pop)   +0x08 raw int   +0x10 int enable
  +0x14 int clear (W1C)   +0x18 CTRL (activate = 0x200|0x800, bit10 deact)
  +0x80 RX count (&0x1ff)   +0x84 TX count
  raw int bit0 = RX data (drain via +0x80/+0x04), bit1 = TX done/empty,
  bit4 = card inactive. Level IRQ: SIM0 table irq 10 (GIC id 0x2a), SIM1 13.

Card: ISO 7816-3 T=0 UICC with a small file system. CLA 0x00 -> UICC/USIM
behaviour (61xx + FCP), CLA 0xA0 -> GSM SIM behaviour (9Fxx + GSM response).
Identities are test-network values (PLMN 001-01), not a real subscription.
"""
from collections import deque


def bcd_swap(digits, pad='F'):
    s = digits + (pad if len(digits) % 2 else '')
    return bytes(int(s[i + 1] + s[i], 16) for i in range(0, len(s), 2))


def imsi_ef(imsi):
    # byte0 = len, byte1 = d1<<4 | parity (9 = odd), then swapped pairs
    d = imsi
    first = (int(d[0]) << 4) | (0x9 if len(d) % 2 else 0x1)
    rest = d[1:]
    rest += 'F' if len(rest) % 2 else ''
    body = bytes([first]) + bytes(int(rest[i + 1] + rest[i], 16)
                                  for i in range(0, len(rest), 2))
    return bytes([len(body)]) + body


USIM_AID = bytes.fromhex("A0000000871002FF49FF0589")

IMSI = "001010123456789"
ICCID = "8900101012345678901"


def _rec(n, ln, fill=0xFF):
    return [bytes([fill]) * ln for _ in range(n)]


class Card:
    """T=0 UICC. Files: {fid: (kind, data)} kind 'T' transparent, 'L' list
    of records, 'D' directory."""

    def __getstate__(self):           # checkpoint: the log callback is per-process
        d = dict(self.__dict__)
        d["log"] = None
        return d

    def __init__(self, log=print):
        self.log = log
        dir_rec = (bytes([0x61, 0x10, 0x4F, 0x0C]) + USIM_AID +
                   bytes([0x50, 0x00]))
        dir_rec = dir_rec + b'\xff' * (0x26 - len(dir_rec))
        ef = {
            0x2FE2: ('T', bcd_swap(ICCID)),                       # ICCID
            0x2F00: ('L', [dir_rec]),                             # EF_DIR
            0x2F05: ('T', b'en' + b'\xff' * 8),                   # PL
            0x6F07: ('T', imsi_ef(IMSI)),                         # IMSI
            0x6FAD: ('T', bytes([0x00, 0x00, 0x00, 0x02])),       # AD, MNC len 2
            0x6F38: ('T', bytes([0x9E, 0x6F, 0x1F, 0x1C, 0x23, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00])),       # UST
            0x6F56: ('T', b'\x00'),                               # EST
            0x6F7E: ('T', b'\xff\xff\xff\xff' + bcd_swap('00101') + b'\xff\xfe\x00\x01'),
            0x6F73: ('T', b'\xff' * 7 + bcd_swap('00101') + b'\xff\xfe\xff\x01'),
            0x6FE3: ('T', b'\xff' * 12 + bcd_swap('00101') + b'\x00\x00\x01'),
            0x6F08: ('T', b'\x07' + b'\xff' * 32),                # KEYS
            0x6F09: ('T', b'\x07' + b'\xff' * 32),                # KEYSPS
            0x6F78: ('T', b'\x00\x01'),                           # ACC
            0x6F7B: ('T', b'\xff' * 12),                          # FPLMN
            0x6F31: ('T', b'\x0a'),                               # HPPLMN
            0x6F46: ('T', b'\x01' + b'EMU-SIM' + b'\xff' * 9),    # SPN
            0x6F05: ('T', b'en' + b'\xff' * 8),                   # LI
            0x6FB7: ('L', _rec(1, 4)),                            # ECC
            0x6F40: ('L', _rec(1, 28)),                           # MSISDN
            0x6F42: ('L', _rec(1, 40)),                           # SMSP
            0x6F3C: ('L', _rec(10, 176, 0x00)),                   # SMS
            0x6F43: ('T', b'\xff\xff'),                           # SMSS
            0x6F5B: ('T', b'\x00' * 6),                           # START-HFN
            0x6F5C: ('T', b'\xff\xff\xff'),                       # THRESHOLD
            0x6FD9: ('T', bcd_swap('00101') + b'\xff' * 12),      # EHPLMN
            0x6F60: ('T', b'\xff' * 50),                          # PLMNwAcT
            0x6F61: ('T', b'\xff' * 50),                          # OPLMNwAcT
            0x6F62: ('T', bcd_swap('00101')[:3] + b'\xc0\x80'),   # HPLMNwAcT
            0x6FC4: ('T', b'\xff' * 32),                          # NETPAR
            0x6F20: ('T', b'\x07'),                               # Kc (GSM)
            0x6F30: ('T', b'\xff' * 30),                          # PLMNsel (GSM)
            0x6F74: ('T', b'\xff' * 7),                           # BCCH (GSM)
            0x6F45: ('T', b'\xff' * 10),                          # CBMI
        }
        self.ef = ef
        self.dirs = {0x3F00, 0x7FFF, 0x7F20, 0x7F10, 0x5F3A, 0x7F25}
        self.cur = 0x3F00
        self.cur_dir = 0x3F00
        self.pending = b''          # GET RESPONSE data
        self.reset_state()

    def reset_state(self):
        self.hdr = b''
        self.need = 0               # data bytes still expected (case 3)
        self.data = b''
        self.cmd = None
        self.pps = None             # PPS request bytes being collected

    # ------------------------------------------------------------------ ATR
    def atr(self):
        self.reset_state()
        self.cur = self.cur_dir = 0x3F00
        # TS=3B direct, T0=0x00: no interface bytes, no historical bytes; T=0
        return bytes([0x3B, 0x00])

    # ------------------------------------------------------------- T=0 link
    CASE3 = {0xA4, 0xD6, 0xDC, 0x20, 0x24, 0x26, 0x28, 0x2C, 0x10, 0xC2, 0x14,
             0x88, 0x89, 0xA2, 0x32, 0x04, 0x44, 0xE2}

    def rx(self, b):
        """terminal -> card byte; returns card -> terminal bytes."""
        if self.pps is not None or (not self.hdr and not self.need and b == 0xFF):
            # PPS (ISO 7816-3 9): PPSS=FF, PPS0 (bits 4-6 say PPS1-3 follow),
            # optional PPS1-3, PCK. Accept by echoing the request unchanged.
            self.pps = (self.pps or b'') + bytes([b])
            if len(self.pps) >= 2:
                n = 3 + bin((self.pps[1] >> 4) & 7).count('1')
                if len(self.pps) == n:
                    req, self.pps = self.pps, None
                    self.log(f"PPS {req.hex()} -> echo")
                    return req
            return b''
        if self.need:
            self.data += bytes([b])
            self.need -= 1
            if self.need:
                return b''
            return self.execute(self.hdr, self.data)
        self.hdr += bytes([b])
        if len(self.hdr) < 5:
            return b''
        cla, ins, p1, p2, p3 = self.hdr
        if ins in self.CASE3 and p3:
            self.need = p3
            self.data = b''
            return bytes([ins])                      # procedure byte: send data
        return self.execute(self.hdr, b'')

    def _sw(self, gsm, sw):
        return bytes(sw)

    def execute(self, hdr, data):
        cla, ins, p1, p2, p3 = hdr
        self.hdr, self.need, self.data = b'', 0, b''
        gsm = (cla == 0xA0)
        out, sw = self.apdu(gsm, ins, p1, p2, p3, data)
        self.log(f"APDU {hdr.hex()} {data.hex()} -> {out.hex()} {bytes(sw).hex()}")
        if out:
            # case 2: procedure byte INS, P3 data bytes (pad/trim), SW
            if p3 == 0:
                return bytes([0x6C, len(out) & 0xFF])
            body = (out + b'\x00' * p3)[:p3]
            return bytes([ins]) + body + bytes(sw)
        return bytes(sw)

    # ---------------------------------------------------------------- APDUs
    def fcp(self, fid):
        if fid in self.dirs:
            pin = bytes.fromhex("C60F900170830101830181830102830182")[:17]
            body = (bytes([0x82, 0x02, 0x78, 0x21, 0x83, 0x02, fid >> 8, fid & 0xFF]) +
                    (bytes([0x84, len(USIM_AID)]) + USIM_AID if fid == 0x7FFF else b'') +
                    bytes([0x8A, 0x01, 0x05]) + pin)
        else:
            kind, d = self.ef[fid]
            if kind == 'T':
                desc = bytes([0x82, 0x02, 0x41, 0x21])
                size = len(d)
            else:
                rl = len(d[0])
                desc = bytes([0x82, 0x05, 0x42, 0x21, 0x00, rl, len(d)])
                size = rl * len(d)
            body = (desc + bytes([0x83, 0x02, fid >> 8, fid & 0xFF, 0x8A, 0x01, 0x05,
                                  0x8B, 0x03, 0x6F, 0x06, 0x01,
                                  0x80, 0x02, size >> 8, size & 0xFF]))
        return bytes([0x62, len(body)]) + body

    def gsm_resp(self, fid):
        if fid in self.dirs:
            # DF: rfu, free mem, fid, type 02, rfu, len 0x0d, file char,
            # #DFs, #EFs, #CHVs, rfu, CHV1 status (0x83 = init, 3 tries)...
            # file char bit8 = 1 -> CHV1 disabled
            return bytes([0, 0, 0x10, 0x00, fid >> 8, fid & 0xFF, 0x02, 0, 0, 0, 0, 0,
                          0x0D, 0x80, 2, 20, 4, 0, 0x83, 0x8A, 0x83, 0x8A, 0, 0x83, 0x8A])
        kind, d = self.ef[fid]
        if kind == 'T':
            size, struct, rl = len(d), 0x00, 0
        else:
            rl = len(d[0])
            size, struct = rl * len(d), 0x01
        return bytes([0, 0, size >> 8, size & 0xFF, fid >> 8, fid & 0xFF, 0x04, 0,
                      0x11, 0xFF, 0x44, 0x01, 0x02, struct, rl])

    def apdu(self, gsm, ins, p1, p2, p3, data):
        ok = (0x90, 0x00)
        if ins == 0xA4:                                    # SELECT
            if p1 == 0x04:                                 # by AID
                fid = 0x7FFF if data[:7] == USIM_AID[:7] else None
            else:
                fid = int.from_bytes(data[-2:], 'big') if len(data) >= 2 else 0x3F00
                if p1 == 0x08 or p1 == 0x09:               # path from MF/current
                    fid = int.from_bytes(data[-2:], 'big')
            if fid is None or not (fid in self.dirs or fid in self.ef):
                return b'', ((0x94, 0x04) if gsm else (0x6A, 0x82))
            self.cur = fid
            if fid in self.dirs:
                self.cur_dir = fid
            if gsm:
                self.pending = self.gsm_resp(fid)
                return b'', (0x9F, len(self.pending))
            if p2 & 0x0C == 0x0C:                          # no data returned
                self.pending = b''
                return b'', ok
            self.pending = self.fcp(fid)
            return b'', (0x61, len(self.pending))
        if ins == 0xC0:                                    # GET RESPONSE
            r, self.pending = self.pending, b''
            return r, ok
        if ins == 0xF2:                                    # STATUS
            fid = self.cur_dir
            return (self.gsm_resp(fid) if gsm else self.fcp(fid)), ok
        if ins == 0xB0:                                    # READ BINARY
            k = self.ef.get(self.cur)
            if not k or k[0] != 'T':
                return b'', ((0x94, 0x08) if gsm else (0x69, 0x81))
            off = (p1 << 8) | p2
            return k[1][off:off + (p3 or 256)] or b'\x00', ok
        if ins == 0xB2:                                    # READ RECORD
            k = self.ef.get(self.cur)
            if not k or k[0] != 'L':
                return b'', ((0x94, 0x08) if gsm else (0x69, 0x81))
            n = p1 if p1 else 1
            if n > len(k[1]):
                return b'', ((0x94, 0x02) if gsm else (0x6A, 0x83))
            return k[1][n - 1], ok
        if ins in (0xD6, 0xDC):                            # UPDATE (accept)
            return b'', ok
        if ins == 0x20:                                    # VERIFY: PIN disabled
            return b'', ok if data else (0x63, 0xC3)
        if ins in (0x10, 0x14, 0xC2):                      # TERMINAL PROFILE/RESPONSE/ENVELOPE
            return b'', ok
        if ins == 0x12:                                    # FETCH: nothing
            return b'', (0x6F, 0x00)
        if ins == 0x70:                                    # MANAGE CHANNEL
            return b'', (0x68, 0x81)
        if ins in (0x88, 0x89):                            # AUTHENTICATE: unsupported
            return b'', (0x98, 0x62) if not gsm else (0x6D, 0x00)
        return b'', ((0x6D, 0x00) if not gsm else (0x6D, 0x00))


class SimCtl:
    """One USIM controller (register model) with an optional card."""

    def __getstate__(self):           # checkpoint: the log callback is per-process
        d = dict(self.__dict__)
        d["log"] = None
        return d

    def __init__(self, base, card, log):
        self.base = base
        self.card = card
        self.log = log
        self.rxq = deque()
        self.raw = 0
        self.en = 0
        self.ctrl = 0
        self.regs = {}
        self.txn = 0

    def irq(self):
        return bool(self.raw & self.en)

    def _rx(self, data):
        for b in data:
            self.rxq.append(b)
        if self.rxq:
            self.raw |= 1

    def read(self, off):
        if off == 0x04:
            v = self.rxq.popleft() if self.rxq else 0
            if not self.rxq:
                self.raw &= ~1
            return v
        if off == 0x08:
            return self.raw | (1 if self.rxq else 0)
        if off == 0x10:
            return self.en
        if off == 0x18:
            return self.ctrl
        if off == 0x80:
            return len(self.rxq) & 0x1FF
        if off == 0x84:
            return 0                       # TX drains instantly
        return self.regs.get(off, 0)

    def write(self, off, v):
        v &= 0xFFFFFFFF
        if off == 0x00:
            self.txn += 1
            if self.card:
                self._rx(self.card.rx(v & 0xFF))
            self.raw |= 2                  # TX done / FIFO empty
            return
        if off == 0x10:
            self.en = v
            return
        if off == 0x14:
            self.raw &= ~v
            return
        if off == 0x18:
            old = self.ctrl
            self.ctrl = v
            act = 0x200 | 0x800
            if (v & act) == act and (old & act) != act:
                if self.card:
                    atr = self.card.atr()
                    self.rxq.clear()
                    self._rx(atr)
                    self.log(f"SIM {self.base:#x}: activate -> ATR {atr.hex()}")
                else:
                    self.log(f"SIM {self.base:#x}: activate, no card")
            if v & 0x400 and not old & 0x400:
                self.log(f"SIM {self.base:#x}: deactivate")
            return
        self.regs[off] = v
