"""plat.ucom -- model of the kernel UCOM serial ops, bridged to a localhost TCP server, so the PC
client of the f286dbg debug agent (an MMI app from the separate app tree; its PC client connects
with --emu HOST:PORT) can talk to the agent running in the emulator.

  plat_run.py TAG ... --plugin ucom[:port=5555,connect=5s,delay=2ms,wait=1,wait_s=600,exit=1,busy=1]
  python app_test.py f286dbg --run 30 --plugin ucom

How: UC_HOOK_CODE at the entry of each UCOM op (addresses are read from the ops table 0x814c8154
and checked against the expected ones) and the function is replaced; no memory hooks (unicorn
IT-block bug, see docs/gotchas.md). Callbacks are delivered by tail-calling the registered cb
from the hooked op (r0 = event, LR untouched), so the guest callback returns straight to the op's
caller.
  open  0x80d49228  records cb, tail-calls cb(2)            close 0x80d49250  tail-calls cb(3)
  pump  0x80d49402  after USB_START(4)+`connect` virtual time, the first pump of each open channel
                    tail-calls cb(1) (the 5 s "UCOM Detect Timer"); then cb(0) when RX bytes wait
  read  0x80d49282  pops min(len, 0x800, pending) from the TCP receive queue (channel 0 only)
  write 0x80d492f8 / 0x80d4934e  refused (returns 0) until connected. Models the ASYNC transfer
        found in the decompile (FUN_80afa3f0): the buffer is read `delay` after the call, not at the
        call, and a write while a transfer is pending is silently dropped (returns len). The
        transfer also needs a TCP client (the host must read the IN pipe); with `busy=1` the busy
        flag the agent polls ([[0x817040d0] pipe -> [0x818fc800+pipe*0x20] desc -> desc+0x20]) is
        modelled in kernel RAM (only if those words are currently zero). A buffer modified before
        completion is logged as "[UCOM] TX buffer changed in flight".
  USB_START 0x81329de2 / USB_STOP 0x81329e5e / USB_CURRENT 0x81329ddc are replaced (service number).
Options: port, host (127.0.0.1), connect (5s virtual), delay (2ms), wait=1 block the emulator when
channel 0 connects until a client is there (wait_s max, wall), exit=1 stop the run 0.3 s virtual
after the last channel closes, busy=1.
"""
import select
import socket
import struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_LR,
                               UC_ARM_REG_PC)
from . import keypad

OPS = 0x814c8154
EXPECT = {0: 0x80d49228, 1: 0x80d49250, 2: 0x80d49402, 3: 0x80d49282, 4: 0x80d492f8, 7: 0x80d4934e,
          11: 0x80d49402}
USB_START, USB_STOP, USB_CURRENT = 0x81329de2, 0x81329e5e, 0x81329ddc
PIPE_TAB, DESC_TAB = 0x817040d0, 0x818fc800
DESC_ADDR = 0x82fffe00                    # fake transfer descriptor (zero kernel RAM at the end of the heap window)
_S = {}                                   # plugin state: checkpoints pickle emu attributes, keep it off emu


def _rd(uc, a, n=4):
    return int.from_bytes(bytes(uc.mem_read(a, n)), "little")


def _log(run, msg):
    run.log(f"[UCOM ] {msg}")


class Net:
    def __init__(self, host, port):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, port))
        self.srv.listen(1)
        self.cli = None
        self.rx = bytearray()
        self.new = False

    def accept(self, timeout=0.0):
        r, _, _ = select.select([self.srv], [], [], timeout)
        if r:
            c, _ = self.srv.accept()
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.cli:
                self.cli.close()
            self.cli = c
            self.new = True
            return True
        return False

    def poll(self):
        self.accept(0.0)
        while self.cli:
            r, _, _ = select.select([self.cli], [], [], 0)
            if not r:
                break
            try:
                d = self.cli.recv(65536)
            except OSError:
                d = b""
            if not d:
                self.cli.close()
                self.cli = None
                break
            self.rx += d

    def send(self, data):
        if not self.cli:
            return False
        try:
            self.cli.sendall(data)
            return True
        except OSError:
            self.cli = None
            return False


def _tail_cb(uc, ch, event):
    """continue into the registered callback instead of returning (LR is the op's caller)"""
    uc.reg_write(UC_ARM_REG_R0, event)
    uc.reg_write(UC_ARM_REG_PC, _S["cb"][ch])


def _ret(uc, v):
    uc.reg_write(UC_ARM_REG_R0, v & 0xFFFFFFFF)
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))


def _complete(emu, uc, force=False):
    """finish a pending TX transfer: read the guest buffer NOW (async DMA model) and send it"""
    t = _S.get("tx")
    if not t or (emu.insn_total < t["due"] and not force):
        return
    net = _S["net"]
    if not net.cli:
        return                            # host is not reading: the transfer stays pending
    cur = bytes(uc.mem_read(t["buf"], t["len"]))
    if cur != t["snap"]:
        _S["tx_changed"] += 1
        _log(emu.run, f"TX buffer changed in flight ({t['buf']:#x}, {t['len']} B, since insn {t['at']})")
    net.send(cur)
    _S["tx_done"] += 1
    _S["tx"] = None
    if _S["desc"]:
        uc.mem_write(_S["desc"] + 0x20, bytes(4))


def install(emu, run, opts):
    uc = emu.mu
    _S.clear()
    _S.update(cb={}, open=set(), conn=set(), svc=0, deadline=None, tx=None, tx_done=0, tx_changed=0,
              tx_dropped=0, tx_refused=0, rx_bytes=0, tx_bytes=0, stop_at=None, desc=0, logged_conn=False,
              connect=keypad.parse_time(opts.get("connect", "5s")),
              delay=keypad.parse_time(opts.get("delay", "2ms")),
              wait=opts.get("wait", "1") == "1", wait_s=float(opts.get("wait_s", 600)),
              exit=opts.get("exit", "1") == "1")
    port = int(opts.get("port", 5555))
    _S["net"] = Net(opts.get("host", "127.0.0.1"), port)
    tab = struct.unpack("<12I", bytes(uc.mem_read(OPS, 48)))
    for i, want in EXPECT.items():
        if (tab[i] & ~1) != want:
            _log(run, f"WARNING ops[{i}] = {tab[i]:#x}, expected {want | 1:#x}")
    if opts.get("busy", "1") == "1" and _rd(uc, PIPE_TAB) == 0 and _rd(uc, DESC_TAB) == 0 \
            and _rd(uc, DESC_ADDR + 0x20) == 0:
        uc.mem_write(DESC_TAB, struct.pack("<I", DESC_ADDR))
        _S["desc"] = DESC_ADDR
    add = getattr(emu, "_raw_hook_add", uc.hook_add)

    def hook(addr, fn):
        add(UC_HOOK_CODE, lambda u, a, s, d: fn(u), None, addr, addr)

    def r(n):
        return uc.reg_read((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)[n])

    def h_start(u):
        _S["svc"] = r(0)
        _S["conn"].clear()
        _S["deadline"] = emu.insn_total + _S["connect"] if _S["svc"] == 4 else None
        _log(run, f"USB_START({_S['svc']}) at insn {emu.insn_total}"
             + (f", channels connect at {_S['deadline']}" if _S["deadline"] else ""))
        _ret(u, 0)

    def h_stop(u):
        _log(run, f"USB_STOP({r(0)}) at insn {emu.insn_total}")
        _S["svc"] = 0
        _S["deadline"] = None
        _S["conn"].clear()
        _ret(u, 0)

    def h_current(u):
        _ret(u, _S["svc"])

    def h_open(u):
        ch, cb = r(0), r(2)
        _S["cb"][ch] = cb
        _S["open"].add(ch)
        _log(run, f"open({ch}) cb={cb:#x}")
        _tail_cb(u, ch, 2)

    def h_close(u):
        ch = r(0)
        if ch not in _S["open"]:
            _ret(u, 4)
            return
        _S["open"].discard(ch)
        _S["conn"].discard(ch)
        _log(run, f"close({ch}) at insn {emu.insn_total}")
        if not _S["open"] and _S["exit"]:
            _S["stop_at"] = emu.insn_total + 60_000_000
        _tail_cb(u, ch, 3)

    def h_pump(u):
        ch = r(0)
        net = _S["net"]
        net.poll()
        _complete(emu, u)
        if ch not in _S["open"]:
            _ret(u, 0)
            return
        dl = _S["deadline"]
        if ch not in _S["conn"] and dl is not None and emu.insn_total >= dl:
            _S["conn"].add(ch)
            _log(run, f"channel {ch} connected (event 1) at insn {emu.insn_total}")
            if ch == 0 and _S["wait"] and not net.cli:
                _log(run, f"waiting for a client on port {port} (up to {_S['wait_s']:.0f} s)")
                net.accept(_S["wait_s"])
            _tail_cb(u, ch, 1)
            return
        if ch == 0 and ch in _S["conn"] and net.rx:
            _tail_cb(u, ch, 0)
            return
        _ret(u, 0)

    def h_read(u):
        ch, buf, ln = r(0), r(1), r(2)
        if ch not in _S["open"]:
            _ret(u, 1)
            return
        if ch != 0:
            _ret(u, 0)
            return
        d = bytes(_S["net"].rx[:min(ln, 0x800)])
        del _S["net"].rx[:len(d)]
        if d:
            u.mem_write(buf, d)
            _S["rx_bytes"] += len(d)
        _ret(u, len(d))

    def h_write(u):
        ch, buf, ln = r(0), r(1), r(2)
        _complete(emu, u)
        if ch not in _S["open"]:
            _ret(u, 1)
            return
        if ch not in _S["conn"]:
            _S["tx_refused"] += 1
            _ret(u, 0)
            return
        if ch != 0:
            _ret(u, ln)
            return
        if _S["tx"] is not None:           # real driver: busy descriptor -> nothing happens, still returns len
            _S["tx_dropped"] += 1
            _log(run, f"write of {ln} B while a transfer is pending: DROPPED (as the kernel does)")
            _ret(u, ln)
            return
        _S["tx"] = dict(buf=buf, len=ln, snap=bytes(u.mem_read(buf, ln)), due=emu.insn_total + _S["delay"],
                        at=emu.insn_total)
        _S["tx_bytes"] += ln
        if _S["desc"]:
            u.mem_write(_S["desc"] + 0x20, struct.pack("<I", 1))
        _ret(u, ln)

    for addr, fn in ((USB_START, h_start), (USB_STOP, h_stop), (USB_CURRENT, h_current),
                     (EXPECT[0], h_open), (EXPECT[1], h_close), (EXPECT[2], h_pump), (EXPECT[3], h_read),
                     (EXPECT[4], h_write), (EXPECT[7], h_write)):
        hook(addr, fn)
    # chunk-granular stop request and transfer completion between pumps
    orig = emu._gic_step

    def gic_step(mu):
        _complete(emu, mu)
        if _S["stop_at"] is not None and emu.insn_total >= _S["stop_at"]:
            _S["stop_at"] = None
            emu.stop_reason = "ucom-exit"
            emu.stop_detail = "agent closed all UCOM channels"
            mu.emu_stop()
        return orig(mu)
    emu._gic_step = gic_step
    _log(run, f"armed: TCP {opts.get('host', '127.0.0.1')}:{port}, connect after {_S['connect']} insns, "
              f"tx delay {_S['delay']} insns, busy descriptor {'at %#x' % _S['desc'] if _S['desc'] else 'not modelled'}")


def finish(emu, run, opts):
    run.log(f"[UCOM ] done: rx {_S.get('rx_bytes')} B, tx {_S.get('tx_bytes')} B in {_S.get('tx_done')} transfers, "
            f"dropped {_S.get('tx_dropped')}, refused {_S.get('tx_refused')}, buffer-changed {_S.get('tx_changed')}")
    net = _S.get("net")
    if net:
        if net.cli:
            net.cli.close()
        net.srv.close()
