"""emu_call.py -- call one firmware function inside a loaded checkpoint.

Library:
    from emu_call import Harness
    h = Harness("runs/ckpt/IDLE2_5500M.ckpt")
    rep = h.call(0x887eab16, [h.buf("out"), h.buf("a"), h.buf("b")])   # dict
CLI (prints the report as JSON):
    python emu_call.py --ckpt runs/ckpt/IDLE2_5500M.ckpt 0x887eab16 ptr:out pair:0,0 pair:9,9
    arg specs: 0x1234 | 42 | big (0xffffffff) | ptr:NAME[:SIZE[:pat]] zeroed (or 0xA5-
    patterned) scratch buffer | hex:NAME:aabbcc... | str:TEXT (ASCII) | ucs2:TEXT |
    pair:A,B (A | B<<16, a packed GUI_POINT) | rect:l,t,r,b gives TWO args (r1,r2 of a
    by-value GUI_RECT_T). Extra args beyond four go on the stack.
    Entry mode: bit0 of the address; if clear, a function-list TSV (funcs/mmi_funcs.tsv,
    funcs/kernel_funcs.tsv, TMode column; see fwpaths.FUNCS_DIR) or the ARM veneer pattern decides, else Thumb.

Each call: save unicorn context, SVC mode with IRQ/FIQ masked, LR = sentinel in the scratch
arena, no tick/IRQ injection (we never run MocorEmu._loop), run <= budget insns, then restore.
RAM writes are found WITHOUT memory hooks (track="diff", default): the tracked RAM windows
(TRACK_WIN) are read back after the call and compared with a persistent baseline taken at load;
dirty 4K pages are byte-diffed for the report and rewritten from the baseline. Reason: a
UC_HOOK_MEM_WRITE covering a stored address breaks Thumb IT blocks in unicorn 2.1.4 (the next
instruction after `it eq; bxeq lr` is skipped, e.g. after the stock memset tail), so the old
RAM-wide write hooks (track="hook", kept for comparison) changed what callees computed.
Only narrow hooks remain: reads/writes of 0..0xff (null faults) and the MMIO devices. Outcomes: returned | budget | timeout | assert |
fatal_assert | os_block | fault_unmapped | fault_null | invalid_insn | exception | runaway.
Not exact: device-model state (C shadow regs, Python models) is not snapshotted; a call that
wrote an MMIO register sets Harness.dirty; start a fresh process (or auto_reload=True,
unreliable after a few reloads) to get pristine device models. Device registers answered in C (AP DMA, SDHCI, counters) are not logged.
"""
import sys, os, json, time, gc, argparse, struct, ctypes, mmap
import numpy as np
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mocor_emu as ME
import fwpaths
from mocor_emu import Run, MocorEmu
from unicorn import (UC_PROT_ALL, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_HOOK_BLOCK, UC_HOOK_CODE,
                     UcError, UC_ERR_INSN_INVALID)
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)

ME.CELL_TRACE = False
ASSERT_ENTRIES = (0x80a0b07a, 0x80a09414)   # kernel assert / target of mmi veneer 0x880a9be0
LOG_CORE = 0x80a0914c
OS_SUSPEND = 0x80a0cd40            # _tx_thread_suspend: every ThreadX blocking wait ends here
SENT = 0x8f000000                  # return sentinel (zeros, inside the scratch arena)
STACK_LO, STACK_TOP = 0x8f010000, 0x8f030000
HEAP = 0x8f100000                  # scratch buffers (bump allocator, reset per call)
HEAP_END = 0x8f800000
PAGE = 0x1000
# track="hook" only: RAM write-hook windows (everything except the scratch stack)
WRITE_WIN = [(0x0, 0x00ffffff), (0x80000000, STACK_LO - 1), (STACK_TOP, 0xc0100fff),
             (0xfff00000, 0xffffffff)]
# track="diff": RAM windows [lo, hi) read back and compared after each call. They hold every
# nonzero page of the IDLE2 checkpoint (kernel+heaps 0x80000000-0x83000000, mmi_app image
# 0x88000000-0x889fffff) plus the scratch arena above the stack; writes to other (all-zero)
# RAM are not seen: Harness.audit(clean=True) finds and zeroes such pages (bulk workers do
# it every 100 functions).
TRACK_WIN = [(0x0, 0x01000000), (0x80000000, 0x83000000), (0x88000000, 0x88a00000),
             (STACK_TOP, HEAP_END), (0xfff00000, 0x100000000)]
AUDIT_WIN = [(0x83000000, 0x88000000), (0x88a00000, STACK_LO),
             (HEAP_END, 0xc0000000), (0xc0000000, 0xc0100000)]
CHUNK = 0x40000                    # memcmp granularity
_memcmp = (ctypes.cdll.msvcrt if sys.platform == "win32" else ctypes.CDLL(None)).memcmp
_memcmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
_memcmp.restype = ctypes.c_int

_ACTIVE = None                     # Recorder for the call in flight (MMIO patch below reads it)

# --- MMIO logging: patch the Python-routed device models (py=1 regions) before any
# MocorEmu is built (the C bridge binds the bound methods at construction).
_orig_r, _orig_w = MocorEmu._py_mmio_read, MocorEmu._py_mmio_write


def _mm_r(self, addr, size):
    if _ACTIVE is not None:
        _ACTIVE.mmio(addr, "R")
    return _orig_r(self, addr, size)


def _mm_w(self, addr, size, value):
    if _ACTIVE is not None:
        _ACTIVE.mmio(addr, "W")
    return _orig_w(self, addr, size, value)


MocorEmu._py_mmio_read, MocorEmu._py_mmio_write = _mm_r, _mm_w


class Recorder:
    def __init__(self, cap_events=200000):
        self.outcome = None
        self.detail = {}
        self.writes = []            # (addr, size)
        self.n_writes = 0
        self.cap = cap_events
        self.mmio_ct = {}           # (addr, rw) -> count
        self.callees = {}
        self.prev_end = None
        self.insns = 0
        self.blocks = 0
        self.cow = {}               # page -> original bytes
        self.automapped = []
        self.dev_write = False
        self.glog = []
        self.asserts = []
        self.order = []             # first sight of each callee: (addr, insns so far)

    def mmio(self, addr, rw):
        k = (addr, rw)
        self.mmio_ct[k] = self.mmio_ct.get(k, 0) + 1
        if rw == "W":
            self.dev_write = True


class Harness:
    def __init__(self, ckpt, budget=200_000, wall_s=10.0, reload_every=0, auto_reload=False,
                 assert_stop=True, track="diff"):
        self.track = track                  # "diff" (hook-free, default) | "hook" (old write hooks)
        self.ckpt = ckpt
        self.budget = budget
        self.wall_s = wall_s
        self.reload_every = reload_every
        self.assert_stop = assert_stop      # False: record up to 5 asserts and keep running
        self.auto_reload = auto_reload      # in-process reload crashes the native lib after a few
                                            # rounds: prefer exiting the process when .dirty
        self.ncalls = 0
        self.dirty = False
        self.emu = None
        self._insn_cache = {}
        self._funcs_mode = None
        self.n_reloads = 0
        self._load()

    # ------------------------------------------------------------ setup
    def _load(self):
        self.emu = None
        self.rec = None
        gc.collect()
        run = Run(tag="ECALL")
        run.log = lambda *a, **k: None
        self._events = []
        run.ev = self._on_ev
        emu = MocorEmu.ckpt_load(run, self.ckpt, mode="unstick", max_insns=10 ** 15,
                                 timeout_s=10 ** 9, pump=False)
        self.emu = emu
        self.run = run
        mu = self.mu = emu.mu
        emu._glog = self._on_glog                # guest printf tap -> report (no file)
        for f in (run.log_f, run.ev_f, run.uart_f):
            f.close()
        try:
            import shutil
            shutil.rmtree(run.dir, ignore_errors=True)
        except Exception:
            pass
        run.close = lambda: None
        self.rec = None
        if self.track == "hook":
            for lo, hi in WRITE_WIN:
                mu.hook_add(UC_HOOK_MEM_WRITE, self._h_write, begin=lo, end=hi)
        else:
            mu.hook_add(UC_HOOK_MEM_WRITE, self._h_write, begin=0, end=0xff)   # null stores only
        mu.hook_add(UC_HOOK_MEM_READ, self._h_null_read, begin=0, end=0xff)
        mu.hook_add(UC_HOOK_BLOCK, self._h_block, begin=1, end=0)
        for ea in ASSERT_ENTRIES:
            emu._raw_hook_add(UC_HOOK_CODE, self._h_assert, None, begin=ea & ~1, end=ea & ~1)
        emu._raw_hook_add(UC_HOOK_CODE, self._h_fatal, None, begin=LOG_CORE & ~1, end=LOG_CORE & ~1)
        emu._raw_hook_add(UC_HOOK_CODE, self._h_suspend, None, begin=OS_SUSPEND & ~1, end=OS_SUSPEND & ~1)
        mu.mem_write(SENT, bytes(16))
        mu.mem_write(STACK_LO, bytes(STACK_TOP - STACK_LO))
        # run as a real thread (ThreadX current_ptr is NULL in the checkpoint's idle loop)
        rd = lambda a: struct.unpack("<I", bytes(mu.mem_read(a, 4)))[0]
        t = first = rd(0x81701F80)
        while t and rd(t) == 0x54485244:
            if t != 0x81760628:                 # not the System Timer Thread
                mu.mem_write(0x81701F78, struct.pack("<I", t))      # current_ptr
                mu.mem_write(0x81701F7C, struct.pack("<I", t))      # execute_ptr: no preemption
                break
            t = rd(t + 0xa8)
            if t == first:
                break
        self._win = []
        if self.track == "diff":
            self._map_windows()
        self._audit_nz = None
        self.ctx0 = mu.context_save()
        self.hw0 = dict(emu.hw_regs)
        self.pc0 = mu.reg_read(UC_ARM_REG_PC)
        self.dirty = False
        self._heap_used = 0
        self._bufs = {}
        self._csd = {}
        try:
            import capstone
            self._cs = {0: capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
                        1: capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)}
        except Exception:
            self._cs = None

    def _on_glog(self, line, *a, **k):
        r = self.rec
        if r is not None and len(r.glog) < 12:
            r.glog.append(str(line)[:200])

    def _on_ev(self, etype, **kw):
        r = self.rec
        if r is not None and etype == "AUTOMAP":
            page = int(kw["addr"], 16)
            r.automapped.append(page)
            if r.outcome is None:
                r.outcome = "fault_unmapped"
                r.detail = {"addr": kw["addr"], "access": kw.get("access"), "pc": kw.get("pc")}
                self.mu.emu_stop()

    def close(self):
        self.emu = None
        gc.collect()

    # ------------------------------------------------------------ hooks
    def _h_write(self, uc, access, addr, size, value, ud):
        r = self.rec
        if r is None:
            return
        r.n_writes += 1
        if addr < 0x100 and r.outcome is None:
            r.outcome = "fault_null"
            r.detail = {"addr": hex(addr), "rw": "W"}
            uc.emu_stop()
            return
        if self.track != "hook":
            return
        if len(r.writes) < r.cap:
            r.writes.append((addr, size))
        cow = r.cow
        pg = addr & ~0xfff
        if pg not in cow:
            cow[pg] = bytes(uc.mem_read(pg, PAGE))
        if ((addr + size - 1) & ~0xfff) != pg:
            pg2 = (addr + size - 1) & ~0xfff
            if pg2 not in cow:
                cow[pg2] = bytes(uc.mem_read(pg2, PAGE))

    def _h_null_read(self, uc, access, addr, size, value, ud):
        r = self.rec
        if r is not None and r.outcome is None:
            r.outcome = "fault_null"
            r.detail = {"addr": hex(addr), "rw": "R"}
            uc.emu_stop()

    def _h_block(self, uc, addr, size, ud):
        r = self.rec
        if r is None:
            return
        addr &= ~1
        if addr < 0x2000 and r.outcome is None:      # low blob = exception / context-switch stubs
            r.outcome = "os_switch"
            r.detail = {"blk": hex(addr)}
            uc.emu_stop()
            return
        key = (addr, size)
        n = self._insn_cache.get(key)
        if n is None:
            n = max(1, size // 4)
            if self._cs:
                th = 1 if uc.reg_read(UC_ARM_REG_CPSR) & 0x20 else 0
                try:
                    code = bytes(uc.mem_read(addr, size))
                    n = sum(1 for _ in self._cs[th].disasm_lite(code, addr)) or n
                except Exception:
                    pass
            self._insn_cache[key] = n
        r.insns += n
        r.blocks += 1
        pe = r.prev_end
        if pe is not None and addr != pe and (uc.reg_read(UC_ARM_REG_LR) & ~1) == pe:
            c = r.callees
            if addr in c:
                c[addr] += 1
            elif len(c) < 1024:
                c[addr] = 1
                r.order.append((addr, r.insns))
        r.prev_end = addr + size

    def _regs(self):
        u = self.mu
        return [u.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]

    def _h_assert(self, uc, address, size, ud):
        r = self.rec
        if r is None:
            return
        a = self._regs()
        d = {"expr": self.emu._rd_cstr(uc, a[0]), "file": self.emu._rd_cstr(uc, a[1]), "line": a[2],
             "lr": hex(uc.reg_read(UC_ARM_REG_LR))}
        for k in ("expr", "file"):               # 0x80a09414 has other callers: need real strings
            v = d[k]
            if not v or v == "?" or not all(32 <= ord(c) < 127 for c in v):
                return
        if len(r.asserts) < 5:
            r.asserts.append(d)
        if self.assert_stop and r.outcome is None:
            r.outcome = "assert"
            r.detail = d
            uc.emu_stop()

    def _h_fatal(self, uc, address, size, ud):
        r = self.rec
        if r is not None and r.outcome is None:
            a = self._regs()
            r.outcome = "fatal_assert"
            r.detail = {"expr": self.emu._rd_cstr(uc, a[0]), "file": self.emu._rd_cstr(uc, a[1]),
                        "line": a[2], "msg": self.emu._rd_cstr(uc, a[3])}
            uc.emu_stop()

    def _h_suspend(self, uc, address, size, ud):
        r = self.rec
        if r is not None and r.outcome is None:
            r.outcome = "os_block"
            r.detail = {"lr": hex(uc.reg_read(UC_ARM_REG_LR))}
            uc.emu_stop()

    # ------------------------------------------------------------ args
    def buf(self, name, size=PAGE, data=None, pat=None):
        """Allocate a scratch buffer (zeroed, or filled with byte `pat`/`data`). Returns
        its address; contents/changes are reported under `name`."""
        size = (size + 15) & ~15
        a = HEAP + self._heap_used
        if a + size > HEAP_END:
            raise MemoryError("scratch arena full")
        self._heap_used += (size + 0xfff) & ~0xfff
        init = bytearray(size) if pat is None else bytearray([pat]) * size
        if data:
            init[:len(data)] = data
        self.mu.mem_write(a, bytes(init))
        self._bufs[name] = (a, size, bytes(init))
        return a

    def cstr(self, name, text):
        return self.buf(name, 256, text.encode("latin1") + b"\0")

    def ucs2(self, name, text):
        return self.buf(name, 512, text.encode("utf-16-le") + b"\0\0")

    def parse_arg(self, spec, idx):
        """CLI-style arg spec -> list of words (rect: gives two)."""
        s = spec.strip()
        if s.startswith("ptr:"):
            p = s.split(":")
            size = int(p[2], 0) if len(p) > 2 and p[2] else PAGE
            pat = int(p[3], 0) if len(p) > 3 else None
            return [self.buf(p[1], size, pat=pat)]
        if s.startswith("hex:"):
            _, nm, hx = s.split(":", 2)
            return [self.buf(nm, max(PAGE, len(hx) // 2), data=bytes.fromhex(hx))]
        if s.startswith("str:"):
            return [self.cstr(f"str{idx}", s[4:])]
        if s.startswith("ucs2:"):
            return [self.ucs2(f"ucs{idx}", s[5:])]
        if s.startswith("pair:"):
            a, b = (int(x, 0) for x in s[5:].split(","))
            return [(a & 0xffff) | (b & 0xffff) << 16]
        if s.startswith("rect:"):
            l, t, r, b = (int(x, 0) for x in s[5:].split(","))
            return [(l & 0xffff) | (t & 0xffff) << 16, (r & 0xffff) | (b & 0xffff) << 16]
        if s == "big":
            return [0xffffffff]
        return [int(s, 0) & 0xffffffff]

    # ------------------------------------------------------------ mode
    def mode_of(self, addr):
        """1 = Thumb, 0 = ARM for an even entry address (no bit0)."""
        if self._funcs_mode is None:
            self._funcs_mode = {}
            for fn in ("mmi_funcs.tsv", "kernel_funcs.tsv"):
                p = os.path.join(fwpaths.FUNCS_DIR, fn)
                if os.path.exists(p):
                    for line in open(p):
                        t = line.rstrip("\n").split("\t")
                        if len(t) >= 5 and t[4] in ("0", "1"):
                            self._funcs_mode[int(t[1], 16)] = int(t[4])
        m = self._funcs_mode.get(addr)
        if m is not None:
            return m
        try:
            w = struct.unpack("<I", bytes(self.mu.mem_read(addr, 4)))[0]
        except UcError:
            return 1
        return 0 if w == 0xe51ff004 else 1

    # ------------------------------------------------------------ call
    def call(self, fn, args=(), budget=None, wall_s=None, force_arm=False):
        """Run fn(*args) and return the report dict. `args` are ints (use buf()/cstr()/...
        beforehand for pointers). Call reset_args() is automatic after each call."""
        global _ACTIVE
        if self.auto_reload and (self.dirty or (self.reload_every and self.ncalls and
                                                self.ncalls % self.reload_every == 0)):
            bufs = self._bufs
            used = self._heap_used
            self._load()
            self.n_reloads += 1
            self._bufs, self._heap_used = bufs, used
            for a, sz, init in bufs.values():
                self.mu.mem_write(a, init)
        self.ncalls += 1
        budget = budget or self.budget
        wall = wall_s or self.wall_s
        mu, emu = self.mu, self.emu
        thumb = fn & 1
        if not thumb and not force_arm and self.mode_of(fn):
            fn |= 1
            thumb = 1
        entry = fn
        r = self.rec = Recorder()
        _ACTIVE = r
        t0 = time.time()
        mu.context_restore(self.ctx0)
        mu.reg_write(UC_ARM_REG_CPSR, 0xd3 | (0x20 if thumb else 0))
        sp = STACK_TOP - 0x40
        args = [a & 0xffffffff for a in args]
        extra = args[4:]
        if extra:
            sp -= (len(extra) * 4 + 7) & ~7
            mu.mem_write(sp, struct.pack("<%dI" % len(extra), *extra))
        for i in range(4):
            mu.reg_write(UC_ARM_REG_R0 + i, args[i] if i < len(args) else 0)
        for i in range(4, 12):
            mu.reg_write(UC_ARM_REG_R0 + i, 0)
        mu.reg_write(UC_ARM_REG_SP, sp)
        mu.reg_write(UC_ARM_REG_LR, SENT | thumb)
        emu._gic_waiting = False
        old_strict = ME.STRICT
        ME.STRICT = True                 # on_invalid must raise, not skip/return-to-lr
        err = None
        start = entry
        try:
            while True:
                emu.stop_reason = None
                emu._stop_cause = None
                emu._py_exc = None
                if getattr(emu, "_native", False):
                    emu.nst.est = 0
                    emu.nst.insn_now = emu.insn_total
                left = budget - r.insns
                if left <= 0:
                    r.outcome = r.outcome or "budget"
                    break
                rem_us = int((wall - (time.time() - t0)) * 1e6)
                if rem_us <= 0:
                    r.outcome = r.outcome or "timeout"
                    break
                try:
                    mu.emu_start(start, SENT, count=left, timeout=rem_us)
                except UcError as e:
                    err = e
                pc = mu.reg_read(UC_ARM_REG_PC)
                if emu._py_exc is not None:
                    r.outcome = r.outcome or "harness_error"
                    import traceback
                    r.detail.setdefault("py_exc", "".join(traceback.format_exception(
                        type(emu._py_exc), emu._py_exc, emu._py_exc.__traceback__))[-600:])
                    break
                if r.outcome:
                    break
                if err is not None:
                    es = str(err)
                    if "Invalid instruction" in es or "INSN_INVALID" in es:
                        r.outcome = "invalid_insn"
                    elif "exception" in es.lower():
                        r.outcome = "exception"
                    else:
                        r.outcome = "fault_unmapped"
                    r.detail = {"err": es, "pc": hex(pc)}
                    break
                if (pc & ~1) == SENT:
                    r.outcome = "returned"
                    break
                if emu.stop_reason and str(emu.stop_reason) == "fatal-assert":
                    fl, _, ex = str(emu.stop_detail).partition(" ")
                    f_, _, ln = fl.rpartition(":")
                    r.outcome = "fatal_assert"
                    r.detail = {"expr": ex, "file": f_, "line": ln}
                    break
                if emu.stop_reason:
                    r.outcome = "exception" if str(emu.stop_reason).startswith("exception") else "fault_unmapped"
                    r.detail = {"stop_reason": emu.stop_reason, "pc": hex(pc)}
                    break
                if time.time() - t0 >= wall:
                    r.outcome = "timeout"
                    break
                if emu._stop_cause:         # a device model asked for a chunk boundary: resume
                    start = pc | (1 if mu.reg_read(UC_ARM_REG_CPSR) & 0x20 else 0)
                    continue
                if r.insns >= budget:
                    r.outcome = "budget"
                    break
                start = pc | (1 if mu.reg_read(UC_ARM_REG_CPSR) & 0x20 else 0)
        finally:
            ME.STRICT = old_strict
            _ACTIVE = None
        pc = mu.reg_read(UC_ARM_REG_PC)
        regs = [mu.reg_read(UC_ARM_REG_R0), mu.reg_read(UC_ARM_REG_R1)]
        if r.outcome == "budget":
            try:
                if int.from_bytes(bytes(mu.mem_read(pc & ~1, 4)), "little") == 0:
                    r.outcome = "runaway"
            except UcError:
                r.outcome = "runaway"
        if self.track == "diff":
            self._diff(r)
        rep = self._report(fn, args, r, regs, pc, time.time() - t0)
        self._restore(r)
        return rep

    # ------------------------------------------------------------ report/restore
    def _where(self, a):
        for nm, (b, sz, _) in self._bufs.items():
            if b <= a < b + sz:
                return f"{nm}+{a - b:#x}"
        return None

    def _map_windows(self):
        """Back each TRACK_WIN window with a host buffer we own (mem_map_ptr), plus a baseline
        copy of it: diffing is then a memcmp over host memory, no mem_read copies."""
        mu = self.mu
        for lo, hi in TRACK_WIN:
            size = hi - lo
            data = mu.mem_read(lo, size)
            live, base = mmap.mmap(-1, size), mmap.mmap(-1, size)
            live[:] = data
            base[:] = data
            la = ctypes.addressof(ctypes.c_char.from_buffer(live))
            ba = ctypes.addressof(ctypes.c_char.from_buffer(base))
            mu.mem_unmap(lo, size)
            mu.mem_map_ptr(lo, size, UC_PROT_ALL, la)
            self._win.append((lo, size, live, base, la, ba))

    def _basepage(self, pg):
        for lo, size, live, base, la, ba in self._win:
            if lo <= pg < lo + size:
                return bytes(base[pg - lo:pg - lo + PAGE])

    def _diff(self, r):
        """Hook-free write detection: compare the tracked windows with the baseline. Fills
        r.dirty {page: current bytes} and r.writes = byte-diff ranges (addr, size) against
        the baseline + the argument buffers we wrote before the call."""
        dirty = r.dirty = {}
        for lo, size, live, base, la, ba in self._win:
            for off in range(0, size, CHUNK):
                n = min(CHUNK, size - off)
                if _memcmp(la + off, ba + off, n) == 0:
                    continue
                ca = np.frombuffer(live, np.uint8, n, off).reshape(-1, PAGE)
                bb = np.frombuffer(base, np.uint8, n, off).reshape(-1, PAGE)
                for i in np.flatnonzero((ca != bb).any(axis=1)):
                    i = int(i)
                    dirty[lo + off + i * PAGE] = bytes(ca[i])
        over = {}                            # reference pages overlapping argument buffers
        for b0, sz, init in self._bufs.values():
            a, left, src = b0, sz, 0
            while left > 0:
                pg = a & ~0xfff
                n = min(left, pg + PAGE - a)
                if pg not in over:
                    over[pg] = bytearray(self._basepage(pg))
                over[pg][a - pg:a - pg + n] = init[src:src + n]
                a, left, src = a + n, left - n, src + n
        runs = []
        for pg in sorted(dirty):
            ra = np.frombuffer(over[pg] if pg in over else self._basepage(pg), np.uint8)
            idx = np.flatnonzero(np.frombuffer(dirty[pg], np.uint8) != ra)
            if not len(idx):
                continue
            for seg in np.split(idx, np.flatnonzero(np.diff(idx) > 1) + 1):
                lo, n = pg + int(seg[0]), int(seg[-1]) - int(seg[0]) + 1
                if runs and lo - (runs[-1][0] + runs[-1][1]) <= 3:      # same word: one range
                    runs[-1][1] = lo + n - runs[-1][0]
                else:
                    runs.append([lo, n])
        r.writes = [(a, n) for a, n in runs]
        r.n_writes = sum(n for _, n in runs)       # dirty bytes (hook mode: store count)

    def audit_snapshot(self):
        """Call right after load: remember which untracked pages are nonzero."""
        self._audit_nz = set(self.audit(snap=True))
        return len(self._audit_nz)

    def audit(self, snap=False, clean=False):
        """Nonzero 4K pages of mapped RAM outside TRACK_WIN that were not nonzero at
        audit_snapshot(): writes the diff cannot see (~1 s). clean=True zeroes them again
        (stray stores through garbage pointers must not leak into later calls)."""
        out = []
        for lo, hi in AUDIT_WIN:
            for a in range(lo, hi, 0x1000000):
                n = min(0x1000000, hi - a)
                m = np.frombuffer(self.mu.mem_read(a, n), np.uint8).reshape(-1, PAGE)
                for i in np.flatnonzero(m.any(axis=1)):
                    p = a + int(i) * PAGE
                    if snap or p not in self._audit_nz:
                        out.append(p)
                        if clean:
                            self.mu.mem_write(p, bytes(PAGE))
        return out

    def _report(self, fn, args, r, regs, pc, dt):
        rng = sorted(r.writes)
        merged = []
        hookmode = self.track == "hook"
        for a, s in rng:
            if merged and a <= merged[-1][1]:
                if a + s > merged[-1][1]:
                    merged[-1][1] = a + s
                merged[-1][2] += 1 if hookmode else s
            else:
                merged.append([a, a + s, 1 if hookmode else s])
        writes = []
        for lo, hi, n in merged[:200]:
            w = {"lo": hex(lo), "hi": hex(hi), "n": n}
            wh = self._where(lo)
            if wh:
                w["buf"] = wh
            writes.append(w)
        mm = {}
        for (a, rw), n in r.mmio_ct.items():
            mm[(a, rw)] = n
        mmio = [{"addr": hex(a), "rw": rw, "n": n} for (a, rw), n in sorted(mm.items())[:64]]
        bufout = {}
        for nm, (b, sz, init) in self._bufs.items():
            now = bytes(self.mu.mem_read(b, min(sz, 64)))
            if now != init[:len(now)]:
                bufout[nm] = now.hex()
        rep = {"fn": hex(fn & ~1), "mode": "T" if fn & 1 else "A", "outcome": r.outcome,
               "ret": hex(regs[0]), "ret1": hex(regs[1]), "insns": r.insns, "blocks": r.blocks,
               "pc_end": hex(pc), "ms": round(dt * 1000, 1),
               "n_callees": len(r.callees),
               "callees": [hex(a) for a in sorted(r.callees)[:128]],
               "callee_order": [[hex(a), n] for a, n in r.order[:200]],
               "n_writes": r.n_writes, "n_write_ranges": len(merged), "writes": writes,
               "mmio": mmio, "buf_changes": bufout}
        if r.asserts:
            rep["asserts"] = r.asserts
        if r.outcome in ("assert", "fatal_assert"):
            rep["assert"] = r.detail
        elif r.detail:
            rep["detail"] = r.detail
        if r.glog:
            rep["guest_log"] = r.glog
        if r.automapped:
            rep["automapped"] = [hex(p) for p in r.automapped]
        rep["dirty_dev"] = r.dev_write
        return rep

    def _restore(self, r):
        mu, emu = self.mu, self.emu
        for pg, data in r.cow.items():
            mu.mem_write(pg, data)
        for pg in getattr(r, "dirty", ()):
            mu.mem_write(pg, self._basepage(pg))
        for pg in r.automapped:
            try:
                mu.mem_unmap(pg, PAGE)
            except UcError:
                pass
        # scratch arena: zero what the call (or the arg builders) used
        if self._heap_used:
            mu.mem_write(HEAP, bytes(self._heap_used))
        mu.mem_write(STACK_TOP - 0x1000, bytes(0x1000))
        mu.mem_write(SENT, bytes(16))
        mu.context_restore(self.ctx0)
        emu.hw_regs.clear()
        emu.hw_regs.update(self.hw0)
        if r.dev_write:
            self.dirty = True
        self._heap_used = 0
        self._bufs = {}
        self.rec = None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("fn")
    ap.add_argument("args", nargs="*")
    ap.add_argument("--ckpt", default=fwpaths.IDLE_CKPT)
    ap.add_argument("--budget", type=lambda x: int(float(x)), default=200_000)
    ap.add_argument("--wall", type=float, default=10.0)
    ap.add_argument("--keep-going", action="store_true", help="do not stop at non-fatal asserts")
    ap.add_argument("--arm", action="store_true", help="force ARM entry")
    ap.add_argument("--hook-writes", action="store_true",
                    help="old RAM-wide write hooks (breaks IT blocks; comparison only)")
    ap.add_argument("--repeat", type=int, default=1, help="call N times (state-restore check)")
    a = ap.parse_args()
    h = Harness(a.ckpt, budget=a.budget, wall_s=a.wall, assert_stop=not a.keep_going,
                track="hook" if a.hook_writes else "diff")
    fn = int(a.fn, 0)
    if a.arm:
        fn &= ~1
    for _ in range(a.repeat):
        words = []
        for i, s in enumerate(a.args):
            words += h.parse_arg(s, i)
        rep = h.call(fn, words, force_arm=a.arm)
        print(json.dumps(rep, indent=1))


if __name__ == "__main__":
    main()
