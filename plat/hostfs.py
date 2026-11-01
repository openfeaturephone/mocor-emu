"""plat/hostfs.py -- host-backed files for the mmi_app SFS (E:\\apps\\*, D:\\apps\\*, D:\\F286_*).

High-level hooks on the mmi_app SFS entry points (addresses in A below). A call is served
here when it names an intercepted path, or a fake handle (0x7f000000+n); everything
else falls through to the real code. Intercepted paths never fall through: a missing
file returns handle 0 (no SD card / no internal file system in the emulator).

  E:\\apps\\x.bin    -> <root>/apps/x.bin      D:\\apps\\x.bin -> <root>/dapps/x.bin
  D:\\F286_ss_vvvvvvvv.TXT (stub breadcrumbs) -> <root>/crumbs/ (empty file, one log line)

opts: root=<dir> (default hostfs/ in the repo), patched=1|0|<path> (default 1: overlay
the changed ranges of the patched mmi_app image (fwpaths.PATCHED_MMI_APP, built by the
separate MMI app tree) onto the mapped mmi_app, so the boot stub at 0x88904100 and the
Facebook hook exist; use patched=0 to keep stock, which is also what happens when the
patched image is not there).
SFS_FindFirstFile/FindNext/FindClose: served for patterns "D:\\<glob>" from the
crumbs folder only (flat), using the SFS_FIND_DATA layout the phone returns: attr u16
at +0x14, size u32 at +0x18, UTF-16 name at +0x1c. So a directory listing over the
emulated USB link (plat.ucom) works. Other patterns fall through.
"""
import fnmatch
import os
import struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

import fwpaths

HERE = os.path.dirname(os.path.abspath(__file__))
DEF_ROOT = os.path.join(HERE, "..", "hostfs")
PATCHED = fwpaths.PATCHED_MMI_APP
STOCK = fwpaths.MMI_APP
MMI_BASE = 0x88000000
FAKE = 0x7f000000
A = dict(create=0x88085b16, read=0x88086562, write=0x880865ba, close=0x88086530,
         size=0x8808671a, seek=0x8808664e,
         ffirst=0x88086754, fnext=0x88086a54, fclose=0x88086a92)
CREATE_NEW, CREATE_ALWAYS, OPEN_EXISTING, OPEN_ALWAYS, TRUNCATE = 0x10, 0x20, 0x30, 0x40, 0x50


def overlay_patched(emu, run, path):
    """Write the bytes where the patched image differs from stock (code only)."""
    if not os.path.exists(path):
        run.log(f"[HOSTFS] no patched mmi_app at {path}: running the stock image")
        return
    a, b = open(STOCK, "rb").read(), open(path, "rb").read()
    n = i = 0
    while i < min(len(a), len(b)):
        if a[i] == b[i]:
            i += 1
            continue
        j = i
        while j < len(b) and (j >= len(a) or a[j] != b[j]):
            j += 1
        emu.mu.mem_write(MMI_BASE + i, b[i:j])
        n += j - i
        i = j
    run.log(f"[HOSTFS] patched mmi_app overlay: {n} bytes from {os.path.basename(path)}")


class HostFS:
    def __init__(self, emu, run, root):
        self.emu, self.run, self.root = emu, run, os.path.abspath(root)
        self.h = {}                  # handle -> [path, bytearray, pos, writable]
        self.next = FAKE + 1
        self.crumbs = []
        self.finds = {}

    def ustr(self, p):
        mu, out = self.emu.mu, []
        for i in range(260):
            c = struct.unpack("<H", bytes(mu.mem_read(p + 2 * i, 2)))[0]
            if not c:
                break
            out.append(chr(c))
        return "".join(out)

    def host_path(self, gp):
        """guest path -> (host path, kind) or None if not intercepted."""
        g = gp.replace("/", "\\")
        low = g.lower()
        if low.startswith(("e:\\apps\\", "d:\\apps\\")):
            return os.path.join(self.root, "apps" if low[0] == "e" else "dapps", *g[8:].split("\\")), "file"
        if low.startswith("d:\\f286_"):
            return os.path.join(self.root, "crumbs", g[3:]), "crumb"
        return None

    def ret(self, uc, v):
        uc.reg_write(UC_ARM_REG_R0, v & 0xffffffff)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def w32(self, p, v):
        if p:
            self.emu.mu.mem_write(p, struct.pack("<I", v & 0xffffffff))

    def create(self, uc, addr, size, ud):
        gp = self.ustr(uc.reg_read(UC_ARM_REG_R0))
        mode = uc.reg_read(UC_ARM_REG_R1)
        hp = self.host_path(gp)
        if hp is None:
            return
        path, kind = hp
        disp, acc = mode & 0xf0, mode & 0xf
        exists = os.path.isfile(path)
        if kind == "crumb" and disp != OPEN_EXISTING:
            # A real breadcrumb (f286_crumb) always creates with CREATE_ALWAYS, so this
            # still fires for those. D:\F286_NOAGENT / D:\F286_BOOTCNT (the boot
            # stub's kill switches) share the "D:\F286_" prefix but are opened with
            # OPEN_EXISTING to check/read, not to write - that must respect the real
            # on-disk `exists` below, not force-create the file as a side effect.
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "wb").close()
            exists = True
            self.crumbs.append(gp)
            self.run.log(f"[HOSTFS] crumb {gp} (insn {self.emu.insn_total})")
        fail = (disp in (OPEN_EXISTING, TRUNCATE) and not exists) or (disp == CREATE_NEW and exists)
        if disp not in (CREATE_NEW, CREATE_ALWAYS, OPEN_EXISTING, OPEN_ALWAYS, TRUNCATE):
            fail = True
        if fail:
            self.run.log(f"[HOSTFS] open {gp} mode={mode:#x} -> not found/exists, h=0")
            return self.ret(uc, 0)
        data = bytearray()
        if exists and disp not in (CREATE_ALWAYS, TRUNCATE):
            data = bytearray(open(path, "rb").read())
        wr = bool(acc & 2)
        if wr or disp in (CREATE_NEW, CREATE_ALWAYS, TRUNCATE):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if not exists or disp in (CREATE_ALWAYS, TRUNCATE):
                open(path, "wb").close()
        h = self.next
        self.next += 1
        self.h[h] = [path, data, 0, wr]
        self.run.log(f"[HOSTFS] open {gp} mode={mode:#x} -> h={h:#x} size={len(data)}")
        self.ret(uc, h)

    # ---- directory enumeration (crumbs folder only; handle space 0x7e000000+) ----
    def ffirst(self, uc, addr, size, ud):
        gp = self.ustr(uc.reg_read(UC_ARM_REG_R0))
        g = gp.replace("/", "\\")
        if not g.lower().startswith("d:\\") or "\\" in g[3:]:
            return
        cdir = os.path.join(self.root, "crumbs")
        names = sorted(n for n in (os.listdir(cdir) if os.path.isdir(cdir) else [])
                       if fnmatch.fnmatch(n.lower(), g[3:].lower()))
        self.run.log(f"[HOSTFS] find {gp} -> {len(names)} match(es)")
        if not names:
            return self.ret(uc, 0xFFFFFFFF)
        hd = 0x7e000000 + len(self.finds) + 1
        self.finds[hd] = [names, 0, cdir]
        self._fill(uc, hd, uc.reg_read(UC_ARM_REG_R1))
        self.ret(uc, hd)

    def _fill(self, uc, hd, fd):
        names, i, cdir = self.finds[hd]
        n = names[i]
        sz = os.path.getsize(os.path.join(cdir, n))
        rec = bytearray(0x400)
        struct.pack_into("<HxxI", rec, 0x14, 0x20, sz)
        nm = n.encode("utf-16-le") + b"\0\0"
        rec[0x1c:0x1c + len(nm)] = nm
        uc.mem_write(fd, bytes(rec))

    def fnext(self, uc, addr, size, ud):
        hd = uc.reg_read(UC_ARM_REG_R0)
        if hd not in self.finds:
            return
        f = self.finds[hd]
        f[1] += 1
        if f[1] >= len(f[0]):
            return self.ret(uc, 1)
        self._fill(uc, hd, uc.reg_read(UC_ARM_REG_R1))
        self.ret(uc, 0)

    def fclose(self, uc, addr, size, ud):
        hd = uc.reg_read(UC_ARM_REG_R0)
        if hd in self.finds:
            self.ret(uc, 0)

    def _get(self, uc):
        return self.h.get(uc.reg_read(UC_ARM_REG_R0))

    def read(self, uc, addr, size, ud):
        f = self._get(uc)
        if f is None:
            return
        buf, n, outp = (uc.reg_read(r) for r in (UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3))
        d = bytes(f[1][f[2]:f[2] + n])
        if d:
            uc.mem_write(buf, d)
        f[2] += len(d)
        self.w32(outp, len(d))
        self.run.log(f"[HOSTFS] read {os.path.basename(f[0])} {len(d)}/{n}")
        self.ret(uc, 0)

    def write(self, uc, addr, size, ud):
        f = self._get(uc)
        if f is None:
            return
        buf, n, outp = (uc.reg_read(r) for r in (UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3))
        f[1][f[2]:f[2] + n] = bytes(uc.mem_read(buf, n))
        f[2] += n
        with open(f[0], "wb") as fh:             # write-through: survives a stopped run
            fh.write(f[1])
        self.w32(outp, n)
        self.run.log(f"[HOSTFS] write {os.path.basename(f[0])} {n}")
        self.ret(uc, 0)

    def close(self, uc, addr, size, ud):
        h = uc.reg_read(UC_ARM_REG_R0)
        if h in self.h:
            self.run.log(f"[HOSTFS] close {os.path.basename(self.h.pop(h)[0])}")
            self.ret(uc, 0)

    def fsize(self, uc, addr, size, ud):
        f = self._get(uc)
        if f is None:
            return
        self.w32(uc.reg_read(UC_ARM_REG_R1), len(f[1]))
        self.ret(uc, 0)

    def seek(self, uc, addr, size, ud):
        """(h, pad, int64 off in r2:r3, origin at [sp]); origin 0 begin, 1 cur, 2 end."""
        f = self._get(uc)
        if f is None:
            return
        off = uc.reg_read(UC_ARM_REG_R2) | uc.reg_read(UC_ARM_REG_R3) << 32
        if off >> 63:
            off -= 1 << 64
        org = struct.unpack("<I", bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_SP), 4)))[0] & 0xff
        base = (0, f[2], len(f[1]))[org] if org < 3 else 0
        f[2] = max(0, base + off)
        self.ret(uc, 0)


def install(emu, run, opts):
    root = opts.get("root") or DEF_ROOT
    os.makedirs(root, exist_ok=True)
    pat = opts.get("patched", "1")
    if pat not in ("0", ""):
        overlay_patched(emu, run, PATCHED if pat == "1" else pat)
    fs = HostFS(emu, run, root)
    emu.hostfs = fs
    # raw code hooks: they also fire under a bare mu.emu_start (the native block
    # dispatch used for single-address hooks only runs inside emu._loop)
    hook = getattr(emu, "_raw_hook_add", emu.mu.hook_add)
    for name, fn in (("create", fs.create), ("read", fs.read), ("write", fs.write),
                     ("close", fs.close), ("size", fs.fsize), ("seek", fs.seek),
                     ("ffirst", fs.ffirst), ("fnext", fs.fnext), ("fclose", fs.fclose)):
        hook(UC_HOOK_CODE, fn, None, A[name], A[name])
    run.log(f"[HOSTFS] root={fs.root}")
    return fs
