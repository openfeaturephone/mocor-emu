"""kdis.py -- static look at the stock kernel image: annotated disassembly, word dumps, literal search.

The kernel partition is loaded with file offset F at VA 0x80a05e00 + F (DHTB header included),
so this works on the raw partition image with no emulator.

  python tools/kdis.py dis 0x80a0914c 0x80a09490          # Thumb by default; --arm for ARM
  python tools/kdis.py words 0x811ae040 0x811ae0d0         # 4 words per row
  python tools/kdis.py find 0x81703a6c                     # every place a 32-bit literal occurs
  python tools/kdis.py push 0x8109dcde                     # nearest push {.., lr} before an address

Annotations on `dis`: PC-relative pool loads show the pool word, direct branches their target,
indirect branches / pop {.., pc} / ldr pc are flagged, and a summary lists every base+disp
access with disp >= 0x100 (useful for guessing struct sizes). Kernel path: --kernel, else
$F286_KERNEL, else firmware/kernel.bin.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import fwpaths                                            # noqa: E402

BASE = 0x80a05e00


def num(x):
    return int(x, 0)


class Img:
    def __init__(self, path):
        self.data = open(fwpaths.need(path, "kernel partition"), "rb").read()

    def off(self, va):
        o = va - BASE
        return o if 0 <= o < len(self.data) else None

    def word(self, va):
        o = self.off(va)
        return None if o is None or o + 4 > len(self.data) else struct.unpack_from("<I", self.data, o)[0]


def cmd_dis(img, lo, hi, arm):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    import capstone.arm as AC
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM if arm else CS_MODE_THUMB)
    md.detail = True
    offs = {}
    o = img.off(lo)
    if o is None:
        sys.exit(f"{lo:#x} is outside the kernel image")
    for ins in md.disasm(img.data[o:img.off(hi) or len(img.data)], lo):
        notes = []
        for op in ins.operands:
            if op.type == AC.ARM_OP_MEM and op.mem.base == AC.ARM_REG_PC:
                pool = ((ins.address + (8 if arm else 4)) & ~3) + op.mem.disp
                w = img.word(pool)
                if w is not None:
                    notes.append(f"pool {pool:#010x} = {w:#010x}")
            elif op.type == AC.ARM_OP_MEM and op.mem.disp >= 0x100:
                offs.setdefault(op.mem.disp, []).append(ins.address)
        if ins.mnemonic in ("bl", "blx", "b", "b.w", "cbz", "cbnz") and ins.operands \
                and ins.operands[-1].type == AC.ARM_OP_IMM:
            notes.append(f"-> {ins.operands[-1].imm & 0xFFFFFFFF:#010x}")
        if ins.mnemonic in ("bx", "blx") and ins.operands and ins.operands[0].type == AC.ARM_OP_REG:
            notes.append(f"<<< INDIRECT {ins.op_str}")
        if ins.mnemonic.startswith("pop") and "pc" in ins.op_str:
            notes.append("<<< RETURN")
        if ins.mnemonic.startswith("ldr") and ins.op_str.split(",")[0].strip() == "pc":
            notes.append("<<< INDIRECT ldr pc")
        print(f"  {ins.address:#010x}  {ins.mnemonic:<8} {ins.op_str}" + ("   ; " + "; ".join(notes) if notes else ""))
    if offs:
        print("  ---- disp >= 0x100: " + ", ".join(f"+{d:#x}@{offs[d][0]:#010x}" for d in sorted(offs)))


def cmd_words(img, lo, hi):
    for a in range(lo & ~3, hi, 16):
        ws = [img.word(a + 4 * i) for i in range(4)]
        print(f"  {a:#010x}: " + " ".join("--------" if w is None else f"{w:08x}" for w in ws))


def cmd_find(img, val):
    tgt = struct.pack("<I", val)
    i = img.data.find(tgt)
    n = 0
    while i >= 0:
        print(f"  file {i:#08x}  VA {BASE + i:#010x}  {'aligned' if i % 4 == 0 else 'unaligned'}")
        n += 1
        i = img.data.find(tgt, i + 1)
    print(f"{n} hits for {val:#010x}")


def cmd_push(img, va, span=0x500):
    for k in range(2, span, 2):
        o = img.off(va - k)
        if o is None:
            break
        hw = struct.unpack_from("<H", img.data, o)[0]
        if (hw & 0xFF00) == 0xB500 or hw == 0xE92D:
            print(f"  push at {va - k:#010x} (hw {hw:04x}, -{k:#x})")
            return
    print("  no push marker found")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["dis", "words", "find", "push"])
    ap.add_argument("a", type=num)
    ap.add_argument("b", type=num, nargs="?")
    ap.add_argument("--arm", action="store_true")
    ap.add_argument("--kernel", default=fwpaths.KERNEL)
    a = ap.parse_args()
    img = Img(a.kernel)
    if a.cmd == "dis":
        cmd_dis(img, a.a & ~1, a.b or (a.a & ~1) + 0x80, a.arm)
    elif a.cmd == "words":
        cmd_words(img, a.a, a.b or a.a + 0x40)
    elif a.cmd == "find":
        cmd_find(img, a.a)
    else:
        cmd_push(img, a.a)


if __name__ == "__main__":
    main()
