"""make_fplinux_baseline.py - register values FPLinux itself saw on the real phone, as an emulator seed.

Sources (FPLinux-side captures before any radio experiment, in LOGDIR):
  baseline.txt  word dumps "ADDR: w0 w1 ..." and "0xADDR: 0xVAL" singles
  pmu.log       "RD 0xADDR = VAL" lines of the first '=== baseline ===' block
Only MMIO addresses are kept (DRAM window dumps are skipped). The first reading of an address wins.

  python tools/make_fplinux_baseline.py LOGDIR   -> fplinux_hw_baseline.json (repo root)
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "fplinux_hw_baseline.json")
MMIO = ((0x40000000, 0x40800000), (0x60000000, 0x61000000), (0x20000000, 0x22000000))


def mmio(a):
    return any(lo <= a < hi for lo, hi in MMIO)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    LOGS = sys.argv[1]
    vals = {}
    for line in open(os.path.join(LOGS, "baseline.txt")):
        m = re.match(r"^([0-9A-Fa-f]{8}):((?:\s+[0-9A-Fa-f]{8})+)\s*$", line)
        if m:
            base = int(m.group(1), 16)
            for i, w in enumerate(m.group(2).split()):
                vals.setdefault(base + 4 * i, int(w, 16))
            continue
        m = re.match(r"^0x([0-9a-f]{8}): 0x([0-9a-f]{8})", line)
        if m:
            vals.setdefault(int(m.group(1), 16), int(m.group(2), 16))
    in_base = False
    for line in open(os.path.join(LOGS, "pmu.log")):
        if "=== baseline ===" in line:
            in_base = True
            continue
        if in_base and "===" in line:
            break
        m = re.search(r"RD 0x([0-9A-F]{8}) = ([0-9A-F]{8})", line)
        if in_base and m:
            vals.setdefault(int(m.group(1), 16), int(m.group(2), 16))
    out = {f"{a:#010x}": f"{v:#010x}" for a, v in sorted(vals.items()) if mmio(a)}
    json.dump(out, open(OUT, "w"), indent=1)
    print(f"{len(out)} MMIO registers -> fplinux_hw_baseline.json")


if __name__ == "__main__":
    main()
