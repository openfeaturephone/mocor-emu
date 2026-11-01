"""app_test.py -- one command: build, install into a host folder, run in the emulator, collect.

  python app_test.py usbprobe --keys "5@+1s,6@+500ms"
  python app_test.py path/to/x.bin --as slot1 --keys "OK@+1s" --build

app       name of an <apps dir>/<name>.bin, or a path to a .bin
--as      launcher (default for usbprobe/launcher): D:\\apps\\launcher.bin, the stub's 2nd choice
          slotN: E:\\apps\\N.bin, run by pressing N in the built-in launcher (default otherwise)
--keys    key script for keypad.parse_keys: "KEY@time[/hold_ms],..". The first time is relative to
          the moment the app is open (T0), unless it ends in G/M (absolute insns); "+t" chains
          after the previous key's release; a bare key without @ follows the previous key by 500ms.
--run     seconds of virtual time after the last key (default 1.5);  --from CKPT (default IDLE2_5500M)
--build   run the app tree's build.py first (--build-script, default <apps dir>/../build.py)
--out DIR (default runs/apptest_<app>_<ts>);  --apps-dir DIR (default $F286_APPS_DIR or apps/)
Every run uses its own host folder (<out>/hostfs: apps/, dapps/, crumbs/) over the patched image,
then collects screenshots (frames + one after every key), crash_reports.txt, breadcrumbs.txt,
run.log tail and summary.txt into <out>. The app is opened by plat.apprun (hook IdleWin_HandleMsg,
LEFT key trigger) - no menu navigation.
"""
import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from plat import keypad                                   # noqa: E402
import fwpaths                                            # noqa: E402

RUNS = fwpaths.RUNS_DIR
BOOT_AT = 5.52e9                                          # trigger key (IDLE2_5500M is at 5.501G)
LAUNCH_SETTLE = 0.8                                       # s virtual: launcher/app window painted


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("app")
    ap.add_argument("--keys", default="")
    ap.add_argument("--as", dest="mode", default=None)
    ap.add_argument("--run", type=float, default=1.5)
    ap.add_argument("--from", dest="ckpt", default=fwpaths.IDLE_CKPT)
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--apps-dir", default=fwpaths.APPS_DIR, help="folder with launcher.bin and the app binaries")
    ap.add_argument("--build-script", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--plugin", action="append", default=[], help="extra plat plugin spec (repeatable)")
    ap.add_argument("--no-fb-frames", action="store_true", help="only the per-key snapshots (every=1000000)")
    a = ap.parse_args()

    OUT_BIN = a.apps_dir
    if not os.path.exists(a.ckpt):
        sys.exit(f"checkpoint not found: {a.ckpt}\nMake the idle checkpoint first (README, 'Getting to idle').")
    if a.build:
        subprocess.run([sys.executable, a.build_script or os.path.join(OUT_BIN, "..", "build.py")], check=True)
    name = os.path.splitext(os.path.basename(a.app))[0]
    src = a.app if os.path.exists(a.app) else os.path.join(OUT_BIN, name + ".bin")
    if not os.path.exists(src):
        sys.exit(f"app binary not found: {src}")
    mode = a.mode or ("launcher" if name in ("usbprobe", "launcher", "f286dbg") else "slot1")
    out = os.path.abspath(a.out or os.path.join(RUNS, f"apptest_{name}_{time.strftime('%H%M%S')}"))
    root = os.path.join(out, "hostfs")
    for d in ("apps", "dapps", "crumbs"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    if mode == "launcher":
        shutil.copy(src, os.path.join(root, "dapps", "launcher.bin"))   # E: copy absent -> stub falls to D:
        slot = None
    else:
        slot = int(mode.replace("slot", ""))
        shutil.copy(os.path.join(OUT_BIN, "launcher.bin"), os.path.join(root, "apps", "launcher.bin"))
        shutil.copy(src, os.path.join(root, "apps", f"{slot}.bin"))

    # key schedule: T0 = app open. User times relative to T0.
    t0 = int(BOOT_AT + LAUNCH_SETTLE * 200e6)
    ents = [e.strip() for e in re.split(r"[,;|\n]", a.keys) if e.strip()]
    spec, first = [], True
    if slot:
        spec.append((str(slot), t0, 100))
        first = False
    prev_end = t0
    parsed = []
    for e in ents:
        key, _, rest = e.partition("@")
        when, _, hold = rest.partition("/")
        hold = int(hold) if hold else 100
        if not when:
            when = "+500ms"
        if when.startswith("+"):
            t = keypad.parse_time(when, prev_end)
        elif when.lower().endswith(("g", "m")):
            t = keypad.parse_time(when)
        else:
            t = t0 + keypad.parse_time(when)
        parsed.append((key.strip(), t, hold))
        prev_end = t + hold * keypad.INSN_PER_MS
    allk = spec + parsed
    if slot:                                              # slot key goes first; user keys follow it
        allk = [spec[0]] + [(k, max(t, spec[0][1] + 40_000_000), h) for k, t, h in parsed]
    kf = os.path.join(out, "keys.txt")
    with open(kf, "w") as f:
        f.write("\n".join(f"{k}@{t}/{h}" for k, t, h in allk) + "\n")
    last = max([t0] + [t + h * keypad.INSN_PER_MS for _, t, h in allk])
    maxi = int(last + a.run * 200e6)
    snaps = [t0] + [t + (h + 400) * keypad.INSN_PER_MS for _, t, h in allk] + [maxi - 1000]
    tag = f"AT_{name}"
    cmd = [sys.executable, os.path.join(HERE, "plat_run.py"), tag, "--no-cell-cuts", "--strict", "--no-trace",
           "--stall", "0", "--from", a.ckpt, "--max-insns", str(maxi),
           "--plugin", "crash",
           "--plugin", f"fb:every={1000000 if a.no_fb_frames else 1},snaps={';'.join(str(s) for s in snaps)}",
           "--plugin", f"hostfs:root={root}",
           "--plugin", f"keypad:keyfile={kf}",
           "--plugin", f"apprun:hook=0x8828a37a,after={int(BOOT_AT)},press=LEFT"]
    for extra in a.plugin:
        cmd += ["--plugin", extra]
    print("running:", " ".join(cmd[2:5]), "...", flush=True)
    before = set(glob.glob(os.path.join(RUNS, f"2*_{tag}")))
    t_start = time.time()
    p = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True)
    run_dirs = sorted(set(glob.glob(os.path.join(RUNS, f"2*_{tag}"))) - before)
    if not run_dirs:
        sys.exit("plat_run produced no run dir:\n" + p.stdout[-2000:] + p.stderr[-2000:])
    rd = run_dirs[-1]

    # ---- collect
    shots = os.path.join(out, "screens")
    os.makedirs(shots, exist_ok=True)
    for f in glob.glob(os.path.join(rd, "fb", "*.png")):
        shutil.copy(f, shots)
    for n in ("run.log", "crash_reports.txt", "events.jsonl", "guest_log.txt"):
        if os.path.exists(os.path.join(rd, n)):
            shutil.copy(os.path.join(rd, n), os.path.join(out, n if n != "run.log" else "run_full.log"))
    log = open(os.path.join(rd, "run.log"), errors="replace").read().splitlines()
    quiet = [l for l in log if "[.... ]" not in l and "[MMIOR]" not in l]
    open(os.path.join(out, "run_tail.log"), "w").write("\n".join(quiet[-120:]) + "\n")
    crumbs = [(re.search(r"insn (\d+)", l).group(1), re.search(r"F286_(\w+)\.TXT", l).group(1))
              for l in log if "[HOSTFS] crumb" in l]
    with open(os.path.join(out, "breadcrumbs.txt"), "w") as f:
        for i, c in crumbs:
            f.write(f"{i}\t{c}\n")
    crash_n = sum(1 for l in log if "=== CRASH" in l)
    stop = next((l for l in reversed(log) if " stop=" in l), "?")
    snap_files = sorted(os.listdir(shots))
    summ = [f"app {name} as {mode}: {src}",
            f"keys: {', '.join(f'{k}@{t}' for k, t, _ in allk) or '(none)'}",
            f"run dir: {rd}",
            f"wall {time.time() - t_start:.0f}s; {stop.split('] ', 1)[-1].strip()}",
            f"crash reports: {crash_n}" + (f" -> {os.path.join(out, 'crash_reports.txt')}" if crash_n else ""),
            "breadcrumbs (app): " + " ".join(c for _, c in crumbs if int(c.split("_")[0], 16) >= 0x30) if crumbs else "breadcrumbs: none",
            f"screens ({len(snap_files)}): {shots}",
            "  snapshots: " + " ".join(f for f in snap_files if f.startswith("snap_")),
            f"  last: {os.path.join(shots, 'final.png')}"]
    open(os.path.join(out, "summary.txt"), "w").write("\n".join(summ) + "\n")
    print("\n".join(summ))
    print("output:", out)
    if p.returncode:
        print("plat_run exit", p.returncode, p.stderr[-800:])


if __name__ == "__main__":
    main()
