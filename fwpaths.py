"""fwpaths.py -- where the emulator finds the firmware images you dumped from your own phone.

Nothing in this repository ships firmware. Every image is looked up here, in this order:

  1. a per-file environment variable (F286_KERNEL, F286_MMI_APP, ...)
  2. <F286_FW>/<default file name>, where F286_FW defaults to the firmware/ folder next to
     this file

See firmware/README.md for the list of partitions and how to get them.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FW_DIR = os.environ.get("F286_FW") or os.path.join(HERE, "firmware")

# env var -> default file name inside FW_DIR
_FILES = {
    "F286_KERNEL": "kernel.bin",              # partition "kernel" (id 0x00000003), 12 MiB
    "F286_MMI_APP": "mmi_app.bin",            # partition "mmi_app" (id 0x00000004), 9.1 MiB
    "F286_MMI_RES": "mmi_res.bin",            # partition "mmi_res" (id 0x10000004), ECC-corrected
    "F286_NVCAL": "nvcal.bin",                # partition "nvcal" (id 0x10000001): fixed NV stream
    "F286_NV_JOURNAL": "p_10000003.bin",      # partition id 0x10000003: RunningNV journal
    "F286_NAND": "nand_full.bin",             # optional: whole NAND, 2048 main + 64 OOB per page
    "F286_PATCHED_MMI_APP": "mmi_app_f286apps.bin",   # optional: mmi_app with the SD-app loader
    "F286_INIT_DATA": "init_data_dec.bin",    # optional, kernel_emu.py only: decompressed init data
    "F286_FPLINUX_IMAGE": "ramboot.bin",      # optional, fplinux_emu.py only: your FPLinux build
}


def fw(env):
    """Path for one firmware file (may not exist; callers check)."""
    p = os.environ.get(env)
    if p:
        return p
    return os.path.join(FW_DIR, _FILES[env])


def need(path, what=""):
    """Exit with a pointer to firmware/README.md if a required image is missing."""
    if not os.path.exists(path):
        raise SystemExit(f"missing firmware file: {path}{' (' + what + ')' if what else ''}\n"
                         f"Put your own dump there or set the matching F286_* variable "
                         f"(see firmware/README.md).")
    return path


# Optional function lists exported from a disassembler: TSV rows
# "name<TAB>0xADDR<TAB>size<TAB>...<TAB>thumb(0/1)". Used for ARM/Thumb entry detection
# (emu_call.py), symbolising RAM dumps (plat/ramdump.py) and the function DB (bulk_classify.py).
FUNCS_DIR = os.environ.get("F286_FUNCS_DIR") or os.path.join(HERE, "funcs")

# Our own MMI app binaries (built by the separate mmiapp tree): launcher.bin, <app>.bin
APPS_DIR = os.environ.get("F286_APPS_DIR") or os.path.join(HERE, "apps")

RUNS_DIR = os.environ.get("F286_RUNS") or os.path.join(HERE, "runs")
CKPT_DIR = os.path.join(RUNS_DIR, "ckpt")
IDLE_CKPT = os.path.join(CKPT_DIR, "IDLE2_5500M.ckpt")

KERNEL = fw("F286_KERNEL")
MMI_APP = fw("F286_MMI_APP")
MMI_RES = fw("F286_MMI_RES")
NVCAL = fw("F286_NVCAL")
NV_JOURNAL = fw("F286_NV_JOURNAL")
NAND = fw("F286_NAND")
PATCHED_MMI_APP = fw("F286_PATCHED_MMI_APP")
INIT_DATA = fw("F286_INIT_DATA")
FPLINUX_IMAGE = fw("F286_FPLINUX_IMAGE")
