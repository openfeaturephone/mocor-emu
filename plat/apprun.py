"""plat/apprun.py -- run the boot stub f286_boot (0x88904100) inside the MMI task.

Bypasses Apps -> Facebook: when the MMI task next enters `hook` (after insn `after`), a
Thumb trampoline runs f286_boot() and then resumes the hooked function with its original
arguments, so the stub (SFS loads, MMK_CreateWindow) runs in the P_APP context it needs.
Needs hostfs (installed here if missing) for E:\\apps\\launcher.bin and the patched image.

opts:
  hook=0x88258c20   MMI-task function to hijack. Default MMIDEFAULT_ConvertKeyCode: runs on
                    any key, so it works before the idle screen exists. Use
                    0x8828a37a (IdleWin_HandleMsg) once idle is up.
  after=4.23G       earliest insn (same syntax as keypad: 4.23G, 4230M, 5s)
  press=KEY         also schedule this key (keypad plugin) at `after` to trigger the hook
  boot=0x88904100   entry to call
"""
import struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_PC
from . import hostfs, keypad

TRAMP = 0x8b030000                     # scratch RAM for the trampoline (unused DDR)


def build(boot, orig):
    b = bytearray(0x20)
    struct.pack_into("<HH", b, 0x00, 0xE92D, 0x500F)       # push {r0-r3,r12,lr}
    struct.pack_into("<HH", b, 0x04, 0xF8DF, 0x000C)       # ldr r0,[pc,#12] -> 0x14
    struct.pack_into("<H", b, 0x08, 0x4780)                # blx r0
    struct.pack_into("<HH", b, 0x0A, 0xE8BD, 0x500F)       # pop {r0-r3,r12,lr}
    struct.pack_into("<HH", b, 0x0E, 0xF8DF, 0xF00C)       # ldr pc,[pc,#12] -> 0x1c
    struct.pack_into("<I", b, 0x14, boot | 1)
    struct.pack_into("<I", b, 0x1C, orig | 1)
    return bytes(b)


def install(emu, run, opts):
    if not hasattr(emu, "hostfs"):
        hostfs.install(emu, run, opts)
    hook = int(opts.get("hook", "0x88258c20"), 0)
    boot = int(opts.get("boot", "0x88904100"), 0)
    after = keypad.parse_time(opts.get("after", "4.23G"))
    if opts.get("press"):
        if not hasattr(emu, "keypad"):
            keypad.install(emu, run, {})
        emu.keypad.press(opts["press"], at=after)
    emu.mu.mem_write(TRAMP, build(boot, hook))
    st = {"done": False}

    def fire(uc, addr, size, ud):
        if st["done"] or emu.insn_total < after:
            return
        st["done"] = True
        run.log(f"[APPRUN] hook {hook:#x} hit at insn {emu.insn_total}: running {boot:#x} first")
        uc.reg_write(UC_ARM_REG_PC, TRAMP | 1)
    getattr(emu, "_raw_hook_add", emu.mu.hook_add)(UC_HOOK_CODE, fire, None, hook, hook)
    emu.apprun = st
    return st
