"""plat.crashtest -- provoke an assert at a chosen block to exercise plat.crash.

  --plugin crashtest:at=0x8824acac,via=mmi|kernel|logcore|und|dabt[,after=N]

On the Nth (after=, default 1) execution of `at`, the caller state is rewritten as if
that function asserted: r0/r1/r2 = (expr, file, line) strings in scratch RAM and the
PC is sent to the assert entry with LR left as the function's own LR.
via=mmi -> veneer 0x880a9be0, kernel -> 0x80a0b07a, logcore -> LOG_CORE 0x80a0914c
(r3=msg), und -> executes an undefined opcode, dabt -> reads an unmapped address.
"""
from unicorn import UC_HOOK_CODE
import unicorn.arm_const as A

SCRATCH = 0x84fe0000


def install(emu, run, opts):
    at = int(opts.get("at", "0x8824acac"), 0)
    via = opts.get("via", "mmi")
    after = int(opts.get("after", "1"))
    uc = emu.mu
    n = [0]
    try:
        uc.mem_write(SCRATCH, b"\0")
    except Exception:
        uc.mem_map(SCRATCH, 0x1000)
    uc.mem_write(SCRATCH, b"ptr != PNULL\0")
    uc.mem_write(SCRATCH + 0x40, b"mmi/test_assert.c\0")
    uc.mem_write(SCRATCH + 0x80, b"forced by plat.crashtest\0")

    uc.mem_write(SCRATCH + 0x100, bytes.fromhex("00de7047"))    # udf #0; bx lr
    uc.mem_write(SCRATCH + 0x110, bytes.fromhex("20687047"))    # ldr r0,[r4]; bx lr

    def hit(uc, a, sz, ud):
        n[0] += 1
        if n[0] != after:
            return
        run.log(f"[CRASHTEST] forcing {via} at {a:#x} insn={emu.insn_total}")
        uc.reg_write(A.UC_ARM_REG_R0, SCRATCH)
        uc.reg_write(A.UC_ARM_REG_R1, SCRATCH + 0x40)
        uc.reg_write(A.UC_ARM_REG_R2, 1234)
        uc.reg_write(A.UC_ARM_REG_R3, SCRATCH + 0x80)
        tgt = {"mmi": 0x880a9be0, "kernel": 0x80a0b07a, "logcore": 0x80a0914c,
               "und": SCRATCH + 0x101, "dabt": SCRATCH + 0x111}[via]
        uc.reg_write(A.UC_ARM_REG_R4, 0x5fff0000)            # unmapped, for via=dabt
        uc.reg_write(A.UC_ARM_REG_PC, tgt & ~1)
        if tgt & 1:
            uc.reg_write(A.UC_ARM_REG_CPSR, uc.reg_read(A.UC_ARM_REG_CPSR) | 0x20)
    uc.hook_add(UC_HOOK_CODE, hit, begin=at & ~1, end=(at & ~1) + 1)
