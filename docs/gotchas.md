# Gotchas

Things that cost me time. Most are about unicorn 2.1.4 (QEMU 5 TCG underneath) or about this
firmware's timing.

## Unicorn

**Never add per-address `UC_HOOK_CODE` hooks.** Unicorn checks every address-bounded code hook on
every executed instruction. Measured on this firmware: no hooks 160 MIPS, 10 hooks 51, 200 hooks 3.9.
At one point the emulator had 357 of them (CP15 sites, unmask sites, behaviour hooks) and ran at
about 1.5 MIPS. Bounded `UC_HOOK_BLOCK` hooks are resolved at translation time (200 hooks: 138
MIPS), so single-address hooks are registered as block hooks (`BLOCK_HOOKS`), and with the native
library they go into one C block hook's sorted address table (`NATIVE_BLOCK_DISPATCH`). Only
addresses in `CODE_HOOK_EXACT` (mid-block) stay real code hooks. A block hook fires only where a
translated block *starts*, so hook function entries, not instructions in the middle.

**Memory hooks slow every load and store.** With any memory hook installed unicorn routes all guest
loads/stores through a helper that scans the hook list (30 memory hooks plus block hooks: 22 MIPS
against 155 bare). Device windows are therefore `uc_mmio_map` regions with C callbacks
(`MMIO_NATIVE`), and Python models are dispatched from one callback.

**A `UC_HOOK_MEM_WRITE` that covers the stored address breaks Thumb IT blocks.** After the stock
memset tail (`it hs; strhs r2,[r0],#4; it eq; bxeq lr` at 0x810a0886) the IT state leaks into the
caller and its next instruction is skipped: `add.w r0,r4,#0x20` at 0x80d0de88 vanishes and the OSA
allocator returns dst+len, a 2-byte aligned "heap" pointer. Global read hooks corrupted the text
engine too. That is why `emu_call.py` tracks RAM writes by diffing host-mapped buffers after the
call instead of hooking them. Repro: map kernel bytes 0x810a0874..0x810a08a2 after a `push {lr}`,
return into `add.w r0,r4,#0x20`, with r1 = len-0x20 for len%32 in {2,6,8,...}: r0 comes back wrong
only when a write hook is installed.

**Unicorn ignores SCTLR.A.** The phone runs with alignment checking on, and its abort handler
resets on any alignment fault. An unaligned `str.w` in one of my apps reset the phone every time and
ran fine here. `plat/mmu.py` (`--plugin mmu:after=5.53G`) decodes every load/store in the code
ranges and flags unaligned accesses. Related: `-mno-unaligned-access` does nothing under
`python -m ziglang cc`; `-Xclang -target-feature -Xclang +strict-align` works.

**Another IT-block bug**: a backward branch that targets the `ittt` itself leaves condexec stuck,
the conditional instructions execute anyway and the loop's `b<cc>.w` raises INSN_INVALID. The
stock memset hot loop does exactly this, inlined at many sites, so the loader rewrites
`22bf a0e80c50 a0e80c50` to an equivalent `bcc` form (`IT_PATCH_FROM/TO`).

**Adding hooks between chunks changed guest behaviour once.** Plugins add all hooks at install.

**WFI ends `emu_start`.** In the idle task's light-sleep loop every chunk boundary then landed in
the masked window, no tick was ever injected and the OS clock stopped. A chunk that stops right
after WFI now counts as idle time and the due IRQ is delivered (`WFI_WAKE`).

**The default CPU is a Cortex-A15 that starts Non-secure with `NSACR = 0`** (`fplinux_emu.py`, but
it would bite any ARMv7 guest that uses VFP). The UMS9117 core is a Cortex-A7, and `NSACR = 0` means
the Non-secure world may not touch CP10/CP11, so unicorn silently drops those bits from every
CPACR write the guest makes. The FPLinux kernel enables VFP through CPACR, the enable was dropped,
and every VFP instruction then trapped as undefined, which looked like a kernel bug rather than a
model one. On the phone the secure boot firmware grants Non-secure CP10/CP11 before Linux runs; the
emulator has no secure firmware, so set the model to Cortex-A7 and write `NSACR` (`cp15 1,1,2`) =
0xC00 yourself before entry. Don't paper over it by forcing CPACR/FPEXC after the trap: that hides
a wrong CPU model.

## Timing

**The OS is tickless; model real time or timers lie.** Firing TMR0 every 1 ms made the OS clock run
about 2000x fast while idle, and the free counters at one count per instruction made every OS timer
expire 200000x early. The LTE AS power-on guard (20 s) expired 10 ms after it was armed and EMM
asserted. With the real rates (`AP_TMR_MODEL`, `CTR_REALTIME`) a fresh boot takes real virtual time:
PS power-on at 4.23G insns = 21 s, idle at 5.43G. So run long boots with `--stall 0`, or the stall
detector stops them in the quiet stretches.

**The MMI was never stuck.** The power-on window starts a 6000 ms MMK timer and opens the idle
window when it fires (5.427G). Every run that "never reached idle" had just stopped earlier.

**`--from` a checkpoint only proves something if the model you changed did not run before it.**
Resources are read at about 200M insns, NV during the first second, so a model change there needs a
fresh boot. Loading warns when flags or the source hash differ.

**Keys sent during a menu transition are lost.** Keep about 700 ms between keys in menus.

## Firmware facts that are easy to get wrong

- **Assert entries.** The real ones are kernel 0x80a0b07a (`movs r3,#0; b.w LOG_CORE`) and the mmi
  path 0x80a09414 (target of the mmi veneer 0x880a9be0). Both are patched to `bx lr` at load, so
  asserts do not kill the boot; `plat/crash.py` and `emu_call.py` hook them to capture file, line and
  expression from r0-r2. `ASSERT_TRAP` 0x80a0b00a, which older code hooked, is in the middle of a
  `bl` and never fires. LOG_CORE (0x80a0914c) never returns by design: its tail is the diag RX loop.
- **mmi_app at 0x88000000, file offset 0** (header included). Not +0x200.
- **Tick IRQ 0x3d**, not 0x20 (`--tick-irq`, default 0x3d).
- **Real KPD key_status is never 0.** Test `& 0x80808080` for "a key is down".
- **The UART range is 0x70000000-0x702fffff.** An older catch-all for 0x70000000-0x71ffffff
  swallowed the SIM controllers, pads and INTCs.
- **`GATE_D_MODE = "timer"`.** The old power-state shim wrote the boot mode field (wrong field) and
  blocked the PS start; now only the AON tick timer is enabled at the master-init wait loop.

## Practical

- Plugin state must not live on `emu`: checkpoints pickle its attributes.
- `app_test.py` runs started in the same second share a run directory. Don't run them in parallel.
- `bulk_classify.py` with more than 16 workers exhausted the Windows page file on my machine.
- In-process checkpoint reloads crash the native library after a few rounds, so bulk workers
  respawn instead.
- `runs/<dir>/guest_log.txt` is the firmware's own debug log (`LOG_TAP`). Read it first.
- Long runs eat disk: checkpoints are 160-180 MB each and cell traces grow fast.
