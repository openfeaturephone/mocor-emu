# mocor-emu

A Unicorn-based emulator for the stock MocorOS firmware (ThreadX) of the Ruio F286, a feature phone
built on the Unisoc UMS9117. It boots the phone's own kernel and mmi_app images to the idle screen,
runs custom MMI apps, calls single firmware functions with a JSON report, and can bulk-classify
every function in the image. I wrote it to reverse-engineer the stock OS for FPLinux hardware
support without having the phone in the loop for every experiment.

It needs your own dump. No firmware is included: see [firmware/README.md](firmware/README.md) for
the partitions it wants and their reference hashes. I have only run it against one phone and one
firmware build, and most addresses in the code are specific to that build.

## Setup

Python 3.11 on Windows is what I use. Linux should work but is untested.

```
pip install -r requirements.txt
cd native
python -m ziglang cc -shared -O2 -target x86_64-windows-gnu -o emu_native.dll emu_native.c
cd ..
```

The native library is optional (the Python fallback gives the same results, slower). Put
`kernel.bin`, `mmi_app.bin`, `mmi_res.bin`, `nvcal.bin` and `p_10000003.bin` into `firmware/`, or
point the `F286_*` environment variables at them (`fwpaths.py` has the list). Output goes to
`runs/` (override with `F286_RUNS`).

## Getting to idle

A fresh boot to the idle screen is about 5.5G instructions (27 s of virtual time) and takes 7-8
minutes of wall time here. Do it once and keep the checkpoints:

```
python plat_run.py RS2_fresh --no-cell-cuts --strict --no-trace --stall 0 --max-insns 5.7e9 --save-at 4.2e9,5.5e9
copy runs\ckpt\RS2_fresh_5500M.ckpt runs\ckpt\IDLE2_5500M.ckpt
```

`--no-cell-cuts` turns off old workaround hooks that are not needed once mmi_app is loaded,
`--strict` stops on faults instead of skipping them, and `--stall 0` keeps the stall detector from
ending the run during the quiet stretches (the OS is tickless and sleeps for seconds at a time).
Along the way: SIM init and IMSI read at ~300M, SMS ready ~340M, PS power-on at 4.23G, the 6 s
power-on window closes and the idle window opens at 5.427G. Add `--plugin fb` to get PNG frames
in `runs/<ts>_<TAG>/fb/`; the idle screen shows the clock, "01-01-1980" and "Searching network...".
`runs/<dir>/guest_log.txt` has the firmware's own debug log, which is usually the quickest way to
see what it is doing.

`IDLE2_5500M.ckpt` is the default starting point for `app_test.py`, `emu_call.py` and
`bulk_classify.py`. For hooks that must run from the MMI task start, also save one at 150M
(`--max-insns 1.5e8 --save-at 1.5e8`); the MMI task starts at about 203M.

Resume from a checkpoint with `--from`. That is only valid if whatever you changed did not run
before the checkpoint's instruction count; the loader warns when switches or the source differ.

## Running an app (app_test.py)

`app_test.py` installs an app into a per-run host folder, starts from the idle checkpoint, opens
the app through the SD-app boot stub (no menu navigation), presses keys, and collects screenshots,
crash reports and breadcrumbs. It needs the patched mmi_app with the loader stub
(`firmware/mmi_app_f286apps.bin`, or `F286_PATCHED_MMI_APP`) and a folder with `launcher.bin` plus
your app binaries (`--apps-dir`, or `F286_APPS_DIR`). Both come from
[mocor-sdk](https://github.com/openfeaturephone/mocor-sdk): its `build.py --stock` writes
`out/mmi_app_patched.bin`, which you copy here under that name, and `build.py --apps-only` builds
the example apps.

```
python app_test.py path\to\x.bin --as slot1 --keys "UP@+500ms,OK@+500ms"
python app_test.py uidemo --as launcher --keys "DOWN@+1s,OK@+700ms" --plugin mmu:after=5.53G
```

Key times are relative to the moment the app is open, `+t` chains after the previous key's
release, and a `G`/`M` suffix means an absolute instruction count. `--as launcher` installs the app
as `D:\apps\launcher.bin`; `--as slotN` installs it as `E:\apps\N.bin` and presses N in the built-in
launcher. Output lands in `runs/apptest_<app>_<hhmmss>/`: `screens/` (every frame, a snapshot 400 ms
after each key, `final.png`), `crash_reports.txt`, `breadcrumbs.txt`, `run_tail.log`,
`summary.txt`. A run takes about 20 s; add the `mmu` plugin and it is 20-30 s. Always add it: it is
the only thing that catches the unaligned accesses the phone resets on.

## Calling one function (emu_call.py)

```
python emu_call.py 0x887eab16 ptr:out rect:0,0,100,100 rect:50,50,200,200
```

Restores the checkpoint, calls the function in SVC mode with IRQs masked and a sentinel LR, and
prints a JSON report: outcome (returned, budget, assert, fatal_assert, os_block, fault_null,
fault_unmapped, ...), r0/r1, instruction count, callees in call order, RAM write ranges labelled by
argument buffer, MMIO accesses, guest printf lines and assert text. Argument specs: `0x..`, `big`,
`ptr:NAME[:SIZE[:pat]]`, `hex:NAME:aabb..`, `str:`, `ucs2:`, `pair:a,b`, `rect:l,t,r,b`. The
example above is GUI_IntersectRect; it writes `32 32 64 64` and returns 1. A tiny call costs about
15 ms. From Python: `Harness(ckpt).call(fn, [h.buf("x"), 1])`.

ARM/Thumb entry comes from bit 0 of the address, else from a function list exported from your
disassembler (`funcs/mmi_funcs.tsv`, `funcs/kernel_funcs.tsv`, rows
`F<TAB>hexaddr<TAB>size<TAB>name<TAB>thumb`), else the ARM veneer pattern, else Thumb.

Limits: there is no task context, so anything that waits on a queue, semaphore or timer shows up
as os_block or runs out of budget; ticks never advance, so polling delay loops hit the budget.
Device model state is not snapshotted between calls.

## Function database (bulk_classify.py)

```
python bulk_classify.py --sample 500
python bulk_classify.py --workers 12          # everything not yet in the DB, resumable
python bulk_classify.py --summary
python bulk_classify.py --export-names runs\func_hints.tsv
```

Calls every function from the two TSVs with four argument patterns and classifies it (pure,
writes-args, writes-global, gui, fs, asserts, faults, hw-mmio, os-blocking, loops) into
`runs/funcdb.sqlite`. The full set on my build (73,779 functions) took about 54 minutes with 16
workers. Most asserts it records are allocator sanity checks tripped by bogus arguments; the useful
ones are the function-specific expressions, which name the checked parameter.

## FPLinux

`fplinux_emu.py` boots an FPLinux `ramboot.bin` in Unicorn (skipping stage 0: zImage at
0x81000000, DTB at 0x82e00000) with GIC, timer and ADI models, seeded with register values read on
the phone (`fplinux_hw_init.json`, `fplinux_hw_baseline.json`). `fplinux_lcd.py` is a display
model for its DRM driver. This is much rougher than the Mocor side.

## Speed

Unicorn tops out well below the phone's ~200 MIPS. On my machine: 5-8 MIPS on cold boot code
(mostly first-time translation), 70-80 MIPS on a hot loop, a fresh boot to 70M instructions in
about 15 s, about 50M instructions per minute after idle with the crash and fb plugins on, and
about 7 minutes for an 8G-instruction run. Checkpoints are what make it usable: most experiments
are 10-30 s from a checkpoint.

## What is modelled, and what isn't

Modelled well enough to boot: GIC-400, AP timer and free-running counters in real virtual time,
PMU set/clear banks and power status, ADI/PMIC registers, RTC, HW spinlock, SDHCI clock, LCDC frame
done, keypad, mailbox, a virtual USIM, NV from your dump, mmi_res, the SPI-NAND controller in early
boot. Details in [docs/hardware-models.md](docs/hardware-models.md); the plugins are listed in
[docs/plugins.md](docs/plugins.md).

Not modelled:

- No DSP, CM4 or modem core runs. The GSM DSP, LTE XDSP and ADX rings are stubs that answer the
  AP's handshakes. The LTE stack gets as far as the band sweep and cell sync request, then stops
  (the sync reply format is unknown), so the network stays at "Searching".
- No USB. `plat/ucom.py` replaces the UCOM serial ops with a TCP bridge, but nothing below that.
- No MMU paging model. The emulator runs MMU-off with a flat map; `plat/mmu.py` only reports what
  the phone would have faulted on. Caches are not modelled either.
- Unicorn ignores alignment checking (the phone traps it), and some placeholder values are guesses:
  RF chip id, eFuse contents, battery ADC, DSP-published fields.
- The main-menu grid paints only partly (titles and lists are fine). RED/power key is on EIC and
  not modelled. Keys sent during a menu transition are lost.

The traps I hit (per-address code hooks, write hooks breaking Thumb IT blocks, tickless timing, the
real assert entries) are in [docs/gotchas.md](docs/gotchas.md).

## Layout

```
mocor_emu.py      the emulator (memory map, device models, boot, checkpoints, debugger)
plat_run.py       runner: boot or --from a checkpoint, --plugin, --save-at, --save-final
plat/             plugins (crash, fb, keypad, hostfs, apprun, mmu, ucom, timeline, ...)
native/           C hot paths (block hook, MMIO callbacks, fast device models)
app_test.py       build-install-run-collect loop for MMI apps
emu_call.py       single-function caller
bulk_classify.py  function database
vsim.py           virtual USIM (test IMSI 001010123456789)
display_model.py, lcd_render.py   panel/DCS model and RGB565 -> PNG
parse_nv.py, decomp_lz.py         NV partition parser, kernel LZ decompressor port
fplinux_emu.py, fplinux_lcd.py    FPLinux kernel boot
fwpaths.py        where firmware, function lists, apps and runs live
tools/            kdis.py (static disassembly/literal search), make_fplinux_baseline.py,
                  kernel_emu.py and hal_emu.py (early isolated tracers, see their headers)
```

## Licence

MIT, see [LICENSE](LICENSE). This covers the code in this repository only; the firmware it runs is
not included and not covered.
