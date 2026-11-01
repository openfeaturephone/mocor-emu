# Plugins

`plat_run.py --plugin name[:k=v,k=v]` imports `plat/<name>.py`. A plugin may define
`pre(run, opts)` (called before the emulator is built, e.g. to wrap `MocorEmu` methods),
`install(emu, run, opts)` (after build or checkpoint load) and `finish(emu, run, opts)` (at stop).
`plat_run.py` splits options on commas, so lists inside an option use `;` or `+`.

| Plugin | What it does | Main options |
|---|---|---|
| `crash` | Assert, LOG_CORE and UND/PABT/DABT reports with thread name, registers and a heuristic backtrace, into `crash_reports.txt` | `stop=1`, `max=N`, `dabt=0` |
| `crashtest` | Forces an assert or fault at a chosen block, to test `crash` | `at=0x..`, `via=mmi\|kernel\|logcore\|und\|dabt`, `after=N` |
| `fb` | Composes LCDC layers into `fb/*.png`; `fb.snapshot(emu, path)` on demand | `every=N`, `snaps=insn;insn`, `dump=1`, `panel=1` |
| `keypad` | Real KPD controller model; keys go through the stock ISR and key service | `keys=OK@5.52G/150;DOWN@+700ms`, `keyfile=`, `hold=` |
| `hostfs` | Serves `E:\apps\*`, `D:\apps\*` and `D:\F286_*` breadcrumbs from a host folder; overlays the patched mmi_app | `root=DIR`, `patched=1\|0\|PATH` |
| `apprun` | Runs the SD-app boot stub (0x88904100) inside the MMI task, no menu navigation | `hook=0x8828a37a`, `after=5.52G`, `press=LEFT` |
| `mmu` | Walks the guest page tables and flags what the phone would fault on: unaligned, read-only writes, XN, unmapped | `after=5.53G`, `until=`, `thread=P_APP`, `stop=1`, `checks=wxa`, `code=lo-hi;lo-hi` |
| `ucom` | Replaces the kernel UCOM serial ops and USB_START/STOP/CURRENT with a TCP bridge on localhost | `port=5555`, `connect=5s`, `wait=1`, `exit=1`, `busy=1` |
| `timeline` | Logs when each hooked function entry runs, with r0-r3, lr and return-address-looking stack words | `addrs=0xA+0xB`, `max=3`, `depth=0x1800` |
| `stackwatch` | Lowest SP per thread against the ThreadX TCB stack bounds | `after=insn` |
| `ramdump` | At each LCDC frame start, dumps layer registers and GUI RAM windows to `rd/f<n>.npz` | `every=N` |
| `dspwrites` | Logs every AP write a DSP or CM4 could see (register space, share RAM, DSP-visible DRAM) with pc/lr, into `dspwrites.jsonl` | `stop_after=insn` |

Times accept `5.52G` / `5520M` (instructions), `1.5s` (virtual), and `+100ms` (after the previous
key's release). `/N` after a key is the hold time in ms.

Keypad gotcha: options are a dict, so `RIGHT@+700ms,RIGHT@+700ms` collapses into one key. Use `;`
or a `keyfile=`.

The route from idle to the stock "Apps -> FaceBook" entry (which the SD-app loader hooks) is
`LSOFT, RIGHT x9, OK, OK`, at least 700 ms apart.
