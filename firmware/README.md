# firmware/

This folder is where the emulator looks for the partition images you read from your own Ruio F286.
Nothing in here is committed (see `.gitignore`), and the repository ships no firmware, no vendor
loaders and no dump tools.

## What goes here

| File | Partition (id) | NAND offset | Size | Needed for |
|---|---|---|---|---|
| `kernel.bin` | kernel (0x00000003) | 0x01400000 | 12,582,912 | everything |
| `mmi_app.bin` | mmi_app (0x00000004) | 0x02000000 | 9,568,256 | booting to the MMI (default on) |
| `mmi_res.bin` | mmi_res (0x10000004) | 0x02920000 | 9,568,256 | fonts, icons, wallpaper (without it the idle screen is black) |
| `nvcal.bin` | nvcal (0x10000001) | 0x00080000 | 917,504 | real NV items (`NV_REAL`, default on) |
| `p_10000003.bin` | RunningNV journal (0x10000003) | 0x01000000 | 4,194,304 | NV items missing from nvcal |
| `nand_full.bin` | whole NAND, 2048 main + 64 OOB bytes per page | | 138,412,032 | optional: the SNF controller model in early boot |
| `mmi_app_f286apps.bin` | your patched mmi_app (SD-app loader) | | | optional: `app_test.py` and the `hostfs` overlay |
| `ramboot.bin` | your FPLinux build | | | optional: `fplinux_emu.py` |
| `init_data_dec.bin` | decompressed kernel init data | | | optional: `tools/kernel_emu.py` |

Offsets are from the partition table on my phone (1 Gbit SPI-NAND, 2048+64 byte pages,
64 pages per block). Without the NV partitions you can still boot with `--no-real-nv`, which
zero-fills every NV read, but the RF and modem paths then behave differently.

Any file can live elsewhere: set `F286_FW` to another folder, or point at single files with
`F286_KERNEL`, `F286_MMI_APP`, `F286_MMI_RES`, `F286_NVCAL`, `F286_NV_JOURNAL`, `F286_NAND`,
`F286_PATCHED_MMI_APP`, `F286_FPLINUX_IMAGE`, `F286_INIT_DATA` (see `fwpaths.py`).

## How to get them

Read the partitions over the Unisoc BootROM download protocol with an FDL-based reader (for
example the open-source `spreadtrum_flash` tool, using the FDL1/FDL2 loaders from your phone's own
firmware package), or from Linux running on the phone. Partition reads through FDL2 go through
the NAND controller's ECC, which is what you want.

Two things bit me:

- `mmi_res.bin` must be ECC-corrected. A slice of a raw NAND main-area dump has random 0->1 bit
  flips (about one per 2 KB page on my chip). In `mmi_res` they land in the vector-font glyphs and
  some characters draw as solid blocks or vanish. The kernel region of my raw dump happened to be
  clean, but don't count on it.
- `nvcal.bin` and the journal hold this phone's RF calibration and product data. They are
  personal to the device: don't publish them, and don't commit them.

## Stock image hashes (my phone)

These are the images the addresses in the code were taken from. If your firmware build differs,
almost every hard-coded address will be wrong.

```
c1c808de1e1c0ed09fc5b3e4562eb438911953ce37c8e87fbf4707622d657de1  kernel.bin
5d5343297d2d10c32107c923d47d903bcd13ad162d903792dde96f1b314f3ce2  mmi_app.bin
bb8c4e874b0d178e7842bd5205bfb865aa85d2b525042d8bf24ba18f0d425cc4  mmi_res.bin  (ECC-corrected)
```

Check with `sha256sum firmware/*.bin` (or `certutil -hashfile file SHA256` on Windows). NV
partitions are device-specific, so there is no reference hash for them.
