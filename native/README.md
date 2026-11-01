# emu_native: C hot paths for mocor_emu.py

Build it with zig, which ships as a pip package, so no system compiler is needed:

    pip install ziglang
    cd native
    python -m ziglang cc -shared -O2 -target x86_64-windows-gnu -o emu_native.dll emu_native.c

On Linux the same source builds as a shared object (`mocor_emu.py` looks for `emu_native.so`
when `os.name != "nt"`), but I have only run the emulator on Windows:

    python -m ziglang cc -shared -O2 -fPIC -target x86_64-linux-gnu -o emu_native.so emu_native.c

`mocor_emu.py` loads the library when `NATIVE = True`. If it is missing, it logs that and falls
back to the Python paths, which are a lot slower but give the same results.

What lives here:

| Piece | Role |
|---|---|
| `native_init` | Receives unicorn's own `uc_reg_read` / `uc_emu_stop` pointers, so the library has no link dependency on unicorn.dll. |
| `blk_unmask_cb` | The single unbounded block hook. It keeps the executed-instruction estimate (`est`), dispatches the sorted table of Python block-hook addresses (`native_add_block_addr` / `native_set_py_block`), and stops the chunk at the guest's unmask while an IRQ waits (GIC model). |
| `mmio_read_cb` / `mmio_write_cb` | Every device window is a `uc_mmio_map` region with a C shadow. Order per access: free-running counters, then the C fast models (`fast_read` / `fast_write`: ADI doorbell, PMIC register store, LTE frame timer, SDHCI CLK_CTRL), then the Python device models (`py=1` regions), else plain echo (`py=0`). |

`NativeState` must stay field-for-field identical to the ctypes mirror in `mocor_emu.py`.
