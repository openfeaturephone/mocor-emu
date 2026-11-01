"""plat_run.py -- run the emulator (fresh boot or from a checkpoint) with platform plugins.

  --plugin name[:k=v,k=v]   (repeatable) import plat.<name>, call install(emu, run, opts)
                            after the emulator is built/loaded, before running.
                            A plugin may also define pre(run, opts), called before
                            construction (to patch MocorEmu class methods).
  --save-final PATH         write a checkpoint when the run stops

  python plat_run.py TAG [--no-cell-cuts] [--strict] [--no-pump]
                             [--no-pmu-model] [--no-real-nv] [--no-trace]
                             [--tick-irq N] [--max-insns N] [--timeout S]
                             [--save-at N[,N...]] [--from CKPT] [--stall N]

Fast turnaround:
  --save-at 26e6,33e6   write full-state checkpoints into runs/ckpt/ at those
                        insn counts (TAG_<n>M.ckpt)
  --from runs/ckpt/X    resume from a checkpoint instead of booting. Valid as
                        long as the model you changed was not exercised
                        before the checkpoint (the load logs FLAGS DIFFER /
                        source changed as a reminder)
  --stall 30e6          stop when nothing new happens for N insns and write
                        stall_profile.txt (default 30M; 0 = off)
  --max-insns           default 1G

Output: runs/<ts>_<TAG>/{run.log, events.jsonl, cell_trace.tsv,
                         cp_stub.tsv, stall_profile.txt}
"""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mocor_emu as ME
from mocor_emu import Run, MocorEmu
from unicorn.arm_const import UC_ARM_REG_PC


def num(x):
    x = x.strip().lower()
    return int(x, 0) if x.startswith("0x") or x.isdigit() else int(float(x))


ap = argparse.ArgumentParser()
ap.add_argument("tag")
ap.add_argument("--no-cell-cuts", action="store_true")
ap.add_argument("--strict", action="store_true")
ap.add_argument("--nv-legacy", action="store_true")
ap.add_argument("--no-mmi", action="store_true")
ap.add_argument("--no-pump", action="store_true")
ap.add_argument("--no-pmu-model", action="store_true")
ap.add_argument("--no-real-nv", action="store_true")
ap.add_argument("--no-trace", action="store_true", help="cell trace off")
# injected tick id: 0x3d = table irq 0x1d TB_AP_TMR0_INT (the OS tick,
# handler 0x80a0b3c5). 0x20 would be table irq 0 - not
# registered; the dispatcher runs off the table into a garbage handler.
ap.add_argument("--tick-irq", type=lambda x: int(x, 0), default=0x3d)
ap.add_argument("--tick-rate", type=num, default=200_000)
ap.add_argument("--max-insns", type=num, default=1_000_000_000)
ap.add_argument("--timeout", type=float, default=7200)
ap.add_argument("--save-at", default="")
ap.add_argument("--from", dest="ckpt", default=None)
ap.add_argument("--stall", type=num, default=30_000_000)
ap.add_argument("--sigtap", action="store_true", help="log every _tx_queue_send signal -> runs/<dir>/signals.txt")
ap.add_argument("--mmio-watch", default="", help="LO-HI hex: log Python-routed MMIO reads/writes in range -> mmio_watch.txt")
ap.add_argument("--wwatch", default="", help="hex RAM address: log pc/lr of every write to that word")
ap.add_argument("--probe-r0", default="", help="hex: only log probes whose r0 equals this")
ap.add_argument("--plugin", action="append", default=[], help="name[:k=v,k=v] platform plugin (repeatable)")
ap.add_argument("--save-final", default="", help="write a checkpoint to PATH when the run stops")
ap.add_argument("--probe", default="", help="comma list of block addresses: log r0-r3/lr when each runs")
args = ap.parse_args()

ME.CELL_TRACE = not args.no_trace
ME.CELL_CUTS = not args.no_cell_cuts
ME.STRICT = args.strict
ME.NV_LEGACY_FILL = args.nv_legacy
ME.MMI_PRELOAD = not args.no_mmi
ME.PMU_MODEL = not args.no_pmu_model
ME.NV_REAL = not args.no_real_nv

run = Run(tag=args.tag)
run.log(f"=== plat_run cuts={ME.CELL_CUTS} strict={ME.STRICT} nv_legacy={ME.NV_LEGACY_FILL} "
        f"mmi={ME.MMI_PRELOAD} pmu={ME.PMU_MODEL} nv_real={ME.NV_REAL} tick_irq={args.tick_irq:#x} "
        f"trace={ME.CELL_TRACE} pump={not args.no_pump} from={args.ckpt} "
        f"save_at={args.save_at} stall={args.stall} ===")
if args.mmio_watch:
    _wlo, _whi = (int(x, 16) for x in args.mmio_watch.split("-"))
    _wf = open(os.path.join(run.dir, "mmio_watch.txt"), "w", buffering=1)
    _orig_r, _orig_w = MocorEmu._py_mmio_read, MocorEmu._py_mmio_write

    def _w_read(self, addr, size):
        v = _orig_r(self, addr, size)
        if _wlo <= addr < _whi:
            _wf.write(f"{self.insn_total}\tR\t{addr:08x}\t{v:08x}\n")
        return v

    def _w_write(self, addr, size, value):
        if _wlo <= addr < _whi:
            _wf.write(f"{self.insn_total}\tW\t{addr:08x}\t{value:08x}\n")
        return _orig_w(self, addr, size, value)
    MocorEmu._py_mmio_read, MocorEmu._py_mmio_write = _w_read, _w_write
import importlib


def _parse_plugin(spec):
    name, _, kv = spec.partition(":")
    opts = {}
    for item in filter(None, kv.split(",")):
        k, _, v = item.partition("=")
        opts[k] = v
    return importlib.import_module("plat." + name), opts


plugins = [_parse_plugin(sp) for sp in args.plugin]
for mod, opts in plugins:
    if hasattr(mod, "pre"):
        mod.pre(run, opts)
kw = dict(mode="unstick", max_insns=args.max_insns, timeout_s=args.timeout,
          pump=not args.no_pump)
emu = MocorEmu.ckpt_load(run, args.ckpt, **kw) if args.ckpt else MocorEmu(run, **kw)
emu.tick_irq_cycle = [args.tick_irq]
# 1 OS tick per 200K insns = 1 ms at the 200 MIPS the timer models assume
# (WTL_TS_PER_INSN). 40K was harmless only while 4/5 ticks were dropped.
emu.tick_rate = args.tick_rate
if args.ckpt:
    # tick schedule is in tick units: rebase it to the current rate (a
    # checkpoint saved under another --tick-rate would otherwise shift the
    # next tick by the rate ratio)
    emu.tick_next = emu.insn_total // emu.tick_rate + 1
emu.stall_insns = args.stall
for mod, opts in plugins:
    mod.install(emu, run, opts)
if args.sigtap:
    from unicorn import UC_HOOK_BLOCK
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR
    _sf = open(os.path.join(run.dir, "signals.txt"), "w", buffering=1)
    _qn = {}

    def _rd(uc, a, n=4):
        try:
            return int.from_bytes(uc.mem_read(a, n), "little")
        except Exception:
            return 0

    def _sigtap(uc, a, size, ud):
        q = uc.reg_read(UC_ARM_REG_R0)
        src = uc.reg_read(UC_ARM_REG_R1)
        name = _qn.get(q)
        if name is None:
            try:
                name = bytes(uc.mem_read(_rd(uc, q + 4), 24)).split(bytes(1))[0].decode("latin1")
            except Exception:
                name = "?"
            _qn[q] = name
        w = [_rd(uc, src + 4 * i) for i in range(4)]
        lr = uc.reg_read(UC_ARM_REG_LR)
        if lr == 0x8109a5cb:            # SCI_SendSignal: msg[0] = signal ptr
            sig = w[0]
            h0, h4 = _rd(uc, sig), _rd(uc, sig + 4)
            desc = (f"S code0={h0 & 0xffff:#06x} sz={h0 >> 16:#x} "
                    f"w4={h4 & 0xffff:#06x} w6={h4 >> 16:#06x}")
        else:                           # ISI/OSAL message
            desc = f"I id={w[1] >> 16:#06x} w0={w[0]:#x} p={w[2]:#x}"
        _sf.write(f"{emu.insn_total}\t{name}\t{desc}\tlr={lr:#x}\n")
    emu.mu.hook_add(UC_HOOK_BLOCK, _sigtap, begin=0x8110a7c0, end=0x8110a7c0)
if args.wwatch:
    from unicorn import UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR
    _wa = int(args.wwatch, 16)

    def _ww(uc, access, address, size, value, ud):
        run.log(f"[WWATCH] {address:#x} <- {value:#x} (size {size}) pc={uc.reg_read(UC_ARM_REG_PC):#x} "
                f"lr={uc.reg_read(UC_ARM_REG_LR):#x} insn={emu.insn_total}")
    emu.mu.hook_add(UC_HOOK_MEM_WRITE, _ww, begin=_wa, end=_wa + 3)
if args.probe:
    from unicorn import UC_HOOK_BLOCK
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R7, UC_ARM_REG_LR
    _pn = {}

    _pr0 = int(args.probe_r0, 16) if args.probe_r0 else None

    def _probe(uc, a, size, ud):
        if _pr0 is not None and uc.reg_read(UC_ARM_REG_R0) != _pr0:
            return
        n = _pn[a] = _pn.get(a, 0) + 1
        if n <= 20:
            r = [uc.reg_read(x) for x in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R7)]
            run.log(f"[PROBE] {a:#x} #{n} r0={r[0]:#x} r1={r[1]:#x} r2={r[2]:#x} r3={r[3]:#x} "
                    f"lr={r[4]:#x} r4={r[5]:#x} r5={r[6]:#x} insn={emu.insn_total}")
            try:
                from unicorn.arm_const import UC_ARM_REG_SP
                sp_ = uc.reg_read(UC_ARM_REG_SP)
                st_ = bytes(uc.mem_read(sp_, 0x200))
                ws_ = [int.from_bytes(st_[i:i + 4], 'little') for i in range(0, 0x200, 4)]
                cs_ = [hex(w) for w in ws_ if (0x80a00000 <= w < 0x82000000 or 0x88000000 <= w < 0x89000000) and w & 1][:14]
                run.log(f"[PROBE]   stack: {' '.join(cs_)}")
            except Exception:
                pass
            for nm, rv in (("r0", r[0]), ("r4", r[5]), ("r7", r[7])):
                if 0x80000000 <= rv < 0xC0000000:
                    try:
                        run.log(f"[PROBE]   [{nm}] = {bytes(uc.mem_read(rv, 0x40)).hex(' ', 4)}")
                    except Exception:
                        pass
    for x in args.probe.split(","):
        emu.mu.hook_add(UC_HOOK_BLOCK, _probe, begin=int(x, 16), end=int(x, 16))
import fwpaths
ckdir = fwpaths.CKPT_DIR
emu.save_at = [(n, os.path.join(ckdir, f"{args.tag}_{n // 1_000_000}M.ckpt"))
               for n in sorted(num(x) for x in args.save_at.split(",") if x)]
if args.ckpt:
    try:
        emu._loop(emu.mu.reg_read(UC_ARM_REG_PC))
    finally:
        emu.close_cell_trace()
else:
    emu.boot_run()
pc = emu.mu.reg_read(UC_ARM_REG_PC)
for mod, opts in plugins:
    if hasattr(mod, "finish"):
        mod.finish(emu, run, opts)
if args.save_final:
    emu.ckpt_save(args.save_final)
    run.log(f"final checkpoint -> {args.save_final}")
run.log(f"stop={emu.stop_reason} detail={emu.stop_detail} pc={pc:#x} "
        f"insns={emu.insn_total}")
try:
    emu.report()
except Exception as e:
    run.log(f"report fail: {e}")
run.close()
