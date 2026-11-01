"""bulk_classify.py -- call every known firmware function under a few argument patterns
(emu_call.Harness) and classify it from the outcomes. Results: runs/funcdb.sqlite.

  python bulk_classify.py --sample 500            # stratified sample, then --summary
  python bulk_classify.py                         # everything not yet in the DB (resumable)
  python bulk_classify.py --workers 12 --ckpt runs/ckpt/IDLE2_5500M.ckpt
  python bulk_classify.py --classify              # recompute funcs.class from calls
  python bulk_classify.py --summary               # counts per class/outcome + top functions

Tables: funcs(addr,image,name,nokia_name,size,mode,tier,class,tags,nokia_addr)
        calls(addr,pattern,outcome,ret,insns,n_callees,callees_json,writes_json,mmio_json,
              assert_text,ms,guest_log)
addr is the entry address as an integer (no Thumb bit). Run with the same --ckpt to resume.

Inputs (all in fwpaths.FUNCS_DIR, default funcs/; you export them from your own disassembler project):
  mmi_funcs.tsv, kernel_funcs.tsv  rows "F<TAB>hexaddr<TAB>size<TAB>name<TAB>thumb" (required)
  names.tsv                        optional "hexaddr<TAB>name": names you trust (tier 0)
  matched.tsv                      optional "hexaddr<TAB>ref_hexaddr<TAB>ref_name": functions matched
                                   against another firmware build (fills nokia_name/nokia_addr;
                                   the column names are historical)
"""
import sys, os, re, json, time, sqlite3, argparse, random, collections
import multiprocessing as mp

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fwpaths                                            # noqa: E402
GH = fwpaths.FUNCS_DIR
DEFAULT_DB = os.path.join(fwpaths.RUNS_DIR, "funcdb.sqlite")
DEFAULT_CKPT = fwpaths.IDLE_CKPT
PATTERNS = ["zeros", "ints", "ptrs", "ucs2"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS funcs(addr INTEGER PRIMARY KEY, image TEXT, name TEXT, nokia_name TEXT,
  size INTEGER, mode INTEGER, tier INTEGER, class TEXT, tags TEXT, nokia_addr INTEGER);
CREATE TABLE IF NOT EXISTS calls(addr INTEGER, pattern TEXT, outcome TEXT, ret INTEGER, insns INTEGER,
  n_callees INTEGER, callees_json TEXT, writes_json TEXT, mmio_json TEXT, assert_text TEXT,
  ms REAL, guest_log TEXT, PRIMARY KEY(addr, pattern));
"""


# ------------------------------------------------------------------ function list
def _tsv(path):
    for line in open(path):
        t = line.rstrip("\n").split("\t")
        if len(t) >= 4 and t[0] == "F":
            yield int(t[1], 16), int(t[2]), t[3], (int(t[4]) if len(t) > 4 else 1)


def api_names():
    """address -> trusted name from funcs/names.tsv (hexaddr<TAB>name), if present."""
    out = {}
    p = os.path.join(GH, "names.tsv")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8", errors="replace"):
            t = line.rstrip("\n").split("\t")
            if len(t) >= 2 and re.match(r"^(0x)?[0-9a-fA-F]+$", t[0]) and \
                    re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", t[1]):
                out.setdefault(int(t[0], 16) & ~1, t[1])
    return out


def matched_names():
    """(address -> ref address, ref address -> Counter(name)) from funcs/matched.tsv, if present."""
    M, NN = {}, {}
    p = os.path.join(GH, "matched.tsv")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8", errors="replace"):
            t = line.rstrip("\n").split("\t")
            if len(t) >= 2 and not t[0].startswith("#"):
                a, ra = int(t[0], 16) & ~1, int(t[1], 16)
                M[a] = ra
                if len(t) >= 3 and t[2]:
                    NN.setdefault(ra, collections.Counter())[t[2]] += 1
    return M, NN


def build_funcs(db):
    cur = db.cursor()
    names = api_names()
    M, NN = matched_names()
    rows = []
    for addr, size, nm, tm in _tsv(os.path.join(GH, "mmi_funcs.tsv")):
        na = M.get(addr)
        nk = None
        if na is not None and na in NN:
            nk = NN[na].most_common(1)[0][0]
        if addr in names:
            nm = names[addr]
            tier = 0
        elif nk:
            tier = 1
        elif na is not None:
            tier = 3
        else:
            tier = 4
        rows.append((addr, "mmi_app", nm, nk, size, tm, tier, None, None, na))
    for addr, size, nm, tm in _tsv(os.path.join(GH, "kernel_funcs.tsv")):
        if addr < 0x2000 or size < 2:
            continue                       # low blob = exception stubs (calls trap as os_switch)
        if addr in names:
            nm = names[addr]
            tier = 0
        else:
            tier = 2 if not nm.startswith(("FUN_", "thunk_FUN_")) else 5
        rows.append((addr, "kernel", nm, None, size, tm, tier, None, None, None))
    cur.executemany("INSERT OR IGNORE INTO funcs VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
    db.commit()
    print(f"funcs: {len(rows)} rows ({sum(1 for r in rows if r[1] == 'mmi_app')} mmi_app)")


# ------------------------------------------------------------------ worker
def _args(h, pat):
    if pat == "zeros":
        return [0, 0, 0, 0]
    if pat == "ints":
        return [1, 2, 3, 4]
    if pat == "ptrs":
        return [h.buf(f"p{i}", 4096) for i in range(4)]
    return [h.ucs2("s0", "E:\\test.txt"), h.buf("p1", 4096), h.ucs2("s2", "abc"), 8]


def _assert_text(rep):
    parts = []
    for a in rep.get("asserts", []):
        parts.append(f"{a.get('file')}:{a.get('line')} {a.get('expr')}")
    a = rep.get("assert")
    if a and rep["outcome"] == "fatal_assert":
        parts.append(f"{a.get('file')}:{a.get('line')} {a.get('expr')}")
    if parts:
        return " | ".join(parts)
    return json.dumps(rep["detail"])[:300] if rep.get("detail") else ""


def _row(addr, pat, rep):
    return (addr, pat, rep["outcome"], int(rep["ret"], 16), rep["insns"], rep["n_callees"],
            json.dumps(rep["callees"]), json.dumps({"n": rep["n_writes"], "ranges": rep["writes"][:32],
                                                    "bufs": rep["buf_changes"]}),
            json.dumps(rep["mmio"][:32]), _assert_text(rep), rep["ms"],
            json.dumps(rep.get("guest_log", []))[:1500])


def worker_main(wid, ckpt, taskq, resq, cur, budget, wall):
    sys.path.insert(0, HERE)
    import emu_call
    h = emu_call.Harness(ckpt, budget=budget, wall_s=wall)
    h.audit_snapshot()                               # stray-write guard (see Harness.audit)
    resq.put(("ready", wid))
    nfun = 0
    while True:
        chunk = taskq.get()
        if chunk is None:
            return
        out = []
        for addr, tm in chunk:
            cur[wid] = addr
            fn = addr | (1 if tm else 0)
            for pat in PATTERNS:
                try:
                    rep = h.call(fn, _args(h, pat), force_arm=(not tm))
                except Exception as e:                       # harness bug: keep going, reload
                    rep = {"outcome": "harness_error", "ret": "0x0", "insns": 0, "n_callees": 0,
                           "callees": [], "n_writes": 0, "writes": [], "buf_changes": {},
                           "mmio": [], "ms": 0, "detail": {"exc": repr(e)[:200]}}
                    h.dirty = True                           # state unknown: recycle the process
                out.append(_row(addr, pat, rep))
        cur[wid] = 0
        resq.put(("rows", wid, out))
        nfun += len(chunk)
        if nfun % 100 < len(chunk):                  # zero pages garbage pointers wrote outside the diff windows
            h.audit(clean=True)
        if h.dirty or nfun >= 600:          # device models touched (or leak guard): fresh process
            resq.put(("bye", wid))
            return


def run_bulk(a):
    db = sqlite3.connect(a.db)
    db.executescript(SCHEMA)
    if db.execute("SELECT COUNT(*) FROM funcs").fetchone()[0] == 0:
        build_funcs(db)
    done = collections.Counter(r[0] for r in db.execute("SELECT addr FROM calls"))
    cand = db.execute("SELECT addr, mode, tier, image FROM funcs WHERE tier<=? ORDER BY tier, addr",
                      (a.tier_max,)).fetchall()
    todo = [(ad, md, t, im) for ad, md, t, im in cand
            if ad not in done]
    if a.sample:
        rnd = random.Random(a.seed)
        want = {0: 60, 1: 150, 2: 140, 3: 100, 4: 50}
        pick = []
        for t, n in want.items():
            pool = [x for x in todo if x[2] == t]
            pick += rnd.sample(pool, min(n, len(pool)))
        todo = pick[:a.sample]
    if a.limit:
        todo = todo[:a.limit]
    print(f"todo {len(todo)} functions x {len(PATTERNS)} patterns, {a.workers} workers", flush=True)
    if not todo:
        return
    mpc = mp.get_context("spawn")
    taskq, resq = mpc.Queue(), mpc.Queue()
    cur = mpc.Array("q", a.workers, lock=False)
    chunks = [[(x[0], x[1])] for x in todo]          # 1 function per chunk: a crash loses only it
    for c in chunks:
        taskq.put(c)
    procs = {}

    def spawn(w):
        p = mpc.Process(target=worker_main, args=(w, a.ckpt, taskq, resq, cur, a.budget, a.wall),
                        daemon=True)
        p.start()
        procs[w] = [p, time.time()]
    for w in range(a.workers):
        spawn(w)
    t0 = time.time()
    n_done = 0
    outcomes = collections.Counter()
    last_print = 0
    pending = len(chunks)
    while pending > 0:
        try:
            msg = resq.get(timeout=5)
        except Exception:
            msg = None
        if msg and msg[0] == "rows":
            rows = msg[2]
            db.executemany("INSERT OR REPLACE INTO calls VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            db.commit()
            for r in rows:
                outcomes[r[2]] += 1
            n_done += len(rows) // len(PATTERNS)
            pending -= 1
            procs[msg[1]][1] = time.time()
        # a dead or hung worker loses its function: record the culprit, respawn
        for w, (p, hb) in list(procs.items()):
            hung = p.is_alive() and (time.time() - hb > a.hang_s) and cur[w] != 0
            if hung or not p.is_alive():
                bad = cur[w]
                if hung:
                    p.terminate()
                if bad:
                    db.execute("INSERT OR REPLACE INTO calls VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                               (bad, "all", "worker_crash", 0, 0, 0, "[]", "{}", "[]",
                                "hung" if hung else f"exit {p.exitcode}", 0, "[]"))
                    db.commit()
                    outcomes["worker_crash"] += 1
                    cur[w] = 0
                    pending -= 1
                spawn(w)
        if time.time() - last_print > 30:
            last_print = time.time()
            el = time.time() - t0
            print(f"[{el:6.0f}s] {n_done}/{len(todo)} funcs ({n_done / max(el, 1):.1f}/s) "
                  f"{dict(outcomes.most_common(8))}", flush=True)
    for p, _ in procs.values():
        p.terminate()
    print(f"finished {n_done}/{len(todo)} in {time.time() - t0:.0f}s", flush=True)
    classify(db)
    db.close()


# ------------------------------------------------------------------ classification
GUI_RE = re.compile(r"^(GUI|GUISTR|LCD|LCDC|IMG|GUIBLOCK|GUIIM|GUIBUTTON|GUILABEL|GUILIST|GUIMENU|GUIEDIT|GUIANIM|MMITHEME)")
FS_RE = re.compile(r"^(SFS|FFS|FS_|FAT|MMIFILE|MMIFMM)")
OS_RE = re.compile(r"^_?(tx_|SCI_(Get|Put|Sleep|Wait|Create|Delete|Receive|Send))")


def _veneers():
    """veneer address -> target from funcs/veneers.tsv (hexaddr<TAB>hexaddr), if present."""
    V = {}
    p = os.path.join(GH, "veneers.tsv")
    if os.path.exists(p):
        for line in open(p):
            t = line.split()
            if len(t) >= 2 and not t[0].startswith("#"):
                V[int(t[0], 16)] = int(t[1], 16)
    return V


def classify(db):
    funcs = {}
    for ad, nm, nk, im in db.execute("SELECT addr,name,nokia_name,image FROM funcs"):
        lab = nk or (nm if not nm.startswith(("FUN_", "thunk_FUN_")) else None)
        funcs[ad] = lab
    for v, k in _veneers().items():
        if funcs.get(k):
            funcs.setdefault(v, funcs[k])
    calls = collections.defaultdict(list)
    for ad, pat, oc, insns, nc, cj, wj, mj, ms in db.execute(
            "SELECT addr,pattern,outcome,insns,n_callees,callees_json,writes_json,mmio_json,assert_text FROM calls"):
        calls[ad].append((pat, oc, json.loads(cj or "[]"), json.loads(wj or "{}"), json.loads(mj or "[]"), ms))
    upd = []
    for ad, cl in calls.items():
        tags = set()
        outs = [c[1] for c in cl]
        ok = [c for c in cl if c[1] == "returned"]
        callee_labels = set()
        for c in cl:
            for x in c[2]:
                l = funcs.get(int(x, 16))
                if l:
                    callee_labels.add(l)
        if any(c[4] for c in cl):
            tags.add("hw-mmio")
        if any(o in ("os_block", "os_switch") for o in outs):
            tags.add("os-blocking")
        if any(GUI_RE.match(l) for l in callee_labels):
            tags.add("gui")
        if any(FS_RE.match(l) for l in callee_labels):
            tags.add("fs")
        if any(OS_RE.match(l) for l in callee_labels):
            tags.add("os-api")
        if any(o in ("assert", "fatal_assert") for o in outs) or any(c[5] and not c[5].startswith("{") for c in cl):
            tags.add("asserts")
        if outs and all(o.startswith(("fault", "invalid", "exception", "harness", "worker")) for o in outs):
            tags.add("faults")
        elif any(o.startswith(("fault", "invalid", "exception")) for o in outs):
            tags.add("fault-on-some")
        if outs and all(o in ("budget", "timeout", "runaway") for o in outs):
            tags.add("loops")
        wargs = False
        wglob = False
        for c in ok:
            w = c[3]
            if w.get("bufs"):
                wargs = True
            for r in w.get("ranges", []):
                if r.get("buf"):
                    wargs = True
                else:
                    wglob = True
        if wargs:
            tags.add("writes-args")
        if wglob:
            tags.add("writes-global")
        if ok and not wargs and not wglob and not any(c[4] for c in cl):
            tags.add("pure")
        for k in ("hw-mmio", "os-blocking", "gui", "fs", "asserts", "faults", "loops", "writes-args",
                  "writes-global", "pure"):
            if k in tags:
                klass = k
                break
        else:
            klass = "unknown"
        upd.append((klass, ",".join(sorted(tags)), ad))
    db.executemany("UPDATE funcs SET class=?, tags=? WHERE addr=?", upd)
    db.commit()
    print(f"classified {len(upd)} functions")


def summary(db, top=8):
    n = db.execute("SELECT COUNT(DISTINCT addr) FROM calls").fetchone()[0]
    tot = db.execute("SELECT COUNT(*) FROM funcs").fetchone()[0]
    print(f"functions in DB: {tot}; with calls: {n} ({db.execute('SELECT COUNT(*) FROM calls').fetchone()[0]} call rows)")
    print("\nclass counts (by priority class):")
    for k, c in db.execute("SELECT class,COUNT(*) FROM funcs WHERE class IS NOT NULL GROUP BY class ORDER BY 2 DESC"):
        print(f"  {k:14s} {c}")
    print("\ntag counts:")
    tc = collections.Counter()
    for (t,) in db.execute("SELECT tags FROM funcs WHERE tags IS NOT NULL"):
        tc.update(t.split(","))
    for k, c in tc.most_common():
        print(f"  {k:14s} {c}")
    print("\noutcome counts (call rows):")
    for k, c in db.execute("SELECT outcome,COUNT(*) FROM calls GROUP BY outcome ORDER BY 2 DESC"):
        print(f"  {k:16s} {c}")
    print("\noutcome counts by pattern:")
    for p in PATTERNS:
        r = db.execute("SELECT outcome,COUNT(*) FROM calls WHERE pattern=? GROUP BY outcome ORDER BY 2 DESC", (p,)).fetchall()
        print(f"  {p:6s} " + ", ".join(f"{o}={c}" for o, c in r))
    print("\ntop functions per class (named first, then most callees):")
    for (k,) in db.execute("SELECT DISTINCT class FROM funcs WHERE class IS NOT NULL ORDER BY class").fetchall():
        rows = db.execute(
            "SELECT f.addr,f.name,f.nokia_name,f.image,f.size,(SELECT MAX(n_callees) FROM calls c WHERE c.addr=f.addr),"
            "(SELECT MAX(insns) FROM calls c WHERE c.addr=f.addr) FROM funcs f WHERE f.class=? "
            "ORDER BY (f.nokia_name IS NULL AND f.name LIKE 'FUN_%'), 6 DESC LIMIT ?", (k, top)).fetchall()
        print(f"\n  [{k}]")
        for ad, nm, nk, im, sz, mc, mi in rows:
            print(f"    {ad:#010x} {im:7s} {nm}{(' / ' + nk) if nk else ''} size={sz} callees<={mc} insns<={mi}")
    files, exprs, cnt = set(), set(), collections.Counter()
    for (t,) in db.execute("SELECT assert_text FROM calls WHERE assert_text!='' AND assert_text NOT LIKE '{%'"):
        for seg in t.split(" | "):
            fl, _, ex = seg.partition(" ")
            files.add(fl.rpartition(":")[0])
            exprs.add(ex)
            cnt[seg] += 1
    nfunc = db.execute("SELECT COUNT(DISTINCT addr) FROM calls WHERE assert_text!='' AND assert_text NOT LIKE '{%'").fetchone()[0]
    print(f"\nasserts captured: {nfunc} functions, {len(files)} distinct files, {len(exprs)} distinct expressions, "
          f"{len(cnt)} distinct file:line+expr")
    for t, c in cnt.most_common(12):
        print("  %5d %s" % (c, t.encode("ascii", "replace").decode()))


def export_names(db, path):
    classify(db)
    funcs = {ad: (nm, nk) for ad, nm, nk in db.execute("SELECT addr,name,nokia_name FROM funcs")}

    def lab(x):
        if x not in funcs:
            return None
        nm, nk = funcs[x]
        return nk or (nm if not nm.startswith(("FUN_", "thunk_")) else None)
    V = _veneers()
    first = {}
    for ad, t in db.execute("SELECT addr,assert_text FROM calls WHERE assert_text!='' AND assert_text NOT LIKE '{%' "
                            "ORDER BY addr, CASE pattern WHEN 'zeros' THEN 0 WHEN 'ints' THEN 1 WHEN 'ptrs' THEN 2 ELSE 3 END"):
        first.setdefault(ad, t.split(" | ")[0])
    cal = collections.defaultdict(collections.Counter)
    for ad, cj in db.execute("SELECT addr,callees_json FROM calls WHERE n_callees>0"):
        for x in json.loads(cj):
            x = int(x, 16)
            l = lab(x) or lab(V.get(x, 0))
            if l:
                cal[ad][l] += 1
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        f.write("\t".join(["addr", "image", "name", "nokia_name", "class", "assert_file:line",
                           "first_assert_expr", "top_callees"]) + "\n")
        for ad, im, nm, nk, cl in db.execute("SELECT addr,image,name,nokia_name,class FROM funcs ORDER BY addr"):
            fa = first.get(ad, "")
            fl, _, ex = fa.partition(" ")
            top = ",".join(k for k, _ in cal[ad].most_common(6)) if ad in cal else ""
            if not (nk or fa or top or not nm.startswith(("FUN_", "thunk_"))):
                continue
            f.write("\t".join([f"{ad:#010x}", im, nm, nk or "", cl or "", fl, ex, top]) + "\n")
            n += 1
    print(f"wrote {n} rows to {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ckpt", default=DEFAULT_CKPT)
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--budget", type=lambda x: int(float(x)), default=200_000)
    ap.add_argument("--wall", type=float, default=6.0, help="wall seconds per call")
    ap.add_argument("--hang-s", type=float, default=240.0, help="kill a worker silent this long")
    ap.add_argument("--sample", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--tier-max", type=int, default=5, help="0 names.tsv names, 1 matched+named mmi, "
                    "2 named kernel, 3 matched mmi, 4 unmatched mmi, 5 unnamed kernel")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--classify", action="store_true")
    ap.add_argument("--build-funcs", action="store_true")
    ap.add_argument("--export-names", default="", help="write a per-function hints TSV")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.db), exist_ok=True)
    if a.summary or a.classify or a.build_funcs or a.export_names:
        db = sqlite3.connect(a.db)
        db.executescript(SCHEMA)
        if a.build_funcs:
            build_funcs(db)
        if a.export_names:
            export_names(db, a.export_names)
        elif a.classify or a.summary:
            classify(db)
        if a.summary:
            summary(db)
        return
    run_bulk(a)


if __name__ == "__main__":
    main()
