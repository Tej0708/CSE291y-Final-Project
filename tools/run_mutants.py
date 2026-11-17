#!/usr/bin/env python3
"""H1/H2 mutation experiment runner (v3).

Applies mutants to tock-flux kernel sources, rebuilds the fuzz targets
(build-then-run per mutant: binaries are only valid until the next source
change), and runs harness arms with fixed seeds/time budgets.

Supports:
  - per-file patches (allocator.rs / mpu.rs) with "@anchor" scoped replaces
  - oracle-level ablation via FUZZ_ORACLE_LEVEL (--levels)
  - arm selection (--arms spec,plain)

Usage: python3 run_mutants.py [--budget 30] [--seeds 5] [--jobs 10]
                              [--only M2,M3|original] [--arms spec]
                              [--levels 1,2,3]
"""
import argparse, json, os, subprocess, tempfile, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from _env import REPO, FUZZ, RESULTS, RELEASE_DIR, ENV, TOOLCHAIN

SOURCES = {
    "allocator": REPO / "kernel/src/allocator.rs",
    "mpu": REPO / "kernel/src/platform/mpu.rs",
}

TARGETS = {
    "allocate_in_grant_region": ("allocate_in_grant_region_spec", "allocate_in_grant_region_plain", ["M1", "M2", "M3", "M4", "M5"]),
    "add_shared_readwrite": ("add_shared_readwrite_buffer_spec", "add_shared_readwrite_buffer_plain", ["M6"]),
    "update_app_memory": ("update_app_memory_spec", "update_app_memory_plain", ["M7", "M8", "M9"]),
    "mpu_default": ("mpu_default_spec", "mpu_default_plain", ["MP"]),
    "api_sequence": ("api_sequence_spec", "api_sequence_plain", ["M3", "M6", "M7", "M8"]),
    "next_available_ipc_idx": ("next_available_ipc_idx_spec", "next_available_ipc_idx_plain", ["MNI", "MIPC"]),
    "allocate_ipc_region": ("allocate_ipc_region_spec", "allocate_ipc_region_plain", ["MIPC"]),
    "get_app_breaks": ("get_app_breaks_spec", "get_app_breaks_plain", ["MGAB"]),
}


def load_mutants():
    source = Path(__file__).resolve().with_name("mutants.rs")
    with tempfile.TemporaryDirectory(prefix="spec-fuzz-mutants-") as tmp:
        catalog = Path(tmp) / "mutants"
        subprocess.run(
            ["rustc", f"+{TOOLCHAIN}", "--edition=2021", str(source), "-o", str(catalog)],
            env=ENV, check=True,
        )
        return json.loads(subprocess.check_output([str(catalog)]))


def write_source(key, text):
    """Write and bump mtime: NFS ~1s granularity makes cargo skip rebuilds."""
    p = SOURCES[key]
    p.write_text(text)
    st = p.stat()
    os.utime(p, (st.st_atime + 5, st.st_mtime + 5))


def read_source(key):
    return SOURCES[key].read_text()


def apply_mutant(key, patches):
    src = read_source(key)
    for pat in patches:
        if pat[0].startswith("@"):
            anchor, old, new = pat
            i = src.index(anchor[1:])  # first occurrence of the anchor fn
            j = src.index(old, i)  # first occurrence of old AFTER the anchor
            src = src[:j] + src[j:].replace(old, new, 1)
        else:
            old, new = pat
            assert src.count(old) == 1, f"pattern not unique/found in {key}: {old[:60]!r} ({src.count(old)})"
            src = src.replace(old, new)
    write_source(key, src)


def build_bins(retries=5):
    # This host has flaky storage (linker Bus errors); cargo caches successes,
    # so retrying only rebuilds the failed link.
    r = None
    for attempt in range(retries):
        r = subprocess.run(
            ["cargo", "fuzz", "build", "--sanitizer", "none"],
            cwd=FUZZ, env=ENV, capture_output=True, text=True, timeout=900,
        )
        if r.returncode == 0:
            return
        print(f"  build attempt {attempt + 1} failed, retrying...", flush=True)
        time.sleep(3)
    raise RuntimeError(f"build failed after {retries} attempts:\n{r.stderr[-1500:]}")


def run_one(bin_name, budget, seed, outdir, level=None):
    env = dict(ENV)
    if level is not None:
        env["FUZZ_ORACLE_LEVEL"] = str(level)
    cmd = [str(RELEASE_DIR / bin_name),
           f"-artifact_prefix={outdir}/", f"-max_total_time={budget}", f"-seed={seed}",
           "-rss_limit_mb=4096"]
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=budget + 180, env=env)
    crashed = r.returncode != 0
    detail = ""
    if crashed:
        lines = [l for l in (r.stdout + r.stderr).splitlines()
                 if "SPEC VIOLATION" in l or "panicked" in l or "ERROR:" in l]
        detail = " | ".join(lines[:3])[:400]
    return {"bin": bin_name, "seed": seed, "detected": crashed,
            "exit": r.returncode, "time": round(time.time() - t0, 1), "detail": detail,
            "level": level}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=30)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--jobs", type=int, default=10)
    ap.add_argument("--only", default="", help="comma list of mutant names or 'original'")
    ap.add_argument("--arms", default="spec,plain")
    ap.add_argument("--levels", default="", help="comma list of FUZZ_ORACLE_LEVEL values; empty = default env")
    args = ap.parse_args()

    only = args.only.split(",")
    do_original = not args.only or "original" in args.only
    mutants = [] if only == ["original"] else load_mutants()
    selected = [m for m in mutants if not args.only or any(o in m[0] for o in only)]
    RESULTS.mkdir(parents=True, exist_ok=True)
    baselines = {k: read_source(k) for k in SOURCES}
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    levels = [int(x) for x in args.levels.split(",") if x.strip()] or [None]
    outdir = RESULTS / "artifacts"
    outdir.mkdir(exist_ok=True)

    results = []
    done_total = [0]

    def dump_results():
        (RESULTS / "results_latest.json").write_text(json.dumps(results, indent=1))

    run_matrix = []  # (tgt, mname, cat, bin, seed, level)

    def run_current():
        with ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = {
                ex.submit(run_one, bin_name, args.budget, seed, str(outdir), level): (tgt, mname, cat, bin_name, seed, level)
                for tgt, mname, cat, bin_name, seed, level in run_matrix
            }
            for f, meta in futs.items():
                res = f.result()
                tgt, mname, cat, bin_name, seed, level = meta
                res.update({"target": tgt, "mutant": mname, "category": cat})
                results.append(res)
                dump_results()
                done_total[0] += 1
                lv = f" lvl={level}" if level else ""
                print(f"[{done_total[0]}] {mname} {bin_name}{lv} seed={seed} detected={res['detected']}", flush=True)
        run_matrix.clear()

    try:
        # Build-then-run per configuration: binaries are only valid until the
        # next source change, so runs must complete before the next build.
        if do_original:
            for k, txt in baselines.items():
                write_source(k, txt)
            print("building original...", flush=True)
            build_bins()
            for name, (spec, plain, _) in TARGETS.items():
                for s in range(args.seeds):
                    for lv in levels:
                        for arm in arms:
                            run_matrix.append(("original", "original", "none", spec if arm == "spec" else plain, s, lv))
            run_current()
        for mname, cat, key, patches in selected:
            for k, txt in baselines.items():
                write_source(k, txt)
            print(f"building {mname}...", flush=True)
            apply_mutant(key, patches)
            build_bins()
            for tgt, (spec, plain, tags) in TARGETS.items():
                if not any(mname.startswith(t) for t in tags):
                    continue
                for s in range(args.seeds):
                    for lv in levels:
                        for arm in arms:
                            run_matrix.append((tgt, mname, cat, spec if arm == "spec" else plain, s, lv))
            run_current()
    finally:
        for k, txt in baselines.items():
            write_source(k, txt)

    out_file = RESULTS / f"h1_results_{int(time.time())}.json"
    out_file.write_text(json.dumps(results, indent=1))

    print("\n=== DETECTION SUMMARY ===")
    by_mutant = {}
    for r in results:
        key = (r["mutant"], r["category"], r["target"], r["level"])
        by_mutant.setdefault(key, []).append(r)
    for (mname, cat, tgt, lv), rs in sorted(by_mutant.items(), key=lambda x: str(x[0])):
        spec = [r for r in rs if r["bin"].endswith("_spec")]
        plain = [r for r in rs if r["bin"].endswith("_plain")]
        sd = sum(r["detected"] for r in spec)
        pd = sum(r["detected"] for r in plain)
        lvs = f" L{lv}" if lv else ""
        print(f"{mname:32s} {cat:10s}{lvs:4s} {tgt:28s} spec {sd}/{len(spec)}  plain {pd}/{len(plain)}")
    print(f"\nresults: {out_file}")


if __name__ == "__main__":
    main()
