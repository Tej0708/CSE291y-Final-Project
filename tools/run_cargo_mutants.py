#!/usr/bin/env python3
"""E1: blind mutation experiment driven by cargo-mutants-generated mutants.

Enumerates all cargo-mutants for allocator.rs (unified-diff JSON), applies
each with `patch`, rebuilds, and runs the relevant harness arms. Detection =
nonzero libFuzzer exit. Unviable (compile-fail) mutants are recorded.

Usage: run_cargo_mutants.py [--budget 10] [--seeds 2] [--jobs 10] [--limit N]
"""
import argparse, json, os, re, subprocess, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from _env import REPO, FUZZ, RESULTS, RELEASE_DIR, ENV

ALLOC = REPO / "kernel/src/allocator.rs"

TARGET_BINS = {
    "allocate_in_grant_region": ("allocate_in_grant_region_spec", "allocate_in_grant_region_plain"),
    "in_app_ram_memory": ("in_app_ram_memory_spec", "in_app_ram_memory_plain"),
    "in_app_flash_memory": ("in_app_flash_memory_spec", "in_app_flash_memory_plain"),
    "add_shared_readwrite": ("add_shared_readwrite_buffer_spec", "add_shared_readwrite_buffer_plain"),
    "update_app_memory": ("update_app_memory_spec", "update_app_memory_plain"),
    "api_sequence": ("api_sequence_spec", "api_sequence_plain"),
    "next_available_ipc_idx": ("next_available_ipc_idx_spec", "next_available_ipc_idx_plain"),
    "allocate_ipc_region": ("allocate_ipc_region_spec", "allocate_ipc_region_plain"),
    "get_app_breaks": ("get_app_breaks_spec", "get_app_breaks_plain"),
}

# diff-header function name -> relevant targets (None = skip: unreachable)
FN_TARGETS = {
    "flash_start": ["update_app_memory", "allocate_in_grant_region"],
    "flash_end": ["update_app_memory", "allocate_in_grant_region"],
    "memory_start": ["update_app_memory", "allocate_in_grant_region"],
    "memory_size": ["update_app_memory", "allocate_in_grant_region"],
    "memory_end": ["update_app_memory", "allocate_in_grant_region"],
    "app_break": ["update_app_memory", "allocate_in_grant_region"],
    "kernel_break": ["update_app_memory", "allocate_in_grant_region"],
    "in_app_ram_memory": ["in_app_ram_memory", "add_shared_readwrite", "api_sequence"],
    "in_app_flash_memory": ["in_app_flash_memory", "api_sequence"],
    "new_regions": ["allocate_in_grant_region", "update_app_memory"],
    "add_shared_readonly_buffer": ["api_sequence"],
    "add_shared_readwrite_buffer": ["add_shared_readwrite", "api_sequence"],
    "allocate_custom_grant": None,
    "allocate_in_grant_region_internal": ["allocate_in_grant_region", "api_sequence"],
    "set_kernel_break": ["allocate_in_grant_region", "api_sequence"],
    "next_available_ipc_idx": ["api_sequence", "next_available_ipc_idx", "allocate_ipc_region"],
    "any_overlaps": ["api_sequence", "allocate_ipc_region"],
    "overlaps_app_block": ["api_sequence", "allocate_ipc_region"],
    "allocate_ipc_region": ["api_sequence", "allocate_ipc_region"],
    "get_flash_region": ["allocate_in_grant_region", "update_app_memory"],
    "get_ram_regions": ["allocate_in_grant_region", "update_app_memory"],
    "get_app_breaks": ["allocate_in_grant_region", "update_app_memory", "get_app_breaks"],
    "allocate_app_memory": ["allocate_in_grant_region", "update_app_memory", "get_app_breaks"],
    "update_app_memory": ["update_app_memory", "api_sequence"],
    "fmt": None,
}


def fn_of(diff):
    """Extract the mutated function name from the cargo-mutants diff title.
    Titles look like:
      '+++ replace AppMemoryAllocator<R>::flash_start -> FluxPtrU8 with ...'
      '+++ replace && with || in AppMemoryAllocator<R>::in_app_ram_memory'
    The first `::name` in the title is the function in both shapes."""
    title = diff.splitlines()[1] if len(diff.splitlines()) > 1 else diff
    m = re.search(r"::(\w+)", title)
    return m.group(1) if m else "?"


def bump(p):
    st = p.stat()
    os.utime(p, (st.st_atime + 5, st.st_mtime + 5))


def build_bins(retries=5):
    r = None
    for attempt in range(retries):
        r = subprocess.run(["cargo", "fuzz", "build", "--sanitizer", "none"],
                           cwd=FUZZ, env=ENV, capture_output=True, text=True, timeout=900)
        if r.returncode == 0:
            return True
        time.sleep(3)
    print(f"  build failed {retries}x -> unviable", flush=True)
    return False


def run_one(bin_name, budget, seed, outdir):
    cmd = [str(RELEASE_DIR / bin_name),
           f"-artifact_prefix={outdir}/", f"-max_total_time={budget}", f"-seed={seed}",
           "-rss_limit_mb=4096"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=budget + 120, env=ENV)
    except subprocess.TimeoutExpired:
        # slow unit / wedged target: a hang is a finding too
        return {"bin": bin_name, "seed": seed, "detected": True, "detail": "TIMEOUT (hang)"}
    detail = ""
    if r.returncode != 0:
        lines = [l for l in (r.stdout + r.stderr).splitlines()
                 if "SPEC VIOLATION" in l or "panicked" in l or "ERROR:" in l]
        detail = " | ".join(lines[:2])[:300]
    return {"bin": bin_name, "seed": seed, "detected": r.returncode != 0, "detail": detail}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=10)
    ap.add_argument("--seeds", type=int, default=2)
    ap.add_argument("--jobs", type=int, default=10)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    outdir = RESULTS / "artifacts"
    outdir.mkdir(exist_ok=True)

    list_file = RESULTS / "cargo_mutants_list.json"
    if not list_file.exists():
        r = subprocess.run(["cargo", "mutants", "--list", "--json", "--diff", "--file", "kernel/src/allocator.rs"],
                           cwd=REPO, env=ENV, capture_output=True, text=True, timeout=600)
        list_file.write_text(r.stdout)
    mutants = json.loads(list_file.read_text())
    if args.limit:
        mutants = mutants[: args.limit]
    print(f"{len(mutants)} cargo-mutants enumerated", flush=True)

    baseline = ALLOC.read_text()
    res_file = RESULTS / "cargo_mutants_results.json"
    results = []
    done_idx = set()
    if args.resume and res_file.exists():
        results = json.loads(res_file.read_text())
        done_idx = {r["idx"] for r in results if r.get("status") != "run"}
        print(f"resuming: {len(done_idx)} mutants already resolved", flush=True)

    def dump():
        (RESULTS / "cargo_mutants_results.json").write_text(json.dumps(results, indent=1))

    def apply_diff(diff):
        # unified diff against kernel/src/allocator.rs, apply from repo root
        df = Path("/tmp/cm_diff.patch")
        df.write_text(diff + "\n")
        r = subprocess.run(["patch", "-p0", "--silent", "-i", str(df)],
                           cwd=REPO, capture_output=True, text=True, timeout=60)
        return r.returncode == 0

    for i, m in enumerate(mutants):
        if i in done_idx:
            continue
        diff = m.get("diff", "")
        fn = fn_of(diff)
        tgts = FN_TARGETS.get(fn)
        if tgts is None:
            results.append({"idx": i, "fn": fn, "status": "skipped-unreachable",
                            "name": diff.splitlines()[1][7:] if len(diff.splitlines()) > 1 else "?"})
            dump()
            continue
        ALLOC.write_text(baseline)
        bump(ALLOC)
        if not apply_diff(diff):
            results.append({"idx": i, "fn": fn, "status": "skipped-apply-failed"})
            dump()
            continue
        bump(ALLOC)
        print(f"[{i + 1}/{len(mutants)}] {fn}: building...", flush=True)
        if not build_bins():
            results.append({"idx": i, "fn": fn, "status": "unviable"})
            dump()
            continue
        runs = []
        for t in tgts:
            spec, plain = TARGET_BINS[t]
            for arm, b in (("spec", spec), ("plain", plain)):
                for s in range(args.seeds):
                    runs.append((t, arm, b, s))
        with ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = {ex.submit(run_one, b, args.budget, s, str(outdir)): (t, arm, s)
                    for t, arm, b, s in runs}
            det_by = {}
            for f, (t, arm, s) in futs.items():
                res = f.result()
                det_by.setdefault((t, arm), []).append(res)
                results.append({"idx": i, "fn": fn, "status": "run", "target": t, "arm": arm,
                                "seed": s, **res})
                dump()
        spec_det = any(r["detected"] for (t, a), rs in det_by.items() if a == "spec" for r in rs)
        plain_det = any(r["detected"] for (t, a), rs in det_by.items() if a == "plain" for r in rs)
        status = "both" if spec_det and plain_det else "spec-only" if spec_det else "plain-only" if plain_det else "survived"
        print(f"    -> {status}", flush=True)
        results.append({"idx": i, "fn": fn, "status": status})
        dump()

    ALLOC.write_text(baseline)
    bump(ALLOC)

    # summary
    stat = {}
    for r in results:
        if r["status"] in ("both", "spec-only", "plain-only", "survived", "unviable",
                           "skipped-unreachable", "skipped-apply-failed"):
            stat[r["status"]] = stat.get(r["status"], 0) + 1
    print("\n=== CARGO-MUTANTS SUMMARY ===")
    for k, v in sorted(stat.items()):
        print(f"  {k}: {v}")
    ns = sum(1 for r in results if r["status"] in ("both", "spec-only"))
    np_ = sum(1 for r in results if r["status"] in ("both", "plain-only"))
    nrun = sum(1 for r in results if r["status"] in ("both", "spec-only", "plain-only", "survived"))
    print(f"  mutants run: {nrun}; killed by spec: {ns}; killed by plain: {np_}")


if __name__ == "__main__":
    main()
