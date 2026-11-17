#!/usr/bin/env python3
"""E3: coverage comparison spec vs plain per target, plus 300s budget tier.

Phase A (coverage): run each target pair for --cov-budget seconds, parse the
last `cov:` value from libFuzzer status output.
Phase B (budget tier): rerun selected handwritten mutants at 300s via
run_mutants.py (invoked separately).

Usage: coverage_compare.py [--cov-budget 30]
"""
import argparse, json, re, subprocess, time
from pathlib import Path

from _env import RELEASE_DIR, RESULTS

PAIRS = [
    ("allocate_in_grant_region", "allocate_in_grant_region_spec", "allocate_in_grant_region_plain"),
    ("in_app_ram_memory", "in_app_ram_memory_spec", "in_app_ram_memory_plain"),
    ("in_app_flash_memory", "in_app_flash_memory_spec", "in_app_flash_memory_plain"),
    ("add_shared_readwrite", "add_shared_readwrite_buffer_spec", "add_shared_readwrite_buffer_plain"),
    ("update_app_memory", "update_app_memory_spec", "update_app_memory_plain"),
    ("api_sequence", "api_sequence_spec", "api_sequence_plain"),
    ("power_of_two", "power_of_two_spec", "power_of_two_plain"),
    ("log_base_two", "log_base_two_spec", "log_base_two_plain"),
    ("ring_buffer", "ring_buffer_spec", "ring_buffer_plain"),
]


def cov_of(bin_name, budget, seed=42):
    cmd = [str(RELEASE_DIR / bin_name), "-max_total_time={}".format(budget), f"-seed={seed}",
           "-rss_limit_mb=4096"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=budget + 120)
    covs = re.findall(r"cov:\s+(\d+)", r.stdout + r.stderr)
    return int(covs[-1]) if covs else None, r.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cov-budget", type=int, default=30)
    args = ap.parse_args()
    out = {}
    for name, spec, plain in PAIRS:
        row = {}
        for arm, b in (("spec", spec), ("plain", plain)):
            c, rc = cov_of(b, args.cov_budget)
            row[arm] = {"cov": c, "exit": rc}
            print(f"{name:28s} {arm:5s} cov={c}", flush=True)
        out[name] = row
    RESULTS.joinpath("coverage_compare.json").write_text(json.dumps(out, indent=1))
    print(f"\nwritten {RESULTS/'coverage_compare.json'}")


if __name__ == "__main__":
    main()
