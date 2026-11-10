# Raw results

All JSONs share the schema of `tools/run_mutants.py` / `tools/run_cargo_mutants.py`:
one entry per harness run with `bin`, `seed`, `detected` (nonzero libFuzzer exit),
`exit`, `time`, `detail` (first panic/oracle message; `TIMEOUT (hang)` = outer
wall-clock cap), plus `target`/`mutant`/`category`/`level` where applicable.

| File | What it is |
|---|---|
| `h1_main_30s5seeds.json` | Main hand-written experiment: 9 mutants + original, {spec,plain} × 5 seeds × 30s |
| `h1_m6m9_evolved_rerun.json` | M6–M9 rerun with state-evolution harnesses + original false-positive recheck |
| `h1_original_false_positive_check.json` | Dedicated original-code false-positive control run |
| `results_latest.json` | Last incremental dump of a runner (the E6/E5 long-budget batch) |
| `cargo_mutants_list.json` | The 156 enumerated cargo-mutants (unified diffs) for allocator.rs |
| `cargo_mutants_results.json` | E1 blind-set run: per-run entries + per-mutant final status (`both`/`spec-only`/`plain-only`/`survived`/`unviable`/`skipped-*`) |
| `coverage_compare.json` | E3: spec-vs-plain libFuzzer edge coverage per target (30s, seed 42) |
| `translate_metrics.json` | E2: auto-generated oracle statements / TODO sites per generated harness |
| `log_*.log` | Console logs of the corresponding experiment batches, including the per-mutant `=== DETECTION SUMMARY ===` tables reproduced in the report |

Numbers in `docs/REPORT.md` §5 and §8 were verified against these files (an
audit pass re-derived the E1 kill matrix, detection-mechanism attribution
(hang vs signal), and the subset property from `cargo_mutants_results.json`).
