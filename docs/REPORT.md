# TickTock Spec→Fuzz Experiment Report

**Project**: Automatically deriving fuzz harnesses from Flux specs and evaluating their effectiveness (TickTock: Tock OS with Flux-verified memory isolation)
**Authors**: Tej Gaonkar, Xuan Zhou · **Executed by**: ZCode agent · **Date**: 2026-10-25
**Artifacts**: `tools/` + `results/` (this repo), `fuzz/` (harness crate), `kernel-patch/fuzz_shim.rs` (kernel shim)

---

## 1. Executive Summary

1. **H3 (census)**: Of the 109 `flux_rs::sig` specs in the kernel, **19 are fully (17.4%), 80 partially (73.4%), and 10 untranslatable (9.2%)**. All ten untranslatable specs are proof lemmas (empty runtime bodies). The hypothesis that the translatable fraction is capped by ghost refinement parameters and higher-order refinements is **partially confirmed but needs revision**: ghost params, `&strg` ownership, and `FluxPtrU8` backing-memory requirements only cause *partial* classifications (recoverable at runtime via invariant re-checks + snapshot diffs); the only hard wall is the lemma class.
2. **H1 (equal-budget detection rate): confirmed.** 9 hand-written mutants × 5 seeds × 30s: spec harness **35/45 (77.8%)** vs plain **5/45 (11.1%)**; all 30 paired disagreements one-directional, McNemar p ≈ 2⁻³⁰. Per mutant: 7/9 vs 1/9.
3. **H2 (spec-only detectable class): confirmed.** M3/M6/M8-class mutants return byte-identical values, never panic, and corrupt only ghost state — undetectable in principle for a plain fuzzer; the spec oracle detects all at 5/5.
4. **Notable findings beyond the hypotheses**:
   - **Verified code's assertions are runtime no-ops**: `flux_rs::assert` / `flux_support::assert` exist only for the Flux checker. The paper's underflow-bug-class mutation (M7) is completely silent under the oracle-free plain arm — the verified binary has **zero runtime protection** for its proven contracts. The spec harness turns ghost assertions into executable oracles: this is the project's most valuable positive result for RQ3 ("can specs check the assumptions proofs rely on").
   - **Implicit-precondition gap (F1)**: the verified constructor always yields `app_break == kernel_break` (zero grant space), so the Some path of `allocate_in_grant_region_internal` is dead unless `update_app_memory` runs first; watermark-class mutations additionally require raising `high_water_mark` first. Neither precondition appears in any spec's `requires` — naive spec→harness translation produces dead oracles and systematic missed detections (the first-round misses of M6/M7 were exactly this).
   - **`align` power-of-two spec gap (F2)**: the Flux spec holds for non-power-of-two `align` (verification is self-consistent), but the intent documented in the code comment is violated. Either the signature should be tightened or the spec should gain an alignment ensures.
   - **Infrastructure pitfalls (F6)**: 1-second NFS mtime granularity makes cargo silently skip rebuilds; the system `ar` segfaults (SIGBUS); build artifacts must live on local disk.

## 2. Method

### 2.1 Harness generation (Phases 2–3)

- **Shim**: `kernel/src/fuzz_shim.rs` (`#[cfg(fuzzing)]`, injected automatically by cargo-fuzz) re-exports the `pub(crate)` allocator internals via pub aliases/wrappers; three type visibilities were relaxed from `pub(crate)` to `pub` (`AppBreaks`, `AppMemoryAllocator`, `AllocateAppMemoryError`; see §7).
- **Generator**: reuses the **verified constructor** `allocate_app_memory` as the invariant-satisfying allocator generator (its ensures are Flux-proven, so generated allocators satisfy the AppBreaks invariant chain by construction); parameter decoding satisfies its requires (flash below RAM, sums ≤ u32::MAX, …) with boundary-biased values.
- **Three-level oracle**: L1 = struct invariant chain re-check; L2 = literal translation of sig ensures (incl. "None ⇒ state unchanged"); L3 = semantic contracts the verifier discharged (exact break movement, alignment, region rewrites). Selectable at runtime via `FUZZ_ORACLE_LEVEL`, default L3.
- **Snapshot**: AppBreaks field-by-field + regions[0..8] as (is_set, start, size) triples (perms / region_number / is_dirty unreachable — recorded as oracle blind spots).
- **10 targets**: 5 spec/plain pairs (allocate_in_grant_region_internal, in_app_ram_memory, in_app_flash_memory, add_shared_readwrite_buffer, update_app_memory); plain decodes identically to spec but has no oracle (results sunk via `black_box` to prevent elision).

### 2.2 Mutation experiment (Phases 5–6)

- Mutant set (9 hand-written; classes in §5); runner `tools/run_mutants.py`: per mutant rebuild → {spec, plain} × 5 seeds × 30s; nonzero libFuzzer exit = detected; detection details (which oracle fired) recorded to JSON.
- Equivalence filtering: M1/M9 predicted equivalent and verified as such; the original code produces zero false positives across 60 runs.

## 3. H3: Spec Census (details in census.md / census.csv)

109 sigs = 19 fully + 80 partial + 10 untranslatable; 12 invariants + 16 refined_by + 15 assoc all registered. All untranslatable attributed to TRUSTED-IMPL (lemmas). The reason-code distribution of partials and which oracle level recovers them is in census.md.

## 4. Findings List

| # | Type | Finding | Evidence |
|---|---|---|---|
| F1 | Methodology | Implicit preconditions (grant space > 0) absent from specs; naive translation yields dead oracles | v1 harness zero detections + `get_app_breaks` math |
| F2 | Spec gap | `align` unconstrained; non-power-of-two values violate documented intent while the Flux spec still holds | `fuzz/tests/align_gap.rs`, 2 passing tests |
| F3 | Hypothesis | A class of mutants exists that plain fuzzers cannot in principle detect (H2) | §5, M3/M6/M8 |
| F4 | Baseline hygiene | Both in-code Flux assertion families are runtime no-ops — the plain arm is not contaminated by verification instrumentation; but the verified binary has zero runtime protection for its contracts (M7 fully silent under plain) | flux-rs/src/lib.rs:10, flux_support/src/lib.rs:28 + M7 result |
| F5 | Oracle blind spots | `is_dirty`, `id`, region perms/region_number are outside the snapshot; corresponding mutants (e.g., dropping `is_dirty.set(true)`) evade even the spec harness — an observability gap between proofs and fuzzing | census + snapshot implementation |
| F6 | Repro pitfalls | NFS mtime → cargo silently skips rebuilds; system `ar` SIGBUS; artifacts must be local | all-zero anomaly → resolved after mtime fix |
| F7 | Tool roadmap | The blind set's survived-by-function distribution is a priority queue of new translator targets: allocate_app_memory (15), next_available_ipc_idx (8), get_app_breaks (5) are coverage holes of the current matrix | E1 survived-by-fn table |

## 5. H1/H2 Results (hand-written mutants)

Setup: per mutant {spec, plain} × 5 seeds × 30s (90 mutant-runs + 60 original-runs); detection = nonzero libFuzzer exit; all TTEs < 0.2s.

| Mutant | Predicted class | spec | plain | Detection mechanism |
|---|---|---|---|---|
| M1-ogte-lte (`<`→`<=`) | equiv | 0/5 | 0/5 | equivalent mutant (prediction verified) |
| M2-space-flip (`>=`→`>`) | H2/L3 | **5/5** | 0/5 | L3: p < old kernel_break |
| M3-drop-set-kernel-break | H2 | **5/5** | 0/5 | L3: post.kernel_break == p (dropped-write detection) |
| M4-align-mask (`!(a-1)`→`!a`) | H2/L3 | **5/5** | 0/5 | L3: alignment equation |
| M5-align-no-min (drop max(align,2)) | panic | 5/5 | 5/5 | Rust overflow check (debug assertions), both arms |
| M6-hwm-no-max (drop max) | H2 | **5/5** | 0/5 | L3: hwm == max(old, buf_end) (needs evolved harness) |
| M7-drop-hwm-check (paper's underflow class) | underflow | **5/5** | 0/5 | **L1 struct invariant** app_break ≥ high_water_mark |
| M8-update-no-ab-write (drop app_break write) | H2 | **5/5** | 0/5 | L3: Ok(old) == previous value ∧ app_break == requested |
| M9-drop-oom-recheck | equiv | 0/5 | 0/5 | equivalent mutant (prediction verified) |
| **Total** | | **35/45 (77.8%)** | **5/45 (11.1%)** | |
| original (false-positive control) | — | 0/30 | 0/30 | zero oracle false positives |

**H1 verdict: confirmed.** Paired comparison: all 30 disagreements one-directional (spec detected, plain missed; 0 reverse), McNemar p ≈ 2⁻³⁰. Per mutant: 7/9 vs 1/9.

**H2 verdict: confirmed.** M3/M6/M8-class mutants: return values byte-identical to the original, no panic, ghost state only. For an oracle-free fuzzer, "behavior differs from the original" is not a signal (no correctness reference), so this class is **undetectable in principle**; the spec oracle asserts the ensures/invariant directly and detects all at 5/5. M2/M4 (different return values but no panic/UB) are likewise spec-only.

**Key background finding (F4, revised)**: both in-code assertion families — `flux_rs::assert` (flux-rs/src/lib.rs:10) and `flux_support::assert` (flux_support/src/lib.rs:28) — are **runtime no-ops** (`pub fn assert(_: bool) {}`); they exist only for the Flux checker. Consequences: (a) the plain arm is not contaminated by verification instrumentation, so the comparison is fair; (b) **the verified binary itself has no runtime protection whatsoever for its proven contracts** — M7 (the paper's underflow-bug class) is fully silent under the oracle-free arm. The spec-derived harness is precisely what converts ghost assertions into executable oracles — the strongest positive evidence for RQ3.

The first-round misses of M6/M7 (pre-evolution harnesses) are themselves another instance of F1: a fresh allocator always has `high_water_mark == memory_start`, making watermark-class mutations context-equivalent; the harnesses became sound only after adding a state-evolution prelude through a verified API (`add_shared_readonly_buffer`). **Spec→harness translation must account for state reachability; single-call-site translation misses systematically.**

## 6. Validity & Limitations

- The hand-written mutant set is small (9) and hypothesis-driven; the cargo-mutants blind set (§8 E1) addresses the confirmation-bias concern.
- The plain arm shares the generator (incl. requires filtering) — the "identical input surface" design means plain also benefits from structured inputs; relative to a raw byte-level fuzzer, our plain arm is already a strengthened baseline.
- Single-Region implementation (`MpuRegionDefault`, `overlaps ≡ false`) — R::overlaps-heavy spec paths are not stress-tested.
- (E1-specific limitations listed in §8.)

## 7. Modifications to tock-flux (harness enablement only; no semantic changes)

1. `kernel/src/fuzz_shim.rs` (new; cfg(fuzzing))
2. `kernel/src/lib.rs`: +2 lines mounting the shim
3. `kernel/src/allocator.rs`: three types `pub(crate)` → `pub`; `next_available_ipc_idx` gains `pub(crate)`
4. workspace `Cargo.toml`: exclude gains `"fuzz/"`
5. `fuzz/` (new crate): 10+ targets + shared lib + align_gap test

See `kernel-patch/README.md` for the exact diffs.

## 8. Extension Results (round 2)

### E6 — H2 long-budget empirical confirmation
M2/M3/M4/M6/M8 × {spec, plain} × 10 seeds × **120s** (4× the original budget): spec detects **10/10** everywhere, plain **0/10** everywhere. Longer budgets do not change the conclusion; "plain cannot detect in principle" now has empirical support.

### E5 — Stateful API-sequence fuzzing (generalizing F1)
`api_sequence_spec/plain`: random sequences of 2–8 calls over the five verified APIs, with L1 + per-op oracles after **every** step, and **no manual reachability fix-ups** (contrast: single-call harnesses need hand-written preludes to catch M6/M7). Results (120s × 10 seeds):

| Mutant | api_sequence spec | api_sequence plain |
|---|---|---|
| M3-drop-set-kernel-break | **10/10** | 0/10 |
| M6-hwm-no-max | **10/10** | 0/10 |
| M7-drop-hwm-check (paper's underflow class) | **10/10** | 0/10 |
| M8-update-no-ab-write | **10/10** | 0/10 |

**Conclusion**: the sequence harness lets the fuzzer discover state evolution on its own (raise the watermark, lower app_break), systematically eliminating the context-equivalence/dead-oracle blind spot of single-call translation. Core design recommendation for a general spec→fuzz tool: **the translator must emit multi-step sequence harnesses, not single-call harnesses**.

### E2 — Minimal translator + oracle-level ablation
`tools/translate.py` mechanically generates 5 harnesses (`fuzz_targets/gen/`) from the census sig text — L1+L2 fully automatic (14 oracle statements), L3 left as explicit TODOs. Ablation (9 mutants × L{1,2,3} × 3 seeds × 15s, spec arm):

| Mutant | L1 invariants | L2 literal spec | L3 semantic |
|---|---|---|---|
| M2 / M3 / M4 / M6 / M8 | 0 | 0 | **3/3** |
| M7 (paper's underflow class) | **3/3** | 3/3 | 3/3 |
| M5 (panic class) | 3/3 | 3/3 | 3/3 |
| M1 / M9 (equivalent) | 0 | 0 | 0 |

**Key conclusion**: literal spec translation (L2) **catches none of the discriminating mutants on its own** — all of L2's incremental information is already covered by L1; all five discriminating mutants require L3 (the semantic contracts the verifier discharged). The answer to "how many specs translate into effective oracles" must be revised: **translatable ≠ detection power**; effective oracles come from the semantic content of the proof process, not from the literal predicates of the spec text.

### E4 — RegionDescriptor trait-impl harness (testability of the trust boundary)
`mpu_default_spec/plain`: oracles over the executable subset of the 8 `MpuRegionDefault` trait methods' specs (perms/region_number are ghost projections with no runtime getter). 4 mpu.rs mutants (30s × 5 seeds):

| Mutant | spec | plain | Notes |
|---|---|---|---|
| MP1-alloc-drop-zero-check | **5/5** | 0/5 | allows zero-size regions, violating size>0 of regions_can_access_exactly |
| MP2-alloc-rnum-off | 0/5 | 0/5 | **blind spot confirmed**: region_number is a ghost projection invisible to any runtime oracle (F5) |
| MP3-create-start-off | **5/5** | 0/5 | start+1, caught by the L2 start-consistency check |
| MP4-update-strict | 0/5 | 0/5 | spec-permissive equivalent: the spec does not forbid returning None |

**Conclusion**: most of the trait trust boundary's specs are executable (6 of 8 methods have nontrivial executable oracles), but ghost-projection fields (perms/region_number) form a principled blind spot — part of the impl-spec consistency the verifier relies on **has no runtime-observable counterpart**. Same root cause as untranslatable lemmas: contracts over the ghost world can only be guaranteed by proof, not rechecked by testing.

### E3 — Coverage comparison and second budget tier
**Coverage** (30s × seed=42, libFuzzer edge counter):

| Target | spec cov | plain cov | Ratio |
|---|---|---|---|
| allocate_in_grant_region | 77 | 39 | 2.0× |
| in_app_ram_memory | 51 | 37 | 1.4× |
| in_app_flash_memory | 51 | 37 | 1.4× |
| add_shared_readwrite | 77 | 43 | 1.8× |
| update_app_memory | 81 | 41 | 2.0× |
| api_sequence | 145 | 76 | 1.9× |

The spec arm's coverage advantage comes from oracle assertions making both success/failure branches necessary (plain satisfies coverage via early-exit paths) and from the generator's invariant constraints steering the fuzzer toward deeper states.

**Second budget tier (300s × 2 seeds)**: all 7 discriminating mutants show detection patterns identical to the 30s/120s tiers (M2/M3/M4/M6/M7/M8 all spec-detected, plain zero; M5 both arms). Conclusions stable across three tiers.

### E1 — cargo-mutants blind mutation set (removing confirmation bias)
All 156 cargo-mutants of allocator.rs enumerated mechanically (no human selection): 11 skipped (`fmt`×1, `allocate_custom_grant`×9 with no direct harness, `configure_mpu`×1 requiring hardware), 1 diff-application failure (next_available_ipc_idx), 17 unviable (compile failures: 4×new_regions + 13 scattered getter/constructor signature replacements), **127 runnable** (budget 10s × 2 seeds × {spec, plain}, multi-target; per-run wall-clock cap 130s, timeouts counted as hang detections):

| Metric | Any detection (incl. hangs) | Signal-only detection (panic/assert) |
|---|---|---|
| spec killed | **89/127 (70.1%)** | **54/127 (42.5%)** |
| plain killed | 60/127 (47.2%) | 16/127 (12.6%) |
| spec-only killed | **29/127 (22.8%), all via signal** | 38 |
| plain-only killed | 0 | 0 |
| survived | 38 | — |

**Mechanism decomposition (post-audit correction)**: of plain's 60 any-detections, **44 are pure hangs** — mechanical mutations create many infinite loops (`+=`→`-=`, loop-condition flips); hang detection is driven by the outer 130s timeout, is **oracle-independent, and catchable by any fuzzer**. This inflates plain's apparent rate from the signal-basis 12.6% to 47.2%. Excluding hang-class mutants, the signal basis gives spec 42.5% vs plain 12.6% — direction and magnitude consistent with the hand-written set (77.8% vs 11.1%). On the spec side, all 29 spec-only detections are **real oracle signals** (not hangs).

**H1 independently confirmed on the blind set**: any-detection 89 vs 60 (McNemar discordant 29:0, one-sided p ≈ 1.9×10⁻⁹), plain's kill set a strict subset of spec's; signal basis 54 vs 16 in the same direction. Spec-only kills concentrate in update_app_memory (24), any_overlaps / allocate_ipc_region (11 each), get_app_breaks (10) — mostly return-value/state semantic errors, exactly the oracle's target class. The survived set is informative: allocate_app_memory 15 (constructor call surface not covered by single-call harnesses — the motivation for E5), next_available_ipc_idx 8 (no direct harness), get_app_breaks 5 (static function needing a dedicated target). Tool roadmap: **the survived-by-function list is the priority queue of translator targets to add next**.
(Limitations: the 10s×2-seeds budget is smaller than the hand-written set's 30s×5, so some survived mutants may be slow detections; hang-class detections are equally available to both arms and constitute an oracle-independent common floor.)

### Extension summary (final status of the three hypotheses)
- **H1**: hand-written set 77.8% vs 11.1%, blind set signal basis 42.5% vs 12.6% (any-detection 70.1% vs 47.2%, of which plain's detections are 44/60 oracle-independent hang-class), consistent across three budget tiers, coverage 1.4–2.0× — confirmed from multiple angles.
- **H2**: M3/M6/M8 (plain zero detections doubly confirmed at 120s×10 seeds and 300s×2 seeds) + blind-set plain-subset property — confirmed.
- **H3**: census + ablation revision: "translatable" must distinguish **literally translatable (L2)** from **detection-capable (L3)**; effective oracles derive mainly from proof semantics, not spec text.

## 9. Reproduction Guide (extended)

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR=/tmp/fuzz-target   # LOCAL DISK! NFS corrupts artifacts
export AR=$HOME/.rustup/toolchains/nightly-2025-03-14-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-ar

# 1. apply kernel-patch/ to your tock-flux checkout, then:
cd tock-flux/fuzz
cargo fuzz build --sanitizer none
/tmp/fuzz-target/x86_64-unknown-linux-gnu/release/allocate_in_grant_region_spec -max_total_time=30

# 2. census + hand-written mutant experiment
python3 tools/spec_census.py <tock-flux-root> census/census.csv
python3 tools/run_mutants.py --budget 30 --seeds 5 --jobs 12

# 3. extensions
python3 tools/translate.py <tock-flux>/fuzz <tock-flux>/fuzz/fuzz_targets/gen
python3 tools/run_mutants.py --only M3,M6,M7,M8 --budget 120 --seeds 10 --jobs 10
python3 tools/run_mutants.py --only M1,M2,M3,M4,M5,M6,M7,M8,M9 --arms spec --levels 1,2,3 --budget 15 --seeds 3
python3 tools/run_mutants.py --only MP1,MP2,MP3,MP4 --budget 30 --seeds 5
python3 tools/coverage_compare.py --cov-budget 30
python3 tools/run_cargo_mutants.py --budget 10 --seeds 2 --jobs 10

# 4. align power-of-two gap tests
RUSTFLAGS="--cfg fuzzing" CARGO_TARGET_DIR=/tmp/fuzz-test-target cargo test --test align_gap
```

Environment notes: the experiment host pinned `nightly-2025-03-14`; `run_mutants.py`/`run_cargo_mutants.py` hardcode `/tmp/fuzz-target` as the target dir and expect `llvm-ar` in `AR` (the system binutils `ar` crashed on this host). The runners bump source mtimes after patching to defeat 1-second NFS timestamp granularity.
