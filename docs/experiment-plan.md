# TickTock Spec→Fuzz Experiment Plan

**Contributors**: Tej Gaonkar, Xuan Zhou
**Date**: 2026-10-25

## Project Context

TickTock is a version of the Tock embedded OS whose memory-isolation logic (the process memory allocator and MPU abstraction) is verified with Flux. Verification only covers what the proofs reach: it rests on trusted components and on implementations of the `RegionDescriptor` trait that must satisfy the trait's specs. Fuzzing lets us test this experimentally, but hand-writing harnesses is tedious — you need generators that produce valid inputs and oracles that define correct behavior. TickTock's Flux specs already contain this information as preconditions, postconditions, and invariants. The target functions are well-chosen: the TickTock paper documents a real underflow bug in `update_app_memory_regions` found during the verification effort. This project builds a tool that turns a subset of those specs into fuzz harnesses and evaluates whether the result is useful.

**Codebase baseline** (established by inspection): the verification code lives in `tock-flux/` (not the upstream `ticktock/` copy). `tock-flux/kernel/src/` contains **109 `flux_rs::sig`, 12 `flux_rs::invariant`, 16 `flux_rs::refined_by`** attributes across 12 files; `allocator.rs` (737 lines, 24 sigs) and `platform/mpu.rs` (29 sigs, incl. the `RegionDescriptor` trait) are the main targets. All candidate target functions were confirmed present: `in_app_ram_memory` (l.137), `in_app_flash_memory` (l.142), `add_shared_readwrite_buffer` (l.194), `allocate_in_grant_region_internal` (l.239), `allocate_ipc_region` (l.344), `get_app_breaks` (l.476), `update_app_memory` (l.649).

## Research Questions

1. How many of TickTock's Flux specs can be translated into input generators and oracles?
2. Can spec-driven harnesses detect injected bugs better than a plain unstructured fuzzer?
3. Can the specs be used to check assumptions the proofs rely on?

## Hypotheses & Success Criteria

| Hypothesis | Operationalization | Decision rule |
|---|---|---|
| **H1** Under equal time budgets, spec-derived harnesses achieve at least the mutation-detection rate of a plain byte-level fuzzer | Per mutant, each arm runs N seeds × budget T; record detection | On the paired mutant set, spec total detection ≥ plain total (McNemar / paired comparison, p<0.05, effect sizes reported) |
| **H2** There is a class of mutants a plain fuzzer cannot in principle detect, but spec-derived oracles can | "Semantic" mutants: violate ensures/invariants only, identical observable return value, no panic | Spec harness detects within budget; plain detects zero over arbitrary time (argument + empirical confirmation) |
| **H3** The translatable fraction is bounded below 100% by ghost refinement parameters and higher-order refinements | Census every sig + invariant, tag fully / partial / untranslatable with reason codes | Every untranslatable spec attributed; distribution table produced |

**Success** = H1 confirmed on our mutant set, ≥1 H2-class mutant caught only by a spec harness, and a per-spec census explaining every untranslatable case.

## Method Overview

```
tock-flux sources ──► [P1] Spec Census ──► census.csv (all 109 sigs classified)
        │                     │
        ▼                     ▼
[P2] Translator  ══►  [P3] Harness generator ──► fuzz/target_N.rs (cargo-fuzz)
  parse Flux attrs       requires → generator + precondition checks
  (syn + custom parser)  ensures/invariants → snapshot-based oracle
        │
        ▼
[P4] Plain baseline arm (same input surface, no oracle)
        │
        ▼
[P5-7] Mutation testing (H1) / H2-class mutants / real-bug exploration ──► results & report
```

### Phase 0 — Environment (Week 1)
Install `cargo-fuzz` / `cargo-mutants`; confirm `cargo flux check` passes on tock-flux; set up a `fuzz/` crate; a `run_experiment.sh`-style driver wrapping execution, crash collection, detection bookkeeping (all results to JSON).

### Phase 1 — Spec Census (Weeks 1–2, answers H3)
Extract every `flux_rs::{sig,invariant,refined_by,assoc}` attribute; classify each sig as fully / partial / untranslatable with reason codes:

| Code | Meaning | Confirmed example |
|---|---|---|
| `GHOST-PARAM` | refinement index is a ghost value; only indirectly observable via invariants | `fn(&Self[@b]) -> FluxPtrU8[b.breaks.flash_start]` |
| `HIGHER-ORDER` | refinement references assoc/trait predicates | `RegionDescriptor` impl specs |
| `STRG-OWNERSHIP` | `&strg Self` strong-update specs; oracle needs snapshots | all mutating allocator methods |
| `EXISTENTIAL` | existentially refined returns | `Option<{idx. usize[idx] \| idx > 2 && idx < 8}>` |
| `TRUSTED-IMPL` | trust-boundary (lemma fns, hardware MPU impls) | the 10 lemma sigs in mpu.rs |
| `NO-RUNTIME` | needs large runtime infrastructure | process_loading / grant constructors |

### Phase 2 — Translator (Weeks 3–5)
Parse the Flux surface syntax from the attributes (M1: reuse Flux's own parser/metadata; M2: syn for the surrounding Rust + a small custom parser for the pseudo-Rust inside `sig(...)`) into an IR; emit cargo-fuzz/libfuzzer harnesses using `arbitrary`. Predicates are interpreted three ways: generator constraints (from `requires`), precondition assertions, postcondition assertions against a snapshot.

### Phase 3 — Harness matrix (Weeks 4–5)
Spec-derived arm (per fully/partial spec) + plain arm: identical decoding, no oracle, ASan-class crashes only. Backing-memory strategy: `FluxPtrU8` values are offsets into a heap buffer.

### Phase 5 — Mutation experiment (Weeks 6–8, answers H1)
cargo-mutants generated + hand-written mutants in four classes (off-by-one, comparison flips, dropped checks, arithmetic overflow) + a re-creation of the paper's underflow bug; equivalence filtering; matrix {spec, plain} × budgets × seeds; McNemar/Fisher statistics; coverage at fixed budget.

### Phase 6 — H2 experiment (Week 7)
Mutants with identical return values and no panic that only corrupt ghost state; plain runs 10×600s (expected zero detections), spec runs short budget.

### Phase 7 — Real-bug / spec-gap exploration (Weeks 5–8)
The `align` power-of-two question: generate unfiltered `align`; a spec violation = finding; spec holds + intent violated = signature should be tightened. Cross-check every finding with `cargo flux check`.

## Timeline (10 weeks)

| Week | Milestone |
|---|---|
| 1 | Phase 0 + census starts |
| 2 | Census complete (H3 answered); translator route decided |
| 3 | Translator MVP: all allocator sigs → IR |
| 4 | Codegen: first fully automatic harness + backing-memory library |
| 5 | ≥8 allocator spec harnesses + plain baselines |
| 6 | Mutant set built, equivalence-filtered |
| 7 | Main experiment (H1) + H2 experiment |
| 8 | Follow-ups, coverage, anomaly triage |
| 9 | Statistics + gap analysis |
| 10 | Report & deliverables finalized |

## Threats to Validity & Mitigations

| Threat | Mitigation |
|---|---|
| Mutant set unrepresentative | Hand-written classes aligned with the paper's real bug + cargo-mutants blind set; per-class breakdown |
| Budget/seed selection bias | Multiple budget tiers, variance & CIs reported |
| Generator leaks oracle info | Generators use only requires/invariants; identical input surface across arms |
| Plain fuzzer strawmanned | Plain arm keeps coverage guidance + debug assertions; detections include all panic/UB forms |
| Equivalent mutants pollute rates | Bidirectional probing filter; all mutants and results published |

## Deliverables

1. `census.csv` + H3 classification report (all 109 sigs attributed);
2. Translator (parse + IR + codegen) and all generated/handwritten harnesses;
3. Mutant set + reproduction scripts + raw result JSONs;
4. H1/H2/H3 conclusions, coverage & TTE figures, spec-gap/bug list;
5. Final report incl. the "what proofs verify but harnesses cannot" gap analysis.
