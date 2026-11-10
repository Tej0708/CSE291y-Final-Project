# TickTock Flux Spec Census (H3 Result)

**Date**: 2026-10-25 · **Subject**: `tock-flux/kernel/src/` (the Flux-verified Tock fork)
**Method**: `tools/spec_census.py` mechanically extracts every `flux_rs::{sig,invariant,refined_by,assoc}` attribute, followed by a manual-review pass (overrides recorded in the script's `OVERRIDES` table).

## Totals

| Category | Count |
|---|---|
| `flux_rs::sig` (function specs) | **109** |
| `flux_rs::invariant` (struct invariants) | 12 |
| `flux_rs::refined_by` (ghost index declarations) | 16 |
| `flux_rs::assoc` (trait assoc predicates) | 15 |

## Sig Translatability Distribution (main H3 result)

| Class | Count | Share | Meaning |
|---|---|---|---|
| **fully** | 19 | 17.4% | generator and oracle both derivable directly from the spec |
| **partial** | 80 | 73.4% | oracle constructible (via invariant re-checks / snapshot diffs) but generator needs engineering, or the spec covers only part of the behavior |
| **untranslatable** | 10 | 9.2% | **all ten** are the 5 proof lemmas in `mpu.rs` (trait decl + software impl); runtime bodies are empty — no observable postcondition exists |

**H3 conclusion**: the hypothesis that the translatable fraction is capped by ghost refinement parameters is **partially confirmed but requires revision** — ghost params (`@b`, `[b.breaks.x]`), `&strg` ownership, and `FluxPtrU8` backing-memory requirements only cause *partial* classifications (our three-level oracle — L1 invariant re-checks + L2 snapshot diffs + L3 semantic contracts — recovers that ghost information at runtime). The only hard wall is the proof-lemma class (9.2%): contracts over ghost functions that no runtime observation can check. Higher-order refinements reduce to the lemma/trusted-impl case in this codebase (hardware MPU implementations are out of repo).

## Reason-code distribution (partial class)

| Code | Meaning | Typical case |
|---|---|---|
| `GHOST-PARAM` | refinement index is a ghost value | the 7 allocator getters (recoverable via L2 snapshot comparison) |
| `STRG-OWNERSHIP` | `&strg Self` strong update | add_shared_readwrite_buffer, update_app_memory |
| `assoc-fn-call` | spec references trait assoc predicates | any_overlaps, get_ram_regions (executable for the software impl `MpuRegionDefault`) |
| `quantifier` | bounded forall/exists | new_regions' `forall i in 0..8` (unrolls to a runtime loop) |
| `existential-return` | existentially refined return | allocate_in_grant_region_internal, next_available_ipc_idx |
| `uses-FluxPtr` | needs backing memory | every pointer parameter (solvable via a low-4GB backing buffer) |
| `NO-RUNTIME` | needs large runtime infrastructure | process_loading, grant constructors |
| `TRUSTED-IMPL` | trust boundary | lemmas, `impl MPU for ()` methods |

## Oracle levels and their census correspondence

| Level | Content | Census class recovered |
|---|---|---|
| L1 | AppBreaks/AppMemoryAllocator struct invariant chain re-check | executable part of invariant/refined_by |
| L2 | literal `ensures` clauses + "None ⇒ state unchanged" | GHOST-PARAM, STRG-OWNERSHIP surface specs |
| L3 | semantic contracts the verifier discharged beyond the surface spec (alignment, exact break movement) | strong interpretation of existential-return |

## Per-file highlights

- `allocator.rs` (24 sigs): in_app_ram/flash_memory fully; getters partial (GHOST-PARAM); all mutating methods partial (STRG-OWNERSHIP);
- `platform/mpu.rs` (29 sigs): 10 untranslatable (lemmas), the rest partial;
- `hil/time.rs` (13 sigs): the saturating_scale/frequency family — all fully;
- `utilities/math.rs` (5 sigs): closest_power_of_two / log_base_two family — all fully;
- `collections/{ring_buffer,queue}.rs` (16 sigs): mixed fully/partial (plain data structures);
- `grant.rs` / `process_*.rs` (19 sigs): mostly NO-RUNTIME (need process/grant infrastructure).

## Link to the experiments

The fully/partial allocator+mpu subset was covered by the first 10 harness targets (5 spec/plain pairs) of the harness matrix. `census.csv` carries the spec text and attribution for every row, satisfying the "every untranslatable case explained" deliverable.
