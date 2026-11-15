//! Spec harness for `AppMemoryAllocator::next_available_ipc_idx`.
//! Flux spec (tock-flux/kernel/src/allocator.rs:294):
//!   fn (&Self) -> Option<{idx. usize[idx] | idx > 2 && idx < 8}>
//! Oracle:
//!   L2: Some(idx) => 2 < idx < 8 (literal spec refinement).
//!   L3: the returned idx is the FIRST unset region >= FLASH_REGION_NUMBER+1 (3);
//!       None => every region in 3..8 is set (semantics of the scan loop).
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim::{self, Snapshot};
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{check, check_invariants, gen_allocator};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some(alloc) = gen_allocator(&mut u) else {
        return;
    };

    let before = Snapshot::take(&alloc);
    let out = fuzz_shim::a_next_available_ipc_idx(&alloc);

    check_invariants(&alloc);

    match out {
        Some(idx) => {
            // ENSURES (L2): refinement 2 < idx < 8
            check!(2, idx > 2 && idx < 8, "idx {idx} outside spec range (2, 8)");
            if idx < 8 {
                // SEMANTIC (L3): idx is unset and is the first unset slot from 3
                check!(3, !before.regions[idx].0, "returned idx {idx} but region is already set");
                for j in 3..idx {
                    check!(3, before.regions[j].0, "idx {idx} not first-unset: region {j} is also unset");
                }
            }
        }
        None => {
            // SEMANTIC (L3): None only when all IPC slots (3..8) are set
            for j in 3..8 {
                check!(3, before.regions[j].0, "None returned but region {j} is unset");
            }
        }
    }
});
