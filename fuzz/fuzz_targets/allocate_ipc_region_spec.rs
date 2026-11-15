//! Spec harness for `AppMemoryAllocator::allocate_ipc_region`.
//! Flux spec (tock-flux/kernel/src/allocator.rs:342):
//!   fn (self: &strg Self, start: FluxPtrU8, size: usize{valid_size(start + size)}, _)
//!       -> Result<_, _> ensures self: Self
//! The surface spec only guarantees the invariant chain is preserved; the
//! stronger semantics (region installed on Ok, state unchanged on Err) are
//! discharged by the verifier and encoded as L3.
//! Oracle:
//!   L1: invariant chain re-check.
//!   L2: Err => allocator state unchanged (no partial mutation).
//!   L3: Ok => exactly the next IPC slot becomes set with start/size == inputs.
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim::{self, Permissions, Snapshot};
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{check, check_invariants, gen_allocator, interesting_or_arbitrary, small, U32MAX};

fn pick_perms(u: &mut Unstructured<'_>) -> Permissions {
    match small(u) % 5 {
        0 => Permissions::ReadWriteExecute,
        1 => Permissions::ReadWriteOnly,
        2 => Permissions::ReadExecuteOnly,
        3 => Permissions::ReadOnly,
        _ => Permissions::ExecuteOnly,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some(mut alloc) = gen_allocator(&mut u) else {
        return;
    };

    // Decode a buffer satisfying the `requires` clause valid_size(start + size),
    // i.e. start + size <= u32::MAX.
    let start = interesting_or_arbitrary(&mut u) as u32 as usize;
    let size = small(&mut u) % (U32MAX - start + 1);
    let perms = pick_perms(&mut u);

    let before = Snapshot::take(&alloc);
    let out = fuzz_shim::a_allocate_ipc_region(&mut alloc, start, size, perms);

    // INVARIANTS (L1)
    check_invariants(&alloc);

    match out {
        Ok(_) => {
            let after = Snapshot::take(&alloc);
            // SEMANTIC (L3): exactly one previously-unset IPC slot (3..8) is now
            // set, and it holds the requested start/size.
            let mut newly_set = 0;
            for i in 3..8 {
                if !before.regions[i].0 && after.regions[i].0 {
                    newly_set += 1;
                    check!(3, after.regions[i].1 == start,
                        "installed region {i} start {:#x} != requested {start:#x}", after.regions[i].1);
                    check!(3, after.regions[i].2 == size,
                        "installed region {i} size {} != requested {size}", after.regions[i].2);
                }
            }
            check!(3, newly_set == 1, "Ok but {newly_set} IPC regions newly set (expected exactly 1)");
            // breaks must not move for an IPC allocation
            check!(3, before.breaks_equal(&alloc), "Ok but breaks changed (IPC alloc must not move breaks)");
        }
        Err(_) => {
            // ENSURES (L2): failure leaves the whole allocator state unchanged
            check!(2, before.state_equal(&alloc), "Err but allocator state changed");
        }
    }
});
