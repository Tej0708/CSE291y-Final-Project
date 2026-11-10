//! Spec harness for `AppMemoryAllocator::allocate_in_grant_region_internal`.
//!
//! Flux spec (tock-flux/kernel/src/allocator.rs:233):
//! ```text
//! fn (self: &strg Self[@old_bc], usize, usize)
//!     -> Option<{p. FluxPtrU8[p] | p < bc.breaks.memory_start + bc.breaks.memory_size}>[#opt]
//!     ensures self: Self[#bc],
//!     (opt => bc.breaks.kernel_break >= bc.breaks.app_break) &&
//!     (!opt => bc == old_bc)
//! ```
//! Translated oracle:
//!   L2 Some(p): p < memory_end (spec)           [L2]
//!      None:    state unchanged (spec)          [L2]
//!      both:    invariants re-check             [L1]
//!   L3 semantic (discharged by verifier, not in surface spec):
//!      Some(p): p == align_down(old_kb - size, max(align,2))
//!               post.kernel_break == p, p < old_kernel_break, p >= app_break
//!
//! Note: the code comment says `align` must be a power of two but the signature
//! does not require it; align is generated unfiltered (see experiment-plan §9).

#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim::{self, Snapshot};
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{check, check_invariants, gen_allocator, small};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some(mut alloc) = gen_allocator(&mut u) else {
        return;
    };
    // Reachability fix-up (see report §"implicit preconditions"): the verified
    // constructor always yields app_break == kernel_break, so the Some path of
    // the target is dead unless the app break is first lowered. Do it through
    // the verified `update_app_memory` (harness sequence mirrors real usage:
    // process setup, brk, then grant allocation).
    let kb0 = alloc.breaks.kernel_break.as_usize();
    let ms0 = alloc.breaks.memory_start.as_usize();
    if kb0 - ms0 < 2 {
        return; // cannot lower app_break while leaving >= 1 byte of grant space
    }
    let new_ab = ms0 + 1 + (small(&mut u) % (kb0 - ms0 - 1));
    if fuzz_shim::a_update_app_memory(&mut alloc, new_ab).is_err() {
        return; // verified constructor guarantees this cannot fail; skip defensively
    }

    let size = small(&mut u);
    let align = small(&mut u);

    let before = Snapshot::take(&alloc);
    let old_kb = before.breaks.kernel_break.as_usize();
    let mem_end = before.breaks.memory_start.as_usize() + before.breaks.memory_size;

    let out = fuzz_shim::a_allocate_in_grant_region_internal(&mut alloc, size, align);

    // INVARIANTS (L1)
    check_invariants(&alloc);

    match out {
        Some(p) => {
            // ENSURES (L2): p < memory_start + memory_size
            check!(2, p < mem_end, "Some(p)={p:#x} >= memory_end={mem_end:#x}");
            // ENSURES (L2): post kernel_break >= post app_break
            let b = &alloc.breaks;
            check!(
                2,
                b.kernel_break.as_usize() >= b.app_break.as_usize(),
                "post kernel_break {:#x} < app_break {:#x}",
                b.kernel_break.as_usize(),
                b.app_break.as_usize()
            );
            // SEMANTIC (L3)
            let eff_align = align.max(2);
            let expected = old_kb.wrapping_sub(size) & !(eff_align - 1);
            check!(
                3,
                p == expected,
                "p={p:#x} != align_down(old_kb={old_kb:#x}-size={size},a={eff_align})={expected:#x}"
            );
            check!(
                3,
                b.kernel_break.as_usize() == p,
                "post.kernel_break={:#x} != returned p={p:#x} (dropped set_kernel_break?)",
                b.kernel_break.as_usize()
            );
            check!(3, p < old_kb, "p={p:#x} >= old kernel_break={old_kb:#x}");
            check!(
                3,
                p >= b.app_break.as_usize(),
                "p={p:#x} < app_break={:#x}",
                b.app_break.as_usize()
            );
        }
        None => {
            // ENSURES (L2): !opt => bc == old_bc
            check!(
                2,
                before.state_equal(&alloc),
                "None but state changed (spec: state unchanged)"
            );
        }
    }
});
