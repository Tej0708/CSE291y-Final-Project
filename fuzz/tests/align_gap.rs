//! Phase 7: the `align` power-of-two gap in `allocate_in_grant_region_internal`.
//!
//! The code comment says "The alignment must be a power of two" but neither
//! the Rust signature nor the Flux spec constrains `align`. This test shows:
//!   1. For non-power-of-two `align`, the *Flux spec* (L2 oracle) still holds —
//!      the verification is consistent; the gap is spec underspecification.
//!   2. The *documented intent* (result aligned to `align`) is violated for
//!      non-power-of-two `align` (sweep over sizes 1..=64), and holds for
//!      power-of-two `align`.
//! ⇒ Either the signature should be tightened to `align: usize{is_pow2}` or
//!   the spec should include the alignment ensures.
#![cfg(fuzzing)]

use kernel::fuzz_shim::{self, Snapshot, TestAllocator};

fn make_allocator() -> TestAllocator {
    // id=1, mem=[0x0010_0000, +0x0010_0000), flash=[0x1000, +0x4000)
    fuzz_shim::gen_allocator(1, 0x0010_0000, 0x0010_0000, 0x8000, 0x8000, 0x8000, 0x1000, 0x4000)
        .ok()
        .expect("allocator construction must succeed")
}

/// Lower app_break through the verified `update_app_memory` so the target's
/// Some path is reachable (see report: implicit precondition app_break < kernel_break).
fn with_grant_space(alloc: &mut TestAllocator, grant: usize) {
    let kb = alloc.breaks.kernel_break.as_usize();
    let ms = alloc.breaks.memory_start.as_usize();
    let new_ab = kb - grant.min(kb - ms - 1);
    fuzz_shim::a_update_app_memory(alloc, new_ab)
        .expect("update_app_memory must succeed for in-range breaks");
}

#[test]
fn l2_spec_holds_for_non_power_of_two_align() {
    for align in [0usize, 1, 3, 5, 6, 7, 9, 12, 100, 1000, 0xFFFF_FFFF] {
        for size in [0usize, 1, 3, 24, 255, 4096] {
            let mut a = make_allocator();
            with_grant_space(&mut a, 0x4000);
            let before = Snapshot::take(&a);
            let out = fuzz_shim::a_allocate_in_grant_region_internal(&mut a, size, align);
            // L1: invariants must always hold
            fuzz_shim::check_allocator_invariants(&a).expect("invariants broken");
            match out {
                Some(p) => {
                    // L2: p < memory_end && post kernel_break >= app_break
                    let mem_end = before.breaks.memory_start.as_usize() + before.breaks.memory_size;
                    assert!(p < mem_end, "align={align} size={size}: p {p:#x} >= memory_end");
                    let b = &a.breaks;
                    assert!(
                        b.kernel_break.as_usize() >= b.app_break.as_usize(),
                        "align={align} size={size}: kernel_break < app_break"
                    );
                }
                None => {
                    assert!(
                        before.state_equal(&a),
                        "align={align} size={size}: None but state changed"
                    );
                }
            }
        }
    }
}

#[test]
fn documented_alignment_intent_violated_for_non_pow2() {
    for (align, expect_aligned) in [
        (2usize, true),
        (4, true),
        (16, true),
        (3, false),
        (5, false),
        (6, false),
        (12, false),
        (100, false),
    ] {
        let mut any_misaligned = false;
        for size in 1..=64usize {
            let mut a = make_allocator();
            with_grant_space(&mut a, 0x4000);
            let out = fuzz_shim::a_allocate_in_grant_region_internal(&mut a, size, align);
            let Some(p) = out else { continue };
            if p % align != 0 {
                any_misaligned = true;
                break;
            }
        }
        assert_eq!(
            !any_misaligned,
            expect_aligned,
            "align={align}: expected aligned={expect_aligned}, found misaligned result = {any_misaligned}"
        );
    }
}
