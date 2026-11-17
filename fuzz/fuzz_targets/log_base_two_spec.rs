//! Spec harness for `log_base_two` and `log_base_two_u64`.
//! Flux specs (tock-flux/kernel/src/utilities/math.rs:85, :104):
//!   fn(num: u32) -> u32{r: (r < 32) && (num > 1 => r > 0)}
//!   fn(num: u64) -> u32{r: r < 64 && (num > 1 => r > 0)}
//! `log_base_two_u32_usize` is excluded: it assumes a 32-bit usize and
//! underflows on 64-bit hosts (tests/math_gap.rs).
//! Oracle:
//!   L2: the literal return refinements above.
//!   L3: r == floor(log2(num)), and 0 for num == 0 (the documented behavior).
#![no_main]

use arbitrary::Unstructured;
use kernel::utilities::math;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{check, log2_inputs};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let (a, b) = log2_inputs(&mut u);

    let r = math::log_base_two(a);
    check!(2, r < 32 && (a <= 1 || r > 0), "log_base_two({a}) = {r} violates the return refinement");
    let expected = a.checked_ilog2().unwrap_or(0);
    check!(3, r == expected, "log_base_two({a}) = {r}, expected {expected}");

    let r = math::log_base_two_u64(b);
    check!(2, r < 64 && (b <= 1 || r > 0), "log_base_two_u64({b}) = {r} violates the return refinement");
    let expected = b.checked_ilog2().unwrap_or(0);
    check!(3, r == expected, "log_base_two_u64({b}) = {r}, expected {expected}");
});
