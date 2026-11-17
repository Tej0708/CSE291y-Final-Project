//! Spec harness for `closest_power_of_two` and `closest_power_of_two_usize`.
//! Flux specs (tock-flux/kernel/src/utilities/math.rs:16, :32):
//!   fn(num: u32) -> u32{r: r >= num && r/2 <= num && num <= u32::MAX / 2 + 1}
//!       requires num <= u32::MAX / 2 + 1
//!   fn(num: usize) -> usize{r: r >= num && r/2 <= num && (r >= 16 => r % 16 == 0)
//!       && r <= u32::MAX / 2 + 1} requires num <= u32::MAX / 2 + 1
//! Oracle:
//!   L2: the literal return refinements above.
//!   L3: r is the smallest power of two >= num. The literal spec does not
//!       require r to be a power of two (e.g. r == num satisfies L2).
#![no_main]

use arbitrary::Unstructured;
use kernel::utilities::math;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{check, pow2_input, POW2_BOUND};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let num = pow2_input(&mut u);

    let r = math::closest_power_of_two(num);
    check!(2, r >= num && r / 2 <= num && num <= POW2_BOUND,
        "closest_power_of_two({num}) = {r} violates the return refinement");
    check!(3, r == num.next_power_of_two(),
        "closest_power_of_two({num}) = {r}, expected {}", num.next_power_of_two());

    let n = num as usize;
    let r = math::closest_power_of_two_usize(n);
    check!(2, r >= n && r / 2 <= n && (r < 16 || r % 16 == 0) && r <= POW2_BOUND as usize,
        "closest_power_of_two_usize({n}) = {r} violates the return refinement");
    check!(3, r == n.next_power_of_two(),
        "closest_power_of_two_usize({n}) = {r}, expected {}", n.next_power_of_two());
});
