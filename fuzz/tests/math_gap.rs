//! Spec gaps in `kernel::utilities::math`, observed under overflow checks
//! (cargo-fuzz and `cargo test` both build with debug assertions).
//!
//! 1. `closest_power_of_two{,_usize}` are `flux_rs::trusted`. Their `requires`
//!    clause (`num <= u32::MAX / 2 + 1`) admits `num == 0`, and the ensures
//!    clause is satisfiable for it (`r ∈ {0, 1}`), but the body starts with
//!    `num -= 1`, which underflows. The fuzz harnesses therefore draw inputs
//!    from `1..=u32::MAX / 2 + 1`.
//! 2. `log_base_two_u32_usize` computes `31 - num.leading_zeros()` on a
//!    `usize`. That is correct for Tock's 32-bit targets but underflows for
//!    every nonzero input on a 64-bit host, so it is excluded from the fuzz
//!    harnesses (it is not testable on this host).
#![cfg(fuzzing)]

use kernel::utilities::math;
use std::panic::catch_unwind;

#[test]
fn closest_power_of_two_zero_is_admitted_by_requires_but_underflows() {
    // 0 <= u32::MAX / 2 + 1, so the requires clause admits num == 0.
    assert!(catch_unwind(|| math::closest_power_of_two(0)).is_err());
    assert!(catch_unwind(|| math::closest_power_of_two_usize(0)).is_err());
}

#[test]
#[cfg(target_pointer_width = "64")]
fn log_base_two_u32_usize_underflows_on_64_bit_hosts() {
    assert_eq!(math::log_base_two_u32_usize(0), 0);
    assert!(catch_unwind(|| math::log_base_two_u32_usize(1)).is_err());
    assert!(catch_unwind(|| math::log_base_two_u32_usize(512)).is_err());
}
