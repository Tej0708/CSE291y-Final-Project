//! Plain baseline for `closest_power_of_two{,_usize}`: identical decoding, no oracle.
#![no_main]

use arbitrary::Unstructured;
use kernel::utilities::math;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{pow2_input, sink};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let num = pow2_input(&mut u);
    sink(math::closest_power_of_two(num) as usize);
    sink(math::closest_power_of_two_usize(num as usize));
});
