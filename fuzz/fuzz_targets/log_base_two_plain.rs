//! Plain baseline for `log_base_two{,_u64}`: identical decoding, no oracle.
#![no_main]

use arbitrary::Unstructured;
use kernel::utilities::math;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{log2_inputs, sink};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let (a, b) = log2_inputs(&mut u);
    sink(math::log_base_two(a) as usize);
    sink(math::log_base_two_u64(b) as usize);
});
