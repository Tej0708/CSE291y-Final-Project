//! Plain baseline for `in_app_flash_memory`: identical decoding, no oracle.
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{gen_allocator, interesting_or_arbitrary, sink};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some(alloc) = gen_allocator(&mut u) else {
        return;
    };
    let start = interesting_or_arbitrary(&mut u) as u32 as usize;
    let end = interesting_or_arbitrary(&mut u) as u32 as usize;

    let out = fuzz_shim::a_in_app_flash_memory(&alloc, start, end);
    sink(out as usize);
});
