//! Plain baseline for `next_available_ipc_idx`: identical decoding, no oracle.
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{gen_allocator, sink};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some(alloc) = gen_allocator(&mut u) else {
        return;
    };

    let out = fuzz_shim::a_next_available_ipc_idx(&alloc);
    sink(out.unwrap_or(usize::MAX));
});
