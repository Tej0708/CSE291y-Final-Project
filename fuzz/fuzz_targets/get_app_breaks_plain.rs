//! Plain baseline for `get_app_breaks`: identical decoding, no oracle.
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{decode_allocator_params, sink};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some((id, us, usz, mins, apps, ksz, fs, fsz)) = decode_allocator_params(&mut u) else {
        return;
    };
    let Ok(alloc) = fuzz_shim::gen_allocator(id, us, usz, mins, apps, ksz, fs, fsz) else {
        return;
    };
    sink(alloc.breaks.kernel_break.as_usize());
});
