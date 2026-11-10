//! Plain baseline for `update_app_memory`: identical decoding, no oracle.
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{gen_allocator, interesting_or_arbitrary, sink, small};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some(mut alloc) = gen_allocator(&mut u) else {
        return;
    };
    // State evolution (see add_shared_readwrite_buffer_spec): register a
    // readonly shared buffer first through the verified API to raise the
    // watermark, mirroring the spec harness's input surface.
    let ms0 = alloc.breaks.memory_start.as_usize();
    let ab0 = alloc.breaks.app_break.as_usize();
    let pre_start = ms0 + (small(&mut u) % (ab0 - ms0));
    let pre_size = 1 + (small(&mut u) % (ab0 - pre_start));
    let _ = fuzz_shim::a_add_shared_readonly_buffer(&mut alloc, pre_start, pre_size);

    let new_app_break = interesting_or_arbitrary(&mut u) as u32 as usize;

    let out = fuzz_shim::a_update_app_memory(&mut alloc, new_app_break);
    sink(out.unwrap_or(0));
});
