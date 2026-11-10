//! Plain baseline for `allocate_in_grant_region_internal`: identical input
//! decoding and call, but no spec oracle — only panics/UB (ASan) are crashes.
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{gen_allocator, sink, small};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some(mut alloc) = gen_allocator(&mut u) else {
        return;
    };
    // Identical reachability fix-up as the spec harness (lower app_break via
    // the verified update_app_memory) so both arms share the input surface.
    let kb0 = alloc.breaks.kernel_break.as_usize();
    let ms0 = alloc.breaks.memory_start.as_usize();
    if kb0 - ms0 < 2 {
        return; // cannot lower app_break while leaving >= 1 byte of grant space
    }
    let new_ab = ms0 + 1 + (small(&mut u) % (kb0 - ms0 - 1));
    if fuzz_shim::a_update_app_memory(&mut alloc, new_ab).is_err() {
        return;
    }

    let size = small(&mut u);
    let align = small(&mut u);

    let out = fuzz_shim::a_allocate_in_grant_region_internal(&mut alloc, size, align);
    sink(out.unwrap_or(0));
});
