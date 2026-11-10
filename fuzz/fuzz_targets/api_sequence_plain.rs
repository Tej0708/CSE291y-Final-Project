//! E5: plain baseline for the API-sequence harness — identical op/arg
//! decoding and call sequence, no oracles.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use kernel::fuzz_shim::{self, Permissions};
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{gen_allocator, interesting_or_arbitrary, sink, small};

fn decode_in_span(u: &mut Unstructured<'_>, alloc: &kernel::fuzz_shim::TestAllocator) -> (usize, usize) {
    let ms = alloc.breaks.memory_start.as_usize();
    let ab = alloc.breaks.app_break.as_usize();
    if bool::arbitrary(u).unwrap_or(false) && ab > ms {
        let s = ms + (small(u) % (ab - ms));
        let sz = small(u) % (ab - s).max(1);
        (s, sz)
    } else {
        (interesting_or_arbitrary(u) as u32 as usize, small(u))
    }
}

fn decode_perms(u: &mut Unstructured<'_>) -> Permissions {
    match small(u) % 5 {
        0 => Permissions::ReadWriteExecute,
        1 => Permissions::ReadWriteOnly,
        2 => Permissions::ReadExecuteOnly,
        3 => Permissions::ReadOnly,
        _ => Permissions::ExecuteOnly,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some(mut alloc) = gen_allocator(&mut u) else {
        return;
    };
    let steps = 2 + (small(&mut u) % 7);
    for _ in 0..steps {
        let op = small(&mut u) % 5;
        match op {
            0 => {
                let (s, sz) = decode_in_span(&mut u, &alloc);
                sink(fuzz_shim::a_add_shared_readonly_buffer(&mut alloc, s, sz).is_ok() as usize);
            }
            1 => {
                let (s, sz) = decode_in_span(&mut u, &alloc);
                sink(fuzz_shim::a_add_shared_readwrite_buffer(&mut alloc, s, sz).is_ok() as usize);
            }
            2 => {
                let nab = interesting_or_arbitrary(&mut u) as u32 as usize;
                sink(fuzz_shim::a_update_app_memory(&mut alloc, nab).unwrap_or(0));
            }
            3 => {
                let size = small(&mut u);
                let align = small(&mut u);
                sink(fuzz_shim::a_allocate_in_grant_region_internal(&mut alloc, size, align).unwrap_or(0));
            }
            _ => {
                let perms = decode_perms(&mut u);
                let s = interesting_or_arbitrary(&mut u) as u32 as usize;
                let sz = small(&mut u);
                sink(fuzz_shim::a_allocate_ipc_region(&mut alloc, s, sz, perms).is_ok() as usize);
            }
        }
    }
});
