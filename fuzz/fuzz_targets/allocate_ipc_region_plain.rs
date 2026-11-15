//! Plain baseline for `allocate_ipc_region`: identical decoding, no oracle.
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim::{self, Permissions};
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{gen_allocator, interesting_or_arbitrary, small, sink, U32MAX};

fn pick_perms(u: &mut Unstructured<'_>) -> Permissions {
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

    let start = interesting_or_arbitrary(&mut u) as u32 as usize;
    let size = small(&mut u) % (U32MAX - start + 1);
    let perms = pick_perms(&mut u);

    let out = fuzz_shim::a_allocate_ipc_region(&mut alloc, start, size, perms);
    sink(out.is_ok() as usize);
});
