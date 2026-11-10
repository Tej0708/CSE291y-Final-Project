//! Spec harness for `add_shared_readwrite_buffer` (strg-ownership spec).
//! Flux spec: fn (self: &strg Self, buf_start_addr: FluxPtrU8Mut, size: usize)
//!            -> Result<{() | valid_size(buf_start_addr + size)}, ()> ensures self: Self
//! Oracle:
//!   L1 invariants re-check (both outcomes)
//!   L2 Err => state unchanged; Ok => post-state is valid (L1 covers `ensures self: Self`)
//!   L3 Ok => high_water_mark == max(old_hwm, buf_end) and buf_end <= app_break
//!      (in_app_ram_memory gate implies buf_end <= app_break for the Ok path)
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim::{self, Snapshot};
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{check, check_invariants, gen_allocator, interesting_or_arbitrary, small};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some(mut alloc) = gen_allocator(&mut u) else {
        return;
    };
    // State evolution (implicit-precondition fix-up, cf. report F1): a fresh
    // allocator has high_water_mark == memory_start, which makes several
    // watermark mutants context-equivalent. Register a readonly shared buffer
    // first through the verified API to raise the watermark.
    let ms0 = alloc.breaks.memory_start.as_usize();
    let ab0 = alloc.breaks.app_break.as_usize();
    let pre_start = ms0 + (small(&mut u) % (ab0 - ms0));
    let pre_size = 1 + (small(&mut u) % (ab0 - pre_start));
    let _ = fuzz_shim::a_add_shared_readonly_buffer(&mut alloc, pre_start, pre_size);

    let start = interesting_or_arbitrary(&mut u) as u32 as usize;
    let size = small(&mut u);
    let end = start.wrapping_add(size);

    let before = Snapshot::take(&alloc);
    let old_hwm = before.breaks.high_water_mark.as_usize();

    let out = fuzz_shim::a_add_shared_readwrite_buffer(&mut alloc, start, size);

    // INVARIANTS (L1): `ensures self: Self`
    check_invariants(&alloc);

    match out {
        Ok(()) => {
            // SEMANTIC (L3): gate in_app_ram_memory(start, end) held, so
            // end <= app_break and the watermark must absorb buf_end.
            let b = &alloc.breaks;
            let in_ram = end >= start
                && start >= before.breaks.memory_start.as_usize()
                && end <= before.breaks.app_break.as_usize();
            if in_ram {
                check!(
                    3,
                    b.high_water_mark.as_usize() == old_hwm.max(end),
                    "Ok: hwm={:#x} != max(old_hwm={old_hwm:#x}, buf_end={end:#x})",
                    b.high_water_mark.as_usize()
                );
                check!(
                    3,
                    b.high_water_mark.as_usize() >= before.breaks.high_water_mark.as_usize(),
                    "Ok: watermark decreased"
                );
            } else {
                // Ok via no flash branch in this function: only ram path exists,
                // so Ok with !in_ram is itself unexpected.
                check!(3, false, "Ok(()) but buffer not in app ram memory");
            }
        }
        Err(()) => {
            check!(
                2,
                before.state_equal(&alloc),
                "Err but state changed (ensures self: Self / no partial update)"
            );
        }
    }
});
