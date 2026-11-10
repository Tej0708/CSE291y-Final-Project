//! Spec harness for `update_app_memory` (strg-ownership spec; the TickTock
//! paper documents a real underflow bug in this area found by verification).
//! Flux spec: fn (self: &strg Self, new_app_break: FluxPtrU8Mut) -> Result<FluxPtrU8, Error>
//!            ensures self: Self
//! Oracle:
//!   L1 invariants re-check (both outcomes) — catches the underflow class:
//!      app_break < high_water_mark / below memory_start / above kernel_break
//!   L2 Err => state unchanged; Ok => valid post-state
//!   L3 Ok(old): old == old app_break, post.app_break == new_app_break,
//!      memory_start/high_water_mark/kernel_break/memory_size unchanged,
//!      region 0 == [memory_start, new_app_break), region 1 unset
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim::{self, RegionDescriptor, Snapshot};
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{check, check_invariants, gen_allocator, interesting_or_arbitrary, small};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some(mut alloc) = gen_allocator(&mut u) else {
        return;
    };
    // State evolution (see add_shared_readwrite_buffer_spec): raise the
    // watermark first so lower-app-break requests are in-context.
    let ms0 = alloc.breaks.memory_start.as_usize();
    let ab0 = alloc.breaks.app_break.as_usize();
    let pre_start = ms0 + (small(&mut u) % (ab0 - ms0));
    let pre_size = 1 + (small(&mut u) % (ab0 - pre_start));
    let _ = fuzz_shim::a_add_shared_readonly_buffer(&mut alloc, pre_start, pre_size);

    let new_app_break = interesting_or_arbitrary(&mut u) as u32 as usize;

    let before = Snapshot::take(&alloc);
    let ms = before.breaks.memory_start.as_usize();
    let hwm = before.breaks.high_water_mark.as_usize();
    let kb = before.breaks.kernel_break.as_usize();
    let old_ab = before.breaks.app_break.as_usize();

    let out = fuzz_shim::a_update_app_memory(&mut alloc, new_app_break);

    // INVARIANTS (L1): catches the underflow bug class
    check_invariants(&alloc);

    match out {
        Ok(old) => {
            // ENSURES (L2): post-state valid (L1 above) + returned value is a
            // real pointer value
            let b = &alloc.breaks;
            // SEMANTIC (L3)
            check!(3, old == old_ab, "Ok(old={old:#x}) != previous app_break={old_ab:#x}");
            check!(
                3,
                b.app_break.as_usize() == new_app_break,
                "Ok: app_break={:#x} != requested new_app_break={new_app_break:#x}",
                b.app_break.as_usize()
            );
            check!(3, b.memory_start.as_usize() == ms, "Ok: memory_start moved");
            check!(3, b.memory_size == before.breaks.memory_size, "Ok: memory_size changed");
            check!(3, b.high_water_mark.as_usize() == hwm, "Ok: high_water_mark moved");
            check!(3, b.kernel_break.as_usize() == kb, "Ok: kernel_break moved");
            let r0 = alloc.regions.get(0);
            check!(
                3,
                RegionDescriptor::is_set(&r0)
                    && RegionDescriptor::start(&r0).map(|p| p.as_usize()) == Some(ms)
                    && RegionDescriptor::size(&r0) == Some(new_app_break - ms),
                "Ok: region 0 not [memory_start, new_app_break)"
            );
            let r1 = alloc.regions.get(1);
            check!(3, !RegionDescriptor::is_set(&r1), "Ok: region 1 set (split not supported)");
        }
        Err(_e) => {
            // ENSURES (L2): error leaves the allocator untouched
            check!(
                2,
                before.state_equal(&alloc),
                "Err but state changed (ensures self: Self / no partial update)"
            );
        }
    }
});
