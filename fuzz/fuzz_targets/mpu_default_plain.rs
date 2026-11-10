//! E4: plain baseline for the MpuRegionDefault trait-method harness —
//! identical decoding and calls, no oracles.
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim::{FluxPtrU8, MpuRegionDefault, Permissions, RegionDescriptor};
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{interesting_or_arbitrary, sink, small, U32MAX};

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
    let rn = small(&mut u) % 16;
    let start = interesting_or_arbitrary(&mut u) as u32 as usize;
    let size = small(&mut u);
    let perms = decode_perms(&mut u);

    let d = <MpuRegionDefault as RegionDescriptor>::default(rn);
    sink(RegionDescriptor::is_set(&d) as usize);

    if rn < 8 && start + size <= U32MAX {
        if let Some(r) =
            <MpuRegionDefault as RegionDescriptor>::create_exact_region(rn, FluxPtrU8::from(start), size, perms)
        {
            sink(RegionDescriptor::start(&r).map(|p| p.as_usize()).unwrap_or(0));
        }
    }

    let max = 1 + (small(&mut u) % 7);
    let avail_start = interesting_or_arbitrary(&mut u) as u32 as usize;
    let avail_size = small(&mut u);
    let region_size = small(&mut u);
    if avail_start + avail_size <= U32MAX {
        if let Some(pair) = <MpuRegionDefault as RegionDescriptor>::allocate_regions(
            max,
            FluxPtrU8::from(avail_start),
            avail_size,
            region_size,
            perms,
        ) {
            sink(RegionDescriptor::start(&pair.fst).map(|p| p.as_usize()).unwrap_or(0)
                + RegionDescriptor::size(&pair.fst).unwrap_or(0));
        }
    }

    let region_start = interesting_or_arbitrary(&mut u) as u32 as usize;
    if region_start + avail_size <= U32MAX {
        if let Some(pair) = <MpuRegionDefault as RegionDescriptor>::update_regions(
            FluxPtrU8::from(region_start),
            avail_size,
            region_size,
            max,
            perms,
        ) {
            sink(RegionDescriptor::size(&pair.fst).unwrap_or(0));
        }
    }

    if rn < 8 && start + size <= U32MAX {
        if let Ok(r) = <MpuRegionDefault as RegionDescriptor>::create_exact_region(
            rn,
            FluxPtrU8::from(start),
            size,
            perms,
        )
        .ok_or(())
        {
            sink(RegionDescriptor::overlaps(&r, start, start + size) as usize);
        }
    }
});
