//! E4: spec harness for the `RegionDescriptor` impl on `MpuRegionDefault`
//! (mpu.rs) — the trait the TickTock proofs take as a trusted boundary whose
//! impls "must satisfy the trait's specs". Oracles are the executable subset
//! of each trait sig; ghost projections without runtime getters (perms,
//! region_number) are documented blind spots (finding F5).
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim::{FluxPtrU8, MpuRegionDefault, Permissions, RegionDescriptor};
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{check, interesting_or_arbitrary, small, U32MAX};

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
    let rn = small(&mut u) % 16; // 0..8 valid, out-of-range exercises requires
    let start = interesting_or_arbitrary(&mut u) as u32 as usize;
    let size = small(&mut u);
    let perms = decode_perms(&mut u);

    // --- default(rnum): spec `!is_set(r) && rnum(r) == rnum` ---
    // (rnum is a ghost projection with no runtime getter: blind spot)
    let d = <MpuRegionDefault as RegionDescriptor>::default(rn);
    check!(2, !RegionDescriptor::is_set(&d), "default(rn) must be unset");

    // --- create_exact_region(rn, start, size, perms) ---
    // requires rn < 8 && valid_size(start + size)
    // ensures Some(r) => region_can_access_exactly(r, start, start+size, perms)
    // executable subset: is_set, start, size; perms equality is ghost (blind)
    if rn < 8 && start + size <= U32MAX {
        if let Some(r) =
            <MpuRegionDefault as RegionDescriptor>::create_exact_region(rn, FluxPtrU8::from(start), size, perms)
        {
            check!(2, RegionDescriptor::is_set(&r), "create_exact_region: unset");
            check!(
                2,
                RegionDescriptor::start(&r).map(|p| p.as_usize()) == Some(start),
                "create_exact_region: start != requested"
            );
            check!(2, RegionDescriptor::size(&r) == Some(size), "create_exact_region: size != requested");
            // TODO(L3/blind): perms(r) == perms — no runtime getter (F5)
        }
    }

    // --- allocate_regions(max, avail_start, avail_size, region_size, perms) ---
    // requires max in 1..8 && valid_size(avail_start + avail_size)
    // ensures: start(fst) >= avail_start && regions_can_access_exactly(...) —
    // executable subset: fst set, size(fst) > 0, snd unset
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
            check!(2, RegionDescriptor::is_set(&pair.fst), "allocate_regions: fst unset");
            check!(
                2,
                RegionDescriptor::start(&pair.fst).map(|p| p.as_usize()).unwrap_or(0) >= avail_start,
                "allocate_regions: start(fst) < avail_start"
            );
            check!(2, RegionDescriptor::size(&pair.fst).unwrap_or(0) > 0, "allocate_regions: size(fst) == 0");
            check!(2, !RegionDescriptor::is_set(&pair.snd), "allocate_regions: snd set (must be default)");
            // TODO(L3/blind): rnum(fst) == max-1, perms(fst) == perms (F5)
        }
    }

    // --- update_regions(region_start, avail, region_size, max, perms) ---
    // ensures: start(fst) == region_start && size(fst) > 0 && snd unset
    let region_start = interesting_or_arbitrary(&mut u) as u32 as usize;
    if region_start + avail_size <= U32MAX {
        if let Some(pair) = <MpuRegionDefault as RegionDescriptor>::update_regions(
            FluxPtrU8::from(region_start),
            avail_size,
            region_size,
            max,
            perms,
        ) {
            check!(
                2,
                RegionDescriptor::start(&pair.fst).map(|p| p.as_usize()) == Some(region_start),
                "update_regions: start(fst) != region_start"
            );
            check!(2, RegionDescriptor::size(&pair.fst).unwrap_or(0) > 0, "update_regions: size(fst) == 0");
            check!(2, !RegionDescriptor::is_set(&pair.snd), "update_regions: snd set");
        }
    }

    // --- getter/consistency + overlaps (impl-defined {false}) ---
    if rn < 8 && start + size <= U32MAX {
        if let Ok(r) = <MpuRegionDefault as RegionDescriptor>::create_exact_region(
            rn,
            FluxPtrU8::from(start),
            size,
            perms,
        )
        .ok_or(())
        {
            let s = RegionDescriptor::start(&r);
            let sz = RegionDescriptor::size(&r);
            check!(2, s.is_some() == RegionDescriptor::is_set(&r), "start/set inconsistent");
            check!(2, sz.is_some() == RegionDescriptor::is_set(&r), "size/set inconsistent");
            let o = RegionDescriptor::overlaps(&r, start, start + size);
            check!(2, !o, "MpuRegionDefault::overlaps must be false (assoc def)");
        }
    }
});
