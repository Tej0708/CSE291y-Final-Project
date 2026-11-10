//! E5: stateful API-sequence spec harness.
//!
//! Random sequences of 2-8 calls over the five verified allocator APIs, with
//! an L1 invariant re-check plus a per-op oracle after EVERY step. Unlike the
//! single-call harnesses there is NO manual reachability prelude (finding F1):
//! the fuzzer must discover state evolution (raise the watermark via readonly
//! buffers, lower app_break via update_app_memory) on its own. Detection of
//! M3/M6/M7/M8 here therefore demonstrates that sequence harnesses remove the
//! systematic blind spot of single-call spec translation.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use kernel::fuzz_shim::{self, Permissions, RegionDescriptor, Snapshot};
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{check, check_invariants, gen_allocator, interesting_or_arbitrary, small};

fn decode_in_span(u: &mut Unstructured<'_>, alloc: &kernel::fuzz_shim::TestAllocator) -> (usize, usize) {
    // 50%: a buffer inside [memory_start, app_break); 50%: arbitrary u32 pair.
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
    let steps = 2 + (small(&mut u) % 7); // 2..=8 API calls
    for _ in 0..steps {
        let op = small(&mut u) % 5;
        let before = Snapshot::take(&alloc);
        let old_hwm = before.breaks.high_water_mark.as_usize();
        let old_ab = before.breaks.app_break.as_usize();
        let old_kb = before.breaks.kernel_break.as_usize();
        let ms = before.breaks.memory_start.as_usize();
        let mem_end = ms + before.breaks.memory_size;

        match op {
            0 => {
                // add_shared_readonly_buffer
                let (s, sz) = decode_in_span(&mut u, &alloc);
                let out = fuzz_shim::a_add_shared_readonly_buffer(&mut alloc, s, sz);
                check_invariants(&alloc);
                let in_ram = s + sz >= s
                    && s >= ms
                    && s + sz <= old_ab;
                let in_flash = s + sz >= s
                    && s >= before.breaks.flash_start.as_usize()
                    && s + sz <= before.breaks.flash_start.as_usize() + before.breaks.flash_size;
                match out {
                    Ok(()) if in_ram => {
                        let b = &alloc.breaks;
                        check!(3, b.high_water_mark.as_usize() == old_hwm.max(s + sz),
                            "readonly Ok: hwm {:#x} != max(old {old_hwm:#x}, end {:#x})",
                            b.high_water_mark.as_usize(), s + sz);
                        check!(3, b.high_water_mark.as_usize() >= old_hwm, "readonly Ok: watermark decreased");
                        check!(3, b.app_break.as_usize() == old_ab, "readonly Ok: app_break moved");
                        check!(3, b.kernel_break.as_usize() == old_kb, "readonly Ok: kernel_break moved");
                    }
                    Ok(()) if in_flash => {
                        check!(2, before.state_equal(&alloc), "flash-buffer Ok but state changed");
                    }
                    Ok(()) => {
                        check!(2, false, "Ok but buffer in neither ram nor flash");
                    }
                    Err(()) => {
                        check!(2, before.state_equal(&alloc), "readonly Err but state changed");
                    }
                }
            }
            1 => {
                // add_shared_readwrite_buffer
                let (s, sz) = decode_in_span(&mut u, &alloc);
                let out = fuzz_shim::a_add_shared_readwrite_buffer(&mut alloc, s, sz);
                check_invariants(&alloc);
                let in_ram = s + sz >= s && s >= ms && s + sz <= old_ab;
                match out {
                    Ok(()) if in_ram => {
                        let b = &alloc.breaks;
                        check!(3, b.high_water_mark.as_usize() == old_hwm.max(s + sz),
                            "rw Ok: hwm {:#x} != max(old {old_hwm:#x}, end {:#x})",
                            b.high_water_mark.as_usize(), s + sz);
                        check!(3, b.high_water_mark.as_usize() >= old_hwm, "rw Ok: watermark decreased");
                    }
                    Ok(()) => check!(2, false, "rw Ok but not in app ram memory"),
                    Err(()) => check!(2, before.state_equal(&alloc), "rw Err but state changed"),
                }
            }
            2 => {
                // update_app_memory
                let nab = interesting_or_arbitrary(&mut u) as u32 as usize;
                let out = fuzz_shim::a_update_app_memory(&mut alloc, nab);
                check_invariants(&alloc);
                match out {
                    Ok(old) => {
                        let b = &alloc.breaks;
                        check!(3, old == old_ab, "update Ok(old={old:#x}) != prev app_break={old_ab:#x}");
                        check!(3, b.app_break.as_usize() == nab, "update Ok: app_break != requested");
                        check!(3, b.memory_start.as_usize() == ms, "update Ok: memory_start moved");
                        check!(3, b.memory_size == before.breaks.memory_size, "update Ok: memory_size changed");
                        check!(3, b.high_water_mark.as_usize() == old_hwm, "update Ok: hwm moved");
                        check!(3, b.kernel_break.as_usize() == old_kb, "update Ok: kernel_break moved");
                        let r0 = alloc.regions.get(0);
                        check!(3, RegionDescriptor::is_set(&r0)
                            && RegionDescriptor::start(&r0).map(|p| p.as_usize()) == Some(ms)
                            && RegionDescriptor::size(&r0) == Some(nab - ms),
                            "update Ok: region 0 not [ms, nab)");
                        check!(3, !RegionDescriptor::is_set(&alloc.regions.get(1)), "update Ok: region 1 set");
                    }
                    Err(_) => check!(2, before.state_equal(&alloc), "update Err but state changed"),
                }
            }
            3 => {
                // allocate_in_grant_region_internal
                let size = small(&mut u);
                let align = small(&mut u);
                let out = fuzz_shim::a_allocate_in_grant_region_internal(&mut alloc, size, align);
                check_invariants(&alloc);
                match out {
                    Some(p) => {
                        check!(2, p < mem_end, "Some(p)={p:#x} >= memory_end={mem_end:#x}");
                        let b = &alloc.breaks;
                        check!(2, b.kernel_break.as_usize() >= b.app_break.as_usize(), "post kb < ab");
                        let eff_align = align.max(2);
                        let expected = old_kb.wrapping_sub(size) & !(eff_align - 1);
                        check!(3, p == expected, "p={p:#x} != align_down({old_kb:#x}-{size},a={eff_align})={expected:#x}");
                        check!(3, b.kernel_break.as_usize() == p, "post.kernel_break != returned p (dropped set?)");
                        check!(3, p < old_kb, "p={p:#x} >= old kernel_break");
                        check!(3, p >= b.app_break.as_usize(), "p < app_break");
                    }
                    None => check!(2, before.state_equal(&alloc), "None but state changed"),
                }
            }
            _ => {
                // allocate_ipc_region
                let perms = decode_perms(&mut u);
                let s = interesting_or_arbitrary(&mut u) as u32 as usize;
                let sz = small(&mut u);
                let out = fuzz_shim::a_allocate_ipc_region(&mut alloc, s, sz, perms);
                check_invariants(&alloc);
                match out {
                    Ok(region) => {
                        // SEMANTIC (L3): the returned region mirrors the request
                        // (MpuRegionDefault::create_exact_region is exact).
                        check!(3, region.start_address().as_usize() == s && region.size() == sz,
                            "ipc Ok: region {:#x}+{:#x} != requested {s:#x}+{sz:#x}",
                            region.start_address().as_usize(), region.size());
                    }
                    Err(()) => {
                        check!(2, before.state_equal(&alloc), "ipc Err but state changed");
                    }
                }
            }
        }
    }
});
