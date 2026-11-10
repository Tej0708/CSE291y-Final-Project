//! Spec harness for `in_app_ram_memory` (fully translatable, value-only spec).
//! Flux spec: fn (&Self[@b], start, end) -> bool[end >= start && start >= b.breaks.memory_start && end <= b.breaks.app_break]
//! Oracle: return value == executable formula on snapshot fields. [L2]
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{check, check_invariants, gen_allocator, interesting_or_arbitrary};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some(alloc) = gen_allocator(&mut u) else {
        return;
    };
    let start = interesting_or_arbitrary(&mut u) as u32 as usize;
    let end = interesting_or_arbitrary(&mut u) as u32 as usize;

    let b = &alloc.breaks;
    let expected = end >= start
        && start >= b.memory_start.as_usize()
        && end <= b.app_break.as_usize();

    let out = fuzz_shim::a_in_app_ram_memory(&alloc, start, end);

    check_invariants(&alloc);
    check!(2, out == expected, "in_app_ram_memory({start:#x},{end:#x}) = {out}, spec formula = {expected}");
});
