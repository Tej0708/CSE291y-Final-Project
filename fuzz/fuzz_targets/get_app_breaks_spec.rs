//! Spec harness for `AppMemoryAllocator::get_app_breaks` (static break builder).
//! get_app_breaks has no direct wrapper, but it runs inside the verified
//! constructor `allocate_app_memory`, so we exercise it by validating the
//! AppBreaks it produces against the known constructor inputs. The ensures
//! clause (tock-flux/kernel/src/allocator.rs:454) pins:
//!   (memory_start + memory_size) - kernel_break == initial_kernel_memory_size,
//!   flash_start/flash_size passthrough; plus the code sets
//!   high_water_mark == memory_start and app_break == kernel_break
//!   (zero initial grant space — the implicit precondition from report F1).
//! Oracle:
//!   L1: invariant chain re-check.
//!   L2: flash_start / flash_size equal the constructor inputs.
//!   L3: high_water_mark == memory_start; app_break == kernel_break;
//!       (memory_start + memory_size) - kernel_break == initial_kernel_memory_size.
#![no_main]

use arbitrary::Unstructured;
use kernel::fuzz_shim;
use libfuzzer_sys::fuzz_target;
use ticktock_spec_fuzz::{check, check_invariants, decode_allocator_params};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Some((id, us, usz, mins, apps, ksz, fs, fsz)) = decode_allocator_params(&mut u) else {
        return;
    };
    // Build via the verified constructor (which calls get_app_breaks); a
    // constructor Err is a skip, same as the shared gen_allocator.
    let Ok(alloc) = fuzz_shim::gen_allocator(id, us, usz, mins, apps, ksz, fs, fsz) else {
        return;
    };

    check_invariants(&alloc);

    let b = &alloc.breaks;
    let ms = b.memory_start.as_usize();
    let msz = b.memory_size;
    let ab = b.app_break.as_usize();
    let hwm = b.high_water_mark.as_usize();
    let kb = b.kernel_break.as_usize();

    // ENSURES (L2): flash fields are passed through unchanged.
    check!(2, b.flash_start.as_usize() == fs, "flash_start {:#x} != input {fs:#x}", b.flash_start.as_usize());
    check!(2, b.flash_size == fsz, "flash_size {} != input {fsz}", b.flash_size);

    // SEMANTIC (L3): break-layout postconditions of get_app_breaks.
    check!(3, hwm == ms, "high_water_mark {hwm:#x} != memory_start {ms:#x}");
    check!(3, ab == kb, "app_break {ab:#x} != kernel_break {kb:#x} (fresh alloc has zero grant space)");
    check!(3, (ms + msz) - kb == ksz,
        "kernel reserve (memory_end - kernel_break) = {} != initial_kernel_memory_size {ksz}", (ms + msz) - kb);
});
