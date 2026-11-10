//! Shared helpers for the TickTock spec-derived fuzz harnesses.
//!
//! Every harness follows the generated-harness shape (see experiment-plan.md §5.3):
//!   1. DECODE  — build inputs satisfying the target's Flux `requires` and the
//!      AppBreaks/AppMemoryAllocator invariants (the generator comes from the
//!      *verified* constructor `allocate_app_memory`);
//!   2. SNAPSHOT — capture observable pre-state;
//!   3. CALL    — invoke the target;
//!   4. ENSURES — check the Flux `ensures` clause against the snapshot;
//!   5. INVARIANTS — re-check the struct invariant chain.
//!
//! Oracle levels (runtime-selected via FUZZ_ORACLE_LEVEL):
//!   L1: struct invariants only
//!   L2: L1 + spec ensures clauses (incl. "None => state unchanged")
//!   L3: L2 + semantic contracts implied by the code the verifier discharged
//!       (alignment, exact break movement, dropped-write detection)

#![allow(dead_code)]

use arbitrary::{Arbitrary, Unstructured};
use kernel::fuzz_shim::{self, TestAllocator};

pub const U32MAX: usize = u32::MAX as usize;

/// Interesting-value pool for address-like quantities (u32 address space).
pub const INTERESTING: &[usize] = &[
    0,
    1,
    2,
    0x100,
    0x2000_0000, // low-4GB backing-memory address
    0x8000_0000,
    0xFFFF_0000,
    0xFFFF_FFF0,
    U32MAX,
    U32MAX - 1,
];

pub fn interesting_or_arbitrary(u: &mut Unstructured<'_>) -> usize {
    if bool::arbitrary(u).unwrap_or(false) {
        let idx = usize::arbitrary(u).unwrap_or(0) % INTERESTING.len();
        INTERESTING[idx]
    } else {
        u32::arbitrary(u).unwrap_or(0) as usize
    }
}

pub fn small(u: &mut Unstructured<'_>) -> usize {
    u32::arbitrary(u).unwrap_or(0) as usize
}

/// Decode allocator-construction parameters satisfying the `requires` clause
/// of `allocate_app_memory`:
///   valid_size(mem_start + mem_size) && flash_start + flash_size < mem_start
/// plus the runtime check `unallocated_start + unallocated_size <= u32::MAX`,
/// and the success constraints of get_ram_regions/get_app_breaks so that the
/// verified constructor yields an Ok allocator most of the time:
///   1 <= ideal <= unallocated_size, 1 <= kernel_size <= unallocated_size - ideal
///
/// Returns None when the input cannot encode a valid allocator (harness skip,
/// same behavior the plain baseline exhibits).
pub fn decode_allocator_params(
    u: &mut Unstructured<'_>,
) -> Option<(usize, usize, usize, usize, usize, usize, usize, usize)> {
    let unalloc_start = (interesting_or_arbitrary(u) % (U32MAX - 256)) | 1;
    let flash_size = small(u) % unalloc_start;
    let flash_start = small(u) % (unalloc_start - flash_size);
    let unalloc_size = 16 + (small(u) % (U32MAX - unalloc_start - 15));
    // unalloc_start + unalloc_size <= U32MAX and unalloc_size >= 16 hold by
    // construction; flash_start + flash_size < unalloc_start cannot overflow.
    let min_size = small(u) % (unalloc_size + 1);
    let app_size = small(u) % (unalloc_size + 1);
    let ideal = min_size.max(app_size);
    let ideal = if ideal == 0 { 1 } else { ideal };
    let remaining = unalloc_size - ideal;
    if remaining == 0 {
        return None; // no room for kernel memory (spec requires > 0)
    }
    let kernel_size = 1 + (small(u) % remaining);
    let id = small(u);
    Some((
        id,
        unalloc_start,
        unalloc_size,
        min_size,
        app_size,
        kernel_size,
        flash_start,
        flash_size,
    ))
}

pub fn gen_allocator(u: &mut Unstructured<'_>) -> Option<TestAllocator> {
    let (id, us, usz, mins, apps, ksz, fs, fsz) = decode_allocator_params(u)?;
    fuzz_shim::gen_allocator(id, us, usz, mins, apps, ksz, fs, fsz).ok()
}

/// Oracle level selection. Default: all levels (L3).
pub fn oracle_level() -> u8 {
    static LEVEL: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
    *LEVEL.get_or_init(|| {
        std::env::var("FUZZ_ORACLE_LEVEL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3)
    })
}

#[macro_export]
macro_rules! check {
    ($lvl:expr, $cond:expr, $($arg:tt)*) => {
        if $crate::oracle_level() >= $lvl && !($cond) {
            panic!("SPEC VIOLATION [L{}]: {}", $lvl, format_args!($($arg)*));
        }
    };
}

/// Re-check the executable AppBreaks invariant chain (L1).
pub fn check_invariants(a: &TestAllocator) {
    if let Err(e) = fuzz_shim::check_allocator_invariants(a) {
        panic!("SPEC VIOLATION [L1] struct invariant: {}", e);
    }
}

/// Consume results in the plain baselines so the compiler cannot elide calls.
#[inline]
pub fn sink(v: usize) {
    std::hint::black_box(v);
}
