// Fuzz-harness shim for spec-driven fuzzing (TickTock spec→fuzz experiment).
//
// Compiled only when `--cfg fuzzing` is set, which cargo-fuzz does
// automatically for every harness build. It re-exports the pub(crate)
// allocator internals behind a public API so the external fuzz crate can:
//   1. construct an AppMemoryAllocator satisfying the AppBreaks invariants
//      (via the Flux-verified constructor `allocate_app_memory`), and
//   2. call the mutation targets directly.
// In normal builds this module contributes nothing.

#![allow(missing_docs)]

// pub(crate) types cannot be `pub use`d (E0365); name them via aliases.
pub type AllocateAppMemoryError = crate::allocator::AllocateAppMemoryError;
pub type AppBreaks = crate::allocator::AppBreaks;
pub type AppMemoryAllocator<R> = crate::allocator::AppMemoryAllocator<R>;
pub use crate::platform::mpu::{MpuRegionDefault, Permissions, Region, RegionDescriptor};
pub use flux_support::{FluxPtrU8, FluxPtrU8Mut, Pair, RArray};

pub type TestAllocator = AppMemoryAllocator<MpuRegionDefault>;

/// Returns the struct invariants of AppBreaks as executable runtime checks.
/// (memory_start <= high_water_mark <= app_break <= kernel_break
///  <= memory_start + memory_size <= u32::MAX; flash entirely below memory_start)
pub fn check_app_breaks_invariants(b: &AppBreaks) -> Result<(), &'static str> {
    let ms = b.memory_start.as_usize();
    let sz = b.memory_size;
    let ab = b.app_break.as_usize();
    let hwm = b.high_water_mark.as_usize();
    let kb = b.kernel_break.as_usize();
    let fs = b.flash_start.as_usize();
    let fsz = b.flash_size;
    if ms + sz > u32::MAX as usize {
        Err("invariant memory_start + memory_size <= u32::MAX")
    } else if kb > ms + sz {
        Err("invariant kernel_break <= memory_start + memory_size")
    } else if fs + fsz >= ms {
        Err("invariant flash_start + flash_size < memory_start")
    } else if ab < hwm {
        Err("invariant app_break >= high_water_mark")
    } else if ab > kb {
        Err("invariant app_break <= kernel_break")
    } else if hwm < ms {
        Err("invariant high_water_mark >= memory_start")
    } else {
        Ok(())
    }
}

/// Returns the struct invariants of AppMemoryAllocator<R> that are checkable
/// at runtime for R = MpuRegionDefault (the R::overlaps conjuncts are
/// trivially false for this impl; the executable remainder is the breaks
/// chain). See census: GHOST-PARAM conjuncts map to these runtime checks.
pub fn check_allocator_invariants(a: &TestAllocator) -> Result<(), &'static str> {
    check_app_breaks_invariants(&a.breaks)
}

/// Point-wise snapshot of the allocator's observable state.
pub struct Snapshot {
    pub breaks: AppBreaks,
    pub regions: [(bool, usize, usize); 8], // (is_set, start, size)
}

impl Snapshot {
    pub fn take(a: &TestAllocator) -> Self {
        let mut regions = [(false, 0usize, 0usize); 8];
        for i in 0..8 {
            let r = a.regions.get(i);
            let start = RegionDescriptor::start(&r).map(|p| p.as_usize()).unwrap_or(0);
            let size = RegionDescriptor::size(&r).unwrap_or(0);
            regions[i] = (RegionDescriptor::is_set(&r), start, size);
        }
        Snapshot {
            breaks: a.breaks,
            regions,
        }
    }

    pub fn breaks_equal(&self, a: &TestAllocator) -> bool {
        let b = &a.breaks;
        self.breaks.memory_start == b.memory_start
            && self.breaks.memory_size == b.memory_size
            && self.breaks.app_break == b.app_break
            && self.breaks.high_water_mark == b.high_water_mark
            && self.breaks.kernel_break == b.kernel_break
            && self.breaks.flash_start == b.flash_start
            && self.breaks.flash_size == b.flash_size
    }

    pub fn regions_equal(&self, a: &TestAllocator) -> bool {
        for i in 0..8 {
            let r = a.regions.get(i);
            let start = RegionDescriptor::start(&r).map(|p| p.as_usize()).unwrap_or(0);
            let size = RegionDescriptor::size(&r).unwrap_or(0);
            let cur = (RegionDescriptor::is_set(&r), start, size);
            if cur != self.regions[i] {
                return false;
            }
        }
        true
    }

    pub fn state_equal(&self, a: &TestAllocator) -> bool {
        self.breaks_equal(a) && self.regions_equal(a)
    }
}

/// Generator: build an invariant-satisfying allocator from raw values using
/// the Flux-verified constructor `allocate_app_memory`. The caller supplies
/// values satisfying the constructor's `requires` clause; a failure here is
/// a generator bug and panics.
pub fn gen_allocator(
    id: usize,
    unallocated_memory_start: usize,
    unallocated_memory_size: usize,
    min_memory_size: usize,
    initial_app_memory_size: usize,
    initial_kernel_memory_size: usize,
    flash_start: usize,
    flash_size: usize,
) -> Result<TestAllocator, AllocateAppMemoryError> {
    AppMemoryAllocator::allocate_app_memory(
        id,
        FluxPtrU8::from(unallocated_memory_start),
        unallocated_memory_size,
        min_memory_size,
        initial_app_memory_size,
        initial_kernel_memory_size,
        FluxPtrU8::from(flash_start),
        flash_size,
    )
}

// ---- wrapper functions for the mutation targets (all pub(crate) fns) ----

pub fn a_in_app_ram_memory(a: &TestAllocator, start: usize, end: usize) -> bool {
    a.in_app_ram_memory(FluxPtrU8::from(start), FluxPtrU8::from(end))
}

pub fn a_in_app_flash_memory(a: &TestAllocator, start: usize, end: usize) -> bool {
    a.in_app_flash_memory(FluxPtrU8::from(start), FluxPtrU8::from(end))
}

pub fn a_add_shared_readonly_buffer(a: &mut TestAllocator, start: usize, size: usize) -> Result<(), ()> {
    a.add_shared_readonly_buffer(FluxPtrU8Mut::from(start), size)
}

pub fn a_add_shared_readwrite_buffer(a: &mut TestAllocator, start: usize, size: usize) -> Result<(), ()> {
    a.add_shared_readwrite_buffer(FluxPtrU8Mut::from(start), size)
}

pub fn a_allocate_in_grant_region_internal(a: &mut TestAllocator, size: usize, align: usize) -> Option<usize> {
    a.allocate_in_grant_region_internal(size, align).map(|p| p.as_usize())
}

pub fn a_allocate_custom_grant(a: &mut TestAllocator, size: usize, align: usize) -> Result<(usize, usize), ()> {
    a.allocate_custom_grant(size, align)
        .map(|(id, ptr)| (id.offset, ptr.as_ptr() as usize))
}

pub fn a_allocate_ipc_region(a: &mut TestAllocator, start: usize, size: usize, perms: Permissions) -> Result<Region, ()> {
    a.allocate_ipc_region(FluxPtrU8::from(start), size, perms)
}

pub fn a_update_app_memory(a: &mut TestAllocator, new_app_break: usize) -> Result<usize, crate::process::Error> {
    a.update_app_memory(FluxPtrU8Mut::from(new_app_break))
        .map(|p| p.as_usize())
}

pub fn a_get_flash_start(a: &TestAllocator) -> usize {
    a.flash_start().as_usize()
}
pub fn a_get_flash_end(a: &TestAllocator) -> usize {
    a.flash_end().as_usize()
}
pub fn a_get_memory_start(a: &TestAllocator) -> usize {
    a.memory_start().as_usize()
}
pub fn a_get_memory_size(a: &TestAllocator) -> usize {
    a.memory_size()
}
pub fn a_get_memory_end(a: &TestAllocator) -> usize {
    a.memory_end().as_usize()
}
pub fn a_get_app_break(a: &TestAllocator) -> usize {
    a.app_break().as_usize()
}
pub fn a_get_kernel_break(a: &TestAllocator) -> usize {
    a.kernel_break().as_usize()
}

pub fn a_next_available_ipc_idx(a: &TestAllocator) -> Option<usize> {
    a.next_available_ipc_idx()
}

/// Unsafe write target used by the set_byte harness; the harness must back
/// `addr` with real mapped memory.
pub unsafe fn a_set_byte(a: &TestAllocator, addr: usize, value: u8) -> bool {
    a.set_byte(FluxPtrU8Mut::from(addr), value)
}
