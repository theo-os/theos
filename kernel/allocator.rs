extern crate alloc;

use crate::paging;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::{Lazy, Mutex};
#[cfg(target_os = "uefi")]
use uefi::boot::{AllocateType};
use uefi::mem::memory_map::MemoryMap as _;
use uefi::boot::MemoryType;
use x86_64::structures::paging::{
    mapper::{FlagUpdateError, MapToError, UnmapError},
    FrameAllocator, Mapper as _, OffsetPageTable, Page, PageSize, PageTableFlags, PhysFrame,
    Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

#[derive(Clone, Copy)]
struct MemoryRegion {
    base: u64,
    length: u64,
}

pub struct BootInfoFrameAllocator {
    regions: Vec<MemoryRegion>,
    recycled: Vec<PhysFrame>,
    current_entry: usize,
    current_addr: u64,
}

pub enum RuntimeFrameAllocator {
    BootInfo(BootInfoFrameAllocator),
    #[cfg(target_os = "uefi")]
    Uefi(UefiFrameAllocator),
}

#[cfg(target_os = "uefi")]
pub struct UefiFrameAllocator {
    recycled: Vec<PhysFrame>,
}

impl BootInfoFrameAllocator {
    pub fn init_from_uefi(memory_map: &uefi::mem::memory_map::MemoryMapOwned) -> Self {
        let mut regions = Vec::new();
        for entry in memory_map.entries() {
            let usable = matches!(entry.ty, MemoryType::CONVENTIONAL);
            if usable {
                regions.push(MemoryRegion {
                    base: entry.phys_start,
                    length: entry.page_count * Size4KiB::SIZE,
                });
            }
        }
        Self::init_from_regions(regions)
    }

    fn init_from_regions(regions: Vec<MemoryRegion>) -> Self {
        BootInfoFrameAllocator {
            regions,
            recycled: Vec::new(),
            current_entry: 0,
            current_addr: 0,
        }
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if let Some(frame) = self.recycled.pop() {
            return Some(frame);
        }
        while self.current_entry < self.regions.len() {
            let entry = self.regions[self.current_entry];
            let start = entry.base;
            let end = entry.base + entry.length;
            if self.current_addr < start {
                self.current_addr = start;
            }
            if self.current_addr < Size4KiB::SIZE {
                self.current_addr = Size4KiB::SIZE;
            }
            let addr = self.current_addr;
            if addr + 4096 <= end {
                self.current_addr += 4096;
                return Some(PhysFrame::containing_address(PhysAddr::new(addr)));
            }

            self.current_entry += 1;
            self.current_addr = 0;
        }
        None
    }
}

unsafe impl FrameAllocator<Size4KiB> for RuntimeFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        match self {
            Self::BootInfo(allocator) => allocator.allocate_frame(),
            #[cfg(target_os = "uefi")]
            Self::Uefi(allocator) => allocator.allocate_frame(),
        }
    }
}

#[cfg(target_os = "uefi")]
unsafe impl FrameAllocator<Size4KiB> for UefiFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if let Some(frame) = self.recycled.pop() {
            return Some(frame);
        }

        let phys = uefi::boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
            .ok()?;
        let addr = phys.as_ptr() as u64;
        if addr < Size4KiB::SIZE {
            return self.allocate_frame();
        }
        Some(PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    RuntimeNotInitialized,
    FrameAllocationFailed,
    PageAlreadyMapped,
    ParentEntryHugePage,
    PageNotMapped,
}

pub fn init_heap(
    mapper: &mut OffsetPageTable,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + HEAP_SIZE as u64 - 1u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_use(x86_64::structures::paging::mapper::MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
    }

    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }
    HEAP_BASE.store(HEAP_START as u64, Ordering::SeqCst);

    Ok(())
}

use linked_list_allocator::LockedHeap;

#[global_allocator]
pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0);
static HEAP_BASE: AtomicU64 = AtomicU64::new(HEAP_START as u64);
static RUNTIME_READY: AtomicBool = AtomicBool::new(false);
pub static FRAME_ALLOCATOR: Lazy<Mutex<Option<RuntimeFrameAllocator>>> =
    Lazy::new(|| Mutex::new(None));

pub fn init_runtime(physical_memory_offset: VirtAddr, frame_allocator: BootInfoFrameAllocator) {
    init_runtime_with_allocator(
        physical_memory_offset,
        RuntimeFrameAllocator::BootInfo(frame_allocator),
    );
}

pub fn init_runtime_with_allocator(
    physical_memory_offset: VirtAddr,
    frame_allocator: RuntimeFrameAllocator,
) {
    PHYSICAL_MEMORY_OFFSET.store(physical_memory_offset.as_u64(), Ordering::SeqCst);
    *FRAME_ALLOCATOR.lock() = Some(frame_allocator);
    RUNTIME_READY.store(true, Ordering::SeqCst);
}

pub fn set_heap_base(addr: u64) {
    HEAP_BASE.store(addr, Ordering::SeqCst);
}

pub fn heap_base() -> u64 {
    HEAP_BASE.load(Ordering::SeqCst)
}

#[cfg(target_os = "uefi")]
pub fn init_uefi_runtime() {
    init_runtime_with_allocator(
        VirtAddr::new(0),
        RuntimeFrameAllocator::Uefi(UefiFrameAllocator {
            recycled: Vec::new(),
        }),
    );
}

pub fn runtime_ready() -> bool {
    RUNTIME_READY.load(Ordering::SeqCst)
}

pub fn allocate_and_map_page(
    page: Page<Size4KiB>,
    flags: PageTableFlags,
) -> Result<PhysFrame<Size4KiB>, VmError> {
    let frame = allocate_frame()?;

    map_existing_page(page, frame, flags)?;
    Ok(frame)
}

pub fn allocate_frame() -> Result<PhysFrame<Size4KiB>, VmError> {
    loop {
        if let Some(frame) = try_allocate_frame()? {
            return Ok(frame);
        }

        let reclaimed = crate::reclaim::reclaim_one().map_err(|err| match err {
            crate::reclaim::ReclaimError::Vm(vm) => vm,
            _ => VmError::FrameAllocationFailed,
        })?;
        if !reclaimed {
            return Err(VmError::FrameAllocationFailed);
        }
    }
}

pub fn zero_frame(frame: PhysFrame<Size4KiB>) -> Result<(), VmError> {
    let offset = physical_memory_offset()?;
    let ptr = (offset.as_u64() + frame.start_address().as_u64()) as *mut u8;
    unsafe {
        core::ptr::write_bytes(ptr, 0, Size4KiB::SIZE as usize);
    }
    Ok(())
}

pub fn map_existing_page(
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), VmError> {
    with_runtime(|mapper, frame_allocator| {
        unsafe {
            mapper
                .map_to(page, frame, flags, frame_allocator)
                .map_err(map_error_to_vm)?
                .flush();
        }
        Ok(())
    })
}

pub fn map_existing_page_in(
    root_frame: PhysFrame<Size4KiB>,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), VmError> {
    with_runtime_in(root_frame, |mapper, frame_allocator| {
        unsafe {
            mapper
                .map_to(page, frame, flags, frame_allocator)
                .map_err(map_error_to_vm)?
                .flush();
        }
        Ok(())
    })
}

pub fn update_page_flags(page: Page<Size4KiB>, flags: PageTableFlags) -> Result<(), VmError> {
    with_runtime(|mapper, _frame_allocator| {
        unsafe {
            mapper
                .update_flags(page, flags)
                .map_err(flag_update_error_to_vm)?
                .flush();
        }
        Ok(())
    })
}

pub fn update_page_flags_in(
    root_frame: PhysFrame<Size4KiB>,
    page: Page<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), VmError> {
    with_runtime_in(root_frame, |mapper, _frame_allocator| {
        unsafe {
            mapper
                .update_flags(page, flags)
                .map_err(flag_update_error_to_vm)?
                .flush();
        }
        Ok(())
    })
}

pub fn unmap_page(page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, VmError> {
    with_runtime(|mapper, _frame_allocator| {
        let (frame, flush) = mapper.unmap(page).map_err(unmap_error_to_vm)?;
        flush.flush();
        Ok(frame)
    })
}

pub fn unmap_page_in(
    root_frame: PhysFrame<Size4KiB>,
    page: Page<Size4KiB>,
) -> Result<PhysFrame<Size4KiB>, VmError> {
    with_runtime_in(root_frame, |mapper, _frame_allocator| {
        let (frame, flush) = mapper.unmap(page).map_err(unmap_error_to_vm)?;
        flush.flush();
        Ok(frame)
    })
}

pub fn deallocate_frame(frame: PhysFrame<Size4KiB>) -> Result<(), VmError> {
    let mut guard = FRAME_ALLOCATOR.lock();
    let frame_allocator = guard.as_mut().ok_or(VmError::RuntimeNotInitialized)?;
    match frame_allocator {
        RuntimeFrameAllocator::BootInfo(frame_allocator) => frame_allocator.recycled.push(frame),
        #[cfg(target_os = "uefi")]
        RuntimeFrameAllocator::Uefi(frame_allocator) => frame_allocator.recycled.push(frame),
    }
    Ok(())
}

pub fn zero_page(page: Page<Size4KiB>) {
    unsafe {
        core::ptr::write_bytes(
            page.start_address().as_mut_ptr::<u8>(),
            0,
            Size4KiB::SIZE as usize,
        );
    }
}

pub fn physical_memory_offset() -> Result<VirtAddr, VmError> {
    if !runtime_ready() {
        Err(VmError::RuntimeNotInitialized)
    } else {
        Ok(VirtAddr::new(PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst)))
    }
}

fn with_runtime<T>(
    f: impl FnOnce(&mut OffsetPageTable, &mut RuntimeFrameAllocator) -> Result<T, VmError>,
) -> Result<T, VmError> {
    let offset = physical_memory_offset()?;
    let (root_frame, _) = x86_64::registers::control::Cr3::read();
    with_runtime_in_with_offset(root_frame, offset, f)
}

fn with_runtime_in<T>(
    root_frame: PhysFrame<Size4KiB>,
    f: impl FnOnce(&mut OffsetPageTable, &mut RuntimeFrameAllocator) -> Result<T, VmError>,
) -> Result<T, VmError> {
    let offset = physical_memory_offset()?;
    with_runtime_in_with_offset(root_frame, offset, f)
}

fn with_runtime_in_with_offset<T>(
    root_frame: PhysFrame<Size4KiB>,
    offset: VirtAddr,
    f: impl FnOnce(&mut OffsetPageTable, &mut RuntimeFrameAllocator) -> Result<T, VmError>,
) -> Result<T, VmError> {
    let mut guard = FRAME_ALLOCATOR.lock();
    let frame_allocator = guard.as_mut().ok_or(VmError::RuntimeNotInitialized)?;
    let mut mapper = unsafe { paging::init_for_frame(offset, root_frame) };
    f(&mut mapper, frame_allocator)
}

fn try_allocate_frame() -> Result<Option<PhysFrame<Size4KiB>>, VmError> {
    let mut guard = FRAME_ALLOCATOR.lock();
    let frame_allocator = guard.as_mut().ok_or(VmError::RuntimeNotInitialized)?;
    Ok(frame_allocator.allocate_frame())
}

fn map_error_to_vm(err: MapToError<Size4KiB>) -> VmError {
    match err {
        MapToError::FrameAllocationFailed => VmError::FrameAllocationFailed,
        MapToError::ParentEntryHugePage => VmError::ParentEntryHugePage,
        MapToError::PageAlreadyMapped(_) => VmError::PageAlreadyMapped,
    }
}

fn unmap_error_to_vm(err: UnmapError) -> VmError {
    match err {
        UnmapError::ParentEntryHugePage => VmError::ParentEntryHugePage,
        UnmapError::PageNotMapped => VmError::PageNotMapped,
        UnmapError::InvalidFrameAddress(_) => VmError::PageNotMapped,
    }
}

fn flag_update_error_to_vm(err: FlagUpdateError) -> VmError {
    match err {
        FlagUpdateError::ParentEntryHugePage => VmError::ParentEntryHugePage,
        FlagUpdateError::PageNotMapped => VmError::PageNotMapped,
    }
}

trait OptionExt<T> {
    fn ok_use<E>(self, err: E) -> Result<T, E>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_use<E>(self, err: E) -> Result<T, E> {
        match self {
            Some(x) => Ok(x),
            None => Err(err),
        }
    }
}
