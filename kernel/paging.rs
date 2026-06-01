use x86_64::VirtAddr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{OffsetPageTable, PageTable, PhysFrame};

/// Initialize a new OffsetPageTable.
///
/// This function is unsafe because the caller must guarantee that the
/// complete physical memory is mapped to virtual memory at the passed
/// `physical_memory_offset`. Also, this function must be only called once
/// to avoid aliasing `&mut` references (which is undefined behavior).
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let (level_4_table_frame, _) = Cr3::read();
    unsafe { init_for_frame(physical_memory_offset, level_4_table_frame) }
}

/// Initialize an OffsetPageTable for a specific level-4 frame.
///
/// This function is unsafe because the caller must guarantee that the
/// referenced page table frame is valid and reachable through the HHDM.
pub unsafe fn init_for_frame(
    physical_memory_offset: VirtAddr,
    level_4_table_frame: PhysFrame,
) -> OffsetPageTable<'static> {
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    unsafe { OffsetPageTable::new(&mut *page_table_ptr, physical_memory_offset) }
}
