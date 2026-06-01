extern crate alloc;

use crate::allocator::{self, VmError};
use crate::zram::{self, ZramDevice, ZramError};
use alloc::collections::{BTreeMap, vec_deque::VecDeque};
use spin::{Lazy, Mutex};
use x86_64::VirtAddr;
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};

const RECLAIM_START: usize = 0x_5555_0000_0000;
const RECLAIM_MAX_PAGES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimError {
    Vm(VmError),
    Zram(ZramError),
    OutOfVirtualSpace,
    UntrackedPage,
    AlreadyReclaimed,
}

impl From<VmError> for ReclaimError {
    fn from(value: VmError) -> Self {
        Self::Vm(value)
    }
}

impl From<ZramError> for ReclaimError {
    fn from(value: ZramError) -> Self {
        Self::Zram(value)
    }
}

#[derive(Debug, Clone, Copy)]
enum EntryState {
    Resident(PhysFrame<Size4KiB>),
    Compressed,
}

#[derive(Debug, Clone, Copy)]
struct ReclaimEntry {
    page_index: usize,
    state: EntryState,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReclaimStats {
    pub allocated_pages: usize,
    pub resident_pages: usize,
    pub compressed_pages: usize,
    pub reclaims: u64,
    pub restored_faults: u64,
}

#[derive(Debug)]
struct ReclaimPager {
    next_region_page: usize,
    next_backend_page: usize,
    entries: BTreeMap<u64, ReclaimEntry>,
    resident_queue: VecDeque<u64>,
    backend: ZramDevice,
    reclaims: u64,
    restored_faults: u64,
}

impl ReclaimPager {
    fn new() -> Self {
        Self {
            next_region_page: 0,
            next_backend_page: 0,
            entries: BTreeMap::new(),
            resident_queue: VecDeque::new(),
            backend: ZramDevice::new(RECLAIM_MAX_PAGES),
            reclaims: 0,
            restored_faults: 0,
        }
    }

    fn allocate_region(&mut self, page_count: usize) -> Result<VirtAddr, ReclaimError> {
        if self.next_region_page + page_count > RECLAIM_MAX_PAGES {
            return Err(ReclaimError::OutOfVirtualSpace);
        }

        let base = VirtAddr::new((RECLAIM_START + self.next_region_page * zram::PAGE_SIZE) as u64);
        for page_offset in 0..page_count {
            let virt = VirtAddr::new(base.as_u64() + (page_offset * zram::PAGE_SIZE) as u64);
            let page = Page::containing_address(virt);
            let frame = allocator::allocate_and_map_page(page, reclaim_flags())?;
            allocator::zero_page(page);

            let page_index = self.next_backend_page;
            self.next_backend_page += 1;
            self.entries.insert(
                page.start_address().as_u64(),
                ReclaimEntry {
                    page_index,
                    state: EntryState::Resident(frame),
                },
            );
            self.resident_queue.push_back(page.start_address().as_u64());
            self.next_region_page += 1;
        }

        Ok(base)
    }

    fn reclaim_page(&mut self, addr: VirtAddr) -> Result<(), ReclaimError> {
        let page = Page::containing_address(addr);
        let page_start = page.start_address().as_u64();
        let entry = self
            .entries
            .get_mut(&page_start)
            .ok_or(ReclaimError::UntrackedPage)?;

        let frame = match entry.state {
            EntryState::Resident(frame) => frame,
            EntryState::Compressed => return Err(ReclaimError::AlreadyReclaimed),
        };

        let bytes = unsafe {
            core::slice::from_raw_parts(page.start_address().as_ptr::<u8>(), zram::PAGE_SIZE)
        }
        .to_vec();

        self.backend.store_page(entry.page_index, &bytes)?;
        let unmapped = allocator::unmap_page(page)?;
        if unmapped.start_address() == frame.start_address() {
            allocator::deallocate_frame(unmapped)?;
        }

        entry.state = EntryState::Compressed;
        self.remove_from_resident_queue(page_start);
        self.reclaims = self.reclaims.saturating_add(1);
        Ok(())
    }

    fn reclaim_one(&mut self) -> Result<bool, ReclaimError> {
        let queue_len = self.resident_queue.len();
        for _ in 0..queue_len {
            let Some(page_start) = self.resident_queue.pop_front() else {
                break;
            };
            self.resident_queue.push_back(page_start);

            let Some(entry) = self.entries.get(&page_start) else {
                continue;
            };
            if matches!(entry.state, EntryState::Resident(_)) {
                return self.reclaim_page(VirtAddr::new(page_start)).map(|_| true);
            }
        }

        Ok(false)
    }

    fn handle_page_fault(&mut self, addr: VirtAddr) -> Result<bool, ReclaimError> {
        let page = Page::containing_address(addr);
        let page_start = page.start_address().as_u64();
        let Some(entry) = self.entries.get_mut(&page_start) else {
            return Ok(false);
        };

        if let EntryState::Resident(_) = entry.state {
            return Ok(false);
        }

        let bytes = self.backend.load_page(entry.page_index)?;
        let frame = allocator::allocate_and_map_page(page, reclaim_flags())?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                page.start_address().as_mut_ptr::<u8>(),
                bytes.len(),
            );
            if bytes.len() < zram::PAGE_SIZE {
                core::ptr::write_bytes(
                    page.start_address().as_mut_ptr::<u8>().add(bytes.len()),
                    0,
                    zram::PAGE_SIZE - bytes.len(),
                );
            }
        }
        self.backend.invalidate_page(entry.page_index)?;
        entry.state = EntryState::Resident(frame);
        self.remove_from_resident_queue(page_start);
        self.resident_queue.push_back(page_start);
        self.restored_faults = self.restored_faults.saturating_add(1);
        Ok(true)
    }

    fn remove_from_resident_queue(&mut self, page_start: u64) {
        if let Some(index) = self
            .resident_queue
            .iter()
            .position(|candidate| *candidate == page_start)
        {
            self.resident_queue.remove(index);
        }
    }

    fn stats(&self) -> ReclaimStats {
        let mut resident_pages = 0;
        let mut compressed_pages = 0;
        for entry in self.entries.values() {
            match entry.state {
                EntryState::Resident(_) => resident_pages += 1,
                EntryState::Compressed => compressed_pages += 1,
            }
        }

        ReclaimStats {
            allocated_pages: self.entries.len(),
            resident_pages,
            compressed_pages,
            reclaims: self.reclaims,
            restored_faults: self.restored_faults,
        }
    }
}

static RECLAIM: Lazy<Mutex<ReclaimPager>> = Lazy::new(|| Mutex::new(ReclaimPager::new()));

fn reclaim_flags() -> PageTableFlags {
    PageTableFlags::PRESENT | PageTableFlags::WRITABLE
}

pub fn allocate_region(page_count: usize) -> Result<VirtAddr, ReclaimError> {
    RECLAIM.lock().allocate_region(page_count)
}

pub fn reclaim_page(addr: VirtAddr) -> Result<(), ReclaimError> {
    RECLAIM.lock().reclaim_page(addr)
}

pub fn reclaim_one() -> Result<bool, ReclaimError> {
    RECLAIM.lock().reclaim_one()
}

pub fn handle_page_fault(addr: VirtAddr) -> Result<bool, ReclaimError> {
    RECLAIM.lock().handle_page_fault(addr)
}

pub fn stats() -> ReclaimStats {
    RECLAIM.lock().stats()
}
