use crate::{
    allocator::{self, VmError},
    println,
};
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::{
    PhysAddr, VirtAddr,
    registers::model_specific::Msr,
    structures::paging::{Page, PageSize, PageTableFlags, PhysFrame, Size4KiB},
};

pub const APIC_BASE_MSR: u32 = 0x1B;
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);
static APIC_MAPPING_BASE: AtomicU64 = AtomicU64::new(0);
const APIC_MMIO_VIRT_BASE: u64 = 0xffff_fe00_0000_0000;

pub struct LocalApic {
    base_addr: u64,
    physical_addr: u64,
}

impl LocalApic {
    pub unsafe fn new() -> Self {
        let apic_base_msr = Msr::new(APIC_BASE_MSR);
        let physical_addr = unsafe { apic_base_msr.read() & 0xFFFFF000 };
        let base_addr = mapped_base_for(physical_addr)
            .unwrap_or_else(|_| physical_addr + HHDM_OFFSET.load(Ordering::SeqCst));
        println!(
            "APIC: physical base={:#x}, virtual base={:#x}",
            physical_addr, base_addr
        );
        Self {
            base_addr,
            physical_addr,
        }
    }

    unsafe fn write(&self, offset: u32, value: u32) {
        let ptr = (self.base_addr + offset as u64) as *mut u32;
        unsafe { ptr.write_volatile(value) };
    }

    unsafe fn read(&self, offset: u32) -> u32 {
        let ptr = (self.base_addr + offset as u64) as *const u32;
        unsafe { ptr.read_volatile() }
    }

    pub unsafe fn init(&self) {
        unsafe {
            // Spurious Interrupt Vector Register
            // Enable APIC by setting bit 8, and use vector 255 for spurious interrupts
            self.write(0xF0, self.read(0xF0) | 0x100 | 0xFF);

            // Timer Divide Configuration Register
            // Divide by 16
            self.write(0x3E0, 0x03);

            // LVT Timer Register
            // Periodic mode (bit 17), Vector 32 (Timer)
            self.write(0x320, (1 << 17) | 32);

            // Initial Count Register
            // Set to a reasonable value for periodic ticks
            self.write(0x380, 0x1000000);
        }

        println!("APIC: Initialized timer at {:#x}.", self.physical_addr);
    }

    pub unsafe fn complete_interrupt(&self) {
        // End of Interrupt (EOI) register
        unsafe { self.write(0x0B0, 0) };
    }
}

pub static mut APIC: Option<LocalApic> = None;

pub fn set_hhdm_offset(offset: VirtAddr) {
    HHDM_OFFSET.store(offset.as_u64(), Ordering::SeqCst);
}

pub fn init() {
    unsafe {
        let apic = LocalApic::new();
        apic.init();
        APIC = Some(apic);
    }
}

pub fn complete_interrupt() {
    unsafe {
        if let Some(ref apic) = APIC {
            apic.complete_interrupt();
        }
    }
}

pub fn current_lapic_id() -> Option<u32> {
    unsafe {
        let apic = core::ptr::addr_of!(APIC).read();
        apic.map(|apic| apic.read(0x20) >> 24)
    }
}

fn mapped_base_for(physical_addr: u64) -> Result<u64, VmError> {
    let hhdm_offset = HHDM_OFFSET.load(Ordering::SeqCst);
    if hhdm_offset == 0 {
        return Ok(physical_addr);
    }

    if !allocator::runtime_ready() {
        return Err(VmError::RuntimeNotInitialized);
    }

    let page_offset = physical_addr & (Size4KiB::SIZE - 1);
    let existing = APIC_MAPPING_BASE.load(Ordering::SeqCst);
    if existing != 0 {
        return Ok(existing + page_offset);
    }

    let virt_page = Page::containing_address(VirtAddr::new(APIC_MMIO_VIRT_BASE));
    let frame = PhysFrame::containing_address(PhysAddr::new(physical_addr));
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;

    match allocator::map_existing_page(virt_page, frame, flags) {
        Ok(()) | Err(VmError::PageAlreadyMapped) => {
            APIC_MAPPING_BASE.store(APIC_MMIO_VIRT_BASE, Ordering::SeqCst);
            Ok(APIC_MMIO_VIRT_BASE + page_offset)
        }
        Err(err) => Err(err),
    }
}
