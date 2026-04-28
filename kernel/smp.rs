use crate::println;
use core::arch::asm;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::PhysFrame;
use x86_64::{PhysAddr};

pub const MAX_CPUS: usize = 32;

static DISCOVERED_CPUS: AtomicUsize = AtomicUsize::new(1);
static ONLINE_CPUS: AtomicUsize = AtomicUsize::new(1);
static AP_READY: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
static LAPIC_IDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(u32::MAX) }; MAX_CPUS];

// Signal from BSP to APs to start kernel-level initialization
pub static AP_START_SIGNAL: AtomicBool = AtomicBool::new(false);
// BSP LAPIC ID discovered during UEFI boot
static BSP_LAPIC_ID: AtomicU32 = AtomicU32::new(0);
// Kernel CR3 for APs to switch to
static KERNEL_CR3: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct CpuTopology {
    pub discovered_cpus: usize,
    pub online_cpus: usize,
    pub bootstrap_lapic_id: u32,
}

pub fn set_discovered_cpus(count: usize) {
    DISCOVERED_CPUS.store(count.max(1).min(MAX_CPUS), Ordering::SeqCst);
}

pub fn set_bsp_lapic_id(id: u32) {
    BSP_LAPIC_ID.store(id, Ordering::SeqCst);
    LAPIC_IDS[0].store(id, Ordering::SeqCst);
}

pub fn init() -> CpuTopology {
    let discovered = DISCOVERED_CPUS.load(Ordering::SeqCst);
    let bsp_id = BSP_LAPIC_ID.load(Ordering::SeqCst);
    
    AP_READY[0].store(true, Ordering::SeqCst);
    
    // Store current CR3 for APs
    let (frame, _) = Cr3::read();
    KERNEL_CR3.store(frame.start_address().as_u64(), Ordering::SeqCst);

    if discovered > 1 {
        println!("SMP: releasing {} APs...", discovered - 1);
        AP_START_SIGNAL.store(true, Ordering::SeqCst);
        
        // Wait for APs to check in
        let mut checked_in = 0;
        for _ in 0..10_000_000 {
            checked_in = ONLINE_CPUS.load(Ordering::SeqCst);
            if checked_in >= discovered {
                break;
            }
            spin_loop();
        }
    }

    let online = ONLINE_CPUS.load(Ordering::SeqCst);
    println!("SMP: {}/{} CPUs online, BSP lapic_id={}", online, discovered, bsp_id);
    
    CpuTopology {
        discovered_cpus: discovered,
        online_cpus: online,
        bootstrap_lapic_id: bsp_id,
    }
}

pub fn discovered_cpus() -> usize {
    DISCOVERED_CPUS.load(Ordering::SeqCst)
}

pub fn online_cpus() -> usize {
    ONLINE_CPUS.load(Ordering::SeqCst)
}

pub fn logical_cpu_id(lapic_id: u32) -> Option<usize> {
    let discovered = DISCOVERED_CPUS.load(Ordering::SeqCst).min(MAX_CPUS);
    (0..discovered).find(|idx| LAPIC_IDS[*idx].load(Ordering::SeqCst) == lapic_id)
}

pub fn current_cpu() -> usize {
    let Some(lapic_id) = crate::apic::current_lapic_id() else {
        return 0;
    };
    logical_cpu_id(lapic_id).unwrap_or(0)
}

// Entry point for APs started via UEFI MpServices
#[unsafe(no_mangle)]
pub extern "efiapi" fn uefi_ap_entry(_arg: *mut core::ffi::c_void) {
    // Spin until BSP signals us to start
    while !AP_START_SIGNAL.load(Ordering::SeqCst) {
        spin_loop();
    }
    
    // Immediately switch to kernel page tables
    let kernel_cr3 = KERNEL_CR3.load(Ordering::SeqCst);
    if kernel_cr3 != 0 {
        unsafe {
            Cr3::write(
                PhysFrame::containing_address(PhysAddr::new(kernel_cr3)),
                Cr3Flags::empty()
            );
        }
    }

    // Perform kernel-level AP initialization
    ap_main();
}

fn ap_main() {
    let logical_id = ONLINE_CPUS.fetch_add(1, Ordering::SeqCst);
    
    if logical_id < MAX_CPUS {
        let lapic_id = crate::apic::current_lapic_id().unwrap_or(logical_id as u32);
        LAPIC_IDS[logical_id].store(lapic_id, Ordering::SeqCst);
        
        crate::gdt::init_for_cpu(logical_id);
        crate::idt::load_local();
        crate::init_local_cpu_features();
        crate::apic::init();
        crate::syscall::init_for_cpu(logical_id);
        
        AP_READY[logical_id].store(true, Ordering::SeqCst);
    }

    // Hang until scheduled tasks arrive (currently just a loop)
    loop {
        unsafe {
            asm!("sti; hlt; cli");
        }
    }
}
