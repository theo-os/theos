#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("This kernel only supports x86_64");

pub mod allocator;
pub mod apic;
pub mod cmdline;
pub mod gdt;
pub mod idt;
pub mod log;
pub mod nt;
pub mod paging;
pub mod pci;
pub mod process;
pub mod reclaim;
pub mod serial;
pub mod smp;
pub mod syscall;
pub mod user;
pub mod vfs;
pub mod virtio_blk;
pub mod zram;

use alloc::string::ToString;
#[cfg(target_os = "uefi")]
use alloc::vec;
use alloc::vec::Vec;
use core::{arch::asm, panic::PanicInfo};

#[cfg(target_os = "uefi")]
use uefi::Identify;
#[cfg(target_os = "uefi")]
use uefi::proto::loaded_image::LoadedImage;
#[cfg(target_os = "uefi")]
use uefi::proto::media::block::BlockIO;
#[cfg(target_os = "uefi")]
use uefi::boot::{SearchType, EventType, Tpl};
#[cfg(target_os = "uefi")]
use uefi::proto::pi::mp::MpServices;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr3Flags, Cr4, Cr4Flags};
use x86_64::structures::paging::{PhysFrame};
use x86_64::{PhysAddr, VirtAddr};

pub struct BootInfo {
    pub hhdm_offset: VirtAddr,
    pub memory_map: Option<uefi::mem::memory_map::MemoryMapOwned>,
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

#[cfg(not(target_os = "uefi"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    kernel_main(BootInfo {
        hhdm_offset: VirtAddr::new(0),
        memory_map: None,
    })
}

#[cfg(target_os = "uefi")]
#[uefi::entry]
fn efi_main() -> uefi::Status {
    let handle = uefi::boot::image_handle();

    println!("NT KERNEL: Booted via direct UEFI path!");

    // Disable Write Protect to allow re-mapping page tables if UEFI locked them
    unsafe {
        Cr0::update(|cr0| {
            cr0.remove(Cr0Flags::WRITE_PROTECT);
        });
    }

    // Allocate a small early heap from UEFI
    let early_heap_size = 16 * 1024 * 1024; // 16 MiB
    let heap_pages = (early_heap_size + 4095) / 4096;
    let heap_ptr = uefi::boot::allocate_pages(
            uefi::boot::AllocateType::AnyPages,
            uefi::boot::MemoryType::LOADER_DATA,
            heap_pages,
        )
        .expect("Failed to allocate heap pages from UEFI");

    unsafe {
        allocator::ALLOCATOR
            .lock()
            .init(heap_ptr.as_ptr(), early_heap_size);
    }
    allocator::set_heap_base(heap_ptr.as_ptr() as u64);

    println!(
        "NT KERNEL: Early heap initialized via UEFI at {:p} ({} bytes)",
        heap_ptr.as_ptr(), early_heap_size
    );

    // Create a new L4 page table to avoid modifying UEFI's potentially read-only L4
    let new_l4_ptr = uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::LOADER_DATA,
        1
    ).expect("Failed to allocate new L4");
    let new_l4_addr = new_l4_ptr.as_ptr() as u64;
    
    unsafe {
        // Zero it out
        core::ptr::write_bytes(new_l4_addr as *mut u8, 0, 4096);
        
        // Copy current L4 entries to maintain identity mapping and UEFI environment
        let (current_l4_frame, _) = Cr3::read();
        let current_l4_ptr = current_l4_frame.start_address().as_u64() as *const u8;
        core::ptr::copy_nonoverlapping(current_l4_ptr, new_l4_addr as *mut u8, 4096);
        
        // Switch to the new, writable L4
        Cr3::write(
            PhysFrame::containing_address(PhysAddr::new(new_l4_addr)),
            Cr3Flags::empty()
        );
    }

    // Attempt to start APs via UEFI Multi-Processor Services
    if let Ok(mp_handle) = uefi::boot::get_handle_for_protocol::<MpServices>() {
        if let Ok(mp) = uefi::boot::open_protocol_exclusive::<MpServices>(mp_handle) {
            if let Ok(count) = mp.get_number_of_processors() {
                smp::set_discovered_cpus(count.total);
                if let Ok(pi) = mp.get_processor_info(0) {
                    smp::set_bsp_lapic_id(pi.location.thread); // In QEMU thread is often lapic_id
                }
                
                if count.total > 1 {
                    println!("NT KERNEL: starting {} APs via UEFI...", count.total - 1);
                    
                    // Create an event for non-blocking AP startup to avoid hang
                    let event = unsafe {
                        uefi::boot::create_event(
                            EventType::empty(),
                            Tpl::CALLBACK,
                            None,
                            None // notify_context
                        ).ok()
                    };

                    let _ = mp.startup_all_aps(
                        false, // all APs
                        smp::uefi_ap_entry,
                        core::ptr::null_mut(),
                        event,
                        None
                    );
                }
            }
        }
    }

    // Get memory map before we potentially lose access to boot services
    let memory_map = uefi::boot::memory_map(uefi::boot::MemoryType::LOADER_DATA)
        .expect("Failed to get UEFI memory map");

    allocator::init_uefi_runtime();
    apic::set_hhdm_offset(x86_64::VirtAddr::new(0));
    println!("NT KERNEL: runtime allocator initialized from UEFI boot services");

    install_uefi_root_device(handle);

    // Transition to the kernel
    println!("Transitioning to kernel..."); 

    kernel_main(BootInfo {
        hhdm_offset: VirtAddr::new(0), // UEFI identity maps by default
        memory_map: Some(memory_map),
    })
}

#[cfg(target_os = "uefi")]
fn install_uefi_root_device(
    image_handle: uefi::Handle,
) {
    const CRABFS_SUPERBLOCK_MAGIC: [u8; 4] = *b"XFSB";

    let Ok(loaded_image) = uefi::boot::open_protocol_exclusive::<LoadedImage>(image_handle)
    else {
        println!("NT KERNEL: failed to open LoadedImage protocol");
        return;
    };
    let boot_device = loaded_image.device();
    drop(loaded_image);

    let Ok(handles) = uefi::boot::locate_handle_buffer(SearchType::ByProtocol(&BlockIO::GUID))
    else {
        println!("NT KERNEL: no UEFI BlockIO handles found");
        return;
    };

    let mut best: Option<(*mut BlockIO, u32, usize, usize, u64)> = None;
    for (i, handle) in handles.iter().copied().enumerate() {
        let is_boot = Some(handle) == boot_device;
        let Ok(block_io) = uefi::boot::open_protocol_exclusive::<BlockIO>(handle)
        else {
            continue;
        };
        let media = block_io.media();
        if !media.is_media_present() || media.is_logical_partition() {
            continue;
        }

        let block_size = media.block_size() as usize;
        let io_align = media.io_align() as usize;
        let media_id = media.media_id();
        let last_block = media.last_block();
        let mut sector0 = vec![0u8; block_size.max(4)];
        if block_io.read_blocks(media_id, 0, &mut sector0).is_err() {
            continue;
        }
        println!(
            "NT KERNEL: probing disk #{} (media_id={} blocks={} is_boot={}) magic={:02x}{:02x}{:02x}{:02x}",
            i, media_id, last_block + 1, is_boot, sector0[0], sector0[1], sector0[2], sector0[3]
        );
        if sector0[..4] != CRABFS_SUPERBLOCK_MAGIC {
            continue;
        }
        let ptr = (&*block_io as *const BlockIO).cast_mut();
        core::mem::forget(block_io);
        let replace = best.is_none_or(|(_, _, _, _, best_last_block)| last_block > best_last_block);
        if replace {
            best = Some((ptr, media_id, block_size, io_align, last_block));
        }
    }

    if let Some((ptr, media_id, block_size, io_align, last_block)) = best {
        vfs::install_uefi_root_device(ptr, media_id, block_size, io_align);
        println!(
            "NT KERNEL: registered UEFI root block device block_size={} io_align={} last_lba={}",
            block_size, io_align, last_block
        );
    } else {
        println!("NT KERNEL: no non-boot UEFI BlockIO root device found");
    }
}

fn prepare_init_task(task_id: usize) -> Option<process::Task> {
    let requested = cmdline::resolved_init_path();
    match user::create_init_task(task_id, &requested) {
        Ok(task) => {
            println!("NT KERNEL: native init {} task prepared", requested);
            return Some(task);
        }
        Err(init_err) => {
            println!(
                "NT KERNEL: native init {} prepare failed: {:#x}",
                requested, init_err
            );
        }
    }
    None
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(boot_info: BootInfo) -> ! {
    unsafe {
        asm!("cli");
    }
    println!("NT KERNEL: Initializing (CPU INTERRUPTS DISABLED)...");

    let mut reclaim_demo_base = None;
    let physical_memory_offset = boot_info.hhdm_offset;
    apic::set_hhdm_offset(physical_memory_offset);
    
    let mut mapper = unsafe { paging::init(physical_memory_offset) };
    if let Some(mmap) = boot_info.memory_map {
        let mut frame_allocator = allocator::BootInfoFrameAllocator::init_from_uefi(&mmap);
        allocator::init_heap(&mut mapper, &mut frame_allocator)
            .expect("Heap initialization failed");
        allocator::init_runtime(physical_memory_offset, frame_allocator);
        reclaim_demo_base =
            Some(reclaim::allocate_region(3).expect("failed to allocate reclaim demo region"));
    } else {
        println!("NT KERNEL: No memory map provided. Memory management might be limited.");
    }

    println!("NT KERNEL: Heap initialized.");
    let params = cmdline::params();
    log::init(params);
    if !params.raw.is_empty() {
        kinfo!("cmdline=\"{}\"", params.raw);
    }
    kdebug!(
        "logging configured debug={} quiet={} loglevel={:?}",
        params.debug,
        params.quiet,
        params.loglevel
    );

    gdt::init();
    idt::init();
    init_local_cpu_features();
    apic::init();
    println!("NT KERNEL: GDT/IDT/APIC initialized.");

    let topology = smp::init();
    process::configure_topology(topology.online_cpus);
    println!(
        "NT KERNEL: SMP topology online_cpus={}, discovered_cpus={}, bsp_lapic_id={}",
        topology.online_cpus, topology.discovered_cpus, topology.bootstrap_lapic_id
    );

    syscall::init();
    println!("NT KERNEL: Syscalls initialized.");

    // Run zram/reclaim demo logic before vfs/task initialization
    // because prepare_init_task will switch Cr3 to the new user process,
    // which lacks the lower-half RECLAIM_START mappings.
    if let Some(reclaim_base) = reclaim_demo_base {
        unsafe {
            for offset in 0..zram::PAGE_SIZE {
                reclaim_base
                    .as_mut_ptr::<u8>()
                    .add(offset)
                    .write((offset % 251) as u8);
                reclaim_base
                    .as_mut_ptr::<u8>()
                    .add(zram::PAGE_SIZE + offset)
                    .write(((offset * 3) % 251) as u8);
                reclaim_base
                    .as_mut_ptr::<u8>()
                    .add(2 * zram::PAGE_SIZE + offset)
                    .write(0x5a);
            }
        }

        reclaim::reclaim_page(reclaim_base + zram::PAGE_SIZE as u64)
            .expect("failed to reclaim page 1");
        reclaim::reclaim_page(reclaim_base + (2 * zram::PAGE_SIZE) as u64)
            .expect("failed to reclaim page 2");

        let restored_byte_1 = unsafe {
            reclaim_base
                .as_ptr::<u8>()
                .add(zram::PAGE_SIZE + 123)
                .read_volatile()
        };
        let restored_byte_2 = unsafe {
            reclaim_base
                .as_ptr::<u8>()
                .add(2 * zram::PAGE_SIZE + 17)
                .read_volatile()
        };
        assert_eq!(restored_byte_1, ((123 * 3) % 251) as u8);
        assert_eq!(restored_byte_2, 0x5a);

        let reclaim_stats = reclaim::stats();
        println!(
            "NT KERNEL: reclaim allocated_pages={}, resident_pages={}, compressed_pages={}, reclaims={}, restored_faults={}",
            reclaim_stats.allocated_pages,
            reclaim_stats.resident_pages,
            reclaim_stats.compressed_pages,
            reclaim_stats.reclaims,
            reclaim_stats.restored_faults
        );
    }

    if true {
        let mut zram_device = zram::ZramDevice::new(64);
        let mut zswap_cache = zram::ZswapCache::new(64);

        let mut raw_page = [0u8; zram::PAGE_SIZE];
        let mut seed = 0x1234_5678u32;
        for byte in raw_page.iter_mut() {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (seed >> 24) as u8;
        }

        let mut compressible_page = [0u8; zram::PAGE_SIZE];
        for (index, byte) in compressible_page.iter_mut().enumerate() {
            *byte = if index % 2 == 0 { b'A' } else { b'B' };
        }

        zram_device
            .store_page(0, &raw_page)
            .expect("zram store failed");
        zram_device
            .store_page(1, &compressible_page)
            .expect("zram store failed");
        let raw_roundtrip = zram_device.load_page(0).expect("zram load failed");
        let compressed_roundtrip = zram_device.load_page(1).expect("zram load failed");
        assert_eq!(raw_page.as_slice(), raw_roundtrip.as_slice());
        assert_eq!(
            compressible_page.as_slice(),
            compressed_roundtrip.as_slice()
        );

        zswap_cache
            .store(7, &compressible_page)
            .expect("zswap store failed");
        let zswap_roundtrip = zswap_cache.load(7).expect("zswap load failed");
        assert_eq!(compressible_page.as_slice(), zswap_roundtrip.as_slice());
        zswap_cache.invalidate(7).expect("zswap invalidate failed");

        let zram_stats = zram_device.stats();
        let zswap_stats = zswap_cache.stats();
        println!(
            "NT KERNEL: zram stores={}, loads={}, raw_pages={}, compressed_pages={}, logical_bytes={}, stored_bytes={}, zspages={}",
            zram_stats.stores,
            zram_stats.loads,
            zram_stats.raw_pages,
            zram_stats.compressed_pages,
            zram_stats.logical_bytes,
            zram_stats.stored_bytes,
            zram_stats.allocator.zspages
        );
        println!(
            "NT KERNEL: zswap hits={}, misses={}, backend_invalidations={}",
            zswap_stats.hits, zswap_stats.misses, zswap_stats.backend.invalidations
        );
    }

    let mut init_task = None;
    match vfs::mount_uefi_root() {
        Ok(()) => {
            println!("NT KERNEL: mounted root via UEFI BlockIO");
            init_task = prepare_init_task(3);
        }
        Err(mount_err) => {
            println!("NT KERNEL: UEFI root mount failed: {:?}", mount_err);
        }
    }

    if let Some(task) = init_task {
        process::SCHEDULER.lock().add_task(task);
        println!("NT KERNEL: added PID1 userspace task");
    } else {
        let task1 = process::Task::with_params(
            1,
            0,
            test_task_1,
            process::SchedParams {
                class_hint: Some(process::TaskClass::Game),
                nice: -5,
                preferred_cpu: Some(process::CpuId(0)),
                process_id: 0,
            },
        );
        let task2 = process::Task::new(2, 0, test_task_2);

        process::SCHEDULER.lock().add_task(task1);
        process::SCHEDULER.lock().add_task(task2);
        println!("NT KERNEL: using fallback kernel demo tasks");
    }

    println!("NT KERNEL: Starting scheduler...");
    crate::process::start();
}

pub fn init_local_cpu_features() {
    unsafe {
        Cr0::update(|cr0| {
            cr0.remove(Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::TASK_SWITCHED);
            cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
        });
        Cr4::update(|cr4| {
            cr4.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);
        });
    }
}

pub extern "C" fn test_task_1() -> ! {
    loop {
        println!("TASK 1: Working...");
        for _ in 0..1000000 {
            unsafe {
                asm!("nop");
            }
        }
    }
}

pub extern "C" fn test_task_2() -> ! {
    loop {
        println!("TASK 2: Working...");
        for _ in 0..1000000 {
            unsafe {
                asm!("nop");
            }
        }
    }
}
