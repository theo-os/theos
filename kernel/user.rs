extern crate alloc;

use crate::nt::{
    self, AccessMask, ClientId, FilePositionInformation, FileStandardInformation, Handle,
    IoStatusBlock, LdrDataTableEntry, ListEntry, NtStatus, ObjectAttributes, Peb, PebLdrData,
    ProcessBasicInformation,
    RtlUserProcessParameters, Teb, UnicodeString, STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL,
    STATUS_CONFLICTING_ADDRESSES, STATUS_END_OF_FILE, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_HANDLE, STATUS_INVALID_IMAGE_FORMAT, STATUS_INVALID_PARAMETER,
    STATUS_NOT_IMPLEMENTED, STATUS_NOT_SUPPORTED, STATUS_NO_MEMORY, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_PENDING, STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_UNSUCCESSFUL,
};
use crate::vfs;
use crate::{allocator, gdt, kdebug, println, process, smp::MAX_CPUS};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use goblin::pe::PE;
use spin::{Lazy, Mutex};
use x86_64::registers::control::Cr3;
use x86_64::registers::model_specific::{FsBase, GsBase};
use x86_64::structures::paging::{Page, PageSize, PageTable, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::VirtAddr;

const PAGE_SIZE: u64 = Size4KiB::SIZE;
const LOW_KERNEL_IDENTITY_LIMIT: u64 = 0x1_0000_0000;
const NT_EPOCH_OFFSET_100NS: i64 = 116_444_736_000_000_000;
const SCHED_TICK_100NS: i64 = 100_000;
const USER_STACK_TOP: u64 = 0x0000_7fff_ff00_0000;
const USER_STACK_PAGES: u64 = 64;
const USER_ENV_BASE: u64 = 0x0000_7fff_f000_0000;
const USER_ENV_PAGES: u64 = 16;
const USER_BOOTSTRAP_BASE: u64 = USER_ENV_BASE + USER_ENV_PAGES * PAGE_SIZE;
const USER_ALLOC_BASE: u64 = 0x0000_1000_0000_0000;
const KERNEL_VIRTIO_DMA_BASE: u64 = 0x0000_6666_0000_0000;

#[derive(Debug, Clone, Copy)]
struct HandleEntry {
    object_id: u32,
    access: AccessMask,
}

#[derive(Debug, Clone)]
enum ExportTarget {
    Address(u64),
    ForwardName { dll_path: String, symbol: String },
    ForwardOrdinal { dll_path: String, ordinal: usize },
}

#[derive(Debug, Clone)]
enum TemplateExportTarget {
    Rva(u32),
    ForwardName { dll_path: String, symbol: String },
    ForwardOrdinal { dll_path: String, ordinal: usize },
}

#[derive(Debug, Clone)]
struct TemplateSection {
    virtual_address: u32,
    virtual_size: u32,
    characteristics: u32,
    data: Arc<[u8]>,
}

#[derive(Debug, Clone, Copy)]
struct TemplateRelocation {
    rva: u32,
    kind: u8,
}

#[derive(Debug, Clone)]
struct TemplateImport {
    dll_path: String,
    name: Option<String>,
    ordinal: usize,
    offset: u32,
    size: usize,
}

#[derive(Debug, Clone)]
struct ModuleTemplate {
    preferred_base: u64,
    size_of_image: u64,
    size_of_headers: usize,
    entry_rva: u32,
    dll_name: String,
    has_relocations: bool,
    headers: Arc<[u8]>,
    sections: Arc<[TemplateSection]>,
    relocations: Arc<[TemplateRelocation]>,
    imports: Arc<[TemplateImport]>,
    exports_by_name: Arc<[(String, TemplateExportTarget)]>,
    exports_by_ordinal: Arc<[(usize, TemplateExportTarget)]>,
}


#[derive(Debug, Clone)]
struct LoadedModule {
    nt_path: String,
    dll_name: String,
    image_base: u64,
    entry: u64,
    size_of_image: u64,
    exports_by_name: Arc<[(String, ExportTarget)]>,
    exports_by_ordinal: Arc<[(usize, ExportTarget)]>,
}

#[derive(Debug, Clone)]
pub struct UserProcess {
    pid: u32,
    ppid: u32,
    address_space_id: u32,
    task_id: Option<usize>,
    image_path: Option<String>,
    peb_addr: u64,
    teb_addr: u64,
    params_addr: u64,
    fs_base: u64,
    gs_base: u64,
    image_base: u64,
    handles: Vec<Option<HandleEntry>>,
    standard_input: Handle,
    standard_output: Handle,
    standard_error: Handle,
    process_object: u32,
    thread_object: u32,
    modules: Vec<LoadedModule>,
    exited: bool,
    exit_status: NtStatus,
}

impl Default for UserProcess {
    fn default() -> Self {
        Self {
            pid: 1,
            ppid: 0,
            address_space_id: 1,
            task_id: None,
            image_path: None,
            peb_addr: 0,
            teb_addr: 0,
            params_addr: 0,
            fs_base: 0,
            gs_base: 0,
            image_base: 0,
            handles: Vec::new(),
            standard_input: 0,
            standard_output: 0,
            standard_error: 0,
            process_object: 0,
            thread_object: 0,
            modules: Vec::new(),
            exited: false,
            exit_status: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UserMapping {
    pub start: u64,
    pub len: u64,
    pub prot: u32,
    pub frame: PhysFrame<Size4KiB>,
}

#[derive(Debug, Clone)]
struct AddressSpace {
    root_frame: PhysFrame<Size4KiB>,
    next_alloc_base: u64,
    mappings: BTreeMap<u64, UserMapping>,
}

impl Default for AddressSpace {
    fn default() -> Self {
        Self {
            root_frame: PhysFrame::containing_address(x86_64::PhysAddr::new(0)),
            next_alloc_base: USER_ALLOC_BASE,
            mappings: BTreeMap::new(),
        }
    }
}

#[derive(Default)]
struct UserRegistry {
    next_pid: u32,
    next_address_space_id: u32,
    active_pids: [u32; MAX_CPUS],
    by_pid: BTreeMap<u32, UserProcess>,
    spaces: BTreeMap<u32, AddressSpace>,
    task_to_pid: BTreeMap<usize, u32>,
}

#[derive(Debug, Clone)]
struct LoadedImage {
    entry: u64,
    image_base: u64,
    size_of_image: u64,
    exports_by_name: Arc<[(String, ExportTarget)]>,
    exports_by_ordinal: Arc<[(usize, ExportTarget)]>,
    dll_name: String,
}

static CURRENTS: Lazy<[Mutex<UserProcess>; MAX_CPUS]> =
    Lazy::new(|| core::array::from_fn(|_| Mutex::new(UserProcess::default())));

static REGISTRY: Lazy<Mutex<UserRegistry>> = Lazy::new(|| {
    Mutex::new(UserRegistry {
        next_pid: 2,
        next_address_space_id: 2,
        ..UserRegistry::default()
    })
});

static WAITERS: Lazy<Mutex<BTreeMap<u32, Vec<usize>>>> = Lazy::new(|| Mutex::new(BTreeMap::new()));
static MODULE_TEMPLATES: Lazy<Mutex<BTreeMap<String, Arc<ModuleTemplate>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

fn current_cpu() -> usize {
    crate::smp::current_cpu().min(MAX_CPUS.saturating_sub(1))
}

fn current_slot() -> &'static Mutex<UserProcess> {
    &CURRENTS[current_cpu()]
}

fn active_pid() -> Option<u32> {
    match REGISTRY.lock().active_pids[current_cpu()] {
        0 => None,
        pid => Some(pid),
    }
}

fn current_pid_internal() -> u32 {
    active_pid().unwrap_or_else(|| current_slot().lock().pid)
}

fn allocate_pid(registry: &mut UserRegistry) -> u32 {
    let pid = registry.next_pid.max(1);
    registry.next_pid = pid.saturating_add(1);
    pid
}

fn allocate_address_space_id(registry: &mut UserRegistry) -> u32 {
    let asid = registry.next_address_space_id.max(1);
    registry.next_address_space_id = asid.saturating_add(1);
    asid
}

fn current_address_space_id() -> u32 {
    current_slot().lock().address_space_id
}

fn current_root_frame() -> Result<PhysFrame<Size4KiB>, NtStatus> {
    let asid = current_address_space_id();
    let registry = REGISTRY.lock();
    registry
        .spaces
        .get(&asid)
        .map(|space| space.root_frame)
        .ok_or(STATUS_UNSUCCESSFUL)
}

fn with_current_address_space<T>(f: impl FnOnce(&mut AddressSpace) -> T) -> T {
    let asid = current_address_space_id();
    let mut registry = REGISTRY.lock();
    let space = registry.spaces.entry(asid).or_default();
    f(space)
}

fn with_current_process<T>(f: impl FnOnce(&mut UserProcess) -> T) -> T {
    f(&mut current_slot().lock())
}

fn region_is_free(start: u64, len: u64) -> bool {
    let start = align_down(start, PAGE_SIZE);
    let end = align_up(start.saturating_add(len), PAGE_SIZE);
    let mappings =
        with_current_address_space(|space| space.mappings.keys().copied().collect::<Vec<u64>>());
    !mappings.into_iter().any(|virt| virt >= start && virt < end)
}

fn mapped_region_len(start: u64) -> Option<u64> {
    with_current_address_space(|space| {
        if !space.mappings.contains_key(&start) {
            return None;
        }
        let mut len = 0u64;
        let mut cursor = start;
        while space.mappings.contains_key(&cursor) {
            len = len.saturating_add(PAGE_SIZE);
            cursor = cursor.saturating_add(PAGE_SIZE);
        }
        Some(len)
    })
}

fn pml4_index(addr: u64) -> usize {
    ((addr >> 39) & 0x1ff) as usize
}

fn pdpt_index(addr: u64) -> usize {
    ((addr >> 30) & 0x1ff) as usize
}

fn clone_low_identity_pml4_slot(
    offset: VirtAddr,
    current_table: &PageTable,
    new_table: &mut PageTable,
    slot_idx: usize,
) -> Result<(), NtStatus> {
    let current_entry = current_table[slot_idx].clone();
    if current_entry.is_unused() {
        return Ok(());
    }

    let new_pdpt_frame = allocator::allocate_frame().map_err(|_| STATUS_NO_MEMORY)?;
    allocator::zero_frame(new_pdpt_frame).map_err(|_| STATUS_NO_MEMORY)?;

    let new_pdpt_ptr =
        (offset.as_u64() + new_pdpt_frame.start_address().as_u64()) as *mut PageTable;
    let current_pdpt_ptr =
        (offset.as_u64() + current_entry.addr().as_u64()) as *const PageTable;
    unsafe {
        let new_pdpt = &mut *new_pdpt_ptr;
        let current_pdpt = &*current_pdpt_ptr;
        let last_idx = pdpt_index(LOW_KERNEL_IDENTITY_LIMIT.saturating_sub(1));
        for idx in 0..=last_idx {
            new_pdpt[idx] = current_pdpt[idx].clone();
        }
        new_table[slot_idx].set_addr(new_pdpt_frame.start_address(), current_entry.flags());
    }
    Ok(())
}

fn map_region_exact(start: u64, len: u64, prot: u32) -> Result<(), NtStatus> {
    let start = align_down(start, PAGE_SIZE);
    let len = align_up(len, PAGE_SIZE);
    if !region_is_free(start, len) {
        return Err(STATUS_CONFLICTING_ADDRESSES);
    }
    map_region(start, len, prot)
}

fn address_space_mappings(asid: u32) -> Vec<UserMapping> {
    let registry = REGISTRY.lock();
    registry
        .spaces
        .get(&asid)
        .map(|space| space.mappings.values().copied().collect())
        .unwrap_or_default()
}

fn with_address_space<T>(asid: u32, f: impl FnOnce(&mut AddressSpace) -> T) -> T {
    let mut registry = REGISTRY.lock();
    let space = registry.spaces.entry(asid).or_default();
    f(space)
}

fn create_address_space() -> Result<AddressSpace, NtStatus> {
    let root_frame = allocator::allocate_frame().map_err(|_| STATUS_NO_MEMORY)?;
    allocator::zero_frame(root_frame).map_err(|_| STATUS_NO_MEMORY)?;

    let offset = allocator::physical_memory_offset().map_err(|_| STATUS_NO_MEMORY)?;
    let new_ptr = (offset.as_u64() + root_frame.start_address().as_u64()) as *mut PageTable;
    let (current_root, _) = Cr3::read();
    let current_ptr = (offset.as_u64() + current_root.start_address().as_u64()) as *const PageTable;
    unsafe {
        let new_table = &mut *new_ptr;
        let current_table = &*current_ptr;
        let mut current_rsp = 0usize;
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, preserves_flags, nostack));

        for idx in 256..512 {
            new_table[idx] = current_table[idx].clone();
        }

        let mut copied_slot0 = false;
        for virt in [
            allocator::heap_base(),
            KERNEL_VIRTIO_DMA_BASE,
            current_rsp as u64,
            create_address_space as *const () as usize as u64,
        ] {
            let idx = ((virt >> 39) & 0x1ff) as usize;
            if idx == 0 {
                if !copied_slot0 {
                    clone_low_identity_pml4_slot(offset, current_table, new_table, idx)?;
                    copied_slot0 = true;
                }
            } else {
                new_table[idx] = current_table[idx].clone();
            }
        }
    }

    Ok(AddressSpace {
        root_frame,
        next_alloc_base: USER_ALLOC_BASE,
        mappings: BTreeMap::new(),
    })
}

fn switch_address_space(asid: u32) -> Result<(), NtStatus> {
    let root_frame = {
        let registry = REGISTRY.lock();
        registry
            .spaces
            .get(&asid)
            .map(|space| space.root_frame)
            .ok_or(STATUS_UNSUCCESSFUL)?
    };
    let (_, flags) = Cr3::read();
    unsafe { Cr3::write(root_frame, flags) };
    Ok(())
}

fn destroy_address_space_contents(asid: u32) -> Result<(), NtStatus> {
    let mappings = address_space_mappings(asid);
    let root_frame = {
        let registry = REGISTRY.lock();
        registry
            .spaces
            .get(&asid)
            .map(|space| space.root_frame)
            .ok_or(STATUS_UNSUCCESSFUL)?
    };
    for mapping in mappings {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mapping.start));
        if let Ok(frame) = allocator::unmap_page_in(root_frame, page) {
            let _ = allocator::deallocate_frame(frame);
        }
    }
    with_address_space(asid, |space| {
        space.mappings.clear();
        space.next_alloc_base = USER_ALLOC_BASE;
    });
    Ok(())
}

fn destroy_address_space(asid: u32) -> Result<(), NtStatus> {
    destroy_address_space_contents(asid)?;
    let root_frame = {
        let mut registry = REGISTRY.lock();
        registry
            .spaces
            .remove(&asid)
            .map(|space| space.root_frame)
            .ok_or(STATUS_UNSUCCESSFUL)?
    };
    let _ = allocator::deallocate_frame(root_frame);
    Ok(())
}

fn switch_active_process(pid: Option<u32>) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let cpu = current_cpu();
        let (next_asid, next_fs_base, next_gs_base) = {
            let mut registry = REGISTRY.lock();
            let old_pid = match registry.active_pids[cpu] {
                0 => None,
                old => Some(old),
            };
            if old_pid == pid {
                return;
            }

            let mut slot = current_slot().lock();
            if let Some(old_pid) = old_pid {
                let old_proc = core::mem::take(&mut *slot);
                registry.by_pid.insert(old_pid, old_proc);
            }

            let (next_asid, next_fs_base, next_gs_base) = if let Some(next_pid) = pid {
                let Some(next_proc) = registry.by_pid.remove(&next_pid) else {
                    registry.active_pids[cpu] = 0;
                    *slot = UserProcess::default();
                    return;
                };
                let asid = next_proc.address_space_id;
                let fs_base = next_proc.fs_base;
                let gs_base = next_proc.gs_base;
                *slot = next_proc;
                (asid, fs_base, gs_base)
            } else {
                *slot = UserProcess::default();
                (0, 0, 0)
            };
            registry.active_pids[cpu] = pid.unwrap_or(0);
            (next_asid, next_fs_base, next_gs_base)
        };

        if pid.is_some() {
            let _ = switch_address_space(next_asid);
            FsBase::write(VirtAddr::new(next_fs_base));
            GsBase::write(VirtAddr::new(next_gs_base));
        } else {
            FsBase::write(VirtAddr::new(0));
            GsBase::write(VirtAddr::new(0));
        }
    });
}

pub fn activate_task(task_id: usize) {
    let pid = REGISTRY.lock().task_to_pid.get(&task_id).copied();
    switch_active_process(pid);
}

pub fn pid() -> u32 {
    current_pid_internal()
}

pub fn current_init_path() -> Option<String> {
    current_slot().lock().image_path.clone()
}

pub fn describe_user_rip(addr: u64) -> Option<(String, u64, u64)> {
    let current = current_slot().lock();
    current
        .modules
        .iter()
        .find(|module| addr >= module.image_base && addr < module.image_base + module.size_of_image)
        .map(|module| {
            (
                module.nt_path.clone(),
                module.image_base,
                addr.saturating_sub(module.image_base),
            )
        })
}

pub fn read_user_rip_bytes(addr: u64, len: usize) -> Option<Vec<u8>> {
    if len == 0 || len > 32 {
        return None;
    }
    let mut out = Vec::with_capacity(len);
    for offset in 0..len {
        let ptr = (addr + offset as u64) as *const u8;
        let byte = unsafe { core::ptr::read_volatile(ptr) };
        out.push(byte);
    }
    Some(out)
}

fn slot_to_handle(slot: usize) -> Handle {
    (slot + 1) * 4
}

fn handle_to_slot(handle: Handle) -> Result<usize, NtStatus> {
    if handle == 0 || (handle & 0x3) != 0 {
        return Err(STATUS_INVALID_HANDLE);
    }
    Ok((handle / 4).saturating_sub(1))
}

fn install_handle(object_id: u32, access: AccessMask) -> Result<Handle, NtStatus> {
    nt::retain(object_id)?;
    let mut current = current_slot().lock();
    if let Some((idx, slot)) = current
        .handles
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| slot.is_none())
    {
        *slot = Some(HandleEntry { object_id, access });
        return Ok(slot_to_handle(idx));
    }
    current
        .handles
        .push(Some(HandleEntry { object_id, access }));
    Ok(slot_to_handle(current.handles.len() - 1))
}

fn resolve_handle_entry(handle: Handle) -> Result<HandleEntry, NtStatus> {
    if handle == usize::MAX {
        let current = current_slot().lock();
        return Ok(HandleEntry {
            object_id: current.process_object,
            access: nt::PROCESS_ALL_ACCESS,
        });
    }
    if handle == usize::MAX - 4 {
        let current = current_slot().lock();
        return Ok(HandleEntry {
            object_id: current.thread_object,
            access: nt::THREAD_ALL_ACCESS,
        });
    }
    let slot = handle_to_slot(handle)?;
    current_slot()
        .lock()
        .handles
        .get(slot)
        .and_then(|entry| *entry)
        .ok_or(STATUS_INVALID_HANDLE)
}

pub fn close_handle(handle: Handle) -> NtStatus {
    if handle == usize::MAX || handle == usize::MAX - 4 {
        return STATUS_ACCESS_DENIED;
    }
    let slot = match handle_to_slot(handle) {
        Ok(slot) => slot,
        Err(status) => return status,
    };
    let object_id = {
        let mut current = current_slot().lock();
        let Some(entry) = current.handles.get_mut(slot).and_then(Option::take) else {
            return STATUS_INVALID_HANDLE;
        };
        entry.object_id
    };
    match nt::release(object_id) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

fn seed_standard_handles(current: &mut UserProcess) -> Result<(), NtStatus> {
    for (path, access, out) in [
        ("/dev/stdin", nt::FILE_GENERIC_READ, 0usize),
        ("/dev/stdout", nt::FILE_GENERIC_WRITE, 1usize),
        ("/dev/stderr", nt::FILE_GENERIC_WRITE, 2usize),
    ] {
        let vfs_handle = vfs::open(path, 0).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
        let object_id = nt::create_file(path.to_string(), vfs_handle);
        nt::retain(object_id)?;
        current
            .handles
            .push(Some(HandleEntry { object_id, access }));
        let handle = slot_to_handle(current.handles.len() - 1);
        match out {
            0 => current.standard_input = handle,
            1 => current.standard_output = handle,
            _ => current.standard_error = handle,
        }
    }
    Ok(())
}

fn current_process_basic() -> ProcessBasicInformation {
    let current = current_slot().lock();
    ProcessBasicInformation {
        peb_base_address: current.peb_addr as usize,
        unique_process_id: current.pid as usize,
        inherited_from_unique_process_id: current.ppid as usize,
        ..ProcessBasicInformation::default()
    }
}

fn map_region(start: u64, len: u64, prot: u32) -> Result<(), NtStatus> {
    let page_count = len.div_ceil(PAGE_SIZE);
    let flags = page_flags(prot);
    let root_frame = current_root_frame()?;
    for idx in 0..page_count {
        let virt = start + idx * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        let frame = allocator::allocate_frame().map_err(|_| STATUS_NO_MEMORY)?;
        allocator::zero_frame(frame).map_err(|_| STATUS_NO_MEMORY)?;
        let frame = match allocator::map_existing_page_in(root_frame, page, frame, flags) {
            Ok(()) => frame,
            Err(allocator::VmError::PageAlreadyMapped) => {
                allocator::deallocate_frame(frame).map_err(|_| STATUS_NO_MEMORY)?;
                allocator::update_page_flags_in(root_frame, page, flags)
                    .map_err(|_| STATUS_NO_MEMORY)?;
                let asid = current_address_space_id();
                let registry = REGISTRY.lock();
                let mapping = registry
                    .spaces
                    .get(&asid)
                    .and_then(|space| space.mappings.get(&virt))
                    .copied()
                    .ok_or(STATUS_UNSUCCESSFUL)?;
                mapping.frame
            }
            Err(_) => return Err(STATUS_NO_MEMORY),
        };
        with_current_address_space(|space| {
            space.mappings.insert(
                virt,
                UserMapping {
                    start: virt,
                    len: PAGE_SIZE,
                    prot,
                    frame,
                },
            );
        });
    }
    Ok(())
}

fn page_flags(prot: u32) -> PageTableFlags {
    let mut flags =
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE;
    let executable = matches!(
        prot,
        nt::PAGE_EXECUTE | nt::PAGE_EXECUTE_READ | nt::PAGE_EXECUTE_READWRITE
    );
    let writable = matches!(prot, nt::PAGE_READWRITE | nt::PAGE_EXECUTE_READWRITE);
    if !writable {
        flags.remove(PageTableFlags::WRITABLE);
    }
    if !executable {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    flags
}

fn allocate_user_region(len: u64, prot: u32) -> Result<u64, NtStatus> {
    let len = align_up(len, PAGE_SIZE);
    let base = with_current_address_space(|space| {
        let base = align_up(space.next_alloc_base, PAGE_SIZE);
        space.next_alloc_base = base.saturating_add(len).saturating_add(PAGE_SIZE);
        base
    });
    map_region(base, len, prot)?;
    Ok(base)
}

pub fn allocate_virtual_memory(
    process_handle: Handle,
    base_address: *mut usize,
    region_size: *mut usize,
    protect: u32,
) -> NtStatus {
    if process_handle != usize::MAX || base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let requested = unsafe { (*region_size) as u64 };
    if requested == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let base = if unsafe { *base_address } != 0 {
        align_down(unsafe { *base_address } as u64, PAGE_SIZE)
    } else {
        match allocate_user_region(requested, protect) {
            Ok(base) => base,
            Err(status) => return status,
        }
    };
    if unsafe { *base_address } != 0 {
        let len = align_up(requested, PAGE_SIZE);
        if let Err(status) = map_region(base, len, protect) {
            return status;
        }
    }
    unsafe {
        *base_address = base as usize;
        *region_size = align_up(requested, PAGE_SIZE) as usize;
    }
    STATUS_SUCCESS
}

pub fn free_virtual_memory(
    process_handle: Handle,
    base_address: *mut usize,
    region_size: *mut usize,
) -> NtStatus {
    if process_handle != usize::MAX || base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let start = align_down(unsafe { *base_address } as u64, PAGE_SIZE);
    let len = align_up(unsafe { *region_size } as u64, PAGE_SIZE);
    let root_frame = match current_root_frame() {
        Ok(frame) => frame,
        Err(status) => return status,
    };
    for idx in 0..(len / PAGE_SIZE) {
        let virt = start + idx * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        if let Ok(frame) = allocator::unmap_page_in(root_frame, page) {
            let _ = allocator::deallocate_frame(frame);
        }
        with_current_address_space(|space| {
            space.mappings.remove(&virt);
        });
    }
    STATUS_SUCCESS
}

pub fn protect_virtual_memory(
    process_handle: Handle,
    base_address: *mut usize,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NtStatus {
    if process_handle != usize::MAX || base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let start = align_down(unsafe { *base_address } as u64, PAGE_SIZE);
    let len = align_up(unsafe { *region_size } as u64, PAGE_SIZE);
    let root_frame = match current_root_frame() {
        Ok(frame) => frame,
        Err(status) => return status,
    };
    let mut prev = new_protect;
    for idx in 0..(len / PAGE_SIZE) {
        let virt = start + idx * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        let old = with_current_address_space(|space| {
            space.mappings.get(&virt).map(|mapping| mapping.prot)
        });
        if let Some(old) = old {
            prev = old;
        }
        if allocator::update_page_flags_in(root_frame, page, page_flags(new_protect)).is_err() {
            return STATUS_UNSUCCESSFUL;
        }
        with_current_address_space(|space| {
            if let Some(mapping) = space.mappings.get_mut(&virt) {
                mapping.prot = new_protect;
            }
        });
    }
    if !old_protect.is_null() {
        unsafe { *old_protect = prev };
    }
    STATUS_SUCCESS
}

fn read_utf16_string(us: *const UnicodeString) -> Result<String, NtStatus> {
    if us.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let us = unsafe { &*us };
    if us.buffer.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let len = usize::from(us.length) / 2;
    let slice = unsafe { core::slice::from_raw_parts(us.buffer, len) };
    let mut out = String::new();
    for ch in core::char::decode_utf16(slice.iter().copied()) {
        out.push(ch.map_err(|_| STATUS_INVALID_PARAMETER)?);
    }
    Ok(out)
}

fn path_from_object_attributes(attributes: *const ObjectAttributes) -> Result<String, NtStatus> {
    if attributes.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let attrs = unsafe { &*attributes };
    if attrs.object_name.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    read_utf16_string(attrs.object_name)
}

fn nt_path_from_vfs_path(path: &str) -> Option<String> {
    let lowered = path.to_ascii_lowercase();
    if lowered.starts_with("/windows/system32/") {
        let base = module_basename(path);
        return Some(nt::canonicalize_nt_path(&format!(
            "\\SystemRoot\\System32\\{}",
            base
        )));
    }
    None
}

pub fn create_file(
    out_handle: *mut Handle,
    _desired_access: AccessMask,
    object_attributes: *const ObjectAttributes,
    io_status: *mut IoStatusBlock,
) -> NtStatus {
    if out_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let nt_path = match path_from_object_attributes(object_attributes) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let vfs_path = match nt::resolve_nt_path(&nt_path) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let vfs_handle = match vfs::open(&vfs_path, 0) {
        Ok(handle) => handle,
        Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
    };
    let object_id = nt::create_file(vfs_path.clone(), vfs_handle);
    let handle = match install_handle(object_id, nt::FILE_GENERIC_READ | nt::FILE_GENERIC_WRITE) {
        Ok(handle) => handle,
        Err(status) => {
            let _ = nt::release(object_id);
            return status;
        }
    };
    let _ = nt::release(object_id);
    unsafe { *out_handle = handle };
    if !io_status.is_null() {
        unsafe {
            *io_status = IoStatusBlock {
                status: STATUS_SUCCESS,
                information: 1,
            };
        }
    }
    STATUS_SUCCESS
}

pub fn read_file(
    handle: Handle,
    io_status: *mut IoStatusBlock,
    buffer: *mut u8,
    length: usize,
) -> NtStatus {
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    let n = match nt::with_file(entry.object_id, |file| {
        let out = unsafe { core::slice::from_raw_parts_mut(buffer, length) };
        vfs::read(file.vfs_handle, out)
    }) {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => return STATUS_UNSUCCESSFUL,
        Err(status) => return status,
    };
    if !io_status.is_null() {
        unsafe {
            *io_status = IoStatusBlock {
                status: if n == 0 {
                    STATUS_END_OF_FILE
                } else {
                    STATUS_SUCCESS
                },
                information: n,
            };
        }
    }
    if n == 0 {
        STATUS_END_OF_FILE
    } else {
        STATUS_SUCCESS
    }
}

pub fn write_file(
    handle: Handle,
    io_status: *mut IoStatusBlock,
    buffer: *const u8,
    length: usize,
) -> NtStatus {
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    let n = match nt::with_file(entry.object_id, |file| {
        let data = unsafe { core::slice::from_raw_parts(buffer, length) };
        vfs::write(file.vfs_handle, data)
    }) {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => return STATUS_UNSUCCESSFUL,
        Err(status) => return status,
    };
    if !io_status.is_null() {
        unsafe {
            *io_status = IoStatusBlock {
                status: STATUS_SUCCESS,
                information: n,
            };
        }
    }
    STATUS_SUCCESS
}

pub fn query_information_file(
    handle: Handle,
    io_status: *mut IoStatusBlock,
    file_information: *mut u8,
    length: u32,
    info_class: u32,
) -> NtStatus {
    if file_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    let status = match info_class {
        nt::FILE_STANDARD_INFORMATION_CLASS => {
            if length < core::mem::size_of::<FileStandardInformation>() as u32 {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                let stat = match nt::with_file(entry.object_id, |file| vfs::fstat(file.vfs_handle))
                {
                    Ok(Ok(stat)) => stat,
                    Ok(Err(_)) => return STATUS_UNSUCCESSFUL,
                    Err(status) => return status,
                };
                unsafe {
                    *(file_information as *mut FileStandardInformation) = FileStandardInformation {
                        allocation_size: stat.size as i64,
                        end_of_file: stat.size as i64,
                        number_of_links: 1,
                        delete_pending: 0,
                        directory: if (stat.mode & 0o040000) != 0 { 1 } else { 0 },
                        reserved: [0; 2],
                    };
                }
                STATUS_SUCCESS
            }
        }
        nt::FILE_POSITION_INFORMATION_CLASS => {
            if length < core::mem::size_of::<FilePositionInformation>() as u32 {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                let offset = match nt::with_file(entry.object_id, |file| {
                    vfs::lseek(file.vfs_handle, 0, 1)
                }) {
                    Ok(Ok(offset)) => offset,
                    Ok(Err(_)) => return STATUS_UNSUCCESSFUL,
                    Err(status) => return status,
                };
                unsafe {
                    *(file_information as *mut FilePositionInformation) = FilePositionInformation {
                        current_byte_offset: offset as i64,
                    };
                }
                STATUS_SUCCESS
            }
        }
        nt::FILE_NAME_INFORMATION_CLASS => {
            let path = match nt::with_file(entry.object_id, |file| file.path.clone()) {
                Ok(path) => path,
                Err(status) => return status,
            };
            let utf16: Vec<u16> = path.encode_utf16().collect();
            let required = 4 + utf16.len() * 2;
            if usize::try_from(length).unwrap_or(0) < required {
                STATUS_BUFFER_TOO_SMALL
            } else {
                unsafe {
                    *(file_information as *mut u32) = (utf16.len() * 2) as u32;
                    core::ptr::copy_nonoverlapping(
                        utf16.as_ptr(),
                        (file_information.add(4)) as *mut u16,
                        utf16.len(),
                    );
                }
                STATUS_SUCCESS
            }
        }
        _ => STATUS_NOT_SUPPORTED,
    };
    if !io_status.is_null() {
        unsafe {
            *io_status = IoStatusBlock {
                status,
                information: usize::try_from(length).unwrap_or(0),
            };
        }
    }
    status
}

pub fn create_event(out_handle: *mut Handle, event_type: u32, initial_state: bool) -> NtStatus {
    if out_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let manual_reset = event_type == nt::EVENT_TYPE_NOTIFICATION;
    let object_id = nt::create_event(manual_reset, initial_state);
    let handle = match install_handle(
        object_id,
        nt::EVENT_QUERY_STATE | nt::EVENT_MODIFY_STATE | nt::SYNCHRONIZE,
    ) {
        Ok(handle) => handle,
        Err(status) => {
            let _ = nt::release(object_id);
            return status;
        }
    };
    let _ = nt::release(object_id);
    unsafe { *out_handle = handle };
    STATUS_SUCCESS
}

pub fn set_event(handle: Handle, previous_state: *mut i32) -> NtStatus {
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    match nt::with_event_mut(entry.object_id, |event| {
        let old = i32::from(event.signaled);
        event.signaled = true;
        (old, event.manual_reset)
    }) {
        Ok((old, _manual_reset)) => {
            wake_waiters(entry.object_id);
            if !previous_state.is_null() {
                unsafe { *previous_state = old };
            }
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub fn clear_event(handle: Handle) -> NtStatus {
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    match nt::with_event_mut(entry.object_id, |event| {
        event.signaled = false;
    }) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

pub fn reset_event(handle: Handle, previous_state: *mut i32) -> NtStatus {
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    match nt::with_event_mut(entry.object_id, |event| {
        let old = i32::from(event.signaled);
        event.signaled = false;
        old
    }) {
        Ok(old) => {
            if !previous_state.is_null() {
                unsafe { *previous_state = old };
            }
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

fn consume_waitable_signal(object_id: u32) -> Result<bool, NtStatus> {
    if let Ok(signaled) = nt::with_event_mut(object_id, |event| {
        if event.signaled {
            if !event.manual_reset {
                event.signaled = false;
            }
            true
        } else {
            false
        }
    }) {
        return Ok(signaled);
    }
    if let Ok(signaled) = nt::with_process(object_id, |process| process.signaled) {
        return Ok(signaled);
    }
    if let Ok(signaled) = nt::with_thread(object_id, |thread| thread.signaled) {
        return Ok(signaled);
    }
    Err(STATUS_NOT_SUPPORTED)
}

fn register_waiter(object_id: u32, task_id: usize) {
    let mut waiters = WAITERS.lock();
    let list = waiters.entry(object_id).or_default();
    if !list.contains(&task_id) {
        list.push(task_id);
    }
}

fn unregister_waiter(object_id: u32, task_id: usize) {
    let mut waiters = WAITERS.lock();
    let Some(list) = waiters.get_mut(&object_id) else {
        return;
    };
    list.retain(|candidate| *candidate != task_id);
    if list.is_empty() {
        waiters.remove(&object_id);
    }
}

fn wake_waiters(object_id: u32) {
    let waiters = WAITERS.lock().remove(&object_id).unwrap_or_default();
    for task_id in waiters {
        process::wake_task(task_id);
    }
}

pub fn wait_for_single_object(handle: Handle, alertable: bool, timeout: *const i64) -> NtStatus {
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };

    if alertable {
        return STATUS_NOT_IMPLEMENTED;
    }

    let finite_timeout = if timeout.is_null() {
        None
    } else {
        Some(unsafe { *timeout })
    };
    if let Some(timeout_ticks) = finite_timeout {
        if timeout_ticks != 0 {
            return STATUS_NOT_IMPLEMENTED;
        }
    }

    match consume_waitable_signal(entry.object_id) {
        Ok(true) => return STATUS_SUCCESS,
        Ok(false) => {}
        Err(status) => return status,
    }

    if finite_timeout == Some(0) {
        return STATUS_TIMEOUT;
    }

    let Some(task_id) = process::current_task_id() else {
        return STATUS_PENDING;
    };
    register_waiter(entry.object_id, task_id);

    loop {
        match consume_waitable_signal(entry.object_id) {
            Ok(true) => {
                unregister_waiter(entry.object_id, task_id);
                return STATUS_SUCCESS;
            }
            Ok(false) => {}
            Err(status) => {
                unregister_waiter(entry.object_id, task_id);
                return status;
            }
        }
        process::block_current();
        unsafe {
            core::arch::asm!("sti; hlt; cli", options(nomem, preserves_flags));
        }
    }
}

pub fn delay_execution(alertable: bool, interval: *const i64) -> NtStatus {
    if alertable {
        return STATUS_NOT_IMPLEMENTED;
    }
    if interval.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let interval = unsafe { *interval };
    if interval == 0 {
        unsafe {
            core::arch::asm!("sti; hlt; cli", options(nomem, preserves_flags));
        }
        return STATUS_SUCCESS;
    }
    if interval > 0 {
        return STATUS_NOT_IMPLEMENTED;
    }

    let delay_100ns = interval.saturating_abs();
    let delay_ticks = (delay_100ns.saturating_add(SCHED_TICK_100NS - 1)) / SCHED_TICK_100NS;
    let start_tick = process::global_tick();
    let wake_tick = start_tick.saturating_add(delay_ticks as u64);
    while process::global_tick() < wake_tick {
        unsafe {
            core::arch::asm!("sti; hlt; cli", options(nomem, preserves_flags));
        }
    }
    STATUS_SUCCESS
}

pub fn query_system_time(system_time: *mut i64) -> NtStatus {
    if system_time.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let ticks = process::global_tick() as i64;
    let value = NT_EPOCH_OFFSET_100NS.saturating_add(ticks.saturating_mul(SCHED_TICK_100NS));
    unsafe {
        *system_time = value;
    }
    STATUS_SUCCESS
}

pub fn yield_execution() -> NtStatus {
    process::yield_current();
    unsafe {
        core::arch::asm!("int 0x20", options(nomem, preserves_flags));
    }
    STATUS_SUCCESS
}

pub fn create_section(
    out_handle: *mut Handle,
    _desired_access: AccessMask,
    object_attributes: *const ObjectAttributes,
    maximum_size: *const i64,
    protection: u32,
    attributes: u32,
    file_handle: Handle,
) -> NtStatus {
    if out_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let path = if file_handle != 0 {
        let entry = match resolve_handle_entry(file_handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        match nt::with_file(entry.object_id, |file| file.path.clone()) {
            Ok(path) => Some(path),
            Err(status) => return status,
        }
    } else {
        None
    };
    let nt_path = path.as_deref().and_then(nt_path_from_vfs_path);
    let name = if object_attributes.is_null() {
        None
    } else {
        Some(match path_from_object_attributes(object_attributes) {
            Ok(name) => name,
            Err(status) => return status,
        })
    };
    let size = if maximum_size.is_null() {
        0
    } else {
        unsafe { *maximum_size }.max(0) as u64
    };
    let object_id = if let Some(name) = name {
        match nt::create_named_section(&name, nt_path, path, protection, attributes, size) {
            Ok(object_id) => object_id,
            Err(status) => return status,
        }
    } else {
        nt::create_section(nt_path, path, protection, attributes, size)
    };
    let handle = match install_handle(object_id, nt::SECTION_ALL_ACCESS) {
        Ok(handle) => handle,
        Err(status) => {
            let _ = nt::release(object_id);
            return status;
        }
    };
    let _ = nt::release(object_id);
    unsafe { *out_handle = handle };
    STATUS_SUCCESS
}

pub fn open_section(
    out_handle: *mut Handle,
    _desired_access: AccessMask,
    object_attributes: *const ObjectAttributes,
) -> NtStatus {
    if out_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let name = match path_from_object_attributes(object_attributes) {
        Ok(name) => name,
        Err(status) => return status,
    };
    let object_id = match nt::open_section(&name) {
        Ok(object_id) => object_id,
        Err(status) => return status,
    };
    let handle = match install_handle(object_id, nt::SECTION_ALL_ACCESS) {
        Ok(handle) => handle,
        Err(status) => {
            let _ = nt::release(object_id);
            return status;
        }
    };
    let _ = nt::release(object_id);
    unsafe { *out_handle = handle };
    STATUS_SUCCESS
}

pub fn map_view_of_section(
    section_handle: Handle,
    process_handle: Handle,
    base_address: *mut usize,
    view_size: *mut usize,
    win32_protect: u32,
) -> NtStatus {
    if base_address.is_null() || view_size.is_null() || process_handle != usize::MAX {
        return STATUS_INVALID_PARAMETER;
    }
    let entry = match resolve_handle_entry(section_handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    let section = match nt::with_section(entry.object_id, |section| section.clone()) {
        Ok(section) => section,
        Err(status) => return status,
    };
    if (section.attributes & nt::SEC_IMAGE) != 0 {
        if unsafe { *base_address } != 0 {
            return STATUS_NOT_IMPLEMENTED;
        }
        let Some(nt_path) = section.nt_path.as_deref() else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let image = match map_image_view(nt_path) {
            Ok(image) => image,
            Err(status) => return status,
        };
        unsafe {
            *base_address = image.image_base as usize;
            *view_size = image.size_of_image as usize;
        }
        return STATUS_SUCCESS;
    }
    let size = unsafe { *view_size }.max(section.size as usize);
    let status = allocate_virtual_memory(process_handle, base_address, view_size, win32_protect);
    if status != STATUS_SUCCESS {
        return status;
    }
    if let Some(path) = section.path {
        let file = match vfs::open(&path, 0) {
            Ok(file) => file,
            Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
        };
        let data = unsafe { core::slice::from_raw_parts_mut(*base_address as *mut u8, size) };
        let n = match vfs::pread(file, 0, data) {
            Ok(n) => n,
            Err(_) => {
                let _ = vfs::close(file);
                return STATUS_UNSUCCESSFUL;
            }
        };
        if n < size {
            unsafe { core::ptr::write_bytes((*base_address + n) as *mut u8, 0, size - n) };
        }
        let _ = vfs::close(file);
    }
    STATUS_SUCCESS
}

pub fn unmap_view_of_section(process_handle: Handle, base_address: usize) -> NtStatus {
    let mut base = base_address;
    let Some(region_len) = mapped_region_len(base_address as u64) else {
        return STATUS_INVALID_PARAMETER;
    };
    let mut size = region_len as usize;
    let _ = process_handle;
    free_virtual_memory(usize::MAX, &mut base, &mut size)
}

pub fn device_io_control_file(
    handle: Handle,
    _event: Handle,
    _apc_routine: *mut (),
    _apc_context: *mut (),
    io_status: *mut IoStatusBlock,
    io_control_code: u32,
    _input_buffer: *const u8,
    _input_buffer_length: u32,
    _output_buffer: *mut u8,
    _output_buffer_length: u32,
) -> NtStatus {
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    kdebug!(
        "NT KERNEL: NtDeviceIoControlFile handle={:#x} object_id={} code={:#x}",
        handle,
        entry.object_id,
        io_control_code
    );
    if !io_status.is_null() {
        unsafe {
            *io_status = IoStatusBlock {
                status: nt::STATUS_INVALID_DEVICE_REQUEST,
                information: 0,
            };
        }
    }
    nt::STATUS_INVALID_DEVICE_REQUEST
}

pub fn query_virtual_memory(
    process_handle: Handle,
    base_address: usize,
    memory_information_class: u32,
    memory_information: *mut u8,
    memory_information_length: usize,
    return_length: *mut usize,
) -> NtStatus {
    if process_handle != usize::MAX || memory_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if memory_information_class == nt::MEMORY_BASIC_INFORMATION_CLASS {
        if memory_information_length < core::mem::size_of::<nt::MemoryBasicInformation>() {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        let asid = current_address_space_id();
        let mut asid_mappings = address_space_mappings(asid);
        asid_mappings.sort_by_key(|m| m.start);

        let target_virt = align_down(base_address as u64, PAGE_SIZE);
        let mut info = nt::MemoryBasicInformation::default();

        if let Some(pos) = asid_mappings.iter().position(|m| m.start == target_virt) {
            let prot = asid_mappings[pos].prot;
            let mut start_idx = pos;
            while start_idx > 0
                && asid_mappings[start_idx - 1].start == asid_mappings[start_idx].start - PAGE_SIZE
                && asid_mappings[start_idx - 1].prot == prot
            {
                start_idx -= 1;
            }
            let alloc_base = asid_mappings[start_idx].start;

            let mut end_idx = pos;
            while end_idx + 1 < asid_mappings.len()
                && asid_mappings[end_idx + 1].start == asid_mappings[end_idx].start + PAGE_SIZE
                && asid_mappings[end_idx + 1].prot == prot
            {
                end_idx += 1;
            }
            let region_size = asid_mappings[end_idx].start + PAGE_SIZE - target_virt;

            info.base_address = target_virt as usize;
            info.allocation_base = alloc_base as usize;
            info.allocation_protect = prot;
            info.region_size = region_size as usize;
            info.state = nt::MEM_COMMIT;
            info.protect = prot;
            info.type_ = nt::MEM_PRIVATE;
        } else {
            info.base_address = target_virt as usize;
            info.state = nt::MEM_FREE;
            info.protect = nt::PAGE_NOACCESS;
            if let Some(next) = asid_mappings.iter().find(|m| m.start > target_virt) {
                info.region_size = (next.start - target_virt) as usize;
            } else {
                info.region_size = (USER_STACK_TOP - target_virt) as usize;
            }
        }

        unsafe {
            *(memory_information as *mut nt::MemoryBasicInformation) = info;
            if !return_length.is_null() {
                *return_length = core::mem::size_of::<nt::MemoryBasicInformation>();
            }
        }
        return STATUS_SUCCESS;
    }

    STATUS_NOT_SUPPORTED
}

pub fn query_information_process(
    process_handle: Handle,
    info_class: u32,
    process_information: *mut u8,
    process_information_length: u32,
    return_length: *mut u32,
) -> NtStatus {
    if process_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = match resolve_handle_entry(process_handle) {
        Ok(entry) => entry,
        Err(_status) if process_handle == usize::MAX => HandleEntry {
            object_id: current_slot().lock().process_object,
            access: nt::PROCESS_ALL_ACCESS,
        },
        Err(status) => return status,
    };
    match info_class {
        nt::PROCESS_BASIC_INFORMATION_CLASS => {
            let required = core::mem::size_of::<ProcessBasicInformation>() as u32;
            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            unsafe {
                *(process_information as *mut ProcessBasicInformation) = current_process_basic();
                if !return_length.is_null() {
                    *return_length = required;
                }
            }
            STATUS_SUCCESS
        }
        _ => STATUS_NOT_SUPPORTED,
    }
}

pub fn terminate_process(handle: Handle, exit_status: NtStatus) -> NtStatus {
    if handle != usize::MAX {
        return STATUS_NOT_IMPLEMENTED;
    }
    exit_current(exit_status);
    process::on_task_exit()
}

pub fn terminate_thread(handle: Handle, exit_status: NtStatus) -> NtStatus {
    if handle != usize::MAX - 4 {
        return STATUS_NOT_IMPLEMENTED;
    }
    exit_current(exit_status);
    process::on_task_exit()
}

fn trim_wrapping_quotes(path: &str) -> &str {
    let trimmed = path.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

fn path_from_process_parameters(
    process_parameters: *const RtlUserProcessParameters,
) -> Result<String, NtStatus> {
    if process_parameters.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let params = unsafe { &*process_parameters };

    if !params.image_path_name.buffer.is_null() && params.image_path_name.length != 0 {
        let us = params.image_path_name;
        let path = read_utf16_string(&us as *const UnicodeString)?;
        let path = trim_wrapping_quotes(&path);
        if !path.is_empty() {
            return Ok(path.to_string());
        }
    }

    if !params.command_line.buffer.is_null() && params.command_line.length != 0 {
        let us = params.command_line;
        let cmdline = read_utf16_string(&us as *const UnicodeString)?;
        let cmdline = trim_wrapping_quotes(&cmdline);
        if !cmdline.is_empty() {
            return Ok(cmdline.to_string());
        }
    }

    Err(STATUS_INVALID_PARAMETER)
}

fn cleanup_failed_spawn(
    pid: u32,
    asid: u32,
    task_id: usize,
    process_object: u32,
    thread_object: u32,
    handle_object_ids: Vec<u32>,
) {
    {
        let mut registry = REGISTRY.lock();
        registry.task_to_pid.remove(&task_id);
        registry.by_pid.remove(&pid);
    }
    // TODO: restore full address-space teardown once frame ownership in failed
    // spawn paths is audited; for now prefer leak over allocator corruption.
    let _ = REGISTRY.lock().spaces.remove(&asid);
    for object_id in handle_object_ids {
        let _ = nt::release(object_id);
    }
    let _ = nt::release(process_object);
    let _ = nt::release(thread_object);
}

pub fn create_user_process(
    process_handle_out: *mut Handle,
    thread_handle_out: *mut Handle,
    process_parameters: *const RtlUserProcessParameters,
) -> NtStatus {
    if process_handle_out.is_null() || thread_handle_out.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let image_path = match path_from_process_parameters(process_parameters) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let parent_pid = current_pid_internal();
    let parent_active = active_pid();

    let task_id = process::allocate_task_id();
    let (pid, asid) = {
        let mut registry = REGISTRY.lock();
        (
            allocate_pid(&mut registry),
            allocate_address_space_id(&mut registry),
        )
    };

    let process_object = nt::create_process(pid);
    let thread_object = nt::create_thread(pid, task_id);
    let mut child = UserProcess {
        pid,
        ppid: parent_pid,
        address_space_id: asid,
        task_id: Some(task_id),
        process_object,
        thread_object,
        ..UserProcess::default()
    };
    if let Err(status) = seed_standard_handles(&mut child) {
        let object_ids: Vec<u32> = child
            .handles
            .iter()
            .filter_map(|entry| entry.map(|entry| entry.object_id))
            .collect();
        cleanup_failed_spawn(pid, asid, task_id, process_object, thread_object, object_ids);
        return status;
    }

    let space = match create_address_space() {
        Ok(space) => space,
        Err(status) => {
            let object_ids: Vec<u32> = child
                .handles
                .iter()
                .filter_map(|entry| entry.map(|entry| entry.object_id))
                .collect();
            cleanup_failed_spawn(pid, asid, task_id, process_object, thread_object, object_ids);
            return status;
        }
    };

    {
        let mut registry = REGISTRY.lock();
        registry.spaces.insert(asid, space);
        registry.by_pid.insert(pid, child);
        registry.task_to_pid.insert(task_id, pid);
    }

    let init_ctx = match x86_64::instructions::interrupts::without_interrupts(|| {
        switch_active_process(Some(pid));
        let res = load_init_context(task_id, pid, &image_path);
        switch_active_process(parent_active);
        res
    }) {
        Ok(ctx) => ctx,
        Err(status) => {
            {
                let mut registry = REGISTRY.lock();
                registry.task_to_pid.remove(&task_id);
                registry.by_pid.remove(&pid);
                registry.spaces.remove(&asid);
            }
            let _ = nt::with_thread_mut(thread_object, |thread| {
                thread.signaled = true;
                thread.exit_status = status;
            });
            let _ = nt::with_process_mut(process_object, |process| {
                process.signaled = true;
                process.exit_status = status;
            });
            return status;
        }
    };

    process::SCHEDULER.lock().add_task(process::Task::with_initial_context(
        task_id,
        0,
        init_ctx,
        process::SchedParams {
            process_id: pid,
            ..process::SchedParams::default()
        },
    ));

    let process_handle = match install_handle(process_object, nt::PROCESS_ALL_ACCESS) {
        Ok(handle) => handle,
        Err(status) => return status,
    };
    let thread_handle = match install_handle(thread_object, nt::THREAD_ALL_ACCESS) {
        Ok(handle) => handle,
        Err(status) => {
            let _ = close_handle(process_handle);
            return status;
        }
    };
    unsafe {
        *process_handle_out = process_handle;
        *thread_handle_out = thread_handle;
    }
    STATUS_SUCCESS
}

pub fn create_thread_ex(
    thread_handle_out: *mut Handle,
    _desired_access: AccessMask,
    _object_attributes: *const ObjectAttributes,
    process_handle: Handle,
    start_routine: usize,
    argument: usize,
    _create_flags: u32,
    _zero_bits: usize,
    stack_size: usize,
    _maximum_stack_size: usize,
    _attribute_list: *const (),
) -> NtStatus {
    if thread_handle_out.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // For now we only support creating threads in the current process
    if process_handle != usize::MAX {
        return STATUS_NOT_IMPLEMENTED;
    }

    let pid = current_pid_internal();
    let task_id = process::allocate_task_id();

    let stack_top = if stack_size == 0 {
        let size = 64 * PAGE_SIZE;
        match allocate_user_region(size, nt::PAGE_READWRITE) {
            Ok(base) => base + size,
            Err(status) => return status,
        }
    } else {
        let size = align_up(stack_size as u64, PAGE_SIZE);
        match allocate_user_region(size, nt::PAGE_READWRITE) {
            Ok(base) => base + size,
            Err(status) => return status,
        }
    };

    let thread_object = nt::create_thread(pid, task_id);

    let ctx = process::SavedTaskContext {
        rip: start_routine,
        rcx: argument,
        cs: usize::from(gdt::user_code_selector().0),
        rflags: 0x202,
        rsp: align_down(stack_top - 0x20, 16) as usize,
        ss: usize::from(gdt::user_data_selector().0),
        ..process::SavedTaskContext::default()
    };

    process::SCHEDULER.lock().add_task(process::Task::with_initial_context(
        task_id,
        0,
        ctx,
        process::SchedParams {
            process_id: pid,
            ..process::SchedParams::default()
        },
    ));

    let handle = match install_handle(thread_object, nt::THREAD_ALL_ACCESS) {
        Ok(handle) => handle,
        Err(status) => {
            let _ = nt::release(thread_object);
            return status;
        }
    };
    let _ = nt::release(thread_object);
    unsafe { *thread_handle_out = handle };

    STATUS_SUCCESS
}

pub fn exit_current(status: NtStatus) {
    let pid = current_pid_internal();
    let task_id = process::current_task_id();
    let mut current = current_slot().lock();
    current.exited = true;
    current.exit_status = status;
    current.task_id = None;
    let process_object = current.process_object;
    let thread_object = current.thread_object;
    let object_ids: Vec<u32> = current
        .handles
        .iter_mut()
        .filter_map(|entry| entry.take().map(|entry| entry.object_id))
        .collect();
    drop(current);
    for object_id in object_ids {
        let _ = nt::release(object_id);
    }
    let mut registry = REGISTRY.lock();
    if let Some(proc) = registry.by_pid.get_mut(&pid) {
        proc.exited = true;
        proc.exit_status = status;
        proc.task_id = None;
    }
    if let Some(task_id) = task_id {
        registry.task_to_pid.remove(&task_id);
    }
    drop(registry);
    let _ = nt::with_thread_mut(thread_object, |thread| {
        thread.signaled = true;
        thread.exit_status = status;
    });
    let _ = nt::with_process_mut(process_object, |process| {
        process.signaled = true;
        process.exit_status = status;
    });
    wake_waiters(thread_object);
    wake_waiters(process_object);
}

pub fn create_init_task(task_id: usize, path: &str) -> Result<process::Task, NtStatus> {
    nt::init_namespace();
    let pid = 1;
    {
        let mut current = current_slot().lock();
        *current = UserProcess::default();
        current.pid = pid;
        current.ppid = 0;
        current.address_space_id = 1;
        current.task_id = Some(task_id);
        current.process_object = nt::create_process(pid);
        current.thread_object = nt::create_thread(pid, task_id);
        seed_standard_handles(&mut current)?;
    }
    {
        let mut registry = REGISTRY.lock();
        let space = match create_address_space() {
            Ok(space) => space,
            Err(status) => {
                println!("NT KERNEL: create_address_space failed: {:#x}", status);
                return Err(status);
            }
        };
        registry.spaces.insert(1, space);
        registry.by_pid.insert(pid, current_slot().lock().clone());
        registry.task_to_pid.insert(task_id, pid);
    }
    switch_active_process(Some(pid));
    let ctx = match load_init_context(task_id, pid, path) {
        Ok(ctx) => ctx,
        Err(status) => {
            println!("NT KERNEL: load_init_context failed: {:#x}", status);
            return Err(status);
        }
    };
    Ok(process::Task::with_initial_context(
        task_id,
        0,
        ctx,
        process::SchedParams {
            process_id: pid,
            ..process::SchedParams::default()
        },
    ))
}

fn load_init_context(
    task_id: usize,
    pid: u32,
    nt_path: &str,
) -> Result<process::SavedTaskContext, NtStatus> {
    let image = match load_module(nt_path) {
        Ok(image) => image,
        Err(status) => {
            println!("NT KERNEL: load_module({}) failed: {:#x}", nt_path, status);
            return Err(status);
        }
    };

    let stack_bottom = USER_STACK_TOP - USER_STACK_PAGES * PAGE_SIZE;
    if let Err(status) = map_region(
        stack_bottom,
        USER_STACK_PAGES * PAGE_SIZE,
        nt::PAGE_READWRITE,
    ) {
        println!("NT KERNEL: user stack map failed: {:#x}", status);
        return Err(status);
    }
    let stack_top = USER_STACK_TOP;

    {
        let mut current = current_slot().lock();
        current.image_base = image.image_base;
    }
    let (peb_addr, teb_addr, params_addr) = match build_process_environment(nt_path, stack_top) {
        Ok(values) => values,
        Err(status) => {
            println!("NT KERNEL: build_process_environment failed: {:#x}", status);
            return Err(status);
        }
    };
    let startup_rip = match install_startup_bootstrap(peb_addr, image.entry) {
        Ok(rip) => rip,
        Err(status) => {
            println!("NT KERNEL: install_startup_bootstrap failed: {:#x}", status);
            return Err(status);
        }
    };
    {
        let mut current = current_slot().lock();
        current.pid = pid;
        current.task_id = Some(task_id);
        current.image_path = Some(nt_path.to_string());
        current.peb_addr = peb_addr;
        current.teb_addr = teb_addr;
        current.params_addr = params_addr;
        current.fs_base = teb_addr;
        current.gs_base = teb_addr;
    }
    FsBase::write(VirtAddr::new(teb_addr));
    GsBase::write(VirtAddr::new(teb_addr));
    Ok(process::SavedTaskContext {
        rip: startup_rip as usize,
        rcx: peb_addr as usize,
        cs: usize::from(gdt::user_code_selector().0),
        rflags: 0x202,
        rsp: align_down(stack_top - 0x20, 16) as usize,
        ss: usize::from(gdt::user_data_selector().0),
        ..process::SavedTaskContext::default()
    })
}

fn install_startup_bootstrap(peb_addr: u64, entry_rip: u64) -> Result<u64, NtStatus> {
    let ntdll = load_module("ntdll.dll")?;
    let rtl_create_heap = match resolve_export_name(&ntdll, "RtlCreateHeap") {
        Ok(addr) => addr,
        Err(status) => {
            println!(
                "NT KERNEL: resolve_export_name(RtlCreateHeap) failed status={:#x}",
                status
            );
            return Err(status);
        }
    };
    map_region(USER_BOOTSTRAP_BASE, PAGE_SIZE, nt::PAGE_EXECUTE_READWRITE)?;

    let mut code = Vec::with_capacity(80);
    code.extend_from_slice(&[0x48, 0x31, 0xC9]); // xor rcx, rcx
    code.extend_from_slice(&[0x48, 0x31, 0xD2]); // xor rdx, rdx
    code.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8, r8
    code.extend_from_slice(&[0x4D, 0x31, 0xC9]); // xor r9, r9
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x30]); // sub rsp, 0x30
    code.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+0x20], 0
    code.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+0x28], 0
    code.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    code.extend_from_slice(&rtl_create_heap.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0]); // call rax
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x30]); // add rsp, 0x30
    code.extend_from_slice(&[0x48, 0xB9]); // mov rcx, imm64
    code.extend_from_slice(&peb_addr.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0x41, 0x30]); // mov [rcx+0x30], rax
    code.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    code.extend_from_slice(&entry_rip.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xE0]); // jmp rax

    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            USER_BOOTSTRAP_BASE as *mut u8,
            code.len(),
        );
    }
    Ok(USER_BOOTSTRAP_BASE)
}

fn load_module(nt_path: &str) -> Result<LoadedImage, NtStatus> {
    let canonical_path = canonical_module_path(nt_path);
    if let Some(existing) = with_current_process(|current| {
        current
            .modules
            .iter()
            .find(|module| module.nt_path.eq_ignore_ascii_case(&canonical_path))
            .cloned()
    }) {
        return Ok(LoadedImage {
            entry: existing.entry,
            image_base: existing.image_base,
            size_of_image: existing.size_of_image,
            exports_by_name: existing.exports_by_name,
            exports_by_ordinal: existing.exports_by_ordinal,
            dll_name: existing.dll_name,
        });
    }

    let template = module_template(&canonical_path)?;
    let image = load_pe_image(&canonical_path, &template)?;
    with_current_process(|current| {
        current.modules.push(LoadedModule {
            nt_path: canonical_path,
            dll_name: image.dll_name.clone(),
            image_base: image.image_base,
            entry: image.entry,
            size_of_image: image.size_of_image,
            exports_by_name: Arc::clone(&image.exports_by_name),
            exports_by_ordinal: Arc::clone(&image.exports_by_ordinal),
        });
    });
    Ok(image)
}

fn module_template(canonical_path: &str) -> Result<Arc<ModuleTemplate>, NtStatus> {
    if let Some(template) = MODULE_TEMPLATES.lock().get(canonical_path).cloned() {
        return Ok(template);
    }

    let vfs_path = match nt::resolve_nt_path(canonical_path) {
        Ok(path) => path,
        Err(status) => {
            println!(
                "NT KERNEL: load_module path resolve failed canonical={} status={:#x}",
                canonical_path, status
            );
            return Err(status);
        }
    };
    let bytes = match vfs::read_all(&vfs_path) {
        Ok(bytes) => bytes,
        Err(err_primary) => {
            let basename = module_basename(&vfs_path);
            let fallback_candidates = [
                format!("/windows/system32/{}", basename),
                format!("/Windows/System32/{}", basename.to_ascii_lowercase()),
            ];
            let mut loaded = None;
            for candidate in fallback_candidates {
                if let Ok(bytes) = vfs::read_all(&candidate) {
                    loaded = Some(bytes);
                    break;
                }
            }
            match loaded {
                Some(bytes) => bytes,
                None => {
                    println!(
                        "NT KERNEL: load_module canonical={} vfs_path={} read_all failed: {:?}",
                        canonical_path, vfs_path, err_primary
                    );
                    return Err(STATUS_OBJECT_NAME_NOT_FOUND);
                }
            }
        }
    };

    let template = Arc::new(build_module_template(canonical_path, &bytes)?);
    MODULE_TEMPLATES
        .lock()
        .insert(canonical_path.to_string(), Arc::clone(&template));
    Ok(template)
}

fn map_image_view(nt_path: &str) -> Result<LoadedImage, NtStatus> {
    let canonical_path = canonical_module_path(nt_path);
    let template = module_template(&canonical_path)?;
    load_pe_image(&canonical_path, &template)
}

fn build_module_template(nt_path: &str, bytes: &[u8]) -> Result<ModuleTemplate, NtStatus> {
    let pe = PE::parse(bytes).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    if !pe.is_64 {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    if pe.header.coff_header.machine != goblin::pe::header::COFF_MACHINE_X86_64 {
        return Err(nt::STATUS_IMAGE_MACHINE_TYPE_MISMATCH);
    }
    let optional = pe
        .header
        .optional_header
        .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let size_of_image = optional.windows_fields.size_of_image as u64;
    let size_of_headers = optional.windows_fields.size_of_headers as usize;
    if size_of_headers as u64 > size_of_image {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }

    let mut sections = Vec::with_capacity(pe.sections.len());
    for section in &pe.sections {
        let raw_offset = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        let virtual_size = section.virtual_size.max(section.size_of_raw_data);
        let section_end = section.virtual_address as u64 + virtual_size as u64;
        if section_end > size_of_image {
            return Err(STATUS_INVALID_IMAGE_FORMAT);
        }
        let end = raw_offset.saturating_add(raw_size).min(bytes.len());
        let data = if raw_size == 0 || end <= raw_offset {
            Arc::<[u8]>::from([])
        } else {
            Arc::<[u8]>::from(&bytes[raw_offset..end])
        };
        sections.push(TemplateSection {
            virtual_address: section.virtual_address,
            virtual_size,
            characteristics: section.characteristics,
            data,
        });
    }

    let mut relocations = Vec::new();
    if let Some(relocation_data) = pe.relocation_data.as_ref() {
        for block in relocation_data.blocks() {
            let block = block.map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
            for word in block.words() {
                let word = word.map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
                relocations.push(TemplateRelocation {
                    rva: block.rva + u32::from(word.offset()),
                    kind: word.reloc_type(),
                });
            }
        }
    }

    let mut imports = Vec::with_capacity(pe.imports.len());
    for import in &pe.imports {
        let name = if import.name.starts_with("ORDINAL ") {
            None
        } else {
            Some(import.name.to_ascii_lowercase())
        };
        imports.push(TemplateImport {
            dll_path: canonical_module_path(import.dll),
            name,
            ordinal: import.ordinal as usize,
            offset: import.offset as u32,
            size: import.size,
        });
    }

    let (exports_by_name, exports_by_ordinal) = collect_template_exports(&pe)?;
    Ok(ModuleTemplate {
        preferred_base: pe.image_base,
        size_of_image,
        size_of_headers,
        entry_rva: pe.entry as u32,
        dll_name: pe.name.unwrap_or(module_basename(nt_path)).to_ascii_lowercase(),
        has_relocations: pe.relocation_data.is_some(),
        headers: Arc::<[u8]>::from(&bytes[..size_of_headers.min(bytes.len())]),
        sections: sections.into(),
        relocations: relocations.into(),
        imports: imports.into(),
        exports_by_name,
        exports_by_ordinal,
    })
}

fn load_pe_image(nt_path: &str, template: &ModuleTemplate) -> Result<LoadedImage, NtStatus> {
    let image_base = if pml4_index(template.preferred_base) == 0 {
        if !template.has_relocations {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        match allocate_user_region(template.size_of_image, nt::PAGE_READWRITE) {
            Ok(base) => base,
            Err(status) => {
                println!(
                    "NT KERNEL: allocate_user_region image {} size={:#x} failed: {:#x}",
                    nt_path, template.size_of_image, status
                );
                return Err(status);
            }
        }
    } else {
        match map_region_exact(template.preferred_base, template.size_of_image, nt::PAGE_READWRITE) {
            Ok(()) => template.preferred_base,
            Err(STATUS_CONFLICTING_ADDRESSES) => {
                if !template.has_relocations {
                    return Err(STATUS_CONFLICTING_ADDRESSES);
                }
                match allocate_user_region(template.size_of_image, nt::PAGE_READWRITE) {
                    Ok(base) => base,
                    Err(status) => {
                        println!(
                            "NT KERNEL: allocate_user_region image {} size={:#x} failed: {:#x}",
                            nt_path, template.size_of_image, status
                        );
                        return Err(status);
                    }
                }
            }
            Err(status) => return Err(status),
        }
    };
    unsafe {
        core::ptr::write_bytes(image_base as *mut u8, 0, template.size_of_image as usize);
        core::ptr::copy_nonoverlapping(
            template.headers.as_ptr(),
            image_base as *mut u8,
            template.headers.len(),
        );
    }
    for section in template.sections.iter() {
        let virt = image_base + section.virtual_address as u64;
        if !section.data.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    section.data.as_ptr(),
                    virt as *mut u8,
                    section.data.len(),
                );
            }
        }
        if section.virtual_size as usize > section.data.len() {
            unsafe {
                core::ptr::write_bytes(
                    (virt + section.data.len() as u64) as *mut u8,
                    0,
                    section.virtual_size as usize - section.data.len(),
                );
            }
        }
    }
    apply_base_relocations(template, image_base)?;
    let exports_by_name = materialize_export_names(template, image_base);
    let exports_by_ordinal = materialize_export_ordinals(template, image_base);
    resolve_imports(template, image_base)?;
    for section in template.sections.iter() {
        let virt = image_base + section.virtual_address as u64;
        let prot = section_to_protection(section.characteristics);
        protect_region(virt, align_up(section.virtual_size as u64, PAGE_SIZE), prot)?;
    }
    let headers_protect = nt::PAGE_READONLY;
    protect_region(
        image_base,
        align_up(template.size_of_headers as u64, PAGE_SIZE),
        headers_protect,
    )?;
    let entry = image_base + template.entry_rva as u64;
    kdebug!(
        "USER-PE path={} image_base={:#x} preferred={:#x} size={:#x} entry={:#x} imports={}",
        nt_path,
        image_base,
        template.preferred_base,
        template.size_of_image,
        entry,
        template.imports.len()
    );
    Ok(LoadedImage {
        entry,
        image_base,
        size_of_image: template.size_of_image,
        exports_by_name,
        exports_by_ordinal,
        dll_name: template.dll_name.clone(),
    })
}

fn apply_base_relocations(template: &ModuleTemplate, image_base: u64) -> Result<(), NtStatus> {
    let delta = image_base.wrapping_sub(template.preferred_base);
    if delta == 0 {
        return Ok(());
    }
    if !template.has_relocations {
        return Err(STATUS_CONFLICTING_ADDRESSES);
    }
    for relocation in template.relocations.iter() {
        let target = image_base + relocation.rva as u64;
        if target < image_base || target + 8 > image_base + template.size_of_image {
            return Err(STATUS_INVALID_IMAGE_FORMAT);
        }
        match relocation.kind {
            x if x == goblin::pe::relocation::IMAGE_REL_BASED_ABSOLUTE as u8 => {}
            x if x == goblin::pe::relocation::IMAGE_REL_BASED_DIR64 as u8 => unsafe {
                let ptr = target as *mut u64;
                *ptr = (*ptr).wrapping_add(delta);
            },
            x if x == goblin::pe::relocation::IMAGE_REL_BASED_HIGHLOW as u8 => unsafe {
                let ptr = target as *mut u32;
                *ptr = (*ptr).wrapping_add(delta as u32);
            },
            _ => return Err(STATUS_NOT_SUPPORTED),
        }
    }
    Ok(())
}

fn collect_template_exports(
    pe: &PE<'_>,
) -> Result<(
    Arc<[(String, TemplateExportTarget)]>,
    Arc<[(usize, TemplateExportTarget)]>,
), NtStatus> {
    let mut exports_by_name = Vec::new();
    let mut exports_by_ordinal = Vec::new();

    if let Some(export_data) = pe.export_data.as_ref() {
        let ordinal_base = export_data.export_directory_table.ordinal_base as usize;
        for (index, entry) in export_data.export_address_table.iter().enumerate() {
            let ordinal = ordinal_base + index;
            let target = match entry {
                goblin::pe::export::ExportAddressTableEntry::ExportRVA(rva) => {
                    TemplateExportTarget::Rva(*rva)
                }
                goblin::pe::export::ExportAddressTableEntry::ForwarderRVA(_) => {
                    let reexport = pe
                        .exports
                        .iter()
                        .find(|export| export.reexport.is_some() && export.rva == entry_rva(entry))
                        .and_then(|export| export.reexport.as_ref());
                    match reexport {
                        Some(goblin::pe::export::Reexport::DLLName { lib, export }) => {
                            TemplateExportTarget::ForwardName {
                                dll_path: canonical_module_path(lib),
                                symbol: export.to_ascii_lowercase(),
                            }
                        }
                        Some(goblin::pe::export::Reexport::DLLOrdinal { lib, ordinal }) => {
                            TemplateExportTarget::ForwardOrdinal {
                                dll_path: canonical_module_path(lib),
                                ordinal: *ordinal,
                            }
                        }
                        None => continue,
                    }
                }
            };
            exports_by_ordinal.push((ordinal, target));
        }
    }

    for export in &pe.exports {
        let Some(name) = export.name else {
            continue;
        };
        let target = if let Some(reexport) = export.reexport.as_ref() {
            match reexport {
                goblin::pe::export::Reexport::DLLName { lib, export } => {
                    TemplateExportTarget::ForwardName {
                        dll_path: canonical_module_path(lib),
                        symbol: export.to_ascii_lowercase(),
                    }
                }
                goblin::pe::export::Reexport::DLLOrdinal { lib, ordinal } => {
                    TemplateExportTarget::ForwardOrdinal {
                        dll_path: canonical_module_path(lib),
                        ordinal: *ordinal,
                    }
                }
            }
        } else {
            TemplateExportTarget::Rva(
                u32::try_from(export.rva).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?,
            )
        };
        exports_by_name.push((name.to_ascii_lowercase(), target));
    }

    Ok((
        exports_by_name.into(),
        exports_by_ordinal.into(),
    ))
}

fn materialize_export_names(
    template: &ModuleTemplate,
    image_base: u64,
) -> Arc<[(String, ExportTarget)]> {
    template
        .exports_by_name
        .iter()
        .map(|(name, target)| {
            (
                name.clone(),
                materialize_export_target(target, image_base),
            )
        })
        .collect::<Vec<_>>()
        .into()
}

fn materialize_export_ordinals(
    template: &ModuleTemplate,
    image_base: u64,
) -> Arc<[(usize, ExportTarget)]> {
    template
        .exports_by_ordinal
        .iter()
        .map(|(ordinal, target)| (*ordinal, materialize_export_target(target, image_base)))
        .collect::<Vec<_>>()
        .into()
}

fn materialize_export_target(target: &TemplateExportTarget, image_base: u64) -> ExportTarget {
    match target {
        TemplateExportTarget::Rva(rva) => ExportTarget::Address(image_base + u64::from(*rva)),
        TemplateExportTarget::ForwardName { dll_path, symbol } => ExportTarget::ForwardName {
            dll_path: dll_path.clone(),
            symbol: symbol.clone(),
        },
        TemplateExportTarget::ForwardOrdinal { dll_path, ordinal } => ExportTarget::ForwardOrdinal {
            dll_path: dll_path.clone(),
            ordinal: *ordinal,
        },
    }
}

fn resolve_imports(template: &ModuleTemplate, image_base: u64) -> Result<(), NtStatus> {
    for import in template.imports.iter() {
        let module = load_module(&import.dll_path)?;
        let symbol = if let Some(name) = import.name.as_deref() {
            resolve_export_name(&module, name)?
        } else {
            resolve_export_ordinal(&module, import.ordinal)?
        };
        let slot = image_base + import.offset as u64;
        let width = import.size as u64;
        if slot < image_base || slot + width > image_base + template.size_of_image {
            return Err(STATUS_INVALID_IMAGE_FORMAT);
        }
        unsafe {
            if import.size == 4 {
                *(slot as *mut u32) = symbol as u32;
            } else if import.size == 8 {
                *(slot as *mut u64) = symbol;
            } else {
                return Err(STATUS_INVALID_IMAGE_FORMAT);
            }
        }
    }
    Ok(())
}

fn entry_rva(entry: &goblin::pe::export::ExportAddressTableEntry) -> usize {
    match entry {
        goblin::pe::export::ExportAddressTableEntry::ExportRVA(rva)
        | goblin::pe::export::ExportAddressTableEntry::ForwarderRVA(rva) => *rva as usize,
    }
}

fn resolve_export_name(module: &LoadedImage, symbol: &str) -> Result<u64, NtStatus> {
    let symbol_lower = symbol.to_ascii_lowercase();
    let Some((_, target)) = module
        .exports_by_name
        .iter()
        .find(|(name, _)| name == &symbol_lower)
    else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    resolve_export_target(target)
}

fn resolve_export_ordinal(module: &LoadedImage, ordinal: usize) -> Result<u64, NtStatus> {
    let Some((_, target)) = module
        .exports_by_ordinal
        .iter()
        .find(|(candidate, _)| *candidate == ordinal)
    else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    resolve_export_target(target)
}

fn resolve_export_target(target: &ExportTarget) -> Result<u64, NtStatus> {
    match target {
        ExportTarget::Address(address) => Ok(*address),
        ExportTarget::ForwardName { dll_path, symbol } => {
            let module = load_module(dll_path)?;
            resolve_export_name(&module, symbol)
        }
        ExportTarget::ForwardOrdinal { dll_path, ordinal } => {
            let module = load_module(dll_path)?;
            resolve_export_ordinal(&module, *ordinal)
        }
    }
}

fn module_basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn canonical_module_path(name: &str) -> String {
    if name.starts_with('\\') || name.contains(':') {
        return nt::canonicalize_nt_path(name);
    }
    let normalized = name.replace('/', "\\");
    if normalized.contains('\\') {
        return nt::canonicalize_nt_path(&normalized);
    }
    nt::canonicalize_nt_path(&format!("\\SystemRoot\\System32\\{}", normalized))
}

fn protect_region(start: u64, len: u64, prot: u32) -> Result<(), NtStatus> {
    let root_frame = current_root_frame()?;
    let page_count = align_up(len, PAGE_SIZE) / PAGE_SIZE;
    for idx in 0..page_count {
        let virt = start + idx * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        allocator::update_page_flags_in(root_frame, page, page_flags(prot))
            .map_err(|_| STATUS_UNSUCCESSFUL)?;
        with_current_address_space(|space| {
            if let Some(mapping) = space.mappings.get_mut(&virt) {
                mapping.prot = prot;
            }
        });
    }
    Ok(())
}

fn section_to_protection(characteristics: u32) -> u32 {
    let executable = (characteristics & 0x2000_0000) != 0;
    let readable = (characteristics & 0x4000_0000) != 0;
    let writable = (characteristics & 0x8000_0000) != 0;
    match (executable, readable, writable) {
        (true, true, true) => nt::PAGE_EXECUTE_READWRITE,
        (true, true, false) => nt::PAGE_EXECUTE_READ,
        (true, false, false) => nt::PAGE_EXECUTE,
        (false, true, true) => nt::PAGE_READWRITE,
        (false, true, false) => nt::PAGE_READONLY,
        _ => nt::PAGE_NOACCESS,
    }
}

fn build_process_environment(nt_path: &str, stack_top: u64) -> Result<(u64, u64, u64), NtStatus> {
    let env_base = USER_ENV_BASE;
    if let Err(status) = map_region(env_base, USER_ENV_PAGES * PAGE_SIZE, nt::PAGE_READWRITE) {
        println!(
            "NT KERNEL: env map failed path={} base={:#x} pages={} status={:#x}",
            nt_path, env_base, USER_ENV_PAGES, status
        );
        return Err(status);
    }
    let mut cursor = env_base;
    let image_utf16: Vec<u16> = nt_path.encode_utf16().collect();
    let cmd_utf16: Vec<u16> = nt_path.encode_utf16().collect();
    let mut modules = current_slot().lock().modules.clone();
    if let Some(main_index) = modules
        .iter()
        .position(|module| module.nt_path.eq_ignore_ascii_case(nt_path))
    {
        let main = modules.remove(main_index);
        modules.insert(0, main);
    }

    let params_addr = cursor;
    cursor += core::mem::size_of::<RtlUserProcessParameters>() as u64;
    let image_buf = align_up(cursor, 2);
    copy_utf16(image_buf, &image_utf16);
    cursor = image_buf + ((image_utf16.len() * 2 + 2) as u64);
    let cmd_buf = align_up(cursor, 2);
    copy_utf16(cmd_buf, &cmd_utf16);
    cursor = cmd_buf + ((cmd_utf16.len() * 2 + 2) as u64);
    let ldr_addr = align_up(cursor, 16);
    cursor = ldr_addr + core::mem::size_of::<PebLdrData>() as u64;
    let ldr_entries_addr = align_up(cursor, 16);
    cursor = ldr_entries_addr
        + (modules.len() as u64 * core::mem::size_of::<LdrDataTableEntry>() as u64);
    let peb_addr = align_up(cursor, 16);
    cursor = peb_addr + core::mem::size_of::<Peb>() as u64;
    let teb_addr = align_up(cursor, 16);
    cursor = teb_addr + core::mem::size_of::<Teb>() as u64;

    let load_head = (ldr_addr + core::mem::offset_of!(PebLdrData, in_load_order_module_list) as u64)
        as *mut ListEntry;
    let memory_head =
        (ldr_addr + core::mem::offset_of!(PebLdrData, in_memory_order_module_list) as u64)
            as *mut ListEntry;
    let init_head =
        (ldr_addr + core::mem::offset_of!(PebLdrData, in_initialization_order_module_list) as u64)
            as *mut ListEntry;

    let mut load_links = Vec::with_capacity(modules.len());
    let mut memory_links = Vec::with_capacity(modules.len());
    let mut init_links = Vec::with_capacity(modules.len());
    for index in 0..modules.len() {
        let entry_addr =
            ldr_entries_addr + (index as u64 * core::mem::size_of::<LdrDataTableEntry>() as u64);
        load_links.push(
            (entry_addr + core::mem::offset_of!(LdrDataTableEntry, in_load_order_links) as u64)
                as *mut ListEntry,
        );
        memory_links.push(
            (entry_addr + core::mem::offset_of!(LdrDataTableEntry, in_memory_order_links) as u64)
                as *mut ListEntry,
        );
        init_links.push(
            (entry_addr
                + core::mem::offset_of!(LdrDataTableEntry, in_initialization_order_links) as u64)
                as *mut ListEntry,
        );
    }

    let mut params = RtlUserProcessParameters::default();
    {
        let current = current_slot().lock();
        params.standard_input = current.standard_input;
        params.standard_output = current.standard_output;
        params.standard_error = current.standard_error;
    }
    params.flags = nt::RTL_USER_PROCESS_PARAMETERS_NORMALIZED;
    params.image_path_name = UnicodeString {
        length: (image_utf16.len() * 2) as u16,
        maximum_length: (image_utf16.len() * 2 + 2) as u16,
        buffer: image_buf as *const u16,
    };
    params.command_line = UnicodeString {
        length: (cmd_utf16.len() * 2) as u16,
        maximum_length: (cmd_utf16.len() * 2 + 2) as u16,
        buffer: cmd_buf as *const u16,
    };
    unsafe { *(params_addr as *mut RtlUserProcessParameters) = params };

    let mut ldr_data = PebLdrData {
        length: core::mem::size_of::<PebLdrData>() as u32,
        initialized: 1,
        ..PebLdrData::default()
    };
    if modules.is_empty() {
        ldr_data.in_load_order_module_list.flink = load_head;
        ldr_data.in_load_order_module_list.blink = load_head;
        ldr_data.in_memory_order_module_list.flink = memory_head;
        ldr_data.in_memory_order_module_list.blink = memory_head;
        ldr_data.in_initialization_order_module_list.flink = init_head;
        ldr_data.in_initialization_order_module_list.blink = init_head;
    } else {
        ldr_data.in_load_order_module_list.flink = load_links[0];
        ldr_data.in_load_order_module_list.blink = *load_links.last().unwrap();
        ldr_data.in_memory_order_module_list.flink = memory_links[0];
        ldr_data.in_memory_order_module_list.blink = *memory_links.last().unwrap();
        ldr_data.in_initialization_order_module_list.flink = init_links[0];
        ldr_data.in_initialization_order_module_list.blink = *init_links.last().unwrap();
    }
    unsafe { *(ldr_addr as *mut PebLdrData) = ldr_data };

    for (index, module) in modules.iter().enumerate() {
        let full_utf16: Vec<u16> = module.nt_path.encode_utf16().collect();
        let base_name = module_basename(&module.nt_path).to_string();
        let base_utf16: Vec<u16> = base_name.encode_utf16().collect();

        let full_buf = align_up(cursor, 2);
        copy_utf16(full_buf, &full_utf16);
        cursor = full_buf + ((full_utf16.len() * 2 + 2) as u64);

        let base_buf = align_up(cursor, 2);
        copy_utf16(base_buf, &base_utf16);
        cursor = base_buf + ((base_utf16.len() * 2 + 2) as u64);

        let prev_load = if index == 0 { load_head } else { load_links[index - 1] };
        let next_load = if index + 1 == modules.len() {
            load_head
        } else {
            load_links[index + 1]
        };
        let prev_memory = if index == 0 {
            memory_head
        } else {
            memory_links[index - 1]
        };
        let next_memory = if index + 1 == modules.len() {
            memory_head
        } else {
            memory_links[index + 1]
        };
        let prev_init = if index == 0 { init_head } else { init_links[index - 1] };
        let next_init = if index + 1 == modules.len() {
            init_head
        } else {
            init_links[index + 1]
        };

        let entry_addr =
            ldr_entries_addr + (index as u64 * core::mem::size_of::<LdrDataTableEntry>() as u64);
        let entry = LdrDataTableEntry {
            in_load_order_links: ListEntry {
                flink: next_load,
                blink: prev_load,
            },
            in_memory_order_links: ListEntry {
                flink: next_memory,
                blink: prev_memory,
            },
            in_initialization_order_links: ListEntry {
                flink: next_init,
                blink: prev_init,
            },
            dll_base: module.image_base as usize,
            entry_point: module.entry as usize,
            size_of_image: module.size_of_image as u32,
            reserved: 0,
            full_dll_name: UnicodeString {
                length: (full_utf16.len() * 2) as u16,
                maximum_length: (full_utf16.len() * 2 + 2) as u16,
                buffer: full_buf as *const u16,
            },
            base_dll_name: UnicodeString {
                length: (base_utf16.len() * 2) as u16,
                maximum_length: (base_utf16.len() * 2 + 2) as u16,
                buffer: base_buf as *const u16,
            },
        };
        unsafe { *(entry_addr as *mut LdrDataTableEntry) = entry };
    }

    let peb = Peb {
        image_base_address: current_slot().lock().image_base as usize,
        ldr: 0,
        process_parameters: params_addr as *mut RtlUserProcessParameters,
        ..Peb::default()
    };
    unsafe { *(peb_addr as *mut Peb) = peb };
    let teb = Teb {
        process_environment_block: peb_addr as *mut Peb,
        client_id: ClientId {
            unique_process: current_slot().lock().pid as usize,
            unique_thread: process::current_task_id().unwrap_or(0),
        },
        ..Teb::default()
    };
    unsafe { *(teb_addr as *mut Teb) = teb };
    let _ = stack_top;
    Ok((peb_addr, teb_addr, params_addr))
}

fn copy_utf16(dst: u64, text: &[u16]) {
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr(), dst as *mut u16, text.len());
        (dst as *mut u16).add(text.len()).write(0);
    }
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> u64 {
    if value == 0 {
        0
    } else {
        (value + align - 1) & !(align - 1)
    }
}
