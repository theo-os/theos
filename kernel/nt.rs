extern crate alloc;

use crate::vfs;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use regf::Hive;
use spin::{Lazy, Mutex};

pub type NtStatus = i32;
pub type Handle = usize;
pub type AccessMask = u32;

pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_NOT_IMPLEMENTED: NtStatus = 0xC000_0002u32 as i32;
pub const STATUS_INVALID_HANDLE: NtStatus = 0xC000_0008u32 as i32;
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000Du32 as i32;
pub const STATUS_NO_MEMORY: NtStatus = 0xC000_0017u32 as i32;
pub const STATUS_CONFLICTING_ADDRESSES: NtStatus = 0xC000_0018u32 as i32;
pub const STATUS_ACCESS_DENIED: NtStatus = 0xC000_0022u32 as i32;
pub const STATUS_OBJECT_TYPE_MISMATCH: NtStatus = 0xC000_0024u32 as i32;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = 0xC000_0034u32 as i32;
pub const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = 0xC000_003Au32 as i32;
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = 0xC000_0035u32 as i32;
pub const STATUS_INFO_LENGTH_MISMATCH: NtStatus = 0xC000_0004u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023u32 as i32;
pub const STATUS_END_OF_FILE: NtStatus = 0xC000_0011u32 as i32;
pub const STATUS_UNSUCCESSFUL: NtStatus = 0xC000_0001u32 as i32;
pub const STATUS_PENDING: NtStatus = 0x0000_0103u32 as i32;
pub const STATUS_TIMEOUT: NtStatus = 0x0000_0102u32 as i32;
pub const STATUS_NO_MORE_ENTRIES: NtStatus = 0x8000_001Au32 as i32;
pub const STATUS_IMAGE_MACHINE_TYPE_MISMATCH: NtStatus = 0x4000_002Eu32 as i32;
pub const STATUS_INVALID_IMAGE_FORMAT: NtStatus = 0xC000_007Bu32 as i32;
pub const STATUS_NOT_SUPPORTED: NtStatus = 0xC000_00BBu32 as i32;
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = 0xC000_0010u32 as i32;
pub const RTL_USER_PROCESS_PARAMETERS_NORMALIZED: u32 = 0x0000_0001;

pub const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
pub const SYNCHRONIZE: AccessMask = 0x0010_0000;
pub const EVENT_QUERY_STATE: AccessMask = 0x0001;
pub const EVENT_MODIFY_STATE: AccessMask = 0x0002;
pub const FILE_READ_DATA: AccessMask = 0x0001;
pub const FILE_WRITE_DATA: AccessMask = 0x0002;
pub const FILE_GENERIC_READ: AccessMask = 0x0012_0089;
pub const FILE_GENERIC_WRITE: AccessMask = 0x0012_0116;
pub const SECTION_MAP_READ: AccessMask = 0x0004;
pub const SECTION_MAP_WRITE: AccessMask = 0x0002;
pub const SECTION_MAP_EXECUTE: AccessMask = 0x0008;
pub const SECTION_ALL_ACCESS: AccessMask = 0x000F_001F;
pub const PROCESS_ALL_ACCESS: AccessMask = 0x001F_FFFF;
pub const THREAD_ALL_ACCESS: AccessMask = 0x001F_FFFF;

pub const SEC_IMAGE: u32 = 0x0100_0000;
pub const SEC_COMMIT: u32 = 0x0800_0000;

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_RELEASE: u32 = 0x8000;
pub const MEM_FREE: u32 = 0x10000;
pub const MEM_PRIVATE: u32 = 0x20000;
pub const MEM_MAPPED: u32 = 0x40000;
pub const MEM_IMAGE: u32 = 0x1000000;

pub const FILE_SUPERSEDE: u32 = 0x0000_0000;
pub const FILE_OPEN: u32 = 0x0000_0001;
pub const FILE_CREATE: u32 = 0x0000_0002;
pub const FILE_OPEN_IF: u32 = 0x0000_0003;
pub const FILE_OVERWRITE: u32 = 0x0000_0004;
pub const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;

pub const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
pub const FILE_STANDARD_INFORMATION_CLASS: u32 = 5;
pub const FILE_POSITION_INFORMATION_CLASS: u32 = 14;
pub const FILE_NAME_INFORMATION_CLASS: u32 = 9;
pub const MEMORY_BASIC_INFORMATION_CLASS: u32 = 0;
pub const FILE_FS_SIZE_INFORMATION_CLASS: u32 = 3;
pub const FILE_FS_DEVICE_INFORMATION_CLASS: u32 = 4;
pub const FILE_FS_ATTRIBUTE_INFORMATION_CLASS: u32 = 5;
pub const FILE_DEVICE_DISK: u32 = 0x00000007;
pub const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x00000001;
pub const FILE_CASE_PRESERVED_NAMES: u32 = 0x00000002;

pub const EVENT_TYPE_NOTIFICATION: u32 = 0;
pub const EVENT_TYPE_SYNCHRONIZATION: u32 = 1;

pub const SECTION_INHERIT_VIEW_SHARE: u32 = 1;
pub const SECTION_INHERIT_VIEW_UNMAP: u32 = 2;

pub const SYSCALL_NT_CLOSE: usize = 0;
pub const SYSCALL_NT_QUERY_INFORMATION_PROCESS: usize = 1;
pub const SYSCALL_NT_QUERY_INFORMATION_FILE: usize = 2;
pub const SYSCALL_NT_READ_FILE: usize = 3;
pub const SYSCALL_NT_WRITE_FILE: usize = 4;
pub const SYSCALL_NT_CREATE_FILE: usize = 5;
pub const SYSCALL_NT_OPEN_FILE: usize = 6;
pub const SYSCALL_NT_CREATE_SECTION: usize = 7;
pub const SYSCALL_NT_MAP_VIEW_OF_SECTION: usize = 8;
pub const SYSCALL_NT_UNMAP_VIEW_OF_SECTION: usize = 9;
pub const SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY: usize = 10;
pub const SYSCALL_NT_FREE_VIRTUAL_MEMORY: usize = 11;
pub const SYSCALL_NT_PROTECT_VIRTUAL_MEMORY: usize = 12;
pub const SYSCALL_NT_CREATE_EVENT: usize = 13;
pub const SYSCALL_NT_SET_EVENT: usize = 14;
pub const SYSCALL_NT_WAIT_FOR_SINGLE_OBJECT: usize = 15;
pub const SYSCALL_NT_CREATE_USER_PROCESS: usize = 16;
pub const SYSCALL_NT_TERMINATE_PROCESS: usize = 17;
pub const SYSCALL_NT_TERMINATE_THREAD: usize = 18;
pub const SYSCALL_NT_DELAY_EXECUTION: usize = 19;
pub const SYSCALL_NT_QUERY_SYSTEM_TIME: usize = 20;
pub const SYSCALL_NT_OPEN_SECTION: usize = 21;
pub const SYSCALL_NT_DEVICE_IO_CONTROL_FILE: usize = 22;
pub const SYSCALL_NT_QUERY_VIRTUAL_MEMORY: usize = 23;
pub const SYSCALL_NT_YIELD_EXECUTION: usize = 24;
pub const SYSCALL_NT_CLEAR_EVENT: usize = 25;
pub const SYSCALL_NT_RESET_EVENT: usize = 26;
pub const SYSCALL_NT_CREATE_THREAD_EX: usize = 27;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MemoryBasicInformation {
    pub base_address: usize,
    pub allocation_base: usize,
    pub allocation_protect: u32,
    pub partition_id: u16,
    pub shared_reserved: u16,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub type_: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: Handle,
    pub object_name: *const UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *const u8,
    pub security_quality_of_service: *const u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoStatusBlock {
    pub status: NtStatus,
    pub information: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ClientId {
    pub unique_process: usize,
    pub unique_thread: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcessBasicInformation {
    pub reserved1: usize,
    pub peb_base_address: usize,
    pub reserved2: [usize; 2],
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileStandardInformation {
    pub allocation_size: i64,
    pub end_of_file: i64,
    pub number_of_links: u32,
    pub delete_pending: u8,
    pub directory: u8,
    pub reserved: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FilePositionInformation {
    pub current_byte_offset: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CurDir {
    pub dos_path: UnicodeString,
    pub handle: Handle,
}

impl Default for CurDir {
    fn default() -> Self {
        Self {
            dos_path: UnicodeString::default(),
            handle: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlUserProcessParameters {
    pub maximum_length: u32,
    pub length: u32,
    pub flags: u32,
    pub debug_flags: u32,
    pub console_handle: usize,
    pub console_flags: u32,
    pub padding0: u32,
    pub standard_input: usize,
    pub standard_output: usize,
    pub standard_error: usize,
    pub current_directory: CurDir,
    pub dll_path: UnicodeString,
    pub image_path_name: UnicodeString,
    pub command_line: UnicodeString,
    pub environment: usize,
}

impl Default for RtlUserProcessParameters {
    fn default() -> Self {
        Self {
            maximum_length: core::mem::size_of::<Self>() as u32,
            length: core::mem::size_of::<Self>() as u32,
            flags: 0,
            debug_flags: 0,
            console_handle: 0,
            console_flags: 0,
            padding0: 0,
            standard_input: 0,
            standard_output: 0,
            standard_error: 0,
            current_directory: CurDir::default(),
            dll_path: UnicodeString::default(),
            image_path_name: UnicodeString::default(),
            command_line: UnicodeString::default(),
            environment: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Peb {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub spare: u8,
    pub mutant: usize,
    pub image_base_address: usize,
    pub ldr: usize,
    pub process_parameters: *mut RtlUserProcessParameters,
    pub sub_system_data: usize,
    pub process_heap: usize,
    pub fast_peb_lock: usize,
    pub atl_thunk_slist_ptr: usize,
    pub ifeo_key: usize,
    pub cross_process_flags: u32,
    pub padding0: u32,
    pub kernel_callback_table: usize,
    pub system_reserved: u32,
    pub atl_thunk_slist_ptr32: u32,
    pub api_set_map: usize,
    pub tls_expansion_counter: u32,
    pub padding1: u32,
    pub tls_bitmap: usize,
    pub tls_bitmap_bits: [u32; 2],
    pub read_only_shared_memory_base: usize,
    pub shared_data: usize,
    pub read_only_static_server_data: usize,
    pub ansi_code_page_data: usize,
    pub oem_code_page_data: usize,
    pub unicode_case_table_data: usize,
    pub number_of_processors: u32,
    pub nt_global_flag: u32,
    pub critical_section_timeout: i64,
    pub heap_segment_reserve: usize,
    pub heap_segment_commit: usize,
    pub heap_decommit_total_free_threshold: usize,
    pub heap_decommit_free_block_threshold: usize,
    pub number_of_heaps: u32,
    pub maximum_number_of_heaps: u32,
    pub process_heaps: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PebLdrData {
    pub length: u32,
    pub initialized: u8,
    pub reserved: [u8; 3],
    pub ss_handle: usize,
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LdrDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    pub dll_base: usize,
    pub entry_point: usize,
    pub size_of_image: u32,
    pub reserved: u32,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Teb {
    pub nt_tib_exception_list: usize,
    pub nt_tib_stack_base: usize,
    pub nt_tib_stack_limit: usize,
    pub nt_tib_sub_system_tib: usize,
    pub nt_tib_fiber_data: usize,
    pub nt_tib_arbitrary_user_pointer: usize,
    pub nt_tib_self: *mut Teb,
    pub environment_pointer: usize,
    pub client_id: ClientId,
    pub active_rpc_handle: usize,
    pub thread_local_storage_pointer: usize,
    pub process_environment_block: *mut Peb,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RtlCriticalSection {
    pub debug_info: usize,
    pub lock_count: i32,
    pub recursion_count: i32,
    pub owning_thread: usize,
    pub lock_semaphore: usize,
    pub spin_count: usize,
}

const _: () = {
    assert!(core::mem::offset_of!(RtlUserProcessParameters, image_path_name) == 0x60);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, command_line) == 0x70);
    assert!(core::mem::offset_of!(Peb, process_heap) == 0x30);
    assert!(core::mem::offset_of!(Peb, nt_global_flag) == 0xbc);
    assert!(core::mem::offset_of!(Peb, heap_segment_reserve) == 0xc8);
    assert!(core::mem::offset_of!(Peb, heap_decommit_free_block_threshold) == 0xe0);
    assert!(core::mem::offset_of!(Peb, process_heaps) == 0xf0);
    assert!(core::mem::offset_of!(Teb, process_environment_block) == 0x60);
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Directory,
    SymbolicLink,
    File,
    Key,
    Section,
    Process,
    Thread,
    Event,
}

#[derive(Debug, Clone)]
pub struct FileObject {
    pub path: String,
    pub vfs_handle: i32,
}

#[derive(Debug, Clone)]
pub struct KeyObject {
    pub path: String,
}

#[derive(Debug, Clone, Copy)]
pub struct EventObject {
    pub signaled: bool,
    pub manual_reset: bool,
}

#[derive(Debug, Clone)]
pub struct SectionObject {
    pub nt_path: Option<String>,
    pub path: Option<String>,
    pub protection: u32,
    pub attributes: u32,
    pub size: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessObject {
    pub pid: u32,
    pub signaled: bool,
    pub exit_status: NtStatus,
}

#[derive(Debug, Clone, Copy)]
pub struct ThreadObject {
    pub tid: usize,
    pub pid: u32,
    pub signaled: bool,
    pub exit_status: NtStatus,
}

#[derive(Debug, Clone)]
pub enum ObjectData {
    Directory,
    SymbolicLink { target: String },
    File(FileObject),
    Key(KeyObject),
    Section(SectionObject),
    Process(ProcessObject),
    Thread(ThreadObject),
    Event(EventObject),
}

#[derive(Debug, Clone)]
struct ObjectRecord {
    object_type: ObjectType,
    name: Option<String>,
    refs: usize,
    data: ObjectData,
}

#[derive(Default)]
struct ObjectManager {
    next_id: u32,
    objects: BTreeMap<u32, ObjectRecord>,
    named: BTreeMap<String, u32>,
}

static OBJECTS: Lazy<Mutex<ObjectManager>> = Lazy::new(|| {
    Mutex::new(ObjectManager {
        next_id: 1,
        ..ObjectManager::default()
    })
});

#[derive(Default)]
struct RegistryState {
    loaded: bool,
    system_hive: Option<Hive>,
}

static REGISTRY: Lazy<Mutex<RegistryState>> = Lazy::new(|| Mutex::new(RegistryState::default()));

pub fn init_namespace() {
    let mut objects = OBJECTS.lock();
    if !objects.named.is_empty() {
        return;
    }

    let _ = create_named(&mut objects, "\\", ObjectData::Directory);
    let _ = create_named(&mut objects, "\\Device", ObjectData::Directory);
    let _ = create_named(&mut objects, "\\??", ObjectData::Directory);
    let _ = create_named(&mut objects, "\\Registry", ObjectData::Directory);
    let _ = create_named(&mut objects, "\\Registry\\Machine", ObjectData::Directory);
    let _ = create_named(&mut objects, "\\KnownDlls", ObjectData::Directory);
    let _ = create_named(&mut objects, "\\Device\\Crabfs0", ObjectData::Directory);
    let _ = create_named(
        &mut objects,
        "\\??\\C:",
        ObjectData::SymbolicLink {
            target: "\\Device\\Crabfs0".to_string(),
        },
    );
    let _ = create_named(
        &mut objects,
        "\\SystemRoot",
        ObjectData::SymbolicLink {
            target: "\\??\\C:\\Windows".to_string(),
        },
    );
}

fn create_named(
    objects: &mut ObjectManager,
    name: &str,
    data: ObjectData,
) -> Result<u32, NtStatus> {
    let canonical = canonicalize_nt_path(name);
    if objects.named.contains_key(&canonical) {
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    let id = objects.next_id;
    objects.next_id = id.saturating_add(1);
    let object_type = object_type_of(&data);
    objects.objects.insert(
        id,
        ObjectRecord {
            object_type,
            name: Some(canonical.clone()),
            refs: 1,
            data,
        },
    );
    objects.named.insert(canonical, id);
    Ok(id)
}

fn insert_unnamed(objects: &mut ObjectManager, data: ObjectData) -> u32 {
    let id = objects.next_id;
    objects.next_id = id.saturating_add(1);
    objects.objects.insert(
        id,
        ObjectRecord {
            object_type: object_type_of(&data),
            name: None,
            refs: 1,
            data,
        },
    );
    id
}

fn object_type_of(data: &ObjectData) -> ObjectType {
    match data {
        ObjectData::Directory => ObjectType::Directory,
        ObjectData::SymbolicLink { .. } => ObjectType::SymbolicLink,
        ObjectData::File(_) => ObjectType::File,
        ObjectData::Key(_) => ObjectType::Key,
        ObjectData::Section(_) => ObjectType::Section,
        ObjectData::Process(_) => ObjectType::Process,
        ObjectData::Thread(_) => ObjectType::Thread,
        ObjectData::Event(_) => ObjectType::Event,
    }
}

fn read_file_all(path: &str) -> Result<Vec<u8>, NtStatus> {
    let fd = vfs::open(path, 0).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = vfs::read(fd, &mut buf).map_err(|_| STATUS_UNSUCCESSFUL)?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    let _ = vfs::close(fd);
    Ok(data)
}

fn ensure_system_hive_loaded() -> Result<(), NtStatus> {
    let mut reg = REGISTRY.lock();
    if reg.loaded {
        return Ok(());
    }
    let data = read_file_all("/Windows/System32/config/SYSTEM")?;
    let hive = Hive::parse(&data).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    reg.system_hive = Some(hive);
    reg.loaded = true;
    Ok(())
}

fn system_hive_subkey(path: &str) -> Option<String> {
    let canonical = canonicalize_nt_path(path);
    let lower = canonical.to_ascii_lowercase();
    let prefix = "\\registry\\machine\\system";
    if lower == prefix {
        return Some(String::new());
    }
    if !lower.starts_with(prefix) {
        return None;
    }
    let mut rest = &canonical[prefix.len()..];
    while rest.starts_with('\\') {
        rest = &rest[1..];
    }
    Some(rest.to_string())
}

pub fn open_key(path: &str) -> Result<u32, NtStatus> {
    init_namespace();
    ensure_system_hive_loaded()?;
    let Some(subkey) = system_hive_subkey(path) else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let reg = REGISTRY.lock();
    let Some(hive) = reg.system_hive.as_ref() else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    if !hive.has_key(&subkey) {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    drop(reg);
    let mut objects = OBJECTS.lock();
    Ok(insert_unnamed(
        &mut objects,
        ObjectData::Key(KeyObject {
            path: canonicalize_nt_path(path),
        }),
    ))
}

pub fn query_key_value(object_id: u32, value_name: &str) -> Result<(u32, Vec<u8>), NtStatus> {
    ensure_system_hive_loaded()?;
    let key_path = {
        let objects = OBJECTS.lock();
        let Some(record) = objects.objects.get(&object_id) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        match &record.data {
            ObjectData::Key(key) => key.path.clone(),
            _ => return Err(STATUS_OBJECT_TYPE_MISMATCH),
        }
    };
    let Some(subkey) = system_hive_subkey(&key_path) else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let reg = REGISTRY.lock();
    let Some(hive) = reg.system_hive.as_ref() else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let Some(value) = hive.query_value(&subkey, value_name) else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    Ok((value.ty, value.data.clone()))
}

pub fn object_name(object_id: u32) -> Result<String, NtStatus> {
    let objects = OBJECTS.lock();
    let Some(record) = objects.objects.get(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    if let Some(name) = &record.name {
        return Ok(name.clone());
    }
    match &record.data {
        ObjectData::Key(key) => Ok(key.path.clone()),
        _ => Err(STATUS_OBJECT_NAME_NOT_FOUND),
    }
}

pub fn create_file(path: String, vfs_handle: i32) -> u32 {
    let mut objects = OBJECTS.lock();
    insert_unnamed(
        &mut objects,
        ObjectData::File(FileObject { path, vfs_handle }),
    )
}

pub fn create_event(manual_reset: bool, initial_state: bool) -> u32 {
    let mut objects = OBJECTS.lock();
    insert_unnamed(
        &mut objects,
        ObjectData::Event(EventObject {
            signaled: initial_state,
            manual_reset,
        }),
    )
}

pub fn create_section(
    nt_path: Option<String>,
    path: Option<String>,
    protection: u32,
    attributes: u32,
    size: u64,
) -> u32 {
    let mut objects = OBJECTS.lock();
    insert_unnamed(
        &mut objects,
        ObjectData::Section(SectionObject {
            nt_path,
            path,
            protection,
            attributes,
            size,
        }),
    )
}

pub fn create_named_section(
    name: &str,
    nt_path: Option<String>,
    path: Option<String>,
    protection: u32,
    attributes: u32,
    size: u64,
) -> Result<u32, NtStatus> {
    let mut objects = OBJECTS.lock();
    create_named(
        &mut objects,
        name,
        ObjectData::Section(SectionObject {
            nt_path,
            path,
            protection,
            attributes,
            size,
        }),
    )
}

pub fn open_section(name: &str) -> Result<u32, NtStatus> {
    init_namespace();
    let canonical = canonicalize_nt_path(name);
    {
        let mut objects = OBJECTS.lock();
        if let Some(id) = objects.named.get(&canonical).copied() {
            let Some(record) = objects.objects.get_mut(&id) else {
                return Err(STATUS_OBJECT_NAME_NOT_FOUND);
            };
            if record.object_type != ObjectType::Section {
                return Err(STATUS_OBJECT_TYPE_MISMATCH);
            }
            record.refs = record.refs.saturating_add(1);
            return Ok(id);
        }
    }

    if canonical.starts_with("\\KnownDlls\\") {
        let dll_name = canonical
            .rsplit('\\')
            .next()
            .filter(|name| !name.is_empty())
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let nt_path = canonicalize_nt_path(&format!("\\SystemRoot\\System32\\{}", dll_name));
        let path = resolve_nt_path(&nt_path)?;
        let id = create_named_section(
            &canonical,
            Some(nt_path),
            Some(path),
            PAGE_EXECUTE_READ,
            SEC_IMAGE,
            0,
        )?;
        retain(id)?;
        return Ok(id);
    }

    Err(STATUS_OBJECT_NAME_NOT_FOUND)
}

pub fn open_directory(name: &str) -> Result<u32, NtStatus> {
    init_namespace();
    let canonical = canonicalize_nt_path(name);
    let mut objects = OBJECTS.lock();
    let Some(id) = objects.named.get(&canonical).copied() else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let Some(record) = objects.objects.get_mut(&id) else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    if record.object_type != ObjectType::Directory {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    record.refs = record.refs.saturating_add(1);
    Ok(id)
}

pub fn open_symbolic_link(name: &str) -> Result<u32, NtStatus> {
    init_namespace();
    let canonical = canonicalize_nt_path(name);
    let mut objects = OBJECTS.lock();
    let Some(id) = objects.named.get(&canonical).copied() else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let Some(record) = objects.objects.get_mut(&id) else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    if record.object_type != ObjectType::SymbolicLink {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    record.refs = record.refs.saturating_add(1);
    Ok(id)
}

pub fn query_symbolic_link_target(object_id: u32) -> Result<String, NtStatus> {
    let objects = OBJECTS.lock();
    let Some(record) = objects.objects.get(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    match &record.data {
        ObjectData::SymbolicLink { target } => Ok(target.clone()),
        _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

fn object_type_name(kind: ObjectType) -> &'static str {
    match kind {
        ObjectType::Directory => "Directory",
        ObjectType::SymbolicLink => "SymbolicLink",
        ObjectType::File => "File",
        ObjectType::Key => "Key",
        ObjectType::Section => "Section",
        ObjectType::Process => "Process",
        ObjectType::Thread => "Thread",
        ObjectType::Event => "Event",
    }
}

pub fn query_directory_entries(object_id: u32) -> Result<Vec<(String, String)>, NtStatus> {
    let objects = OBJECTS.lock();
    let Some(record) = objects.objects.get(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    if record.object_type != ObjectType::Directory {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let Some(dir_path) = record.name.as_ref() else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };

    let mut entries: BTreeMap<String, String> = BTreeMap::new();
    if dir_path == "\\" {
        for (name, child_id) in &objects.named {
            if name == "\\" {
                continue;
            }
            let Some(rest) = name.strip_prefix('\\') else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            let child = rest.split('\\').next().unwrap_or("");
            if child.is_empty() {
                continue;
            }
            let full = format!("\\{}", child);
            let Some(child_record) = objects.objects.get(child_id) else {
                continue;
            };
            entries.insert(
                child.to_string(),
                object_type_name(child_record.object_type).to_string(),
            );
            let _ = full;
        }
    } else {
        let prefix = format!("{dir_path}\\");
        for (name, child_id) in &objects.named {
            if !name.starts_with(&prefix) {
                continue;
            }
            let rest = &name[prefix.len()..];
            if rest.is_empty() {
                continue;
            }
            let child = rest.split('\\').next().unwrap_or("");
            if child.is_empty() {
                continue;
            }
            let Some(child_record) = objects.objects.get(child_id) else {
                continue;
            };
            entries.insert(
                child.to_string(),
                object_type_name(child_record.object_type).to_string(),
            );
        }
    }
    Ok(entries.into_iter().collect())
}

pub fn create_process(pid: u32) -> u32 {
    let mut objects = OBJECTS.lock();
    insert_unnamed(
        &mut objects,
        ObjectData::Process(ProcessObject {
            pid,
            signaled: false,
            exit_status: STATUS_PENDING,
        }),
    )
}

pub fn create_thread(pid: u32, tid: usize) -> u32 {
    let mut objects = OBJECTS.lock();
    insert_unnamed(
        &mut objects,
        ObjectData::Thread(ThreadObject {
            pid,
            tid,
            signaled: false,
            exit_status: STATUS_PENDING,
        }),
    )
}

pub fn retain(object_id: u32) -> Result<(), NtStatus> {
    let mut objects = OBJECTS.lock();
    let Some(record) = objects.objects.get_mut(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    record.refs = record.refs.saturating_add(1);
    Ok(())
}

pub fn release(object_id: u32) -> Result<(), NtStatus> {
    let mut objects = OBJECTS.lock();
    let Some(record) = objects.objects.get_mut(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    if record.refs > 1 {
        record.refs -= 1;
        return Ok(());
    }
    let name = record.name.clone();
    let data = record.data.clone();
    objects.objects.remove(&object_id);
    if let Some(name) = name {
        objects.named.remove(&name);
    }
    drop(objects);
    if let ObjectData::File(file) = data {
        let _ = vfs::close(file.vfs_handle);
    }
    Ok(())
}

pub fn object_type(object_id: u32) -> Result<ObjectType, NtStatus> {
    let objects = OBJECTS.lock();
    objects
        .objects
        .get(&object_id)
        .map(|record| record.object_type)
        .ok_or(STATUS_INVALID_HANDLE)
}

pub fn with_file<T>(object_id: u32, f: impl FnOnce(&FileObject) -> T) -> Result<T, NtStatus> {
    let objects = OBJECTS.lock();
    let Some(record) = objects.objects.get(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    match &record.data {
        ObjectData::File(file) => Ok(f(file)),
        _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

pub fn with_section<T>(object_id: u32, f: impl FnOnce(&SectionObject) -> T) -> Result<T, NtStatus> {
    let objects = OBJECTS.lock();
    let Some(record) = objects.objects.get(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    match &record.data {
        ObjectData::Section(section) => Ok(f(section)),
        _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

pub fn with_process<T>(object_id: u32, f: impl FnOnce(&ProcessObject) -> T) -> Result<T, NtStatus> {
    let objects = OBJECTS.lock();
    let Some(record) = objects.objects.get(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    match &record.data {
        ObjectData::Process(process) => Ok(f(process)),
        _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

pub fn with_process_mut<T>(
    object_id: u32,
    f: impl FnOnce(&mut ProcessObject) -> T,
) -> Result<T, NtStatus> {
    let mut objects = OBJECTS.lock();
    let Some(record) = objects.objects.get_mut(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    match &mut record.data {
        ObjectData::Process(process) => Ok(f(process)),
        _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

pub fn with_thread<T>(object_id: u32, f: impl FnOnce(&ThreadObject) -> T) -> Result<T, NtStatus> {
    let objects = OBJECTS.lock();
    let Some(record) = objects.objects.get(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    match &record.data {
        ObjectData::Thread(thread) => Ok(f(thread)),
        _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

pub fn with_thread_mut<T>(
    object_id: u32,
    f: impl FnOnce(&mut ThreadObject) -> T,
) -> Result<T, NtStatus> {
    let mut objects = OBJECTS.lock();
    let Some(record) = objects.objects.get_mut(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    match &mut record.data {
        ObjectData::Thread(thread) => Ok(f(thread)),
        _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

pub fn with_event_mut<T>(
    object_id: u32,
    f: impl FnOnce(&mut EventObject) -> T,
) -> Result<T, NtStatus> {
    let mut objects = OBJECTS.lock();
    let Some(record) = objects.objects.get_mut(&object_id) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    match &mut record.data {
        ObjectData::Event(event) => Ok(f(event)),
        _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

pub fn resolve_nt_path(input: &str) -> Result<String, NtStatus> {
    init_namespace();
    let canonical = canonicalize_nt_path(input);
    if canonical.is_empty() {
        return Err(STATUS_OBJECT_PATH_NOT_FOUND);
    }

    let resolved = resolve_named_path(&canonical, 0)?;
    if let Some(rest) = resolved.strip_prefix("\\Device\\Crabfs0") {
        let rest = rest.replace('\\', "/");
        if rest.is_empty() {
            return Ok("/".to_string());
        }
        if rest.starts_with('/') {
            return Ok(rest);
        }
        return Ok(format!("/{}", rest));
    }

    Err(STATUS_OBJECT_PATH_NOT_FOUND)
}

fn resolve_named_path(path: &str, depth: usize) -> Result<String, NtStatus> {
    if depth > 16 {
        return Err(STATUS_OBJECT_PATH_NOT_FOUND);
    }
    let objects = OBJECTS.lock();
    if let Some(id) = objects.named.get(path).copied() {
        if let Some(record) = objects.objects.get(&id) {
            if let ObjectData::SymbolicLink { target } = &record.data {
                let target = target.clone();
                drop(objects);
                return resolve_named_path(&target, depth + 1);
            }
            return Ok(path.to_string());
        }
    }

    let mut best_prefix = None;
    for prefix in objects.named.keys() {
        if path == prefix || !path.starts_with(prefix) {
            continue;
        }
        let boundary = path.as_bytes().get(prefix.len()).copied();
        if boundary != Some(b'\\') {
            continue;
        }
        if best_prefix
            .as_ref()
            .is_none_or(|existing: &&String| prefix.len() > existing.len())
        {
            best_prefix = Some(prefix);
        }
    }

    let Some(prefix) = best_prefix.cloned() else {
        return Ok(path.to_string());
    };
    let id = objects.named[&prefix];
    let Some(record) = objects.objects.get(&id) else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let suffix = &path[prefix.len()..];
    match &record.data {
        ObjectData::SymbolicLink { target } => {
            let next = format!("{}{}", target, suffix);
            drop(objects);
            resolve_named_path(&next, depth + 1)
        }
        _ => Ok(path.to_string()),
    }
}

pub fn canonicalize_nt_path(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let mut path = input.replace('/', "\\");
    if let Some(rest) = path.strip_prefix("\\\\?\\") {
        path = format!("\\??\\{}", rest);
    }
    if path.len() >= 2 && path.as_bytes()[1] == b':' && path.as_bytes()[0].is_ascii_alphabetic() {
        path = format!("\\??\\{}", path);
    } else if !path.starts_with('\\') {
        path = format!("\\{}", path);
    }
    while path.contains("\\\\") {
        path = path.replace("\\\\", "\\");
    }
    if path.len() > 1 && path.ends_with('\\') {
        path.pop();
    }
    path
}
