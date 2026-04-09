extern crate alloc;

use crate::{gdt, nt, println, user};
use core::sync::atomic::{AtomicUsize, Ordering};
use x86_64::instructions::segmentation::Segment;
use x86_64::registers::model_specific::{
    Efer, EferFlags, GsBase, KernelGsBase, LStar, SFMask, Star,
};
use x86_64::registers::rflags::RFlags;
use x86_64::VirtAddr;

use crate::smp::MAX_CPUS;

#[repr(C)]
struct SyscallCpuLocal {
    kernel_rsp: usize,
    user_rsp: usize,
    return_rax: usize,
}

const SYSCALL_STACK_SIZE: usize = 4096 * 16;

#[repr(align(16))]
struct SyscallStack([u8; SYSCALL_STACK_SIZE]);

static mut SYSCALL_CPU_LOCALS: [SyscallCpuLocal; MAX_CPUS] = [const {
    SyscallCpuLocal {
        kernel_rsp: 0,
        user_rsp: 0,
        return_rax: 0,
    }
}; MAX_CPUS];

static mut SYSCALL_STACKS: [SyscallStack; MAX_CPUS] =
    [const { SyscallStack([0; SYSCALL_STACK_SIZE]) }; MAX_CPUS];
static UNKNOWN_SYSCALL_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static FAILED_SYSCALL_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
pub struct SyscallFrame {
    pub nr: usize,
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub user_rsp: usize,
    pub rcx: usize,
    pub r11: usize,
    pub rdi: usize,
    pub rsi: usize,
    pub rdx: usize,
    pub r10: usize,
    pub r8: usize,
    pub r9: usize,
    pub rbp: usize,
    pub rbx: usize,
    pub r12: usize,
    pub r13: usize,
    pub r14: usize,
    pub r15: usize,
}

pub fn init() {
    init_for_cpu(0);
}

pub fn init_for_cpu(cpu_id: usize) {
    let handler_addr = syscall_handler as *const () as usize;
    unsafe {
        let cpu = cpu_id.min(MAX_CPUS.saturating_sub(1));
        let stack_top =
            core::ptr::addr_of!(SYSCALL_STACKS[cpu]) as *const u8 as usize + SYSCALL_STACK_SIZE;
        SYSCALL_CPU_LOCALS[cpu].kernel_rsp = stack_top;
        let cpu_local = VirtAddr::from_ptr(core::ptr::addr_of!(SYSCALL_CPU_LOCALS[cpu]));
        KernelGsBase::write(cpu_local);
        GsBase::write(VirtAddr::new(0));
    }
    Star::write(
        gdt::user_code_selector(),
        gdt::user_data_selector(),
        x86_64::instructions::segmentation::CS::get_reg(),
        x86_64::instructions::segmentation::SS::get_reg(),
    )
    .expect("invalid syscall STAR selectors");
    LStar::write(VirtAddr::new(handler_addr as u64));
    SFMask::write(
        RFlags::INTERRUPT_FLAG
            | RFlags::TRAP_FLAG
            | RFlags::DIRECTION_FLAG
            | RFlags::ALIGNMENT_CHECK
            | RFlags::NESTED_TASK,
    );
    unsafe {
        Efer::update(|efer| efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS));
    }
}

pub fn set_kernel_stack_top(stack_top: usize) {
    unsafe {
        let cpu = crate::smp::current_cpu().min(MAX_CPUS.saturating_sub(1));
        SYSCALL_CPU_LOCALS[cpu].kernel_rsp = stack_top;
    }
}

#[unsafe(naked)]
pub unsafe extern "C" fn syscall_handler() -> ! {
    core::arch::naked_asm!(
        "swapgs",
        "mov %rsp, %gs:8",
        "mov %gs:0, %rsp",
        "sub $176, %rsp",
        "mov %rax, 0(%rsp)",
        "mov %rdi, 8(%rsp)",
        "mov %rsi, 16(%rsp)",
        "mov %rdx, 24(%rsp)",
        "mov %r10, 32(%rsp)",
        "mov %r8, 40(%rsp)",
        "mov %r9, 48(%rsp)",
        "mov %gs:8, %rax",
        "mov %rax, 56(%rsp)",
        "mov %rcx, 64(%rsp)",
        "mov %r11, 72(%rsp)",
        "mov %rdi, 80(%rsp)",
        "mov %rsi, 88(%rsp)",
        "mov %rdx, 96(%rsp)",
        "mov %r10, 104(%rsp)",
        "mov %r8, 112(%rsp)",
        "mov %r9, 120(%rsp)",
        "mov %rbp, 128(%rsp)",
        "mov %rbx, 136(%rsp)",
        "mov %r12, 144(%rsp)",
        "mov %r13, 152(%rsp)",
        "mov %r14, 160(%rsp)",
        "mov %r15, 168(%rsp)",
        "mov %rsp, %rdi",
        "call syscall_dispatch",
        "mov %rax, %gs:16",
        "mov 168(%rsp), %r15",
        "mov 160(%rsp), %r14",
        "mov 152(%rsp), %r13",
        "mov 144(%rsp), %r12",
        "mov 136(%rsp), %rbx",
        "mov 128(%rsp), %rbp",
        "mov 120(%rsp), %r9",
        "mov 112(%rsp), %r8",
        "mov 104(%rsp), %r10",
        "mov 96(%rsp), %rdx",
        "mov 88(%rsp), %rsi",
        "mov 80(%rsp), %rdi",
        "mov 72(%rsp), %r11",
        "mov 64(%rsp), %rcx",
        "mov 56(%rsp), %rsp",
        "mov %gs:16, %rax",
        "swapgs",
        "sysretq",
        options(att_syntax)
    )
}

fn stack_arg(frame: &SyscallFrame, index: usize) -> usize {
    let ptr = (frame.user_rsp + 0x28 + index * core::mem::size_of::<usize>()) as *const usize;
    unsafe { ptr.read_volatile() }
}

#[unsafe(no_mangle)]
extern "sysv64" fn syscall_dispatch(frame: *mut SyscallFrame) -> usize {
    if frame.is_null() {
        return nt::STATUS_INVALID_PARAMETER as usize;
    }
    let frame = unsafe { &*frame };
    let result = match frame.nr {
        // Windows x64 native syscall compatibility for real ntdll stubs.
        4 => user::wait_for_single_object(frame.r10, frame.rdx != 0, frame.r8 as *const i64) as usize,
        6 => user::read_file(
            frame.r10,
            stack_arg(frame, 0) as *mut nt::IoStatusBlock,
            stack_arg(frame, 1) as *mut u8,
            stack_arg(frame, 2),
        ) as usize,
        7 => user::device_io_control_file(
            frame.r10,
            frame.rdx,
            frame.r8 as *mut (),
            frame.r9 as *mut (),
            stack_arg(frame, 0) as *mut nt::IoStatusBlock,
            stack_arg(frame, 1) as u32,
            stack_arg(frame, 2) as *const u8,
            stack_arg(frame, 3) as u32,
            stack_arg(frame, 4) as *mut u8,
            stack_arg(frame, 5) as u32,
        ) as usize,
        8 => user::write_file(
            frame.r10,
            stack_arg(frame, 0) as *mut nt::IoStatusBlock,
            stack_arg(frame, 1) as *const u8,
            stack_arg(frame, 2),
        ) as usize,
        14 => user::set_event(frame.r10, frame.rdx as *mut i32) as usize,
        15 => user::close_handle(frame.r10) as usize,
        17 => user::query_information_file(
            frame.r10,
            frame.rdx as *mut nt::IoStatusBlock,
            frame.r8 as *mut u8,
            frame.r9 as u32,
            stack_arg(frame, 0) as u32,
        ) as usize,
        18 => user::open_key(
            frame.r10 as *mut usize,
            frame.rdx as u32,
            frame.r8 as *const nt::ObjectAttributes,
        ) as usize,
        23 => user::query_value_key(
            frame.r10,
            frame.rdx as *const nt::UnicodeString,
            frame.r8 as u32,
            frame.r9 as *mut u8,
            stack_arg(frame, 0) as u32,
            stack_arg(frame, 1) as *mut u32,
        ) as usize,
        24 if frame.rdx != 0 && frame.r9 != 0 => user::allocate_virtual_memory(
            frame.r10,
            frame.rdx as *mut usize,
            frame.r9 as *mut usize,
            stack_arg(frame, 1) as u32,
        ) as usize,
        25 => user::query_information_process(
            frame.r10,
            frame.rdx as u32,
            frame.r8 as *mut u8,
            frame.r9 as u32,
            stack_arg(frame, 0) as *mut u32,
        ) as usize,
        30 => user::free_virtual_memory(
            frame.r10,
            frame.rdx as *mut usize,
            frame.r8 as *mut usize,
        ) as usize,
        35 => user::query_virtual_memory(
            frame.r10,
            frame.rdx,
            frame.r8 as u32,
            frame.r9 as *mut u8,
            stack_arg(frame, 0),
            stack_arg(frame, 1) as *mut usize,
        ) as usize,
        39 => user::query_information_file(
            frame.r10,
            frame.rdx as *mut nt::IoStatusBlock,
            frame.r8 as *mut u8,
            frame.r9 as u32,
            stack_arg(frame, 0) as u32,
        ) as usize,
        40 => user::map_view_of_section(
            frame.r10,
            frame.rdx,
            frame.r8 as *mut usize,
            stack_arg(frame, 3) as *mut usize,
            stack_arg(frame, 6) as u32,
        ) as usize,
        42 => user::unmap_view_of_section(frame.r10, frame.rdx) as usize,
        // Windows native syscall number for NtTerminateProcess on recent x64 builds.
        44 => user::terminate_process(frame.r10, frame.rdx as i32) as usize,
        51 => user::create_file(
            frame.r10 as *mut usize,
            frame.rdx as u32,
            frame.r8 as *const nt::ObjectAttributes,
            frame.r9 as *mut nt::IoStatusBlock,
        ) as usize,
        52 => user::delay_execution(frame.r10 != 0, frame.rdx as *const i64) as usize,
        // Windows native syscall number for NtQuerySystemInformation on recent x64 builds.
        54 => user::query_system_information(
            frame.r10 as u32,
            frame.rdx as *mut u8,
            frame.r8 as u32,
            frame.r9 as *mut u32,
        ) as usize,
        55 => user::open_section(
            frame.r10 as *mut usize,
            frame.rdx as u32,
            frame.r8 as *const nt::ObjectAttributes,
        ) as usize,
        57 => user::device_io_control_file(
            frame.r10,
            frame.rdx,
            frame.r8 as *mut (),
            frame.r9 as *mut (),
            stack_arg(frame, 0) as *mut nt::IoStatusBlock,
            stack_arg(frame, 1) as u32,
            stack_arg(frame, 2) as *const u8,
            stack_arg(frame, 3) as u32,
            stack_arg(frame, 4) as *mut u8,
            stack_arg(frame, 5) as u32,
        ) as usize,
        62 => user::clear_event(frame.r10) as usize,
        70 => user::yield_execution() as usize,
        72 => user::create_event(
            frame.r10 as *mut usize,
            frame.r9 as u32,
            stack_arg(frame, 0) != 0,
        ) as usize,
        73 => user::query_volume_information_file(
            frame.r10,
            frame.rdx as *mut nt::IoStatusBlock,
            frame.r8 as *mut u8,
            frame.r9 as u32,
            stack_arg(frame, 0) as u32,
        ) as usize,
        74 => user::create_section(
            frame.r10 as *mut usize,
            frame.rdx as u32,
            frame.r8 as *const nt::ObjectAttributes,
            frame.r9 as *const i64,
            stack_arg(frame, 0) as u32,
            stack_arg(frame, 1) as u32,
            stack_arg(frame, 2),
        ) as usize,
        80 => user::protect_virtual_memory(
            frame.r10,
            frame.rdx as *mut usize,
            frame.r8 as *mut usize,
            frame.r9 as u32,
            stack_arg(frame, 0) as *mut u32,
        ) as usize,
        83 => user::terminate_thread(frame.r10, frame.rdx as i32) as usize,
        85 => user::create_file(
            frame.r10 as *mut usize,
            frame.rdx as u32,
            frame.r8 as *const nt::ObjectAttributes,
            frame.r9 as *mut nt::IoStatusBlock,
        ) as usize,
        91 => user::query_system_time(frame.r10 as *mut i64) as usize,
        228 => user::display_string(frame.r10 as *const nt::UnicodeString) as usize,
        88 => user::open_directory_object(
            frame.r10 as *mut usize,
            frame.rdx as u32,
            frame.r8 as *const nt::ObjectAttributes,
        ) as usize,
        312 => user::open_symbolic_link_object(
            frame.r10 as *mut usize,
            frame.rdx as u32,
            frame.r8 as *const nt::ObjectAttributes,
        ) as usize,
        334 => user::query_directory_object(
            frame.r10,
            frame.rdx as *mut u8,
            frame.r8 as u32,
            frame.r9 != 0,
            stack_arg(frame, 0) != 0,
            stack_arg(frame, 1) as *mut u32,
            stack_arg(frame, 2) as *mut u32,
        ) as usize,
        363 => user::query_symbolic_link_object(
            frame.r10,
            frame.rdx as *mut nt::UnicodeString,
            frame.r8 as *mut u32,
        ) as usize,
        nt::SYSCALL_NT_CLOSE => user::close_handle(frame.a0) as usize,
        nt::SYSCALL_NT_QUERY_INFORMATION_PROCESS => user::query_information_process(
            frame.a0,
            frame.a1 as u32,
            frame.a2 as *mut u8,
            frame.a3 as u32,
            frame.a4 as *mut u32,
        ) as usize,
        nt::SYSCALL_NT_QUERY_INFORMATION_FILE => user::query_information_file(
            frame.a0,
            frame.a1 as *mut nt::IoStatusBlock,
            frame.a2 as *mut u8,
            frame.a3 as u32,
            frame.a4 as u32,
        ) as usize,
        nt::SYSCALL_NT_READ_FILE => user::read_file(
            frame.a0,
            stack_arg(frame, 0) as *mut nt::IoStatusBlock,
            stack_arg(frame, 1) as *mut u8,
            stack_arg(frame, 2),
        ) as usize,
        nt::SYSCALL_NT_WRITE_FILE => user::write_file(
            frame.a0,
            stack_arg(frame, 0) as *mut nt::IoStatusBlock,
            stack_arg(frame, 1) as *const u8,
            stack_arg(frame, 2),
        ) as usize,
        nt::SYSCALL_NT_CREATE_FILE => user::create_file(
            frame.a0 as *mut usize,
            frame.a1 as u32,
            frame.a2 as *const nt::ObjectAttributes,
            frame.a3 as *mut nt::IoStatusBlock,
        ) as usize,
        nt::SYSCALL_NT_OPEN_FILE => user::create_file(
            frame.a0 as *mut usize,
            frame.a1 as u32,
            frame.a2 as *const nt::ObjectAttributes,
            frame.a3 as *mut nt::IoStatusBlock,
        ) as usize,
        nt::SYSCALL_NT_CREATE_SECTION => user::create_section(
            frame.a0 as *mut usize,
            frame.a1 as u32,
            frame.a2 as *const nt::ObjectAttributes,
            frame.a3 as *const i64,
            frame.a4 as u32,
            frame.a5 as u32,
            stack_arg(frame, 2),
        ) as usize,
        nt::SYSCALL_NT_MAP_VIEW_OF_SECTION => user::map_view_of_section(
            frame.a0,
            frame.a1,
            frame.a2 as *mut usize,
            stack_arg(frame, 2) as *mut usize,
            stack_arg(frame, 5) as u32,
        ) as usize,
        nt::SYSCALL_NT_UNMAP_VIEW_OF_SECTION => {
            user::unmap_view_of_section(frame.a0, frame.a1) as usize
        }
        nt::SYSCALL_NT_ALLOCATE_VIRTUAL_MEMORY => user::allocate_virtual_memory(
            frame.a0,
            frame.a1 as *mut usize,
            frame.a3 as *mut usize,
            stack_arg(frame, 1) as u32,
        ) as usize,
        nt::SYSCALL_NT_FREE_VIRTUAL_MEMORY => {
            user::free_virtual_memory(frame.a0, frame.a1 as *mut usize, frame.a2 as *mut usize)
                as usize
        }
        nt::SYSCALL_NT_PROTECT_VIRTUAL_MEMORY => user::protect_virtual_memory(
            frame.a0,
            frame.a1 as *mut usize,
            frame.a2 as *mut usize,
            frame.a3 as u32,
            frame.a4 as *mut u32,
        ) as usize,
        nt::SYSCALL_NT_CREATE_EVENT => {
            user::create_event(frame.a0 as *mut usize, frame.a3 as u32, frame.a4 != 0) as usize
        }
        nt::SYSCALL_NT_SET_EVENT => user::set_event(frame.a0, frame.a1 as *mut i32) as usize,
        nt::SYSCALL_NT_WAIT_FOR_SINGLE_OBJECT => {
            user::wait_for_single_object(frame.a0, frame.a1 != 0, frame.a2 as *const i64) as usize
        }
        nt::SYSCALL_NT_CREATE_USER_PROCESS => user::create_user_process(
            frame.a0 as *mut usize,
            frame.a1 as *mut usize,
            stack_arg(frame, 4) as *const nt::RtlUserProcessParameters,
        ) as usize,
        nt::SYSCALL_NT_TERMINATE_PROCESS => {
            user::terminate_process(frame.a0, frame.a1 as i32) as usize
        }
        nt::SYSCALL_NT_TERMINATE_THREAD => {
            user::terminate_thread(frame.a0, frame.a1 as i32) as usize
        }
        nt::SYSCALL_NT_DELAY_EXECUTION => {
            user::delay_execution(frame.a0 != 0, frame.a1 as *const i64) as usize
        }
        nt::SYSCALL_NT_QUERY_SYSTEM_TIME => user::query_system_time(frame.a0 as *mut i64) as usize,
        nt::SYSCALL_NT_OPEN_SECTION => user::open_section(
            frame.a0 as *mut usize,
            frame.a1 as u32,
            frame.a2 as *const nt::ObjectAttributes,
        ) as usize,
        nt::SYSCALL_NT_DEVICE_IO_CONTROL_FILE => user::device_io_control_file(
            frame.a0,
            frame.a1,
            frame.a2 as *mut (),
            frame.a3 as *mut (),
            frame.a4 as *mut nt::IoStatusBlock,
            frame.a5 as u32,
            stack_arg(frame, 0) as *const u8,
            stack_arg(frame, 1) as u32,
            stack_arg(frame, 2) as *mut u8,
            stack_arg(frame, 3) as u32,
        ) as usize,
        nt::SYSCALL_NT_QUERY_VIRTUAL_MEMORY => user::query_virtual_memory(
            frame.a0,
            frame.a1 as usize,
            frame.a2 as u32,
            frame.a3 as *mut u8,
            frame.a4 as usize,
            frame.a5 as *mut usize,
        ) as usize,
        nt::SYSCALL_NT_YIELD_EXECUTION => user::yield_execution() as usize,
        nt::SYSCALL_NT_CLEAR_EVENT => user::clear_event(frame.a0) as usize,
        nt::SYSCALL_NT_RESET_EVENT => user::reset_event(frame.a0, frame.a1 as *mut i32) as usize,
        nt::SYSCALL_NT_CREATE_THREAD_EX => user::create_thread_ex(
            frame.a0 as *mut usize,
            frame.a1 as u32,
            frame.a2 as *const nt::ObjectAttributes,
            frame.a3,
            frame.a4 as usize,
            frame.a5 as usize,
            stack_arg(frame, 0) as u32,
            stack_arg(frame, 1) as usize,
            stack_arg(frame, 2) as usize,
            stack_arg(frame, 3) as usize,
            stack_arg(frame, 4) as *const (),
        ) as usize,
        _ => {
            let seen = UNKNOWN_SYSCALL_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
            if seen < 128 {
                println!(
                    "NT KERNEL: unknown syscall nr={} rcx={:#x} r10={:#x} rdx={:#x} r8={:#x} r9={:#x}",
                    frame.nr,
                    frame.rcx,
                    frame.r10,
                    frame.rdx,
                    frame.r8,
                    frame.r9
                );
            }
            nt::STATUS_NOT_IMPLEMENTED as usize
        }
    };
    if result != nt::STATUS_SUCCESS as usize
        && result != nt::STATUS_TIMEOUT as usize
        && result != nt::STATUS_END_OF_FILE as usize
        && result != nt::STATUS_INVALID_DEVICE_REQUEST as usize
    {
        let seen = FAILED_SYSCALL_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
        if seen < 256 {
            println!(
                "NT KERNEL: syscall failure nr={} status={:#x} rcx={:#x} r10={:#x}",
                frame.nr, result as u32, frame.rcx, frame.r10
            );
        }
    }
    result
}
