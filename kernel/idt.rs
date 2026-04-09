use crate::println;
use pic8259::ChainedPics;
use spin::Lazy;
use x86_64::instructions::port::Port;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use x86_64::VirtAddr;

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: Lazy<spin::Mutex<ChainedPics>> =
    Lazy::new(|| spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) }));

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }
}

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.divide_error.set_handler_fn(divide_error_handler);
    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
    idt.general_protection_fault
        .set_handler_fn(general_protection_fault_handler);
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(crate::gdt::DOUBLE_FAULT_IST_INDEX);
    }
    unsafe {
        idt[InterruptIndex::Timer as u8]
            .set_handler_addr(VirtAddr::new(crate::process::timer_handler_addr() as u64));
    }
    idt[InterruptIndex::Keyboard as u8].set_handler_fn(keyboard_interrupt_handler);
    idt[255].set_handler_fn(apic_spurious_interrupt_handler);
    unsafe {
        idt.page_fault
            .set_handler_fn(page_fault_handler)
            .set_stack_index(crate::gdt::DOUBLE_FAULT_IST_INDEX);
    }
    idt
});

pub fn init() {
    IDT.load();
    unsafe {
        PICS.lock().initialize();
        // Unmask all interrupts on both PICs
        Port::<u8>::new(0x21).write(0x00);
        Port::<u8>::new(0xA1).write(0x00);
    };
}

pub fn load_local() {
    IDT.load();
}

extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    handle_fault("DIVIDE ERROR", &stack_frame, None, 136);
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    handle_fault("INVALID OPCODE", &stack_frame, None, 132);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    handle_fault(
        "GENERAL PROTECTION FAULT",
        &stack_frame,
        Some(format_args!("Error Code: {:#x}", error_code)),
        139,
    );
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: x86_64::structures::idt::PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;
    let fault_addr = Cr2::read().expect("failed to read CR2");
    if is_user_fault(&stack_frame)
        && (0x7ffe_0000..0x7ffe_1000).contains(&fault_addr.as_u64())
        && crate::user::enable_user_shared_data_page()
    {
        return;
    }
    if let Ok(true) = crate::reclaim::handle_page_fault(fault_addr) {
        return;
    }
    handle_fault(
        "PAGE FAULT",
        &stack_frame,
        Some(format_args!(
            "Accessed Address: {:?}\nError Code: {:?}",
            fault_addr, error_code
        )),
        139,
    );
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    let mut port = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };
    println!("KEYBOARD: 0x{:02x}", scancode);

    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}

extern "x86-interrupt" fn apic_spurious_interrupt_handler(_stack_frame: InterruptStackFrame) {
    crate::apic::complete_interrupt();
}

fn handle_fault(
    name: &str,
    stack_frame: &InterruptStackFrame,
    extra: Option<core::fmt::Arguments<'_>>,
    status: i32,
) -> ! {
    if is_user_fault(stack_frame) {
        log_user_fault(name, stack_frame, extra);
        crate::user::exit_current(status);
        crate::process::on_task_exit()
    } else {
        log_kernel_fault(name, stack_frame, extra);
        panic!("{}", name);
    }
}

fn is_user_fault(stack_frame: &InterruptStackFrame) -> bool {
    (stack_frame.code_segment.0 & 0x3) == 0x3
}

fn log_user_fault(
    name: &str,
    stack_frame: &InterruptStackFrame,
    extra: Option<core::fmt::Arguments<'_>>,
) {
    println!("USER EXCEPTION: {}", name);
    println!(
        "pid={} task={} exe={}",
        crate::user::pid(),
        crate::process::current_task_id().unwrap_or(0),
        crate::user::current_init_path()
            .as_deref()
            .unwrap_or("<unknown>")
    );
    if let Some(extra) = extra {
        println!("{}", extra);
    }
    println!(
        "rip={:?} rsp={:?} cs={:#x} ss={:#x} rflags={:#x}",
        stack_frame.instruction_pointer,
        stack_frame.stack_pointer,
        stack_frame.code_segment.0,
        stack_frame.stack_segment.0,
        stack_frame.cpu_flags.bits()
    );
    let rip = stack_frame.instruction_pointer.as_u64();
    if let Some((module, base, offset)) = crate::user::describe_user_rip(rip) {
        println!(
            "rip module={} base={:#x} offset={:#x}",
            module, base, offset
        );
    }
    if let Some(bytes) = crate::user::read_user_rip_bytes(rip, 8) {
        println!(
            "rip bytes={:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            bytes.first().copied().unwrap_or(0),
            bytes.get(1).copied().unwrap_or(0),
            bytes.get(2).copied().unwrap_or(0),
            bytes.get(3).copied().unwrap_or(0),
            bytes.get(4).copied().unwrap_or(0),
            bytes.get(5).copied().unwrap_or(0),
            bytes.get(6).copied().unwrap_or(0),
            bytes.get(7).copied().unwrap_or(0),
        );
    }
    println!("{:#?}", stack_frame);
}

fn log_kernel_fault(
    name: &str,
    stack_frame: &InterruptStackFrame,
    extra: Option<core::fmt::Arguments<'_>>,
) {
    println!("EXCEPTION: {}", name);
    if let Some(extra) = extra {
        println!("{}", extra);
    }
    println!("{:#?}", stack_frame);
}
