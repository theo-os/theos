extern crate alloc;

use crate::smp::MAX_CPUS;
use alloc::boxed::Box;
use alloc::vec::Vec;
use spin::{Lazy, Mutex};
use x86_64::VirtAddr;
use x86_64::instructions::tables::load_tss;
use x86_64::registers::segmentation::{CS, SS, Segment};
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

const STACK_SIZE: usize = 4096 * 5;

struct CpuGdt {
    privilege_stack_top: VirtAddr,
    _privilege_stack: &'static mut [u8; STACK_SIZE],
    _df_stack: &'static mut [u8; STACK_SIZE],
    gdt: GlobalDescriptorTable,
    selectors: Selectors,
}

#[derive(Clone, Copy)]
struct Selectors {
    code_selector: SegmentSelector,
    data_selector: SegmentSelector,
    user_code_selector: SegmentSelector,
    user_data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}

static CPU_GDTS: Lazy<Mutex<Vec<Option<CpuGdt>>>> =
    Lazy::new(|| Mutex::new(core::iter::repeat_with(|| None).take(MAX_CPUS).collect()));

fn build_cpu_gdt() -> CpuGdt {
    let privilege_stack = Box::leak(Box::new([0; STACK_SIZE]));
    let df_stack = Box::leak(Box::new([0; STACK_SIZE]));
    let privilege_stack_top = VirtAddr::from_ptr(privilege_stack.as_ptr()) + STACK_SIZE as u64;

    let tss = Box::leak(Box::new(TaskStateSegment::new()));
    tss.privilege_stack_table[0] = privilege_stack_top;
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        VirtAddr::from_ptr(df_stack.as_ptr()) + STACK_SIZE as u64;
    let tss_ref: &'static TaskStateSegment = &*tss;

    let mut gdt = GlobalDescriptorTable::new();
    let code_selector = gdt.append(Descriptor::kernel_code_segment());
    let data_selector = gdt.append(Descriptor::kernel_data_segment());
    let user_data_selector = gdt.append(Descriptor::user_data_segment());
    let user_code_selector = gdt.append(Descriptor::user_code_segment());
    let tss_selector = gdt.append(Descriptor::tss_segment(tss_ref));

    CpuGdt {
        privilege_stack_top,
        _privilege_stack: privilege_stack,
        _df_stack: df_stack,
        gdt,
        selectors: Selectors {
            code_selector,
            data_selector,
            user_code_selector,
            user_data_selector,
            tss_selector,
        },
    }
}

pub fn init() {
    init_for_cpu(0);
}

pub fn init_for_cpu(cpu_id: usize) {
    let mut gdts = CPU_GDTS.lock();
    if gdts.get(cpu_id).is_none() {
        return;
    }
    if gdts[cpu_id].is_none() {
        gdts[cpu_id] = Some(build_cpu_gdt());
    }
    let cpu = gdts[cpu_id].as_ref().unwrap() as *const CpuGdt;
    drop(gdts);
    let cpu = unsafe { &*cpu };
    cpu.gdt.load();
    unsafe {
        CS::set_reg(cpu.selectors.code_selector);
        SS::set_reg(cpu.selectors.data_selector);
        load_tss(cpu.selectors.tss_selector);
    }
}

fn selectors_for_cpu(cpu_id: usize) -> Selectors {
    let mut gdts = CPU_GDTS.lock();
    if gdts[cpu_id].is_none() {
        gdts[cpu_id] = Some(build_cpu_gdt());
    }
    gdts[cpu_id].as_ref().unwrap().selectors
}

pub fn user_code_selector() -> SegmentSelector {
    selectors_for_cpu(crate::smp::current_cpu()).user_code_selector
}

pub fn user_data_selector() -> SegmentSelector {
    selectors_for_cpu(crate::smp::current_cpu()).user_data_selector
}

pub fn kernel_privilege_stack_top() -> VirtAddr {
    let cpu_id = crate::smp::current_cpu();
    let mut gdts = CPU_GDTS.lock();
    if gdts[cpu_id].is_none() {
        gdts[cpu_id] = Some(build_cpu_gdt());
    }
    gdts[cpu_id].as_ref().unwrap().privilege_stack_top
}
