use crate::smp::MAX_CPUS;
use crate::{apic, ktrace, println};
use alloc::collections::{BTreeMap, vec_deque::VecDeque};
use alloc::vec;
use alloc::vec::Vec;
use core::arch::{asm, global_asm};
use core::array;
use core::cmp::min;
use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Lazy, Mutex};
use x86_64::instructions::segmentation::{CS, SS, Segment};

global_asm!(include_str!("switch.s"), options(att_syntax));

unsafe extern "sysv64" {
    fn restore_task_context(next_ctx: *const SavedTaskContext) -> !;
}

unsafe extern "C" {
    fn timer_interrupt_entry();
}

const KERNEL_STACK_SIZE: usize = 4096 * 16;
const KERNEL_STACK_RESERVE: usize = 4096;
const SCHEDULER_STACK_SIZE: usize = 4096 * 4;
const NUM_CLASSES: usize = 4;
const CLASS_QUANTA: [i64; NUM_CLASSES] = [6, 4, 2, 1];
const CLASS_WEIGHTS: [u64; NUM_CLASSES] = [4, 3, 2, 1];
const RUNNABLE_SCALE: u64 = 1024;
const HOG_UTIL_THRESHOLD: u64 = 896;
const HOG_SLICE_THRESHOLD: u64 = 4;
const WAKE_CREDIT_PER_TICK: u64 = 32;
const MAX_SLEEP_CREDIT: u64 = 256;

#[repr(align(16))]
#[allow(dead_code)]
pub struct AlignedStack([u8; SCHEDULER_STACK_SIZE]);

#[unsafe(no_mangle)]
pub static mut SCHEDULER_STACK: AlignedStack = AlignedStack([0; SCHEDULER_STACK_SIZE]);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SavedTaskContext {
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,
    pub r12: usize,
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rbp: usize,
    pub rdi: usize,
    pub rsi: usize,
    pub rdx: usize,
    pub rcx: usize,
    pub rbx: usize,
    pub rax: usize,
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
    pub rsp: usize,
    pub ss: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,
    Exited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskClass {
    Game = 0,
    Normal = 1,
    Hog = 2,
    Background = 3,
}

impl TaskClass {
    const fn index(self) -> usize {
        self as usize
    }

    const fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Game,
            1 => Self::Normal,
            2 => Self::Hog,
            _ => Self::Background,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuId(pub usize);

#[derive(Debug, Clone, Copy)]
pub struct SchedParams {
    pub class_hint: Option<TaskClass>,
    pub nice: i8,
    pub preferred_cpu: Option<CpuId>,
    pub process_id: u32,
}

impl Default for SchedParams {
    fn default() -> Self {
        Self {
            class_hint: None,
            nice: 0,
            preferred_cpu: None,
            process_id: 0,
        }
    }
}

pub struct Task {
    pub id: usize,
    pub process_id: u32,
    pub thread_id: usize,
    pub state: TaskState,
    pub stack: Vec<u8>,
    pub saved_rsp: usize,
    pub class_hint: Option<TaskClass>,
    pub class: TaskClass,
    pub nice: i8,
    pub preferred_cpu: Option<CpuId>,
    pub last_cpu: CpuId,
    pub runtime_ticks: u64,
    pub runnable_avg: u64,
    pub vruntime: u64,
    pub sleep_credit: u64,
    pub deficit: i64,
    pub slice_ticks: u64,
    pub voluntary_yields: u64,
    pub full_slice_runs: u64,
    pub sleep_started_at: Option<u64>,
    pub queued: bool,
}

impl Task {
    fn stack_end(&self) -> usize {
        align_down(self.stack.as_ptr() as usize + self.stack.len(), 16)
    }

    fn kernel_stack_top(&self) -> usize {
        self.stack_end().saturating_sub(KERNEL_STACK_RESERVE)
    }

    pub fn new(id: usize, thread_id: usize, entry: extern "C" fn() -> !) -> Self {
        Self::with_params(id, thread_id, entry, SchedParams::default())
    }

    pub fn with_params(
        id: usize,
        thread_id: usize,
        entry: extern "C" fn() -> !,
        params: SchedParams,
    ) -> Self {
        let mut task = Self {
            id,
            process_id: params.process_id,
            thread_id,
            state: TaskState::Ready,
            stack: alloc::vec![0; KERNEL_STACK_SIZE],
            saved_rsp: 0,
            class_hint: params.class_hint,
            class: params.class_hint.unwrap_or(TaskClass::Normal),
            nice: params.nice.clamp(-20, 19),
            preferred_cpu: params.preferred_cpu,
            last_cpu: CpuId(0),
            runtime_ticks: 0,
            runnable_avg: 0,
            vruntime: 0,
            sleep_credit: 0,
            deficit: 0,
            slice_ticks: 0,
            voluntary_yields: 0,
            full_slice_runs: 0,
            sleep_started_at: None,
            queued: false,
        };

        let stack_top = task.stack_end();
        // The initial task frame must look like a normal Win64 call site because the
        // UEFI target uses the Microsoft x64 ABI, including 32 bytes of shadow space.
        let call_like_rsp = stack_top - 40;
        let context_rsp = call_like_rsp - size_of::<SavedTaskContext>();
        let cs = usize::from(CS::get_reg().0);
        let ss = usize::from(SS::get_reg().0);

        unsafe {
            (call_like_rsp as *mut usize).write(task_return_trampoline as *const () as usize);

            let context = &mut *(context_rsp as *mut SavedTaskContext);
            *context = SavedTaskContext {
                rip: entry as usize,
                cs,
                rflags: 0x202,
                rsp: call_like_rsp,
                ss,
                ..SavedTaskContext::default()
            };
        }

        task.saved_rsp = context_rsp;
        task
    }

    pub fn with_initial_context(
        id: usize,
        thread_id: usize,
        context: SavedTaskContext,
        params: SchedParams,
    ) -> Self {
        let mut task = Self {
            id,
            process_id: params.process_id,
            thread_id,
            state: TaskState::Ready,
            stack: alloc::vec![0; KERNEL_STACK_SIZE],
            saved_rsp: 0,
            class_hint: params.class_hint,
            class: params.class_hint.unwrap_or(TaskClass::Normal),
            nice: params.nice.clamp(-20, 19),
            preferred_cpu: params.preferred_cpu,
            last_cpu: CpuId(0),
            runtime_ticks: 0,
            runnable_avg: 0,
            vruntime: 0,
            sleep_credit: 0,
            deficit: 0,
            slice_ticks: 0,
            voluntary_yields: 0,
            full_slice_runs: 0,
            sleep_started_at: None,
            queued: false,
        };
        let stack_top = task.stack_end();
        let context_rsp = stack_top - size_of::<SavedTaskContext>();
        unsafe {
            *(context_rsp as *mut SavedTaskContext) = context;
        }
        task.saved_rsp = context_rsp;
        task
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct CpuRunQueue {
    id: CpuId,
    llc_id: usize,
    current_task: Option<usize>,
    class_cursor: usize,
    class_deficits: [i64; NUM_CLASSES],
    queues: [VecDeque<usize>; NUM_CLASSES],
}

impl CpuRunQueue {
    fn new(id: CpuId, llc_id: usize) -> Self {
        Self {
            id,
            llc_id,
            current_task: None,
            class_cursor: 0,
            class_deficits: [0; NUM_CLASSES],
            queues: array::from_fn(|_| VecDeque::new()),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct LlcDomain {
    id: usize,
    cpus: Vec<CpuId>,
}

pub struct Scheduler {
    tasks: Vec<Task>,
    task_lookup: BTreeMap<usize, usize>,
    cpus: Vec<CpuRunQueue>,
    #[allow(dead_code)]
    llc_domains: Vec<LlcDomain>,
    global_tick: u64,
    started: bool,
    next_task_id: usize,
}

static CURRENT_TASK_IDS: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];

fn current_cpu_id() -> CpuId {
    CpuId(crate::smp::current_cpu().min(MAX_CPUS.saturating_sub(1)))
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            task_lookup: BTreeMap::new(),
            cpus: vec![CpuRunQueue::new(CpuId(0), 0)],
            llc_domains: vec![LlcDomain {
                id: 0,
                cpus: vec![CpuId(0)],
            }],
            global_tick: 0,
            started: false,
            next_task_id: 1,
        }
    }

    pub fn add_task(&mut self, mut task: Task) {
        let task_id = task.id;
        let cpu = self.select_cpu_for_task(&task);
        task.last_cpu = cpu;
        self.recompute_task_class(&mut task);
        task.deficit = task_quantum(task.class, task.nice);

        let index = self.tasks.len();
        self.tasks.push(task);
        self.task_lookup.insert(task_id, index);
        self.enqueue_task(task_id);
        self.next_task_id = self.next_task_id.max(task_id.saturating_add(1));
    }

    pub fn allocate_task_id(&mut self) -> usize {
        let task_id = self.next_task_id.max(1);
        self.next_task_id = task_id.saturating_add(1);
        task_id
    }

    pub fn configure_topology(&mut self, cpu_count: usize) {
        if !self.tasks.is_empty() || self.started {
            return;
        }

        let cpu_count = cpu_count.max(1);
        self.cpus = (0..cpu_count)
            .map(|cpu| CpuRunQueue::new(CpuId(cpu), 0))
            .collect();
        self.llc_domains = vec![LlcDomain {
            id: 0,
            cpus: (0..cpu_count).map(CpuId).collect(),
        }];
    }

    pub fn start(&mut self) -> Option<usize> {
        self.started = true;
        self.pick_next_task(CpuId(0), None)
    }

    pub fn on_timer_tick(&mut self, cpu: CpuId, current_rsp: usize) -> usize {
        if !self.started {
            return current_rsp;
        }

        self.global_tick = self.global_tick.wrapping_add(1);
        if self.global_tick % 10 == 0 {
            ktrace!("sched tick={}", self.global_tick);
        }

        let prev = self.cpus[cpu.0].current_task;
        if let Some(task_id) = prev {
            self.account_running_task(cpu, task_id, current_rsp);
        }

        self.pick_next_task(cpu, prev).unwrap_or(current_rsp)
    }

    pub fn request_yield(&mut self, cpu: CpuId) {
        let Some(task_id) = self.cpus[cpu.0].current_task else {
            return;
        };

        let index = self.task_index(task_id);
        let task = &mut self.tasks[index];
        task.voluntary_yields = task.voluntary_yields.saturating_add(1);
        task.slice_ticks = 0;
        task.deficit = 0;
    }

    pub fn block_current(&mut self, cpu: CpuId) {
        let Some(task_id) = self.cpus[cpu.0].current_task else {
            return;
        };

        let index = self.task_index(task_id);
        let task = &mut self.tasks[index];
        task.state = TaskState::Blocked;
        task.queued = false;
        task.slice_ticks = 0;
        task.deficit = 0;
        task.sleep_started_at = Some(self.global_tick);
    }

    pub fn wake_task(&mut self, task_id: usize) {
        let index = self.task_index(task_id);
        let task = &mut self.tasks[index];
        if task.state != TaskState::Blocked {
            return;
        }

        let slept = task
            .sleep_started_at
            .take()
            .map(|start| self.global_tick.saturating_sub(start))
            .unwrap_or(0);

        task.sleep_credit = min(
            MAX_SLEEP_CREDIT,
            task.sleep_credit
                .saturating_add(slept.saturating_mul(WAKE_CREDIT_PER_TICK)),
        );
        task.state = TaskState::Ready;
        task.deficit = task_quantum(task.class, task.nice);
        self.enqueue_task(task_id);
    }

    pub fn exit_current(&mut self, cpu: CpuId) -> Option<usize> {
        if let Some(task_id) = self.cpus[cpu.0].current_task.take() {
            let index = self.task_index(task_id);
            let task = &mut self.tasks[index];
            task.state = TaskState::Exited;
            task.queued = false;
        }

        self.pick_next_task(cpu, None)
    }

    pub fn timer_handler_addr(&self) -> usize {
        timer_interrupt_entry as *const () as usize
    }

    pub fn select_cpu(&self, task_id: usize) -> CpuId {
        let task = self.task(task_id);
        self.select_cpu_for_task(task)
    }

    fn select_cpu_for_task(&self, task: &Task) -> CpuId {
        if self.cpu_is_idle(task.last_cpu) {
            return task.last_cpu;
        }

        if let Some(preferred_cpu) = task.preferred_cpu {
            if preferred_cpu.0 < self.cpus.len() && self.cpu_is_idle(preferred_cpu) {
                return preferred_cpu;
            }
        }

        self.cpus
            .iter()
            .min_by_key(|rq| {
                let queued = rq.queues.iter().map(VecDeque::len).sum::<usize>();
                usize::from(rq.current_task.is_some()) + queued
            })
            .map(|rq| rq.id)
            .unwrap_or(CpuId(0))
    }

    fn cpu_is_idle(&self, cpu: CpuId) -> bool {
        let rq = &self.cpus[cpu.0];
        rq.current_task.is_none() && rq.queues.iter().all(VecDeque::is_empty)
    }

    fn task_index(&self, task_id: usize) -> usize {
        *self
            .task_lookup
            .get(&task_id)
            .unwrap_or_else(|| panic!("unknown task id {}", task_id))
    }

    fn task(&self, task_id: usize) -> &Task {
        &self.tasks[self.task_index(task_id)]
    }

    fn task_mut(&mut self, task_id: usize) -> &mut Task {
        let index = self.task_index(task_id);
        &mut self.tasks[index]
    }

    fn account_running_task(&mut self, cpu: CpuId, task_id: usize, current_rsp: usize) {
        let index = self.task_index(task_id);
        let old_class = self.tasks[index].class;
        let task_quantum = task_quantum(old_class, self.tasks[index].nice) as u64;
        {
            let task = &mut self.tasks[index];
            task.saved_rsp = current_rsp;
            task.runtime_ticks = task.runtime_ticks.saturating_add(1);
            task.slice_ticks = task.slice_ticks.saturating_add(1);
            task.runnable_avg = ((task.runnable_avg * 7) + RUNNABLE_SCALE) / 8;
            task.vruntime = task
                .vruntime
                .saturating_add(vruntime_delta(task.class, task.nice));
            task.sleep_credit = task.sleep_credit.saturating_sub(1);

            if task.slice_ticks >= task_quantum {
                task.full_slice_runs = task.full_slice_runs.saturating_add(1);
                task.slice_ticks = 0;
            }

            if task.state == TaskState::Running {
                task.state = TaskState::Ready;
            }
        }

        self.recompute_task_class_by_id(task_id);

        if self.task(task_id).state == TaskState::Ready {
            self.enqueue_task(task_id);
        }

        self.cpus[cpu.0].current_task = None;
    }

    fn recompute_task_class_by_id(&mut self, task_id: usize) {
        let index = self.task_index(task_id);
        let mut class = self.tasks[index].class_hint.unwrap_or(TaskClass::Normal);

        if self.tasks[index].class_hint.is_none() {
            if self.tasks[index].nice >= 10 {
                class = TaskClass::Background;
            } else if self.tasks[index].runnable_avg >= HOG_UTIL_THRESHOLD
                && self.tasks[index].full_slice_runs >= HOG_SLICE_THRESHOLD
            {
                class = TaskClass::Hog;
            } else {
                class = TaskClass::Normal;
            }
        }

        self.tasks[index].class = class;
    }

    fn recompute_task_class(&self, task: &mut Task) {
        task.class = task.class_hint.unwrap_or_else(|| {
            if task.nice >= 10 {
                TaskClass::Background
            } else {
                TaskClass::Normal
            }
        });
    }

    fn enqueue_task(&mut self, task_id: usize) {
        let (cpu, class, should_enqueue) = {
            let task = self.task(task_id);
            (
                task.last_cpu,
                task.class,
                task.state == TaskState::Ready && !task.queued,
            )
        };

        if !should_enqueue {
            return;
        }

        self.cpus[cpu.0].queues[class.index()].push_back(task_id);
        self.task_mut(task_id).queued = true;
    }

    fn pick_next_task(&mut self, cpu: CpuId, previous: Option<usize>) -> Option<usize> {
        let cpu_idx = cpu.0;
        for _ in 0..2 {
            for offset in 0..NUM_CLASSES {
                let class_idx = (self.cpus[cpu_idx].class_cursor + offset) % NUM_CLASSES;
                if self.cpus[cpu_idx].class_deficits[class_idx] <= 0 {
                    continue;
                }

                let class = TaskClass::from_index(class_idx);
                if let Some(task_id) = self.pick_task_from_class(cpu, class) {
                    self.cpus[cpu_idx].class_cursor = (class_idx + 1) % NUM_CLASSES;
                    self.cpus[cpu_idx].class_deficits[class_idx] -= 1;

                    let next_rsp = {
                        let task = self.task_mut(task_id);
                        task.state = TaskState::Running;
                        task.last_cpu = cpu;
                        if Some(task_id) != previous {
                            task.slice_ticks = 0;
                        }
                        if task.deficit <= 0 {
                            task.deficit = task_quantum(task.class, task.nice);
                        }
                        task.deficit -= 1;
                        task.saved_rsp
                    };

                    self.cpus[cpu_idx].current_task = Some(task_id);
                    crate::user::activate_task(task_id);
                    CURRENT_TASK_IDS[cpu_idx].store(task_id, Ordering::SeqCst);
                    crate::syscall::set_kernel_stack_top(self.task(task_id).kernel_stack_top());
                    ktrace!(
                        "sched switch cpu={} task={} pid={} rsp={:#x}",
                        cpu_idx,
                        task_id,
                        self.task(task_id).process_id,
                        next_rsp
                    );
                    return Some(next_rsp);
                }
            }

            self.refill_class_deficits(cpu);
        }

        if let Some(task_id) = previous {
            let next_rsp = {
                let task = self.task_mut(task_id);
                if task.state == TaskState::Ready || task.state == TaskState::Running {
                    task.state = TaskState::Running;
                    Some(task.saved_rsp)
                } else {
                    None
                }
            };

            if next_rsp.is_some() {
                self.cpus[cpu_idx].current_task = Some(task_id);
                crate::user::activate_task(task_id);
                CURRENT_TASK_IDS[cpu_idx].store(task_id, Ordering::SeqCst);
                crate::syscall::set_kernel_stack_top(self.task(task_id).kernel_stack_top());
                ktrace!(
                    "sched resume cpu={} task={} pid={} rsp={:#x}",
                    cpu_idx,
                    task_id,
                    self.task(task_id).process_id,
                    next_rsp.unwrap_or(0)
                );
            }
            return next_rsp;
        }

        CURRENT_TASK_IDS[cpu_idx].store(0, Ordering::SeqCst);
        None
    }

    fn refill_class_deficits(&mut self, cpu: CpuId) {
        let cpu_idx = cpu.0;
        for class_idx in 0..NUM_CLASSES {
            if self.has_ready_task_in_class(cpu, TaskClass::from_index(class_idx)) {
                let quantum = CLASS_QUANTA[class_idx];
                let deficit = &mut self.cpus[cpu_idx].class_deficits[class_idx];
                *deficit = (*deficit).max(0).saturating_add(quantum).min(quantum * 2);
            }
        }
    }

    fn has_ready_task_in_class(&self, cpu: CpuId, class: TaskClass) -> bool {
        self.cpus[cpu.0].queues[class.index()]
            .iter()
            .any(|task_id| self.task(*task_id).state == TaskState::Ready)
    }

    fn pick_task_from_class(&mut self, cpu: CpuId, class: TaskClass) -> Option<usize> {
        for pass in 0..2 {
            let mut best_task_id = None;
            let mut best_vruntime = u64::MAX;
            let queue_snapshot: Vec<usize> = self.cpus[cpu.0].queues[class.index()]
                .iter()
                .copied()
                .collect();

            for task_id in queue_snapshot {
                let task = self.task(task_id);
                if task.state != TaskState::Ready || task.deficit <= 0 {
                    continue;
                }

                let effective_vruntime = task.vruntime.saturating_sub(task.sleep_credit);
                if effective_vruntime < best_vruntime {
                    best_vruntime = effective_vruntime;
                    best_task_id = Some(task_id);
                }
            }

            if let Some(task_id) = best_task_id {
                let position = self.cpus[cpu.0].queues[class.index()]
                    .iter()
                    .position(|candidate| *candidate == task_id)
                    .unwrap();
                self.cpus[cpu.0].queues[class.index()].remove(position);
                self.task_mut(task_id).queued = false;
                return Some(task_id);
            }

            if pass == 0 {
                self.refill_task_deficits(cpu, class);
            }
        }

        None
    }

    fn refill_task_deficits(&mut self, cpu: CpuId, class: TaskClass) {
        let queue_snapshot: Vec<usize> = self.cpus[cpu.0].queues[class.index()]
            .iter()
            .copied()
            .collect();

        for task_id in queue_snapshot {
            let task = self.task_mut(task_id);
            if task.state != TaskState::Ready {
                continue;
            }

            let quantum = task_quantum(class, task.nice);
            task.deficit = task.deficit.max(0).saturating_add(quantum).min(quantum * 2);
        }
    }
}

fn nice_weight(nice: i8) -> u64 {
    u64::from((40 - (nice.clamp(-20, 19) as i32 + 20)).max(1) as u32)
}

fn task_quantum(class: TaskClass, nice: i8) -> i64 {
    let base = CLASS_QUANTA[class.index()];
    let weight = nice_weight(nice) as i64;
    ((base * weight) / 20).max(1)
}

fn vruntime_delta(class: TaskClass, nice: i8) -> u64 {
    let weight = CLASS_WEIGHTS[class.index()]
        .saturating_mul(nice_weight(nice))
        .max(1);
    1024 / weight
}

const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

#[unsafe(no_mangle)]
pub extern "sysv64" fn scheduler_timer_tick(
    current_ctx: *mut SavedTaskContext,
) -> *const SavedTaskContext {
    if current_ctx.is_null() {
        apic::complete_interrupt();
        return core::ptr::null();
    }

    let cs = unsafe { (*current_ctx).cs };
    let cpl = cs & 0x3;
    if cpl == 0x3 {
        apic::complete_interrupt();
        return current_ctx;
    }

    let next_ctx = {
        let mut scheduler = SCHEDULER.lock();
        scheduler.on_timer_tick(current_cpu_id(), current_ctx as usize)
    };

    apic::complete_interrupt();
    next_ctx as *const SavedTaskContext
}

#[unsafe(no_mangle)]
pub extern "C" fn task_return_trampoline() -> ! {
    println!("TASK: returned unexpectedly, tearing it down");
    on_task_exit()
}

pub fn start() -> ! {
    let next_ctx = {
        let mut scheduler = SCHEDULER.lock();
        scheduler.start()
    }
    .expect("scheduler started without a runnable task");

    unsafe { restore_task_context(next_ctx as *const SavedTaskContext) }
}

pub fn configure_topology(cpu_count: usize) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        SCHEDULER.lock().configure_topology(cpu_count);
    });
}

pub fn timer_handler_addr() -> usize {
    SCHEDULER.lock().timer_handler_addr()
}

pub fn yield_current() {
    x86_64::instructions::interrupts::without_interrupts(|| {
        SCHEDULER.lock().request_yield(current_cpu_id());
    });
}

pub fn block_current() {
    x86_64::instructions::interrupts::without_interrupts(|| {
        SCHEDULER.lock().block_current(current_cpu_id());
    });
}

pub fn wake_task(task_id: usize) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        SCHEDULER.lock().wake_task(task_id);
    });
}

pub fn current_task_id() -> Option<usize> {
    let cpu = current_cpu_id().0;
    match CURRENT_TASK_IDS[cpu].load(Ordering::SeqCst) {
        0 => None,
        task_id => Some(task_id),
    }
}

pub fn allocate_task_id() -> usize {
    x86_64::instructions::interrupts::without_interrupts(|| SCHEDULER.lock().allocate_task_id())
}

pub fn global_tick() -> u64 {
    x86_64::instructions::interrupts::without_interrupts(|| SCHEDULER.lock().global_tick)
}

pub fn on_task_exit() -> ! {
    x86_64::instructions::interrupts::disable();

    let next_ctx = {
        let mut scheduler = SCHEDULER.lock();
        scheduler.exit_current(current_cpu_id())
    };

    if let Some(next_ctx) = next_ctx {
        unsafe { restore_task_context(next_ctx as *const SavedTaskContext) }
    }

    loop {
        unsafe {
            asm!("sti; hlt; cli");
        }
    }
}

pub static SCHEDULER: Lazy<Mutex<Scheduler>> = Lazy::new(|| Mutex::new(Scheduler::new()));
