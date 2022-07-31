//! Implementation of [`TaskManager`]
//!
//! It is only used to manage processes and schedule process based on ready queue.
//! Other CPU process monitoring functions are in Processor.


use super::{TaskControlBlock, current_task};
use super::task::TaskStatistics;
use crate::config::PAGE_SIZE;
use crate::mm::{MemorySet, VPNRange, VirtAddr};
use crate::sync::UPSafeCell;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;
use crate::mm::MapPermission;

pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
}

// YOUR JOB: FIFO->Stride
/// A simple FIFO scheduler.
impl TaskManager {
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        // self.ready_queue.push_back(task);
        // Modified by LAB3, maintain task in with increasing order of task_stride
        let task_inner = task.inner_exclusive_access();
        let stride = task_inner.task_stride;
        drop(task_inner);
        let len = self.ready_queue.len();
        for queue in 0..len {
            let task1 = self.ready_queue.get_mut(queue).unwrap();
            let stride1 = task1.inner_exclusive_access().task_stride;
            if stride < stride1 {
                self.ready_queue.insert(queue, task);
                return;
            }
        }
        self.ready_queue.push_back(task)
    }
    /// Take a process out of the ready queue
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.ready_queue.pop_front()
    }
    // Synced from LAB1, bend it to our need
    fn get_task_info(&self) -> TaskStatistics {
        // let inner = self.inner.exclusive_access();
        // inner.tasks[inner.current_task].task_statistics;
        // Modified to suit LAB3 framework
        let current = current_task().unwrap();
        let inner = current.inner_exclusive_access();
        inner.task_statistics
    }

    fn update_task_info(&self, syscall_id: usize) {
        // let mut inner = self.inner.exclusive_access();
        // let cur = inner.current_task;
        // inner.tasks[cur].task_statistics.syscall_times[syscall_id] += 1;
        // Modified to suit LAB3 framework
        let current = current_task().unwrap();
        let mut inner = current.inner_exclusive_access();
        inner.task_statistics.syscall_times[syscall_id] += 1
    }

    fn mmap(&self, start: usize, len: usize, port: usize) -> isize {
        // sanity check
        // 1. [start, end) start be on page boundaries
        // 2. port must be legal
        if start % PAGE_SIZE != 0 {
            return -1;
        }
        // only R/W/X can be set, R/W/X/ all zero is also not valid
        if port & !0x7 != 0 || port & 0x7 == 0  {
            return -1;
        }
        // according to RISC-V manual, if pte.r = 0 and pte.w = 1, stop and raise an access exception
        if port & 0x2 != 0 && port & 0x1 == 0 {
            return -1;
        }

        // let mut inner = self.inner.exclusive_access();
        // let current = inner.current_task;
        // let ref mut memory_set: MemorySet = inner.tasks[current].memory_set;
        // Modified to suit LAB3 framework
        let current = current_task().unwrap();
        let mut inner = current.inner_exclusive_access();
        let ref mut memory_set = inner.memory_set;

        let vpnrange = VPNRange::new(
            VirtAddr::from(start).floor(),
            VirtAddr::from(start + len).ceil(),
        );
        for vpn in vpnrange {
            if let Some(pte) = memory_set.translate(vpn) {
                if pte.is_valid() {
                    // some vpn in range has already been mapped!
                    return -1;
                }
            }
        }
        let mut map_prem = MapPermission::U;
        if (port & 1) != 0 {
            map_prem |= MapPermission::R;
        }
        if (port & 2) != 0 {
            map_prem |= MapPermission::W;
        }
        if (port & 4) != 0 {
            map_prem |= MapPermission::X;
        }
        println!(
            "start_va:{:#x}~end_va:{:#x} map_perm:{:#x}",
            start,
            start + len,
            map_prem
        );
        memory_set.insert_framed_area(VirtAddr::from(start), VirtAddr::from(start + len), map_prem);
        0
    }

    fn munmap(&self, start: usize, len: usize) -> isize {
        // sanity check
        // [start, end) start be on page boundaries
        if start % PAGE_SIZE != 0 {
            return -1;
        }

        // let mut inner = self.inner.exclusive_access();
        // let current = inner.current_task;
        // let ref mut memory_set: MemorySet = inner.tasks[current].memory_set;
        // Modified to suit LAB3 framework
        let current = current_task().unwrap();
        let mut inner = current.inner_exclusive_access();
        let ref mut memory_set = inner.memory_set;

        let vpnrange = VPNRange::new(
            VirtAddr::from(start).floor(),
            VirtAddr::from(start + len).ceil(),
        );
        for vpn in vpnrange {
            let pte = memory_set.translate(vpn);
            // 1st-level or 2nd-level pagetable pte invalid || 3rd-level pagetable pte invalid
            if pte.is_none() || !pte.unwrap().is_valid() {
                return -1;
            }
        }
        for vpn in vpnrange {
            memory_set.munmap(vpn);
        }
        0
    }
}

// Synced from LAB1, bend it to our need
pub fn get_task_info() -> TaskStatistics {
    TASK_MANAGER.exclusive_access().get_task_info()
}

pub fn update_task_info(syscall_id: usize) {
    TASK_MANAGER.exclusive_access().update_task_info(syscall_id)
}

// Added by LAB2
pub fn mmap(start: usize, len: usize, port: usize) -> isize {
    TASK_MANAGER.exclusive_access().mmap(start, len, port)
}

pub fn munmap(start: usize, len: usize) -> isize {
    TASK_MANAGER.exclusive_access().munmap(start, len)
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

pub fn add_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.exclusive_access().add(task);
}

pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    TASK_MANAGER.exclusive_access().fetch()
}
