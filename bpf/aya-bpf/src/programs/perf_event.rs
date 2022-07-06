use core::ffi::c_void;

use crate::BpfContext;

// aarch64 uses user_pt_regs instead of pt_regs
#[cfg(not(bpf_target_arch = "aarch64"))]
use crate::bindings::pt_regs;
#[cfg(bpf_target_arch = "aarch64")]
use crate::bindings::user_pt_regs as pt_regs;

pub struct PerfEventContext {
    pub regs: *mut pt_regs,
    pub sample_period: u64,
    pub addr: u64,
}

impl PerfEventContext {
    pub fn new(ctx: *mut c_void) -> PerfEventContext {
        let regs = ctx as *mut pt_regs;
        let sample_period = unsafe { *(ctx.add(1) as *mut u64) };
        let addr = unsafe { *(ctx.add(2) as *mut u64) };
        PerfEventContext {
            regs,
            sample_period,
            addr,
        }
    }
}

impl BpfContext for PerfEventContext {
    fn as_ptr(&self) -> *mut c_void {
        self.regs as *mut _
    }
}
