use crate::{args::FromBtfArgument, helpers::bpf_probe_read, BpfContext};
use core::ffi::c_void;

pub struct TracePointContext {
    ctx: *mut c_void,
}

impl TracePointContext {
    pub fn new(ctx: *mut c_void) -> TracePointContext {
        TracePointContext { ctx }
    }

    pub unsafe fn read_at<T>(&self, offset: usize) -> Result<T, i64> {
        bpf_probe_read(self.ctx.add(offset) as *const T)
    }

    pub unsafe fn arg<T: FromBtfArgument>(&self, n: usize) -> T {
        T::from_argument(self.ctx as *const _, n)
    }
}

impl BpfContext for TracePointContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
