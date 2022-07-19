use core::{cmp, ffi::c_void};

use aya_bpf_bindings::helpers::bpf_xdp_load_bytes;
use aya_bpf_cty::c_long;

use crate::{bindings::xdp_md, BpfContext};

pub struct XdpContext {
    pub ctx: *mut xdp_md,
}

impl XdpContext {
    pub fn new(ctx: *mut xdp_md) -> XdpContext {
        XdpContext { ctx }
    }

    #[inline]
    pub fn data(&self) -> usize {
        unsafe { (*self.ctx).data as usize }
    }

    #[inline]
    pub fn data_end(&self) -> usize {
        unsafe { (*self.ctx).data_end as usize }
    }

    /// Return the raw address of the XdpContext metadata.
    #[inline(always)]
    pub fn metadata(&self) -> usize {
        unsafe { (*self.ctx).data_meta as usize }
    }

    /// Return the raw address immediately after the XdpContext's metadata.
    #[inline(always)]
    pub fn metadata_end(&self) -> usize {
        self.data()
    }

    #[inline(always)]
    pub fn load_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<(), c_long> {
        if offset >= self.data_end() {
            return Err(-1);
        }
        if offset >= dst.len() {
            return Err(-1);
        }
        let len = cmp::min(
            self.data_end() as isize - offset as isize,
            dst.len() as isize,
        );
        if len <= 0 {
            return Err(-1);
        }
        if len > dst.len() as isize {
            return Err(-1);
        }
        let ret = unsafe {
            bpf_xdp_load_bytes(
                self.ctx as *mut _,
                offset as u32,
                dst.as_mut_ptr() as *mut _,
                len as u32,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

impl BpfContext for XdpContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx as *mut _
    }
}
