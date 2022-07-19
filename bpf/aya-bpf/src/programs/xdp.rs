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

    /// Reads some bytes from the packet into the specified buffer, returning
    /// how many bytes were read.
    ///
    /// Starts reading at `offset` and reads at most `dst.len()` or
    /// `self.len() - offset` bytes, depending on which one is smaller.
    ///
    /// # Examples
    ///
    /// Read into a `PerCpuArray`.
    ///
    /// ```no_run
    /// use core::mem;
    ///
    /// use aya_bpf::{bindings::xdp_action, macros::map, maps::PerCpuArray, programs::XdpContext};
    /// # #[allow(non_camel_case_types)]
    /// # struct ethhdr {};
    /// # #[allow(non_camel_case_types)]
    /// # struct iphdr {};
    /// # #[allow(non_camel_case_types)]
    /// # struct tcphdr {};
    ///
    /// const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
    /// const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
    /// const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
    ///
    /// #[repr(C)]
    /// pub struct Buf {
    ///    pub buf: [u8; 1500],
    /// }
    ///
    /// #[map]
    /// pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);
    ///
    /// fn try_classifier(ctx: &mut XdpContext) -> Result<u32, u32> {
    ///     let buf = unsafe {
    ///         let ptr = BUF.get_ptr_mut(0).ok_or(xdp_action::XDP_PASS)?;
    ///         &mut *ptr
    ///     };
    ///     let offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    ///     ctx.load_bytes(offset, &mut buf.buf).map_err(|_| xdp_action::XDP_PASS)?;
    ///
    ///     // do something with `buf`
    ///
    ///     Ok(xdp_action::XDP_PASS)
    /// }
    /// ```
    #[inline(always)]
    pub fn load_bytes(&mut self, offset: usize, dst: &mut [u8]) -> Result<usize, c_long> {
        if offset >= self.data_end() {
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
        if offset > 0xfff {
            return Err(-69);
        }
        if len > 0xfff {
            return Err(-420);
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
            Ok(len as usize)
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
