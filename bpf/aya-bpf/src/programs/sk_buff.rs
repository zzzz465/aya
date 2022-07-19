use core::{
    cmp,
    ffi::c_void,
    mem::{self, MaybeUninit},
};

use aya_bpf_bindings::helpers::{
    bpf_clone_redirect, bpf_get_socket_uid, bpf_l3_csum_replace, bpf_l4_csum_replace,
    bpf_skb_adjust_room, bpf_skb_change_type, bpf_skb_load_bytes, bpf_skb_store_bytes,
};
use aya_bpf_cty::c_long;

use crate::{bindings::__sk_buff, BpfContext};

pub struct SkBuffContext {
    pub skb: *mut __sk_buff,
}

impl SkBuffContext {
    pub fn new(skb: *mut __sk_buff) -> SkBuffContext {
        SkBuffContext { skb }
    }

    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> u32 {
        unsafe { *self.skb }.len
    }

    #[inline]
    pub fn set_mark(&mut self, mark: u32) {
        unsafe { *self.skb }.mark = mark;
    }

    #[inline]
    pub fn cb(&self) -> &[u32] {
        unsafe { &(*self.skb).cb }
    }

    #[inline]
    pub fn cb_mut(&mut self) -> &mut [u32] {
        unsafe { &mut (*self.skb).cb }
    }

    /// Returns the owner UID of the socket associated to the SKB context.
    #[inline]
    pub fn get_socket_uid(&self) -> u32 {
        unsafe { bpf_get_socket_uid(self.skb) }
    }

    #[inline]
    pub fn load<T>(&self, offset: usize) -> Result<T, c_long> {
        unsafe {
            let mut data = MaybeUninit::<T>::uninit();
            let ret = bpf_skb_load_bytes(
                self.skb as *const _,
                offset as u32,
                &mut data as *mut _ as *mut _,
                mem::size_of::<T>() as u32,
            );
            if ret == 0 {
                Ok(data.assume_init())
            } else {
                Err(ret)
            }
        }
    }

    /// Writes bytes from the SKB context to the given bytes slice.
    ///
    /// Reads at most `self.len() - offset` bytes from the SKB context.
    ///
    /// # Examples
    ///
    /// With a `PerCpuArray` (with size suitable for high jumbo frames MTU):
    ///
    /// ```no_run
    /// use core::mem;
    ///
    /// use aya_bpf::{bindings::TC_ACT_PIPE, macros::map, maps::PerCpuArray, programs::SkBuffContext};
    /// # #[allow(non_camel_case_types)]
    /// # struct ethhdr {};
    /// # #[allow(non_camel_case_types)]
    /// # struct iphdr {};
    /// # #[allow(non_camel_case_types)]
    /// # struct tcphdr {};
    ///
    /// #[repr(C)]
    /// pub struct Buf {
    ///    pub buf: [u8; 9198],
    /// }
    ///
    /// #[map]
    /// pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);
    ///
    /// fn try_classifier(ctx: SkBuffContext) -> Result<i32, i32> {
    ///     let buf = unsafe {
    ///         let ptr = BUF.get_ptr_mut(0).ok_or(TC_ACT_PIPE)?;
    ///         &mut *ptr
    ///     };
    ///     let offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
    ///     ctx.load_bytes(offset, &mut buf.buf).map_err(|_| TC_ACT_PIPE)?;
    ///
    ///     // do something with `buf`
    ///
    ///     Ok(TC_ACT_PIPE)
    /// }
    ///
    /// const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
    /// const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
    /// const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
    /// ```
    #[inline(always)]
    pub fn load_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<(), c_long> {
        if offset >= self.len() as usize {
            return Err(-1);
        }
        if offset >= dst.len() {
            return Err(-1);
        }
        let len = cmp::min(self.len() as isize - offset as isize, dst.len() as isize);
        if len <= 0 {
            return Err(-1);
        }
        if len > dst.len() as isize {
            return Err(-1);
        }
        let ret = unsafe {
            bpf_skb_load_bytes(
                self.skb as *const _,
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

    #[inline]
    pub fn store<T>(&mut self, offset: usize, v: &T, flags: u64) -> Result<(), c_long> {
        unsafe {
            let ret = bpf_skb_store_bytes(
                self.skb as *mut _,
                offset as u32,
                v as *const _ as *const _,
                mem::size_of::<T>() as u32,
                flags,
            );
            if ret == 0 {
                Ok(())
            } else {
                Err(ret)
            }
        }
    }

    #[inline]
    pub fn l3_csum_replace(
        &self,
        offset: usize,
        from: u64,
        to: u64,
        size: u64,
    ) -> Result<(), c_long> {
        unsafe {
            let ret = bpf_l3_csum_replace(self.skb as *mut _, offset as u32, from, to, size);
            if ret == 0 {
                Ok(())
            } else {
                Err(ret)
            }
        }
    }

    #[inline]
    pub fn l4_csum_replace(
        &self,
        offset: usize,
        from: u64,
        to: u64,
        flags: u64,
    ) -> Result<(), c_long> {
        unsafe {
            let ret = bpf_l4_csum_replace(self.skb as *mut _, offset as u32, from, to, flags);
            if ret == 0 {
                Ok(())
            } else {
                Err(ret)
            }
        }
    }

    #[inline]
    pub fn adjust_room(&self, len_diff: i32, mode: u32, flags: u64) -> Result<(), c_long> {
        let ret = unsafe { bpf_skb_adjust_room(self.as_ptr() as *mut _, len_diff, mode, flags) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }

    #[inline]
    pub fn clone_redirect(&self, if_index: u32, flags: u64) -> Result<(), c_long> {
        let ret = unsafe { bpf_clone_redirect(self.as_ptr() as *mut _, if_index, flags) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }

    #[inline]
    pub fn change_type(&self, ty: u32) -> Result<(), c_long> {
        let ret = unsafe { bpf_skb_change_type(self.as_ptr() as *mut _, ty) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}

impl BpfContext for SkBuffContext {
    fn as_ptr(&self) -> *mut c_void {
        self.skb as *mut _
    }
}
