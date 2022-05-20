use core::{marker::PhantomData, mem};

use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_SOCKHASH, bpf_sock_ops},
    helpers::{bpf_msg_redirect_hash, bpf_sk_redirect_hash, bpf_sock_hash_update},
    maps::PinningType,
    programs::{SkBuffContext, SkMsgContext},
    BpfContext,
};

#[repr(transparent)]
pub struct SockHash<K> {
    def: bpf_map_def,
    _k: PhantomData<K>,
}

/// A hash map that stores sockets to which messages or socket buffers can be
/// redirected.
impl<K> SockHash<K> {
    /// Creates a `SockHash` map with the maximum number of elements.
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> SockHash<K> {
        SockHash {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_SOCKHASH,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            },
            _k: PhantomData,
        }
    }

    /// Creates a `SockHash` map pinned in the BPPFS filesystem, with the
    /// maximum number of elements.
    pub const fn pinned(max_entries: u32, flags: u32) -> SockHash<K> {
        SockHash {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_SOCKHASH,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            },
            _k: PhantomData,
        }
    }

    /// Adds an entry or updates an existing one in the map referencing
    /// sockets.
    pub fn update(
        &mut self,
        key: &mut K,
        sk_ops: &mut bpf_sock_ops,
        flags: u64,
    ) -> Result<(), i64> {
        let ret = unsafe {
            bpf_sock_hash_update(
                sk_ops as *mut _,
                &mut self.def as *mut _ as *mut _,
                key as *mut _ as *mut c_void,
                flags,
            )
        };
        (ret >= 0).then(|| ()).ok_or(ret)
    }

    /// Redirects a message to the socket associated with the given key.
    pub fn redirect_msg(&mut self, ctx: &SkMsgContext, key: &mut K, flags: u64) -> i64 {
        unsafe {
            bpf_msg_redirect_hash(
                ctx.as_ptr() as *mut _,
                &mut self.def as *mut _ as *mut _,
                key as *mut _ as *mut _,
                flags,
            )
        }
    }

    /// Redirects a socket buffer to the socket associated with the given key.
    pub fn redirect_skb(&mut self, ctx: &SkBuffContext, key: &mut K, flags: u64) -> i64 {
        unsafe {
            bpf_sk_redirect_hash(
                ctx.as_ptr() as *mut _,
                &mut self.def as *mut _ as *mut _,
                key as *mut _ as *mut _,
                flags,
            )
        }
    }
}
