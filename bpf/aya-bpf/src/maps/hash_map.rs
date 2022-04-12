use core::{marker::PhantomData, mem, ptr::NonNull};

use aya_bpf_bindings::bindings::bpf_map_type::{
    BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_HASH,
};
use aya_bpf_cty::{c_long, c_void};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_HASH},
    helpers::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem},
    maps::PinningType,
};

/// A hash map that can be shared between eBPF programs and user space.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 3.19.
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::map, maps::HashMap};
/// # use aya_bpf::programs::LsmContext;
///
/// #[map]
/// static mut MY_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
///
/// # unsafe fn try_test(ctx: &LsmContext) -> Result<i32, i32> {
/// let key: u32 = 13;
/// let value: u32 = 42;
/// MY_MAP.insert(&key, &value, 0).map_err(|e| e as i32)?;
/// # Ok(0)
/// # }
/// ```
#[repr(transparent)]
pub struct HashMap<K, V> {
    def: bpf_map_def,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> HashMap<K, V> {
    /// Creates a `HashMap` with the maximum number of elements.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya_bpf::{macros::map, maps::HashMap};
    ///
    /// #[map]
    /// static mut MY_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
    /// ```
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> HashMap<K, V> {
        HashMap {
            def: build_def::<K, V>(BPF_MAP_TYPE_HASH, max_entries, flags, PinningType::None),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Creates an empty `HashMap<K, V>` with the specified maximum number of
    /// elements, and pins it to the BPF file system (bpffs).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya_bpf::{macros::map, maps::HashMap};
    ///
    /// #[map]
    /// static mut MY_MAP: HashMap<u32, u32> = HashMap::pinned(1024, 0);
    /// ```
    pub const fn pinned(max_entries: u32, flags: u32) -> HashMap<K, V> {
        HashMap {
            def: build_def::<K, V>(BPF_MAP_TYPE_HASH, max_entries, flags, PinningType::ByName),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Returns a copy of the value associated with the key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya_bpf::{macros::map, maps::HashMap};
    /// # use aya_bpf::programs::LsmContext;
    ///
    /// #[map]
    /// static mut MY_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
    ///
    /// # unsafe fn try_test(ctx: &LsmContext) -> Result<i32, i32> {
    /// let key: u32 = 13;
    /// let value = MY_MAP.get(&key);
    /// # Ok(0)
    /// # }
    /// ```
    #[inline]
    pub fn get(&mut self, key: &K) -> Option<&V> {
        get(&mut self.def, key)
    }

    /// Returns a mutable copy of the value associated with the key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya_bpf::{macros::map, maps::HashMap};
    /// # use aya_bpf::programs::LsmContext;
    ///
    /// #[map]
    /// static mut MY_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
    ///
    /// # unsafe fn try_test(ctx: &LsmContext) -> Result<i32, i32> {
    /// let key: u32 = 13;
    /// if let Some(mut value) = MY_MAP.get_mut(&key) {
    ///    *value += 42;
    /// }
    /// # Ok(0)
    /// # }
    /// ```
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        get_mut(&mut self.def, key)
    }

    /// Inserts a key-value pair into the map.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya_bpf::{macros::map, maps::HashMap};
    /// # use aya_bpf::programs::LsmContext;
    ///
    /// #[map]
    /// static mut MY_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
    ///
    /// # unsafe fn try_test(ctx: &LsmContext) -> Result<i32, i32> {
    /// let key: u32 = 13;
    /// let value: u32 = 42;
    /// MY_MAP.insert(&key, &value, 0).map_err(|e| e as i32)?;
    /// # Ok(0)
    /// # }
    /// ```
    #[inline]
    pub fn insert(&mut self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(&mut self.def, key, value, flags)
    }

    /// Removes a key from the map.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aya_bpf::{macros::map, maps::HashMap};
    /// # use aya_bpf::programs::LsmContext;
    ///
    /// #[map]
    /// static mut MY_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
    ///
    /// # unsafe fn try_test(ctx: &LsmContext) -> Result<i32, i32> {
    /// let key: u32 = 13;
    /// MY_MAP.remove(&key).map_err(|e| e as i32)?;
    /// # Ok(0)
    /// # }
    /// ```
    #[inline]
    pub fn remove(&mut self, key: &K) -> Result<(), c_long> {
        remove(&mut self.def, key)
    }
}

#[repr(transparent)]
pub struct LruHashMap<K, V> {
    def: bpf_map_def,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> LruHashMap<K, V> {
    /// Creates an `LruHashMap` with the maximum number of elements.
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> LruHashMap<K, V> {
        LruHashMap {
            def: build_def::<K, V>(BPF_MAP_TYPE_LRU_HASH, max_entries, flags, PinningType::None),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Creates an `LruHashMap` pinned in the BPFFS filesystem, with the maximum
    /// number of elements.
    pub const fn pinned(max_entries: u32, flags: u32) -> LruHashMap<K, V> {
        LruHashMap {
            def: build_def::<K, V>(
                BPF_MAP_TYPE_LRU_HASH,
                max_entries,
                flags,
                PinningType::ByName,
            ),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Returns a copy of the value associated with the key.
    #[inline]
    pub fn get(&mut self, key: &K) -> Option<&V> {
        get(&mut self.def, key)
    }

    /// Returns a mutable copy of the value associated with the key.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        get_mut(&mut self.def, key)
    }

    /// Inserts a key-value pair into the map.
    #[inline]
    pub fn insert(&mut self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(&mut self.def, key, value, flags)
    }

    /// Removes a key from the map.
    #[inline]
    pub fn remove(&mut self, key: &K) -> Result<(), c_long> {
        remove(&mut self.def, key)
    }
}

/// A hash map that can be shared between eBPF programs and user space. Each
/// CPU has its own separate copy of the map. The copies are not synchronized
/// in any way.
///
/// Due to limits defined in the kernel, the `K` and `V` types cannot be larger
/// than 32KB in size.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.6.
///
/// # Examples
///
/// ```no_run
/// use aya_bpf::{macros::map, maps::PerCpuHashMap};
/// # use aya_bpf::programs::LsmContext;
///
/// #[map]
/// static mut MY_MAP: PerCpuHashMap<u32, u32> = PerCpuHashMap::with_max_entries(1024, 0);
///
/// # unsafe fn try_test(ctx: &LsmContext) -> Result<i32, i32> {
/// let key: u32 = 13;
/// let value: u32 = 42;
/// MY_MAP.insert(&key, &value, 0).map_err(|e| e as i32)?;
/// # Ok(0)
/// # }
/// ```
#[repr(transparent)]
pub struct PerCpuHashMap<K, V> {
    def: bpf_map_def,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> PerCpuHashMap<K, V> {
    /// Creates a `PerCpuHashMap` with the maximum number of elements.
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> PerCpuHashMap<K, V> {
        PerCpuHashMap {
            def: build_def::<K, V>(
                BPF_MAP_TYPE_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::None,
            ),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Creates a `PerCpuHashMap` pinned in the BPFFS filesystem, with the maximum
    /// number of elements.
    pub const fn pinned(max_entries: u32, flags: u32) -> PerCpuHashMap<K, V> {
        PerCpuHashMap {
            def: build_def::<K, V>(
                BPF_MAP_TYPE_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::ByName,
            ),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Returns a copy of the value associated with the key.
    #[inline]
    pub fn get(&mut self, key: &K) -> Option<&V> {
        get(&mut self.def, key)
    }

    /// Returns a mutable copy of the value associated with the key.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        get_mut(&mut self.def, key)
    }

    /// Inserts a key-value pair into the map.
    #[inline]
    pub fn insert(&mut self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(&mut self.def, key, value, flags)
    }

    /// Removes a key from the map.
    #[inline]
    pub fn remove(&mut self, key: &K) -> Result<(), c_long> {
        remove(&mut self.def, key)
    }
}

#[repr(transparent)]
pub struct LruPerCpuHashMap<K, V> {
    def: bpf_map_def,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> LruPerCpuHashMap<K, V> {
    /// Creates an `LruPerCpuHashMap` with the maximum number of elements.
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> LruPerCpuHashMap<K, V> {
        LruPerCpuHashMap {
            def: build_def::<K, V>(
                BPF_MAP_TYPE_LRU_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::None,
            ),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Creates an `LruPerCpuHashMap` pinned in the BPFFS filesystem, with the maximum
    /// number of elements.
    pub const fn pinned(max_entries: u32, flags: u32) -> LruPerCpuHashMap<K, V> {
        LruPerCpuHashMap {
            def: build_def::<K, V>(
                BPF_MAP_TYPE_LRU_PERCPU_HASH,
                max_entries,
                flags,
                PinningType::ByName,
            ),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    /// Returns a copy of the value associated with the key.
    #[inline]
    pub fn get(&mut self, key: &K) -> Option<&V> {
        get(&mut self.def, key)
    }

    /// Returns a mutable copy of the value associated with the key.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        get_mut(&mut self.def, key)
    }

    /// Inserts a key-value pair into the map.
    #[inline]
    pub fn insert(&mut self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(&mut self.def, key, value, flags)
    }

    /// Removes a key from the map.
    #[inline]
    pub fn remove(&mut self, key: &K) -> Result<(), c_long> {
        remove(&mut self.def, key)
    }
}

const fn build_def<K, V>(ty: u32, max_entries: u32, flags: u32, pin: PinningType) -> bpf_map_def {
    bpf_map_def {
        type_: ty,
        key_size: mem::size_of::<K>() as u32,
        value_size: mem::size_of::<V>() as u32,
        max_entries,
        map_flags: flags,
        id: 0,
        pinning: pin as u32,
    }
}

#[inline]
fn get<'a, K, V>(def: &mut bpf_map_def, key: &K) -> Option<&'a V> {
    unsafe {
        let value = bpf_map_lookup_elem(def as *mut _ as *mut _, key as *const _ as *const c_void);
        // FIXME: alignment
        NonNull::new(value as *mut V).map(|p| p.as_ref())
    }
}

#[inline]
fn get_mut<'a, K, V>(def: &mut bpf_map_def, key: &K) -> Option<&'a mut V> {
    unsafe {
        let value = bpf_map_lookup_elem(def as *mut _ as *mut _, key as *const _ as *const c_void);
        // FIXME: alignment
        NonNull::new(value as *mut V).map(|mut p| p.as_mut())
    }
}

#[inline]
fn insert<K, V>(def: &mut bpf_map_def, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
    let ret = unsafe {
        bpf_map_update_elem(
            def as *mut _ as *mut _,
            key as *const _ as *const _,
            value as *const _ as *const _,
            flags,
        )
    };
    (ret >= 0).then(|| ()).ok_or(ret)
}

#[inline]
fn remove<K>(def: &mut bpf_map_def, key: &K) -> Result<(), c_long> {
    let ret =
        unsafe { bpf_map_delete_elem(def as *mut _ as *mut _, key as *const _ as *const c_void) };
    (ret >= 0).then(|| ()).ok_or(ret)
}
