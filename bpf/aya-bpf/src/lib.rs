//! A library to write eBPF programs.
//!
//! eBPF is a technology that allows running user-supplied programs inside the
//! Linux kernel. For more info see
//! [https://ebpf.io/what-is-ebpf](https://ebpf.io/what-is-ebpf).
//!
//! Aya is an eBPF library built with a focus on operability and developer
//! experience. It does not rely on [libbpf](https://github.com/libbpf/libbpf)
//! nor [bcc](https://github.com/iovisor/bcc) - it's built from the ground up
//! purely in Rust, where the Rust compiler is used to build the eBPF object
//! file. With BTF support, it offers a true
//! [compile once, run everywhere solution](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html),
//! where a single self-contained binary can be deployed on many linux
//! distributions and kernel versions.
//!
//! Some of the major features provided include:
//!
//! * Support for the **BPF Type Format** (BTF), which is transparently enabled when
//!   supported by the target kernel. This allows eBPF programs compiled against
//!   one kernel version to run on different kernel versions without the need to
//!   recompile.
//! * Support for function call relocation and global data maps, which
//!   allows eBPF programs to make **function calls** and use **global variables
//!   and initializers**.
#![feature(never_type)]
#![allow(clippy::missing_safety_doc)]
#![no_std]

pub use aya_bpf_bindings::bindings;

mod args;
pub mod helpers;
pub mod maps;
pub mod programs;

pub use aya_bpf_cty as cty;

use core::ffi::c_void;
use cty::{c_char, c_int, c_long};
use helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid};

pub use aya_bpf_macros as macros;

pub const TASK_COMM_LEN: usize = 16;

pub trait BpfContext {
    fn as_ptr(&self) -> *mut c_void;

    #[inline]
    fn command(&self) -> Result<[c_char; TASK_COMM_LEN], c_long> {
        bpf_get_current_comm()
    }

    fn pid(&self) -> u32 {
        bpf_get_current_pid_tgid() as u32
    }

    fn tgid(&self) -> u32 {
        (bpf_get_current_pid_tgid() >> 32) as u32
    }
}

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut u8, c: c_int, n: usize) {
    let base = s as usize;
    for i in 0..n {
        *((base + i) as *mut u8) = c as u8;
    }
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *mut u8, n: usize) {
    let dest_base = dest as usize;
    let src_base = src as usize;
    for i in 0..n {
        *((dest_base + i) as *mut u8) = *((src_base + i) as *mut u8);
    }
}
