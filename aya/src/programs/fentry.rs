//! fentry programs.
use thiserror::Error;

use crate::{
    generated::{bpf_attach_type::BPF_TRACE_FENTRY, bpf_prog_type::BPF_PROG_TYPE_TRACING},
    obj::btf::{Btf, BtfError, BtfKind},
    programs::{load_program, utils::attach_btf_id, LinkRef, ProgramData, ProgramError},
};

#[derive(Debug)]
#[doc(alias = "BPF_TRACE_FENTRY")]
#[doc(alias = "BPF_PROG_TYPE_TRACING")]
pub struct FEntry {
    pub(crate) data: ProgramData,
}

#[derive(Debug, Error)]
pub enum FEntryLoadError {
    #[error(transparent)]
    Btf(#[from] BtfError),

    #[error(transparent)]
    Program(#[from] ProgramError),
}

/// Marks a function as a fentry eBPF program that can be attached to almost
/// any function inside the kernel. The difference between fexit and kretprobe
/// is that fexit has practically zero overhead to call before kernel function.
/// fentry programs can be also attached to other eBPF programs.
///
/// # Minimumm kernel version
///
/// The minimum kernel version required to use this feature is 5.5.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     BtfError(#[from] aya::BtfError),
/// #     #[error(transparent)]
/// #     FEntry(#[from] aya::programs::FEntryLoadError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Bpf(#[from] aya::BpfError),
/// # }
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::FEntry, BtfError, Btf};
/// use std::convert::TryInto;
///
/// let btf = Btf::from_sys_fs()?;
/// let program: &mut FEntry = bpf.program_mut("filename_lookup").unwrap().try_into()?;
/// program.load("filename_lookup", &btf)?;
/// program.attach()?;
/// # Ok::<(), Error>(())
/// ```
impl FEntry {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::program::Program::load).
    ///
    /// # Arguments
    ///
    /// * `fn_name` - functionn name inside the kernel to attach
    /// * `btf` - btf information for the target system
    pub fn load(&mut self, fn_name: &str, btf: &Btf) -> Result<(), FEntryLoadError> {
        self.data.expected_attach_type = Some(BPF_TRACE_FENTRY);
        self.data.attach_btf_id = Some(btf.id_by_type_name_kind(fn_name, BtfKind::Func)?);
        load_program(BPF_PROG_TYPE_TRACING, &mut self.data).map_err(FEntryLoadError::from)
    }

    /// Attaches the program
    pub fn attach(&mut self) -> Result<LinkRef, ProgramError> {
        attach_btf_id(&mut self.data, None)
    }
}
