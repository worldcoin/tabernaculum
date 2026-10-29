//! Sandboxed worker support for Nitro enclaves.
//!
//! The enclave receives one verified executable over vsock at boot, launches it under Minijail
//! with an embedded seccomp policy, and exchanges length-framed messages with it over FD 3.
//! Payloads are the caller's: this crate never decodes worker messages.

#![deny(clippy::all, missing_docs)]

mod connection;
#[cfg(target_os = "linux")]
mod debug;
mod output;
mod policy;
#[cfg(target_os = "linux")]
mod process;
mod transport;

pub use connection::{ConnectionConfig, ConnectionError};
#[cfg(target_os = "linux")]
pub use debug::{DebugEnclave, DebugEnclaveError, WorkerOutput};
pub use policy::{Policy, PolicyError};
#[cfg(target_os = "linux")]
pub use process::{SandboxConfig, WORKER_UID, Worker, WorkerError, check_alive_if_idle};
/// The worker bundle format and enclave-side bootstrap.
pub use tabernaculum_bundle as bundle;

/// Worker resource limits, enforced as rlimits inside the jail.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Hard virtual-address-space ceiling; leave physical memory for the broker and kernel.
    pub address_space_bytes: u64,
    /// Hard per-UID task ceiling, including the main thread (1..=256).
    pub max_threads: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            address_space_bytes: 3 * 1024 * 1024 * 1024,
            max_threads: 32,
        }
    }
}
