//! Sideload a worker executable into an enclave launched by the caller.
//!
//! The library uses explicit arguments. The caller owns artifact acquisition and verification,
//! enclave launch and termination, signal handling, the overall bootstrap deadline and readiness.

use std::{path::PathBuf, time::Duration};

use anyhow::{Result, ensure};
use tabernaculum_bundle::host::Bundle;

mod console;
pub use console::{ConsoleOptions, forward_console};

/// Explicit inputs for provisioning one already-running enclave.
pub struct ProvisionOptions {
    /// Local worker executable, already downloaded and extracted by the caller.
    /// Keep this regular file available and unchanged until provisioning completes.
    pub executable: PathBuf,
    /// CID of the enclave launched by the caller; must be greater than 3.
    pub enclave_cid: u32,
    /// Connection retry budget and timeout for each socket operation.
    /// Must be nonzero and at most 900 seconds; this is not the overall bootstrap deadline.
    pub io_timeout: Duration,
}

/// Hashes and sideloads an executable, then awaits the enclave's initialization acknowledgement.
///
/// Transfer metadata is generated internally. Its checksum provides transfer integrity; the
/// caller is responsible for choosing and authenticating the executable. This function does not
/// download or unpack artifacts, read environment configuration, or manage the enclave lifecycle.
///
/// The acknowledgement means worker initialization completed. Application configuration and
/// health checks still belong to the caller: its RPC server may not yet be listening. A caller
/// such as Flamingo can then load its release manifest and check health before marking readiness.
///
/// Bound this future with the caller's overall bootstrap deadline. Dropping it closes its owned
/// transfer socket; the caller remains responsible for terminating the enclave on failure or
/// cancellation. Only connection refusal/reset before transfer is retried automatically.
///
/// # Example
///
/// ```no_run
/// use std::{path::PathBuf, time::Duration};
/// use tabernaculum_provisioner::{ProvisionOptions, provision};
///
/// async fn sideload(worker_path: PathBuf, enclave_cid: u32) -> anyhow::Result<()> {
///     provision(ProvisionOptions {
///         executable: worker_path,
///         enclave_cid,
///         io_timeout: Duration::from_secs(120),
///     }).await
/// }
/// ```
///
/// # Errors
/// Returns an error for invalid options or executable metadata, failed transfer, or a missing
/// or invalid initialization acknowledgement.
pub async fn provision(options: ProvisionOptions) -> Result<()> {
    ensure!(
        options.enclave_cid > 3,
        "enclave CID must be greater than 3"
    );
    ensure!(
        !options.io_timeout.is_zero() && options.io_timeout <= Duration::from_secs(900),
        "provisioning I/O timeout must be positive and at most 900 seconds"
    );

    let bundle = Bundle::prepare(&options.executable).await?;
    bundle
        .provision(options.enclave_cid, options.io_timeout)
        .await?;
    Ok(())
}
