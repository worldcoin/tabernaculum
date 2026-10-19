//! Host-side enclave provisioning with application initialization before readiness.
//!
//! [run] owns one enclave's lifecycle, using the same environment configuration as the
//! tabernaculum-provisioner binary. Kubernetes owns restart and backoff.

mod artifact;
mod config;
mod enclave;
mod process;

use std::future::Future;

use anyhow::{Context, Result};
use config::Config;
use enclave::{Enclave, clear_readiness};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::timeout,
};

/// Provisions one enclave, initializes its application, then marks it ready and monitors it.
///
/// Configuration comes from the provisioner's existing environment variables. Logging is left
/// to the caller. The initializer is invoked once with the enclave CID after the worker bundle has
/// been acknowledged, and must finish before readiness is written. It can load application
/// configuration and await application health; any connection retries belong in this future,
/// since the application's server may not be listening immediately after acknowledgement.
/// Initialization shares the overall bootstrap deadline with artifact download and worker startup.
///
/// This function owns process-level SIGTERM/SIGINT handling. On either signal, a bootstrap
/// timeout, or an error, it clears readiness and attempts to terminate only its owned enclave.
/// Initializers must be safe to cancel by dropping their future: avoid detached tasks and blocking
/// work. Callers must drive this future to completion rather than drop or abort it, so its
/// asynchronous cleanup can finish. Only one provisioner lifecycle should run in a process.
///
/// # Example
///
/// ```no_run
/// # async fn load_application_configuration(_: u32) -> anyhow::Result<()> { Ok(()) }
/// # async fn wait_for_application_health(_: u32) -> anyhow::Result<()> { Ok(()) }
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     tabernaculum_provisioner::run(|cid| async move {
///         load_application_configuration(cid).await?;
///         wait_for_application_health(cid).await
///     }).await
/// }
/// ```
///
/// # Errors
/// Returns an error if configuration, provisioning, initialization, monitoring or cleanup fails.
/// A handled shutdown signal returns successfully after cleanup.
pub async fn run<F, I>(initialize: F) -> Result<()>
where
    F: FnOnce(u32) -> I,
    I: Future<Output = Result<()>>,
{
    clear_readiness(&config::ready_file()).await?;
    let config = Config::from_env()?;
    let directory = tempfile::tempdir()?;
    let suffix = directory
        .path()
        .file_name()
        .context("missing temporary directory name")?
        .to_string_lossy();
    let enclave = Enclave::new(&config, &suffix);

    // Install handlers before launch so shutdown during any bootstrap step is handled.
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    run_lifecycle(
        &config,
        async {
            tracing::debug!("fetching sandbox bundle");
            let bundle = artifact::fetch(&config, directory.path()).await?;
            tracing::debug!("launching enclave");
            enclave.launch().await?;
            tracing::debug!("provisioning sandbox bundle");
            bundle.provision(config.cid, config.io_timeout).await?;
            Ok(())
        },
        |cid| {
            let enclave = &enclave;
            async move {
                initialize(cid).await?;
                // Initialization may take time; check again before publishing readiness.
                enclave.running().await
            }
        },
        enclave.monitor(),
        async {
            tokio::select! {
                _ = terminate.recv() => {},
                _ = interrupt.recv() => {},
            }
        },
        enclave.stop(),
    )
    .await
}

// Keep lifecycle ordering independent of the external Nitro and vsock operations so deadline,
// readiness and cleanup behavior can be exercised without an enclave-capable host.
async fn run_lifecycle<B, F, I, M, S, C>(
    config: &Config,
    bootstrap: B,
    initialize: F,
    monitor: M,
    shutdown: S,
    cleanup: C,
) -> Result<()>
where
    B: Future<Output = Result<()>>,
    F: FnOnce(u32) -> I,
    I: Future<Output = Result<()>>,
    M: Future<Output = Result<()>>,
    S: Future<Output = ()>,
    C: Future<Output = Result<()>>,
{
    let result = tokio::select! {
        result = async {
            timeout(config.bootstrap_timeout, async {
                bootstrap.await?;
                tracing::debug!("initializing enclave application");
                initialize(config.cid).await.context("application initialization failed")
            })
            .await
            .context("provisioner bootstrap deadline exceeded")??;

            mark_ready(&config.ready_file).await?;
            tracing::info!(cid = config.cid, "enclave ready");
            monitor.await
        } => result,
        () = shutdown => Ok(()),
    };

    // Attempt both cleanup operations, even if either fails. Preserve the original error in logs.
    if let Err(error) = &result {
        tracing::error!(error = format!("{error:#}"), "enclave provisioning failed");
    }
    let readiness = clear_readiness(&config.ready_file).await;
    let termination = cleanup.await;
    readiness?;
    termination.context("enclave termination failed")?;
    result
}

async fn mark_ready(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, b"ready\n").await?;
    Ok(())
}

#[cfg(test)]
mod tests;
