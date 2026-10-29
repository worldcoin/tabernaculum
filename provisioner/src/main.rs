//! Host-side enclave provisioner: Kubernetes owns restart/backoff; each container provisions one enclave.
mod artifact;
mod config;
mod enclave;
mod process;

use anyhow::{Context, Result};
use config::Config;
use enclave::{Enclave, clear_readiness};
use tabernaculum_provisioner::{ConsoleOptions, forward_console};
use tokio::{
    signal::unix::{SignalKind, signal},
    task::JoinHandle,
    time::timeout,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    clear_readiness(&config::ready_file()).await?;

    let config = Config::from_env()?;
    let directory = tempfile::tempdir()?;
    let suffix = directory
        .path()
        .file_name()
        .context("missing temporary directory name")?
        .to_string_lossy();
    let enclave = Enclave::new(&config, &suffix);

    // Install handlers before launch so SIGTERM during any bootstrap step is handled.
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    // Outlives bootstrap so teardown output is relayed too.
    let mut relay = None;
    let result = tokio::select! {
        result = run_enclave(&config, &enclave, directory.path(), &mut relay) => result,
        _ = terminate.recv() => Ok(()),
        _ = interrupt.recv() => Ok(()),
    };
    // Attempt both cleanup operations, even if either one fails. Preserve the
    // bootstrap/health error in logs if cleanup itself also fails.
    if let Err(error) = &result {
        tracing::error!(error = format!("{error:#}"), "enclave provisioning failed");
    }

    let readiness = clear_readiness(&config.ready_file).await;
    let termination = enclave.stop().await;
    drop(relay);

    readiness?;
    termination.context("enclave termination failed")?;

    result
}

/// Stops the console relay with the enclave it follows.
struct Relay(JoinHandle<()>);

impl Drop for Relay {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn run_enclave(
    config: &Config,
    enclave: &Enclave<'_>,
    directory: &std::path::Path,
    relay: &mut Option<Relay>,
) -> Result<()> {
    timeout(config.bootstrap_timeout, async {
        tracing::debug!("fetching sandbox bundle");
        let bundle = artifact::fetch(config, directory).await?;

        tracing::debug!("launching enclave");
        let enclave_id = enclave.launch().await?;
        // Attach before provisioning so the worker's startup output is relayed.
        if config.console_logs {
            *relay = Some(Relay(tokio::spawn(async move {
                let Err(error) = forward_console(ConsoleOptions { enclave_id }).await;
                tracing::error!(error = format!("{error:#}"), "enclave console relay failed");
            })));
        }

        tracing::debug!("provisioning sandbox bundle");
        bundle.provision(config.cid, config.io_timeout).await?;

        enclave.running().await
    })
    .await
    .context("provisioner bootstrap deadline exceeded")??;

    mark_ready(&config.ready_file).await?;
    tracing::info!(enclave = %enclave.name, "enclave ready");

    enclave.monitor().await
}

async fn mark_ready(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    tokio::fs::write(path, b"ready\n").await?;
    Ok(())
}
