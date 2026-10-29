//! Relays a debug enclave's console to stdout, where the node's log agent collects it.

use std::{
    collections::hash_map::RandomState,
    convert::Infallible,
    ffi::OsStr,
    hash::BuildHasher,
    io::{self, Write},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use tabernaculum_bundle::lines::{Line, Lines};
use tokio::{io::AsyncReadExt, process::Command, time::sleep};

/// Longest relayed line; the enclave's own JSON events stay far below this.
const MAX_LINE_BYTES: usize = 16 * 1024;

/// Inputs for following one debug-mode enclave's console.
pub struct ConsoleOptions {
    /// `EnclaveID` reported by `nitro-cli run-enclave` or `describe-enclaves`.
    pub enclave_id: String,
}

/// Reattach delays after the console stream ends.
#[derive(Clone, Copy)]
pub(crate) struct Backoff {
    pub(crate) initial: Duration,
    pub(crate) max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(30),
        }
    }
}

impl Backoff {
    /// Exponential with full jitter in its upper half, so restarted relays do not align.
    fn delay(self, attempt: u32) -> Duration {
        let ceiling = self
            .initial
            .saturating_mul(1 << attempt.min(16))
            .min(self.max);
        let jitter = RandomState::new().hash_one(attempt) % 1000;
        ceiling / 2 + ceiling / 2 * u32::try_from(jitter).unwrap_or(0) / 1000
    }
}

/// Copies `nitro-cli console` output to stdout line by line, unchanged except for sanitizing.
///
/// Only a `--debug-mode` enclave exposes its console. Enclave JSON events therefore reach the log
/// agent as-is. Each line is written whole, so it never interleaves with this process's logs.
/// Lines printed before the console attaches are not replayed.
///
/// Runs until dropped and reattaches with bounded exponential backoff and jitter when the
/// console ends. It never affects readiness, so a missing log stream cannot fail the enclave.
///
/// # Errors
/// Returns only for an invalid enclave ID.
pub async fn forward_console(options: ConsoleOptions) -> Result<Infallible> {
    let id = options.enclave_id;
    ensure!(
        id.len() <= 64
            && id.starts_with(|c: char| c.is_ascii_alphanumeric())
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid enclave ID"
    );
    let args = ["console".as_ref(), "--enclave-id".as_ref(), id.as_ref()];
    relay("nitro-cli", &args, Backoff::default(), &mut io::stdout()).await
}

pub(crate) async fn relay(
    program: &str,
    args: &[&OsStr],
    backoff: Backoff,
    out: &mut impl Write,
) -> Result<Infallible> {
    let mut attempt = 0;
    loop {
        let started = Instant::now();
        let error = match attach(program, args, out).await {
            Ok(()) => "console stream ended".to_owned(),
            Err(error) => format!("{error:#}"),
        };
        // A stream that stayed up longer than the longest delay was healthy; retry quickly.
        if started.elapsed() > backoff.max {
            attempt = 0;
        }
        let delay = backoff.delay(attempt);
        tracing::warn!(
            dependency = "nitro-cli",
            retry_count = attempt,
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            error,
            "enclave console relay interrupted; reattaching"
        );
        attempt = attempt.saturating_add(1);
        sleep(delay).await;
    }
}

async fn attach(program: &str, args: &[&OsStr], out: &mut impl Write) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("cannot start {program}"))?;
    let mut stdout = child.stdout.take().context("missing console stdout")?;
    let mut lines = Lines::new(MAX_LINE_BYTES);
    let mut buffer = vec![0; 8192];
    loop {
        let read = stdout
            .read(&mut buffer)
            .await
            .context("console read failed")?;
        if read == 0 {
            break;
        }
        for line in lines.push(&buffer[..read]) {
            write_line(out, &line)?;
        }
    }
    if let Some(line) = lines.finish() {
        write_line(out, &line)?;
    }
    let status = child.wait().await?;
    ensure!(status.success(), "{program} console exited ({status})");
    Ok(())
}

fn write_line(out: &mut impl Write, line: &Line) -> Result<()> {
    let marker = if line.truncated { " [truncated]" } else { "" };
    out.write_all(format!("{}{marker}\n", line.text).as_bytes())
        .and_then(|()| out.flush())
        .context("cannot write console line to stdout")
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Backoff = Backoff {
        initial: Duration::from_millis(5),
        max: Duration::from_millis(20),
    };

    #[test]
    fn backoff_grows_to_its_cap_with_jitter() {
        let backoff = Backoff::default();
        for attempt in [0, 1, 5, 40, u32::MAX] {
            let ceiling = (backoff.initial * 2_u32.pow(attempt.min(6))).min(backoff.max);
            let delay = backoff.delay(attempt);
            assert!(
                delay >= ceiling / 2 && delay <= ceiling,
                "{attempt}: {delay:?}"
            );
        }
    }

    #[tokio::test]
    async fn console_lines_are_relayed_whole_and_reattached_after_exit() {
        let directory = tempfile::tempdir().unwrap();
        let runs = directory.path().join("runs");
        let script = format!(
            r#"echo run >> '{}'; printf '{{"level":"WARN","message":"a"}}\n\033[2mkernel\r\n%020000d\npartial' 0; exit 1"#,
            runs.display()
        );
        let args = ["-c".as_ref(), script.as_ref()];
        let mut out = Vec::new();
        let relay = relay("/bin/sh", &args, FAST, &mut out);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), relay)
                .await
                .is_err()
        );

        assert!(std::fs::read_to_string(&runs).unwrap().lines().count() >= 2);
        let out = String::from_utf8(out).unwrap();
        let first: Vec<_> = out.lines().take(4).collect();
        let cut = format!("{} [truncated]", "0".repeat(MAX_LINE_BYTES));
        assert_eq!(
            first,
            [
                r#"{"level":"WARN","message":"a"}"#,
                "\u{FFFD}[2mkernel",
                cut.as_str(),
                "partial",
            ]
        );
    }

    #[tokio::test]
    async fn invalid_enclave_ids_are_rejected_before_running_nitro_cli() {
        for enclave_id in ["", "i-0abc enc", "--help", &"a".repeat(65)] {
            let enclave_id = enclave_id.to_owned();
            assert!(
                forward_console(ConsoleOptions { enclave_id })
                    .await
                    .is_err()
            );
        }
    }
}
