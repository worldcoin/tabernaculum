//! Debug-enclave forwarding of worker stdout/stderr into the enclave's tracing subscriber.

// Only the Linux worker forwards output; elsewhere the level parser is built for its tests.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use tracing::Level;

/// Longest forwarded line; the rest of it is dropped.
pub(crate) const MAX_LINE_BYTES: usize = 8 * 1024;
/// Lines buffered between the pipe readers and a slow subscriber before new ones are dropped.
pub(crate) const QUEUE_LINES: usize = 1024;

/// Reads a leading level token such as `ERROR` or `[warn]`; unlabelled lines are INFO.
pub(crate) fn level(text: &str) -> Level {
    let token = text
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|c| c == '[' || c == ']');
    match token.to_ascii_uppercase().as_str() {
        "ERROR" => Level::ERROR,
        "WARN" | "WARNING" => Level::WARN,
        "DEBUG" => Level::DEBUG,
        "TRACE" => Level::TRACE,
        _ => Level::INFO,
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{Forwarder, pipe};

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs::File,
        io::{self, Read},
        os::fd::FromRawFd,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
            mpsc::{self, Receiver, SyncSender, TrySendError},
        },
        thread,
        time::Duration,
    };

    use tabernaculum_bundle::lines::{Line, Lines};
    use tracing::Level;

    use super::{MAX_LINE_BYTES, QUEUE_LINES, level};

    type Queued = (&'static str, Line);

    /// Returns a close-on-exec `(read, write)` pipe.
    pub(crate) fn pipe() -> io::Result<(File, File)> {
        let mut fds = [0; 2];
        // SAFETY: pipe2 writes two descriptors into this owned array on success.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Both descriptors are new and owned only here.
        Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
    }

    /// Readers never wait on the subscriber, so a slow log sink cannot stall the worker.
    #[derive(Debug)]
    pub(crate) struct Forwarder {
        /// Disconnects once the emitter has written every queued line.
        done: Receiver<()>,
    }

    impl Forwarder {
        /// Starts draining the read ends; they reach EOF once the worker exits.
        pub(crate) fn start(
            pid: libc::pid_t,
            streams: [(&'static str, File); 2],
        ) -> io::Result<Self> {
            let (lines, queued) = mpsc::sync_channel::<Queued>(QUEUE_LINES);
            let dropped = Arc::new(AtomicU64::new(0));
            for (stream, file) in streams {
                let (lines, dropped) = (lines.clone(), Arc::clone(&dropped));
                thread::Builder::new()
                    .name(format!("worker-{stream}"))
                    .spawn(move || read(pid, stream, file, &lines, &dropped))?;
            }
            drop(lines);
            let (signal, done) = mpsc::sync_channel(0);
            thread::Builder::new()
                .name("worker-output".into())
                .spawn(move || {
                    let _signal: SyncSender<()> = signal;
                    for (stream, line) in queued {
                        report_dropped(pid, &dropped);
                        emit(pid, stream, &line);
                    }
                    report_dropped(pid, &dropped);
                })?;
            Ok(Self { done })
        }

        /// Waits up to `timeout` for output already written by a killed worker.
        pub(crate) fn drain(&self, timeout: Duration) {
            let _ = self.done.recv_timeout(timeout);
        }
    }

    fn read(
        pid: libc::pid_t,
        stream: &'static str,
        mut file: File,
        queue: &SyncSender<Queued>,
        dropped: &AtomicU64,
    ) {
        let mut lines = Lines::new(MAX_LINE_BYTES);
        let mut buffer = [0; 8192];
        let send = |line| match queue.try_send((stream, line)) {
            Ok(()) => {}
            // A disconnected emitter panicked; keep draining so the worker never blocks.
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
        };
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => lines.push(&buffer[..read]).into_iter().for_each(&send),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    tracing::error!(dependency = "worker", pid, stream, %error, "worker output read failed");
                    break;
                }
            }
        }
        lines.finish().into_iter().for_each(&send);
    }

    fn report_dropped(pid: libc::pid_t, dropped: &AtomicU64) {
        let count = dropped.swap(0, Ordering::Relaxed);
        if count > 0 {
            tracing::warn!(
                dependency = "worker",
                pid,
                dropped = count,
                "worker output lines dropped: log subscriber too slow"
            );
        }
    }

    fn emit(pid: libc::pid_t, stream: &'static str, line: &Line) {
        // Callsite levels are static, so each level needs its own event.
        macro_rules! event {
            ($level:expr) => {
                tracing::event!(
                    target: "tabernaculum::worker",
                    $level,
                    dependency = "worker",
                    pid,
                    stream,
                    truncated = line.truncated,
                    "{}",
                    line.text
                )
            };
        }
        match level(&line.text) {
            Level::ERROR => event!(Level::ERROR),
            Level::WARN => event!(Level::WARN),
            Level::DEBUG => event!(Level::DEBUG),
            Level::TRACE => event!(Level::TRACE),
            _ => event!(Level::INFO),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_level_tokens_set_the_event_level() {
        for (text, expected) in [
            ("ERROR [engine] model failed", Level::ERROR),
            ("[warn] slow frame", Level::WARN),
            ("WARNING low light", Level::WARN),
            ("debug: x", Level::INFO),
            ("DEBUG x", Level::DEBUG),
            ("TRACE x", Level::TRACE),
            ("loaded model", Level::INFO),
            ("", Level::INFO),
        ] {
            assert_eq!(level(text), expected, "{text}");
        }
    }
}
