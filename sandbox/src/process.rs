//! Linux worker ownership through Minijail; launch before threads or keys exist.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("the worker seccomp policy is reviewed for x86_64 Linux only");

use std::{
    fs::File,
    io,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::Arc,
};

use crate::{ConnectionConfig, ConnectionError, connection::Connection};

#[path = "jail.rs"]
mod jail;
pub use jail::{SandboxConfig, WORKER_UID};

// Upstream's Cargo fallback builds static Minijail but does not declare its libcap dependency.
#[link(name = "cap")]
unsafe extern "C" {}

/// Owns one worker for the enclave's lifetime. Fatal failures terminate the enclave.
pub struct Worker {
    /// Closes permanently after the first fatal failure.
    connection: Connection,
    /// Never reaped here, so it cannot be reused before the enclave exits.
    pid: libc::pid_t,
    /// Enclave-owned exit policy; must not unwind or wait for worker cleanup.
    on_fatal: fn(ConnectionError) -> !,
}

impl Worker {
    /// Launches an open executable with FD 3 inside the embedded sandbox and returns it with
    /// its undecoded readiness frame. Call from a single-threaded bootstrap before generating
    /// keys. `on_fatal` must exit the enclave process immediately, not panic or stop a task.
    ///
    /// # Errors
    /// Returns an error if the sandbox, configuration or launch is invalid, or the worker
    /// never becomes ready.
    pub fn spawn(
        binary: &File,
        sandbox: SandboxConfig<'_>,
        config: ConnectionConfig,
        on_fatal: fn(ConnectionError) -> !,
    ) -> Result<(Self, Vec<u8>), WorkerError> {
        config.validate()?;
        let (rpc, child) = UnixStream::pair()?;

        let jail = sandbox.create_jail()?;

        let argv = [c"worker".as_ptr(), c"--bundled".as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null::<libc::c_char>()];
        // SAFETY: Minijail checks that the caller is single-threaded and remaps/closes FDs.
        // In the child, only libc calls run; failed exec exits without dropping Rust owners.
        // run_fd_remap uses LD_PRELOAD, which would let a supplied loader run before seccomp.
        let pid = unsafe { jail.fork_remap(&[(child.as_raw_fd(), 3), (binary.as_raw_fd(), 4)])? };
        if pid == 0 {
            // SAFETY: FD 4 is the executable. Close it on exec; only IPC and null stdio survive.
            unsafe {
                if libc::fcntl(4, libc::F_SETFD, libc::FD_CLOEXEC) == 0 {
                    libc::syscall(
                        libc::SYS_execveat,
                        4,
                        c"".as_ptr(),
                        argv.as_ptr(),
                        envp.as_ptr(),
                        libc::AT_EMPTY_PATH,
                    );
                }
                libc::_exit(127);
            }
        }

        // Minijail::drop only frees the parent's configuration; it neither signals nor waits
        // for the child, so this owner can move to a blocking worker thread.
        drop(jail);
        // Close the parent's duplicate so an initialization failure is observed as EOF.
        drop(child);
        let (connection, ready) = Connection::open(rpc, config).map_err(|error| {
            kill(pid);
            WorkerError::Connection(error)
        })?;

        Ok((
            Self {
                connection,
                pid,
                on_fatal,
            },
            ready,
        ))
    }

    /// Sends one request and returns the response undecoded. Returns only recoverable errors;
    /// a fatal failure kills the worker and exits through `on_fatal`.
    ///
    /// # Errors
    /// Returns [`ConnectionError::InvalidRequest`] for an empty or oversized request.
    #[tracing::instrument(skip_all, fields(dependency = "worker", pid = self.pid))]
    pub fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, ConnectionError> {
        self.check_alive();
        let result = self.connection.exchange(request);
        if let Some(error) = self.connection.failure().cloned() {
            tracing::error!(dependency = "worker", pid = self.pid, %error, "worker exchange failed");
            kill(self.pid);
            (self.on_fatal)(error);
        }

        result
    }

    /// Ends the worker after the caller rejects one of its responses.
    pub fn fail(&mut self) -> ! {
        tracing::error!(
            dependency = "worker",
            pid = self.pid,
            "worker response rejected"
        );
        self.connection.close(ConnectionError::Protocol);
        kill(self.pid);
        (self.on_fatal)(ConnectionError::Protocol)
    }

    /// Detects idle exits without reaping, signalling a healthy worker, or sending IPC.
    pub fn check_alive(&self) {
        // SAFETY: Zero initializes siginfo_t, and waitid writes only this owned buffer.
        // WNOWAIT preserves the child PID so Drop can never signal a reused process ID.
        let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                &mut status,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        let error = if result != 0 {
            Some(io::Error::last_os_error())
        } else if unsafe { status.si_pid() } != 0 {
            Some(io::Error::new(io::ErrorKind::BrokenPipe, "worker exited"))
        } else {
            None
        };

        if let Some(error) = error {
            tracing::error!(dependency = "worker", pid = self.pid, %error, "worker liveness check failed");
            kill(self.pid);
            (self.on_fatal)(ConnectionError::Transport(Arc::new(error)));
        }
    }
}

/// Requests namespace termination without waiting; guest teardown owns final cleanup.
fn kill(pid: libc::pid_t) {
    // SAFETY: This owner never reaps pid. SIGKILL terminates namespace PID 1 and its
    // descendants; a failed signal must not prevent the enclave's fatal exit.
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            tracing::error!(dependency = "worker", pid, %error, "worker kill failed");
        }
    }
}

impl Drop for Worker {
    /// Requests termination on normal shutdown or unwinding, without reaping.
    fn drop(&mut self) {
        kill(self.pid);
    }
}

/// Launch failures; failures after launch go through the enclave's exit handler.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// Invalid trusted root or resource configuration, rejected before forking.
    #[error("invalid worker sandbox: {0}")]
    InvalidSandbox(&'static str),
    /// Required whole-process seccomp termination is unavailable or blocked.
    #[error("worker requires kernel support for seccomp KILL_PROCESS: {0}")]
    UnsupportedKernel(#[source] io::Error),
    /// Socket, runtime root or policy storage failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Minijail could not launch or configure the worker.
    #[error(transparent)]
    Jail(#[from] minijail::Error),
    /// Invalid limits, or the worker failed before its readiness frame.
    #[error(transparent)]
    Connection(#[from] ConnectionError),
}
