//! The launcher process and the production pool built on it.
//!
//! The launcher is forked while the enclave is single-threaded and stays single-threaded, so
//! Minijail can fork from it at any time. It owns every pool worker as their parent: only it
//! signals and reaps them, so a worker PID is never reused while the pool can still name it.
//! Requests and replies travel over a `SOCK_SEQPACKET` pair; each spawned worker's IPC socket,
//! and its stdout and stderr read ends when output is captured, are passed back with
//! `SCM_RIGHTS`.

use std::{
    collections::HashSet,
    fs::File,
    io::{self, PipeReader},
    mem::{self, MaybeUninit},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
    sync::{Mutex, mpsc::Receiver},
    time::Duration,
};

use super::{
    Backend, Endpoint, Handle, Leased, MAX_POOL_SIZE, POOL_UID_BASE, PoolConfig, PoolError,
    PoolMode, PoolStatus, WorkerId, lock,
    output::{Drain, OutputLine},
};
use crate::{
    ConnectionConfig, ConnectionError, SandboxConfig, WorkerOutput,
    connection::Connection,
    process::{Launched, launch},
};

/// Bounds every launcher round trip; forking and reaping a jailed worker is fast.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const SPAWN: u8 = 1;
const KILL: u8 = 2;
/// `op`, slot (`u32` LE) and PID (`i32` LE).
const REQUEST_BYTES: usize = 9;
/// Status, PID (`i32` LE) and an error message of at most 256 bytes.
const REPLY_BYTES: usize = 5 + 256;
/// A spawn reply's IPC socket plus captured stdout and stderr.
const MAX_PASSED_FDS: usize = 3;

/// Sandboxed workers spawned on demand after the enclave has started other threads.
pub struct Pool {
    handle: Handle<Launcher>,
}

impl Pool {
    /// Forks the launcher, then fills every slot. Call from a single-threaded bootstrap before
    /// generating keys, like [`crate::Worker::spawn`]; the launcher keeps a copy of this memory.
    /// `sandbox.root` must stay unchanged for the pool's lifetime. `on_fatal` must exit the
    /// enclave immediately; it runs on a crash loop or when the launcher fails.
    /// With [`WorkerOutput::Capture`], read output through [`Pool::take_output`].
    ///
    /// # Errors
    /// Returns an error for invalid configuration, a multi-threaded caller, or a worker that
    /// fails to start.
    pub fn start(
        binary: &File,
        sandbox: SandboxConfig<'_>,
        connection: ConnectionConfig,
        config: PoolConfig,
        on_fatal: fn(PoolError) -> !,
    ) -> Result<Self, PoolError> {
        config.validate()?;
        connection
            .validate()
            .map_err(|_| PoolError::InvalidConfig("invalid worker connection configuration"))?;
        let launcher = Launcher::start(binary, &sandbox, connection, config.output_capacity)?;
        Ok(Self {
            handle: Handle::start(launcher, config, on_fatal)?,
        })
    }

    /// Waits up to the acquire timeout for an idle worker.
    ///
    /// # Errors
    /// Returns [`PoolError::Busy`] when no worker became idle in time.
    pub fn acquire(&self) -> Result<Lease<'_>, PoolError> {
        self.handle.core.acquire().map(|inner| Lease { inner })
    }

    /// Sends one request to an idle worker and returns the response undecoded.
    ///
    /// # Errors
    /// Returns [`PoolError::Busy`] without a free worker, [`PoolError::Request`] for an invalid
    /// request, or [`PoolError::Worker`] when the worker failed and was retired.
    pub fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, PoolError> {
        self.acquire()?.exchange(request)
    }

    /// Kills a worker now, or after its current request. A supervised pool replaces it;
    /// kills do not count towards the crash-loop limit.
    ///
    /// # Errors
    /// Returns [`PoolError::UnknownWorker`] if the ID is not running.
    pub fn kill(&self, id: WorkerId) -> Result<(), PoolError> {
        self.handle.core.kill(id)
    }

    /// Starts a worker in an empty slot of a manual pool and waits for its readiness.
    ///
    /// # Errors
    /// Returns [`PoolError::Full`] without an empty slot, or the launch failure.
    pub fn spawn(&self) -> Result<WorkerId, PoolError> {
        self.handle.core.spawn()
    }

    /// Running workers, idle or busy.
    #[must_use]
    pub fn workers(&self) -> Vec<WorkerId> {
        self.handle.core.workers()
    }

    /// Slot counts for readiness and metrics.
    #[must_use]
    pub fn status(&self) -> PoolStatus {
        self.handle.core.status()
    }

    /// Captured output of every worker, tagged by worker; `None` without
    /// [`WorkerOutput::Capture`] or once taken. The bytes may hold biometric diagnostics.
    /// Lines that arrive while the channel is full, or after the receiver is dropped, are lost.
    pub fn take_output(&self) -> Option<Receiver<OutputLine>> {
        self.handle.core.backend.output.as_ref()?.take_receiver()
    }

    /// Captured lines lost to a full or dropped receiver, for metrics.
    #[must_use]
    pub fn dropped_output_lines(&self) -> u64 {
        self.handle
            .core
            .backend
            .output
            .as_ref()
            .map_or(0, Drain::dropped)
    }
}

/// A supervised pool whose workers each serve exactly one request, then are killed and
/// replaced, so no request reaches a process that held another request's data.
pub struct OneShotPool {
    pool: Pool,
}

impl OneShotPool {
    /// Starts like [`Pool::start`]; `config.mode` must be [`PoolMode::Supervised`].
    ///
    /// # Errors
    /// Returns [`PoolError::InvalidConfig`] for a manual pool, or any [`Pool::start`] error.
    pub fn start(
        binary: &File,
        sandbox: SandboxConfig<'_>,
        connection: ConnectionConfig,
        config: PoolConfig,
        on_fatal: fn(PoolError) -> !,
    ) -> Result<Self, PoolError> {
        if config.mode != PoolMode::Supervised {
            return Err(PoolError::InvalidConfig(
                "one-shot pools must be supervised",
            ));
        }
        Pool::start(binary, sandbox, connection, config, on_fatal).map(|pool| Self { pool })
    }

    /// Sends one request to a fresh worker, kills it, and returns the response undecoded.
    ///
    /// # Errors
    /// Returns [`PoolError::Busy`] without a free worker, [`PoolError::Request`] for an invalid
    /// request, or [`PoolError::Worker`] when the worker failed.
    pub fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, PoolError> {
        self.exchange_checked(request, |_| true)
    }

    /// Like [`OneShotPool::exchange`]; a response `accept` rejects counts toward the crash-loop
    /// limit, so reject only protocol violations. The worker is killed either way.
    ///
    /// # Errors
    /// As [`OneShotPool::exchange`], plus [`PoolError::Worker`] for a rejected response.
    pub fn exchange_checked(
        &self,
        request: &[u8],
        accept: impl FnOnce(&[u8]) -> bool,
    ) -> Result<Vec<u8>, PoolError> {
        self.pool.handle.core.exchange_once(request, accept)
    }

    /// Slot counts for metrics; replacements keep `starting` above zero under load.
    #[must_use]
    pub fn status(&self) -> PoolStatus {
        self.pool.status()
    }

    /// As [`Pool::take_output`].
    pub fn take_output(&self) -> Option<Receiver<OutputLine>> {
        self.pool.take_output()
    }

    /// As [`Pool::dropped_output_lines`].
    #[must_use]
    pub fn dropped_output_lines(&self) -> u64 {
        self.pool.dropped_output_lines()
    }
}

/// Exclusive use of one pooled worker; dropping it returns the worker to the pool.
pub struct Lease<'p> {
    inner: Leased<'p, Launcher>,
}

impl Lease<'_> {
    /// The leased worker.
    #[must_use]
    pub fn id(&self) -> WorkerId {
        self.inner.id
    }

    /// Sends one request and returns the response undecoded.
    ///
    /// # Errors
    /// Returns [`PoolError::Request`] for an invalid request, or [`PoolError::Worker`] once the
    /// worker failed; it is retired when the lease ends.
    pub fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, PoolError> {
        self.inner.exchange(request)
    }

    /// Kills the worker instead of returning it, so no later request reaches a process that
    /// held this one's data. A supervised pool replaces it; this is not a failure.
    pub fn retire(self) {
        self.inner.retire();
    }

    /// Retires the worker after it broke protocol; this counts toward the crash-loop limit.
    /// To drop a valid response the application merely rejects, use [`Lease::retire`].
    pub fn fail(self) {
        self.inner.fail();
    }
}

/// The parent's end of the launcher; dropping it ends the launcher and its workers.
pub(crate) struct Launcher {
    /// `None` once a round trip failed, since replies may no longer match requests.
    control: Mutex<Option<OwnedFd>>,
    pid: libc::pid_t,
    connection: ConnectionConfig,
    /// Present with captured output; started after the fork, since it is a thread.
    output: Option<Drain>,
}

impl Launcher {
    fn start(
        binary: &File,
        sandbox: &SandboxConfig<'_>,
        connection: ConnectionConfig,
        output_capacity: usize,
    ) -> Result<Self, PoolError> {
        let tasks = std::fs::read_dir("/proc/self/task")
            .map_err(|error| PoolError::Launcher(format!("cannot count threads: {error}")))?
            .count();
        if tasks != 1 {
            return Err(PoolError::MultiThreaded);
        }
        let (parent, child) = seqpacket_pair().map_err(launcher_error)?;
        // SAFETY: getpid has no preconditions.
        let parent_pid = unsafe { libc::getpid() };
        // SAFETY: The process is single-threaded, so the child may run ordinary Rust code.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(launcher_error(io::Error::last_os_error()));
        }
        if pid == 0 {
            drop(parent);
            serve(&child, binary, sandbox, parent_pid);
        }
        drop(child);
        let mut launcher = Self {
            control: Mutex::new(Some(parent)),
            pid,
            connection,
            output: None,
        };
        if let Some(control) = lock(&launcher.control).as_ref() {
            set_timeouts(control.as_raw_fd(), CONTROL_TIMEOUT).map_err(launcher_error)?;
        }
        if sandbox.output == WorkerOutput::Capture {
            launcher.output = Some(Drain::start(output_capacity).map_err(launcher_error)?);
        }
        Ok(launcher)
    }

    fn request(
        &self,
        op: u8,
        slot: u32,
        pid: libc::pid_t,
    ) -> Result<(libc::pid_t, Vec<OwnedFd>), PoolError> {
        let mut control = lock(&self.control);
        let fd = control
            .as_ref()
            .ok_or_else(|| PoolError::Launcher("launcher connection closed".into()))?
            .as_raw_fd();
        let mut request = [0; REQUEST_BYTES];
        request[0] = op;
        request[1..5].copy_from_slice(&slot.to_le_bytes());
        request[5..9].copy_from_slice(&pid.to_le_bytes());
        let mut reply = [0; REPLY_BYTES];
        let result = send_message(fd, &request, &[]).and_then(|()| recv_message(fd, &mut reply));
        let (length, passed) = match result {
            Ok((length, passed)) if length >= 5 => (length, passed),
            Ok(_) => {
                control.take();
                return Err(PoolError::Launcher("truncated launcher reply".into()));
            }
            Err(error) => {
                control.take();
                return Err(launcher_error(error));
            }
        };
        let pid = libc::pid_t::from_le_bytes(reply[1..5].try_into().expect("four bytes"));
        if reply[0] == 0 {
            return Ok((pid, passed));
        }
        let message = String::from_utf8_lossy(&reply[5..length]).into_owned();
        Err(if op == SPAWN {
            PoolError::Launch(message)
        } else {
            PoolError::Launcher(message)
        })
    }
}

impl Backend for Launcher {
    type Worker = PooledWorker;

    fn spawn(&self, id: WorkerId) -> Result<(PooledWorker, Vec<u8>), PoolError> {
        let slot =
            u32::try_from(id.slot).map_err(|_| PoolError::InvalidConfig("slot out of range"))?;
        let (pid, passed) = self.request(SPAWN, slot, 0)?;
        let expected = if self.output.is_some() {
            MAX_PASSED_FDS
        } else {
            1
        };
        if passed.len() != expected {
            self.request(KILL, 0, pid)?;
            return Err(PoolError::Launcher(format!(
                "spawn reply passed {} descriptors, expected {expected}",
                passed.len()
            )));
        }
        let mut passed = passed.into_iter();
        let socket = UnixStream::from(passed.next().expect("length checked"));
        if let Some(output) = &self.output {
            let stdout = PipeReader::from(passed.next().expect("length checked"));
            let stderr = PipeReader::from(passed.next().expect("length checked"));
            if let Err(error) = output.add(id, stdout, stderr) {
                self.request(KILL, 0, pid)?;
                return Err(PoolError::Launch(format!(
                    "cannot drain worker output: {error}"
                )));
            }
        }
        match Connection::open(socket, self.connection.clone()) {
            Ok((connection, ready)) => Ok((PooledWorker { pid, connection }, ready)),
            Err(error) => {
                self.request(KILL, 0, pid)?;
                Err(PoolError::Launch(error.to_string()))
            }
        }
    }

    fn kill(&self, worker: PooledWorker) -> Result<(), PoolError> {
        self.request(KILL, 0, worker.pid).map(drop)
    }

    /// A busy control socket is skipped: that round trip reports a dead launcher itself.
    fn is_alive(&self) -> bool {
        match self.control.try_lock() {
            Ok(control) => control.as_ref().is_some_and(|fd| idle_open(fd.as_raw_fd())),
            Err(std::sync::TryLockError::Poisoned(control)) => control
                .into_inner()
                .as_ref()
                .is_some_and(|fd| idle_open(fd.as_raw_fd())),
            Err(std::sync::TryLockError::WouldBlock) => true,
        }
    }
}

impl Drop for Launcher {
    /// Closing the control socket makes the launcher kill and reap its workers, then exit.
    fn drop(&mut self) {
        lock(&self.control).take();
        let mut status = 0;
        // SAFETY: The launcher is this process's own child and is reaped only here.
        while unsafe { libc::waitpid(self.pid, &mut status, 0) } < 0
            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {}
    }
}

/// A pool worker reached through its IPC socket; the launcher holds its PID.
pub(crate) struct PooledWorker {
    pid: libc::pid_t,
    connection: Connection,
}

impl Endpoint for PooledWorker {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, ConnectionError> {
        self.connection.exchange(request)
    }

    fn failure(&self) -> Option<&ConnectionError> {
        self.connection.failure()
    }

    fn close(&mut self, error: ConnectionError) {
        self.connection.close(error);
    }

    fn is_alive(&self) -> bool {
        self.connection
            .stream()
            .is_some_and(|stream| idle_open(stream.as_raw_fd()))
    }
}

/// An idle peer never writes, so readability or hangup means it exited or broke protocol.
fn idle_open(fd: RawFd) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: poll reads and writes only this one owned pollfd.
    match unsafe { libc::poll(&mut poll, 1, 0) } {
        0 => true,
        result if result > 0 => false,
        _ => io::Error::last_os_error().kind() == io::ErrorKind::Interrupted,
    }
}

/// The launcher's loop; it never returns and never logs, so it needs no subscriber threads.
fn serve(control: &OwnedFd, binary: &File, sandbox: &SandboxConfig<'_>, parent: libc::pid_t) -> ! {
    // SAFETY: These calls affect only this process. Exiting without unwinding avoids running
    // the parent's destructors in the copy.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent {
            libc::_exit(1);
        }
    }
    if close_inherited(&[control.as_raw_fd(), binary.as_raw_fd()]).is_err() {
        // SAFETY: See above.
        unsafe { libc::_exit(1) };
    }

    let fd = control.as_raw_fd();
    let mut live = HashSet::new();
    let mut request = [0; REQUEST_BYTES + 1];
    loop {
        let length = match recv_message(fd, &mut request) {
            Ok((length, _)) => length,
            // EOF or a broken control socket: the pool is gone.
            Err(_) => break,
        };
        let slot = u32::from_le_bytes(request[1..5].try_into().expect("four bytes"));
        let pid = libc::pid_t::from_le_bytes(request[5..9].try_into().expect("four bytes"));
        let sent = match (length, request[0]) {
            (REQUEST_BYTES, SPAWN) if (slot as usize) < MAX_POOL_SIZE => {
                match launch(binary, sandbox, POOL_UID_BASE + slot) {
                    Ok(Launched {
                        pid,
                        rpc,
                        stdout,
                        stderr,
                    }) => {
                        live.insert(pid);
                        let mut pass = vec![rpc.as_raw_fd()];
                        pass.extend(stdout.iter().chain(&stderr).map(AsRawFd::as_raw_fd));
                        // The launcher's copies close here; the enclave now holds the only ones.
                        send_message(fd, &reply(0, pid, ""), &pass)
                    }
                    Err(error) => send_message(fd, &reply(1, 0, &error.to_string()), &[]),
                }
            }
            (REQUEST_BYTES, KILL) if live.remove(&pid) => {
                kill_and_reap(pid);
                send_message(fd, &reply(0, pid, ""), &[])
            }
            (REQUEST_BYTES, KILL) => send_message(fd, &reply(1, pid, "unknown worker"), &[]),
            _ => send_message(fd, &reply(1, 0, "malformed launcher request"), &[]),
        };
        if sent.is_err() {
            break;
        }
    }
    for pid in live {
        kill_and_reap(pid);
    }
    // SAFETY: See above.
    unsafe { libc::_exit(0) }
}

fn reply(status: u8, pid: libc::pid_t, message: &str) -> Vec<u8> {
    let mut reply = vec![status];
    reply.extend_from_slice(&pid.to_le_bytes());
    let mut end = message.len().min(REPLY_BYTES - 5);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    reply.extend_from_slice(&message.as_bytes()[..end]);
    reply
}

/// SIGKILL ends namespace PID 1 and every descendant; waiting cannot outlive that.
fn kill_and_reap(pid: libc::pid_t) {
    let mut status = 0;
    // SAFETY: `pid` is an unreaped child of this launcher, so it cannot have been reused.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        while libc::waitpid(pid, &mut status, 0) < 0
            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {}
    }
}

/// Closes every descriptor above stdio except `keep`, so the launcher holds no parent sockets.
fn close_inherited(keep: &[RawFd]) -> io::Result<()> {
    let mut keep: Vec<_> = keep
        .iter()
        .filter_map(|&fd| u32::try_from(fd).ok())
        .collect();
    keep.sort_unstable();
    let mut low = 3;
    for fd in keep.into_iter().chain([u32::MAX]) {
        if fd > low {
            // SAFETY: Closing descriptors owned only by this forked copy.
            if unsafe { libc::syscall(libc::SYS_close_range, low, fd - 1, 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        low = low.max(fd.saturating_add(1));
    }
    Ok(())
}

fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: socketpair writes two descriptors into this owned array on success.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Both descriptors are new and owned only here.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn set_timeouts(fd: RawFd, timeout: Duration) -> io::Result<()> {
    let timeval = libc::timeval {
        tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: setsockopt reads one initialized timeval.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&raw const timeval).cast(),
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Ancillary space for up to [`MAX_PASSED_FDS`] descriptors, aligned for `cmsghdr`.
#[repr(C, align(8))]
struct Control([u8; 32]);

fn send_message(fd: RawFd, bytes: &[u8], pass: &[RawFd]) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut control = Control([0; 32]);
    // SAFETY: An all-zero msghdr is valid; the fields set below point at live locals.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    if !pass.is_empty() {
        let fd_bytes = u32::try_from(mem::size_of_val(pass)).unwrap_or(u32::MAX);
        // SAFETY: CMSG_SPACE only computes a size.
        let space = unsafe { libc::CMSG_SPACE(fd_bytes) } as usize;
        if pass.len() > MAX_PASSED_FDS || space > control.0.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many descriptors for one launcher message",
            ));
        }
        // SAFETY: The control buffer holds `space` bytes, and CMSG_FIRSTHDR returns its
        // aligned start; the descriptors are written unaligned into CMSG_DATA.
        unsafe {
            message.msg_control = control.0.as_mut_ptr().cast();
            message.msg_controllen = space as _;
            let header = libc::CMSG_FIRSTHDR(&raw const message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(fd_bytes) as _;
            let data = libc::CMSG_DATA(header).cast::<RawFd>();
            for (index, &passed) in pass.iter().enumerate() {
                data.add(index).write_unaligned(passed);
            }
        }
    }
    loop {
        // SAFETY: The message points at live buffers for the duration of the call.
        if unsafe { libc::sendmsg(fd, &raw const message, libc::MSG_NOSIGNAL) } >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Receives one message and at most [`MAX_PASSED_FDS`] descriptors; extra or truncated data
/// is an error.
fn recv_message(fd: RawFd, buffer: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut control = MaybeUninit::<Control>::zeroed();
    // SAFETY: An all-zero msghdr is valid; the fields set below point at live locals.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = mem::size_of::<Control>() as _;
    let length = loop {
        // SAFETY: The message points at live buffers for the duration of the call.
        let length = unsafe { libc::recvmsg(fd, &raw mut message, libc::MSG_CMSG_CLOEXEC) };
        if length >= 0 {
            break length as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    let mut passed = Vec::new();
    // SAFETY: The kernel initialized msg_controllen bytes of control messages; the iteration
    // macros stay within them, and each SCM_RIGHTS payload holds whole descriptors.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&raw const message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(header).cast::<RawFd>();
                let count = ((*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                    / mem::size_of::<RawFd>();
                for index in 0..count {
                    passed.push(OwnedFd::from_raw_fd(data.add(index).read_unaligned()));
                }
            }
            header = libc::CMSG_NXTHDR(&raw const message, header);
        }
    }
    if length == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || passed.len() > MAX_PASSED_FDS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected launcher message size",
        ));
    }
    Ok((length, passed))
}

fn launcher_error(error: io::Error) -> PoolError {
    let error = if error.kind() == io::ErrorKind::WouldBlock {
        "launcher timed out".to_owned()
    } else {
        error.to_string()
    };
    PoolError::Launcher(error)
}
