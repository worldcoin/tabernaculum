//! Drains captured worker output into a bounded channel, one line per message, tagged by worker.
//!
//! The drain never blocks on its consumer: when the channel is full, lines are dropped and
//! counted, so slow or absent readers cannot stall workers on a full pipe.

use std::{
    io::{self, PipeReader, Read},
    os::fd::{AsRawFd, RawFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use super::{WorkerId, lock};

/// Longest line delivered whole; longer output arrives in chunks of this size.
pub const MAX_OUTPUT_LINE_BYTES: usize = 64 * 1024;
/// Upper bound on how long newly launched workers wait to be drained, and on shutdown.
const REFRESH: Duration = Duration::from_millis(20);

/// Which worker stream a line came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputStream {
    /// The worker's stdout.
    Stdout,
    /// The worker's stderr.
    Stderr,
}

/// One line of captured worker output, without its trailing newline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputLine {
    /// The worker that wrote it.
    pub worker: WorkerId,
    /// The stream it was written to.
    pub stream: OutputStream,
    /// At most [`MAX_OUTPUT_LINE_BYTES`] bytes.
    pub line: Vec<u8>,
}

struct Pipe {
    worker: WorkerId,
    stream: OutputStream,
    reader: PipeReader,
    /// Bytes after the last newline.
    partial: Vec<u8>,
}

struct Shared {
    /// Pipes of newly launched workers, picked up by the drain thread.
    added: Mutex<Vec<Pipe>>,
    stop: AtomicBool,
    dropped: AtomicU64,
}

/// The drain thread and the channel it fills.
pub(crate) struct Drain {
    shared: Arc<Shared>,
    receiver: Mutex<Option<Receiver<OutputLine>>>,
    thread: Option<JoinHandle<()>>,
}

impl Drain {
    pub(crate) fn start(capacity: usize) -> io::Result<Self> {
        let (sender, receiver) = sync_channel(capacity);
        let shared = Arc::new(Shared {
            added: Mutex::new(Vec::new()),
            stop: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
        });
        let thread = thread::Builder::new().name("worker-output".into()).spawn({
            let shared = Arc::clone(&shared);
            move || run(&shared, &sender)
        })?;
        Ok(Self {
            shared,
            receiver: Mutex::new(Some(receiver)),
            thread: Some(thread),
        })
    }

    /// Drains a new worker's pipes until they reach EOF at its exit.
    pub(crate) fn add(
        &self,
        worker: WorkerId,
        stdout: PipeReader,
        stderr: PipeReader,
    ) -> io::Result<()> {
        set_nonblocking(stdout.as_raw_fd())?;
        set_nonblocking(stderr.as_raw_fd())?;
        let mut added = lock(&self.shared.added);
        for (stream, reader) in [
            (OutputStream::Stdout, stdout),
            (OutputStream::Stderr, stderr),
        ] {
            added.push(Pipe {
                worker,
                stream,
                reader,
                partial: Vec::new(),
            });
        }
        Ok(())
    }

    pub(crate) fn take_receiver(&self) -> Option<Receiver<OutputLine>> {
        lock(&self.receiver).take()
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!(dependency = "worker_output", "worker output drain panicked");
        }
    }
}

fn run(shared: &Shared, sender: &SyncSender<OutputLine>) {
    let mut pipes: Vec<Pipe> = Vec::new();
    let mut buffer = vec![0; MAX_OUTPUT_LINE_BYTES];
    let mut deliver = |line: OutputLine| {
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = sender.try_send(line) {
            shared.dropped.fetch_add(1, Ordering::Relaxed);
        }
    };
    while !shared.stop.load(Ordering::Relaxed) {
        pipes.append(&mut lock(&shared.added));
        let mut fds: Vec<_> = pipes
            .iter()
            .map(|pipe| libc::pollfd {
                fd: pipe.reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let timeout = i32::try_from(REFRESH.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: poll reads and writes only the `fds.len()` owned pollfds.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                tracing::error!(dependency = "worker_output", %error, "worker output poll failed");
                thread::sleep(REFRESH);
            }
            continue;
        }
        let mut open = Vec::with_capacity(pipes.len());
        for (mut pipe, fd) in pipes.drain(..).zip(&fds) {
            if fd.revents == 0 || read_once(&mut pipe, &mut buffer, &mut deliver) {
                open.push(pipe);
            }
        }
        pipes = open;
    }
}

/// One read per round, so a chatty worker cannot starve the others. False once closed.
fn read_once(pipe: &mut Pipe, buffer: &mut [u8], deliver: &mut impl FnMut(OutputLine)) -> bool {
    match pipe.reader.read(buffer) {
        Ok(0) => {
            flush(pipe, deliver);
            false
        }
        Ok(length) => {
            split(pipe, &buffer[..length], deliver);
            true
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            true
        }
        Err(error) => {
            tracing::warn!(dependency = "worker_output", worker = %pipe.worker, %error, "worker output read failed");
            flush(pipe, deliver);
            false
        }
    }
}

/// Emits every complete line and every full chunk; keeps the rest for the next read.
fn split(pipe: &mut Pipe, bytes: &[u8], deliver: &mut impl FnMut(OutputLine)) {
    for piece in bytes.split_inclusive(|&byte| byte == b'\n') {
        let complete = piece.last() == Some(&b'\n');
        let mut body = if complete {
            &piece[..piece.len() - 1]
        } else {
            piece
        };
        while pipe.partial.len() + body.len() > MAX_OUTPUT_LINE_BYTES {
            let take = MAX_OUTPUT_LINE_BYTES - pipe.partial.len();
            pipe.partial.extend_from_slice(&body[..take]);
            body = &body[take..];
            emit(pipe, deliver);
        }
        pipe.partial.extend_from_slice(body);
        if complete {
            emit(pipe, deliver);
        }
    }
}

fn flush(pipe: &mut Pipe, deliver: &mut impl FnMut(OutputLine)) {
    if !pipe.partial.is_empty() {
        emit(pipe, deliver);
    }
}

fn emit(pipe: &mut Pipe, deliver: &mut impl FnMut(OutputLine)) {
    deliver(OutputLine {
        worker: pipe.worker,
        stream: pipe.stream,
        line: std::mem::take(&mut pipe.partial),
    });
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl only reads and updates the flags of this owned descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{io::Write, time::Instant};

    use super::*;

    const WORKER: WorkerId = WorkerId {
        slot: 1,
        generation: 7,
    };

    fn pipes() -> (PipeReader, io::PipeWriter, PipeReader, io::PipeWriter) {
        let (stdout, stdout_writer) = io::pipe().unwrap();
        let (stderr, stderr_writer) = io::pipe().unwrap();
        (stdout, stdout_writer, stderr, stderr_writer)
    }

    fn line(stream: OutputStream, bytes: &[u8]) -> OutputLine {
        OutputLine {
            worker: WORKER,
            stream,
            line: bytes.to_vec(),
        }
    }

    fn receive(receiver: &Receiver<OutputLine>) -> OutputLine {
        receiver.recv_timeout(Duration::from_secs(2)).unwrap()
    }

    #[test]
    fn lines_are_tagged_and_split_and_flushed_at_eof() {
        let drain = Drain::start(64).unwrap();
        let receiver = drain.take_receiver().unwrap();
        assert!(drain.take_receiver().is_none());
        let (stdout, mut stdout_writer, stderr, mut stderr_writer) = pipes();
        drain.add(WORKER, stdout, stderr).unwrap();

        stdout_writer.write_all(b"one\ntwo\npar").unwrap();
        assert_eq!(receive(&receiver), line(OutputStream::Stdout, b"one"));
        assert_eq!(receive(&receiver), line(OutputStream::Stdout, b"two"));
        stdout_writer.write_all(b"tial\n").unwrap();
        assert_eq!(receive(&receiver), line(OutputStream::Stdout, b"partial"));

        stderr_writer.write_all(b"\n").unwrap();
        assert_eq!(receive(&receiver), line(OutputStream::Stderr, b""));
        // The worker exits mid-line: the rest still arrives.
        stderr_writer.write_all(b"last words").unwrap();
        drop((stdout_writer, stderr_writer));
        assert_eq!(
            receive(&receiver),
            line(OutputStream::Stderr, b"last words")
        );
        assert_eq!(drain.dropped(), 0);
    }

    #[test]
    fn long_lines_arrive_in_bounded_chunks() {
        let drain = Drain::start(64).unwrap();
        let receiver = drain.take_receiver().unwrap();
        let (stdout, mut stdout_writer, stderr, _stderr_writer) = pipes();
        drain.add(WORKER, stdout, stderr).unwrap();
        let writer = thread::spawn(move || {
            let mut bytes = vec![b'z'; 2 * MAX_OUTPUT_LINE_BYTES + 5];
            bytes.push(b'\n');
            stdout_writer.write_all(&bytes).unwrap();
        });
        let lengths: Vec<_> = (0..3).map(|_| receive(&receiver).line.len()).collect();
        writer.join().unwrap();
        assert_eq!(lengths, [MAX_OUTPUT_LINE_BYTES, MAX_OUTPUT_LINE_BYTES, 5]);
    }

    #[test]
    fn a_full_channel_drops_lines_instead_of_blocking_the_worker() {
        let drain = Drain::start(1).unwrap();
        let (stdout, mut stdout_writer, stderr, _stderr_writer) = pipes();
        drain.add(WORKER, stdout, stderr).unwrap();
        // Far more than the pipe holds: this only finishes because the drain keeps reading.
        let writer = thread::spawn(move || {
            for _ in 0..10_000 {
                stdout_writer.write_all(&[b'x'; 99]).unwrap();
                stdout_writer.write_all(b"\n").unwrap();
            }
        });
        writer.join().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while drain.dropped() < 9_999 {
            assert!(Instant::now() < deadline, "dropped {}", drain.dropped());
            thread::sleep(Duration::from_millis(5));
        }
        let receiver = drain.take_receiver().unwrap();
        assert_eq!(receiver.try_iter().count(), 1);
    }
}
