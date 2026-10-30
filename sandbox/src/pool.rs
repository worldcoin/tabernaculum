//! A fixed-capacity pool of sandboxed workers.
//!
//! Minijail can only fork from a single-threaded process, so a launcher process is forked at
//! bootstrap and spawns, kills and reaps every pool worker on request. The enclave may start
//! threads afterwards. A worker failure retires only that worker; a supervised pool replaces
//! it, and repeated failures within the restart window are fatal.

// Only the Linux pool drives the core; elsewhere it is built for its tests.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{
    collections::{VecDeque, hash_map::RandomState},
    fmt,
    hash::BuildHasher,
    io,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::ConnectionError;

#[cfg(target_os = "linux")]
mod launcher;
#[cfg(target_os = "linux")]
pub use launcher::{Lease, Pool};

/// Largest pool; each slot runs under its own UID.
pub const MAX_POOL_SIZE: usize = 64;
/// Slot `i` runs as `POOL_UID_BASE + i`, so workers share no thread budget or signal rights.
pub const POOL_UID_BASE: u32 = 70_000;

/// Whether the pool keeps itself at its configured size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolMode {
    /// Retired workers leave an empty slot until [`Pool::spawn`] refills it.
    Manual,
    /// Retired workers are replaced automatically, with backoff after failures.
    Supervised,
}

/// Replacement pacing and the crash-loop limit.
#[derive(Clone, Copy, Debug)]
pub struct RestartPolicy {
    /// Delay before a replacement after one recent failure.
    pub initial_backoff: Duration,
    /// Ceiling for the exponential delay.
    pub max_backoff: Duration,
    /// More failures than this within `window` call the pool's fatal handler.
    pub max_failures: usize,
    /// Sliding window over which failures are counted.
    pub window: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            max_failures: 5,
            window: Duration::from_secs(60),
        }
    }
}

impl RestartPolicy {
    /// Exponential in recent failures, jittered within its upper half; zero without failures.
    fn delay(&self, recent_failures: usize) -> Duration {
        let Some(exponent) = recent_failures.checked_sub(1) else {
            return Duration::ZERO;
        };
        let ceiling = self
            .initial_backoff
            .saturating_mul(1_u32 << exponent.min(16))
            .min(self.max_backoff);
        let jitter =
            u32::try_from(RandomState::new().hash_one(recent_failures) % 1000).unwrap_or(0);
        ceiling / 2 + ceiling / 2 * jitter / 1000
    }
}

/// Pool sizing, admission and restart behavior.
#[derive(Clone, Copy, Debug)]
pub struct PoolConfig {
    /// Slots, all filled at start (1..=[`MAX_POOL_SIZE`]).
    pub size: usize,
    /// Manual or supervised replacement.
    pub mode: PoolMode,
    /// Longest wait for an idle worker before a request is shed with [`PoolError::Busy`].
    pub acquire_timeout: Duration,
    /// How often idle workers are checked for exits.
    pub health_interval: Duration,
    /// Replacement pacing and crash-loop limit.
    pub restart: RestartPolicy,
    /// Accepts a worker's readiness frame; a rejected worker counts as a failed launch.
    pub ready: fn(&[u8]) -> bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            size: 1,
            mode: PoolMode::Supervised,
            acquire_timeout: Duration::from_secs(5),
            health_interval: Duration::from_secs(1),
            restart: RestartPolicy::default(),
            ready: |_| true,
        }
    }
}

impl PoolConfig {
    fn validate(&self) -> Result<(), PoolError> {
        let restart = &self.restart;
        let reason = if !(1..=MAX_POOL_SIZE).contains(&self.size) {
            "size must be between 1 and MAX_POOL_SIZE"
        } else if self.acquire_timeout.is_zero() || self.health_interval.is_zero() {
            "timeouts must be positive"
        } else if restart.initial_backoff.is_zero() || restart.initial_backoff > restart.max_backoff
        {
            "restart backoff must be positive and at most its ceiling"
        } else if restart.max_failures == 0 || restart.window.is_zero() {
            "crash-loop limit and window must be positive"
        } else {
            return Ok(());
        };
        Err(PoolError::InvalidConfig(reason))
    }
}

/// One worker generation in one slot; a replacement gets a new ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WorkerId {
    /// Slot index, which also selects the worker's UID.
    pub slot: usize,
    /// Unique per launched worker.
    pub generation: u64,
}

impl fmt::Display for WorkerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.slot, self.generation)
    }
}

/// A snapshot for readiness and metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolStatus {
    /// Configured slots.
    pub size: usize,
    /// Workers waiting for a request.
    pub idle: usize,
    /// Workers serving a request.
    pub busy: usize,
    /// Slots waiting for or running a replacement launch.
    pub starting: usize,
    /// Failures inside the restart window.
    pub recent_failures: usize,
}

impl PoolStatus {
    /// Every slot holds a running worker.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.idle + self.busy == self.size
    }
}

/// Pool failures. Only [`PoolError::Busy`] and [`PoolError::Request`] leave every worker running.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PoolError {
    /// Rejected before launching anything.
    #[error("invalid worker pool configuration: {0}")]
    InvalidConfig(&'static str),
    /// The launcher must be forked before the process starts other threads.
    #[error("worker pool must start before the process has other threads")]
    MultiThreaded,
    /// No worker became idle within the acquire timeout.
    #[error("no idle worker within the acquire timeout")]
    Busy,
    /// The request's worker failed and was retired.
    #[error("pooled worker failed: {0}")]
    Worker(ConnectionError),
    /// The request was rejected before sending; the worker stays usable.
    #[error(transparent)]
    Request(ConnectionError),
    /// The ID names no running worker.
    #[error("no running pooled worker with this ID")]
    UnknownWorker,
    /// Every slot already holds or is starting a worker.
    #[error("worker pool has no free slot")]
    Full,
    /// A worker did not start or sent an unacceptable readiness frame.
    #[error("pooled worker launch failed: {0}")]
    Launch(String),
    /// The launcher process failed, so workers can no longer be started or reaped.
    #[error("worker launcher failed: {0}")]
    Launcher(String),
    /// Too many failures inside the restart window.
    #[error("{failures} pooled worker failures within the restart window")]
    CrashLoop {
        /// Failures counted in the window.
        failures: usize,
    },
}

/// One launched worker as the pool sees it.
pub(crate) trait Endpoint: Send + 'static {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, ConnectionError>;
    fn failure(&self) -> Option<&ConnectionError>;
    fn close(&mut self, error: ConnectionError);
    /// False once the worker exited, or sent bytes while idle.
    fn is_alive(&self) -> bool;
}

/// Starts and reaps workers; the launcher process in production.
pub(crate) trait Backend: Send + Sync + 'static {
    type Worker: Endpoint;
    /// Starts the worker for `slot` and returns it with its readiness frame.
    fn spawn(&self, slot: usize) -> Result<(Self::Worker, Vec<u8>), PoolError>;
    /// Terminates and reaps the worker. An error means reaping is no longer possible.
    fn kill(&self, worker: Self::Worker) -> Result<(), PoolError>;
}

enum SlotState<W> {
    Idle(W),
    /// `kill` retires the worker when its lease ends.
    Busy {
        kill: bool,
    },
    Starting,
    Empty,
}

struct Slot<W> {
    /// The current or most recent worker's generation.
    generation: u64,
    state: SlotState<W>,
}

struct State<W> {
    slots: Vec<Slot<W>>,
    /// Supervised slots waiting for a replacement, oldest first.
    pending: VecDeque<usize>,
    failures: VecDeque<Instant>,
    /// Earliest next replacement launch.
    not_before: Instant,
    next_generation: u64,
    shutdown: bool,
}

enum Retirement {
    Failed(ConnectionError),
    Killed,
}

pub(crate) struct Core<B: Backend> {
    backend: B,
    config: PoolConfig,
    on_fatal: fn(PoolError) -> !,
    state: Mutex<State<B::Worker>>,
    /// Signals waiting requests that a worker became idle.
    idle: Condvar,
    /// Wakes the supervisor for replacements and shutdown.
    wake: Condvar,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Slot updates never panic midway, so a poisoned state is still consistent.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl<B: Backend> Core<B> {
    /// Fills every slot; any launch failure stops the pool and is returned.
    fn start(
        backend: B,
        config: PoolConfig,
        on_fatal: fn(PoolError) -> !,
    ) -> Result<Self, PoolError> {
        config.validate()?;
        let core = Self {
            backend,
            config,
            on_fatal,
            state: Mutex::new(State {
                slots: (0..config.size)
                    .map(|_| Slot {
                        generation: 0,
                        state: SlotState::Starting,
                    })
                    .collect(),
                pending: VecDeque::new(),
                failures: VecDeque::new(),
                not_before: Instant::now(),
                next_generation: 0,
                shutdown: false,
            }),
            idle: Condvar::new(),
            wake: Condvar::new(),
        };
        for slot in 0..config.size {
            if let Err(error) = core.launch(slot) {
                core.shutdown();
                return Err(error);
            }
        }
        Ok(core)
    }

    /// Launches into a slot already marked `Starting`.
    fn launch(&self, slot: usize) -> Result<WorkerId, PoolError> {
        let (worker, ready) = self.backend.spawn(slot)?;
        if !(self.config.ready)(&ready) {
            self.reap(worker);
            return Err(PoolError::Launch("rejected readiness frame".into()));
        }
        let mut state = lock(&self.state);
        if state.shutdown {
            drop(state);
            self.reap(worker);
            return Err(PoolError::Launcher("worker pool shut down".into()));
        }
        let generation = state.next_generation;
        state.next_generation += 1;
        state.slots[slot] = Slot {
            generation,
            state: SlotState::Idle(worker),
        };
        self.idle.notify_one();
        Ok(WorkerId { slot, generation })
    }

    fn reap(&self, worker: B::Worker) {
        if let Err(error) = self.backend.kill(worker) {
            tracing::error!(dependency = "worker_launcher", %error, "pooled worker could not be reaped");
            (self.on_fatal)(error);
        }
    }

    fn acquire(&self) -> Result<Leased<'_, B>, PoolError> {
        let deadline = Instant::now() + self.config.acquire_timeout;
        let mut state = lock(&self.state);
        loop {
            if let Some(slot) = state
                .slots
                .iter()
                .position(|slot| matches!(slot.state, SlotState::Idle(_)))
            {
                let entry = &mut state.slots[slot];
                let SlotState::Idle(worker) =
                    std::mem::replace(&mut entry.state, SlotState::Busy { kill: false })
                else {
                    unreachable!("position matched an idle slot");
                };
                return Ok(Leased {
                    core: self,
                    id: WorkerId {
                        slot,
                        generation: entry.generation,
                    },
                    worker: Some(worker),
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || state.shutdown {
                return Err(PoolError::Busy);
            }
            state = self
                .idle
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    fn release(&self, id: WorkerId, worker: B::Worker) {
        if let Some(error) = worker.failure().cloned() {
            return self.retire(id, worker, Retirement::Failed(error));
        }
        let mut state = lock(&self.state);
        let entry = &mut state.slots[id.slot];
        if matches!(entry.state, SlotState::Busy { kill: true }) {
            drop(state);
            return self.retire(id, worker, Retirement::Killed);
        }
        entry.state = SlotState::Idle(worker);
        self.idle.notify_one();
    }

    /// Reaps a worker taken out of its slot and refills or empties the slot.
    fn retire(&self, id: WorkerId, worker: B::Worker, reason: Retirement) {
        if let Retirement::Failed(error) = &reason {
            tracing::error!(dependency = "worker", worker = %id, %error, "pooled worker failed; retiring");
        }
        self.reap(worker);
        let mut state = lock(&self.state);
        if matches!(reason, Retirement::Failed(_)) {
            self.record_failure(state);
            state = lock(&self.state);
        }
        state.slots[id.slot].state = match self.config.mode {
            PoolMode::Manual => SlotState::Empty,
            PoolMode::Supervised => {
                state.pending.push_back(id.slot);
                self.wake.notify_one();
                SlotState::Starting
            }
        };
    }

    /// Counts a failure, delays the next replacement, and ends the enclave on a crash loop.
    fn record_failure(&self, mut state: MutexGuard<'_, State<B::Worker>>) {
        let now = Instant::now();
        let window = self.config.restart.window;
        state.failures.push_back(now);
        while state
            .failures
            .front()
            .is_some_and(|&at| now.duration_since(at) > window)
        {
            state.failures.pop_front();
        }
        let failures = state.failures.len();
        state.not_before = now + self.config.restart.delay(failures);
        drop(state);
        if failures > self.config.restart.max_failures {
            tracing::error!(dependency = "worker", failures, "pooled worker crash loop");
            (self.on_fatal)(PoolError::CrashLoop { failures });
        }
    }

    fn kill(&self, id: WorkerId) -> Result<(), PoolError> {
        let mut state = lock(&self.state);
        let entry = state
            .slots
            .get_mut(id.slot)
            .filter(|entry| entry.generation == id.generation)
            .ok_or(PoolError::UnknownWorker)?;
        match entry.state {
            SlotState::Busy { ref mut kill } => *kill = true,
            SlotState::Idle(_) => {
                let SlotState::Idle(worker) =
                    std::mem::replace(&mut entry.state, SlotState::Busy { kill: false })
                else {
                    unreachable!("matched an idle slot");
                };
                drop(state);
                self.retire(id, worker, Retirement::Killed);
            }
            SlotState::Starting | SlotState::Empty => return Err(PoolError::UnknownWorker),
        }
        Ok(())
    }

    fn spawn(&self) -> Result<WorkerId, PoolError> {
        let slot = {
            let mut state = lock(&self.state);
            let slot = state
                .slots
                .iter()
                .position(|slot| matches!(slot.state, SlotState::Empty))
                .ok_or(PoolError::Full)?;
            state.slots[slot].state = SlotState::Starting;
            slot
        };
        self.launch(slot).inspect_err(|_| {
            lock(&self.state).slots[slot].state = SlotState::Empty;
        })
    }

    fn workers(&self) -> Vec<WorkerId> {
        lock(&self.state)
            .slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| matches!(slot.state, SlotState::Idle(_) | SlotState::Busy { .. }))
            .map(|(index, slot)| WorkerId {
                slot: index,
                generation: slot.generation,
            })
            .collect()
    }

    fn status(&self) -> PoolStatus {
        let state = lock(&self.state);
        let count = |pred: fn(&SlotState<B::Worker>) -> bool| {
            state.slots.iter().filter(|slot| pred(&slot.state)).count()
        };
        let window = self.config.restart.window;
        PoolStatus {
            size: self.config.size,
            idle: count(|state| matches!(state, SlotState::Idle(_))),
            busy: count(|state| matches!(state, SlotState::Busy { .. })),
            starting: count(|state| matches!(state, SlotState::Starting)),
            recent_failures: state
                .failures
                .iter()
                .filter(|at| at.elapsed() <= window)
                .count(),
        }
    }

    /// Retires idle workers that exited; busy ones report their own failure.
    fn check_alive(&self) {
        let dead: Vec<_> = {
            let mut state = lock(&self.state);
            state
                .slots
                .iter_mut()
                .enumerate()
                .filter_map(|(index, entry)| {
                    let alive = match &entry.state {
                        SlotState::Idle(worker) => worker.is_alive(),
                        _ => true,
                    };
                    if alive {
                        return None;
                    }
                    let SlotState::Idle(worker) =
                        std::mem::replace(&mut entry.state, SlotState::Busy { kill: false })
                    else {
                        unreachable!("only idle workers are probed");
                    };
                    Some((
                        WorkerId {
                            slot: index,
                            generation: entry.generation,
                        },
                        worker,
                    ))
                })
                .collect()
        };
        for (id, worker) in dead {
            let error = io::Error::new(io::ErrorKind::BrokenPipe, "worker exited while idle");
            self.retire(
                id,
                worker,
                Retirement::Failed(ConnectionError::Transport(Arc::new(error))),
            );
        }
    }

    /// Runs health checks and paced replacements until shutdown.
    fn supervise(&self) {
        let interval = self.config.health_interval;
        let mut next_check = Instant::now() + interval;
        let mut state = lock(&self.state);
        while !state.shutdown {
            let now = Instant::now();
            if now >= next_check {
                drop(state);
                self.check_alive();
                next_check = now + interval;
            } else if let Some(&slot) = state.pending.front()
                && now >= state.not_before
            {
                state.pending.pop_front();
                drop(state);
                if let Err(error) = self.launch(slot) {
                    let mut state = lock(&self.state);
                    if state.shutdown {
                        break;
                    }
                    // Without a launcher no slot can be refilled or reaped.
                    if let PoolError::Launcher(_) = error {
                        drop(state);
                        tracing::error!(dependency = "worker_launcher", %error, "worker launcher failed");
                        (self.on_fatal)(error);
                    }
                    let retry_count = state.failures.len();
                    tracing::error!(dependency = "worker", slot, retry_count, %error, "pooled worker replacement failed");
                    state.pending.push_front(slot);
                    self.record_failure(state);
                }
            } else {
                let wake_at = if state.pending.is_empty() {
                    next_check
                } else {
                    next_check.min(state.not_before)
                };
                state = self
                    .wake
                    .wait_timeout(state, wake_at.saturating_duration_since(now))
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0;
                continue;
            }
            state = lock(&self.state);
        }
    }

    /// Stops supervision and reaps idle workers; outstanding leases cannot exist here.
    fn shutdown(&self) {
        let idle: Vec<_> = {
            let mut state = lock(&self.state);
            state.shutdown = true;
            self.wake.notify_all();
            self.idle.notify_all();
            state
                .slots
                .iter_mut()
                .filter_map(
                    |slot| match std::mem::replace(&mut slot.state, SlotState::Empty) {
                        SlotState::Idle(worker) => Some(worker),
                        _ => None,
                    },
                )
                .collect()
        };
        for worker in idle {
            if let Err(error) = self.backend.kill(worker) {
                tracing::error!(dependency = "worker_launcher", %error, "pooled worker could not be reaped at shutdown");
            }
        }
    }
}

/// A running core and its supervisor thread; shared by the production pool and tests.
pub(crate) struct Handle<B: Backend> {
    core: Arc<Core<B>>,
    supervisor: Option<JoinHandle<()>>,
}

impl<B: Backend> Handle<B> {
    fn start(
        backend: B,
        config: PoolConfig,
        on_fatal: fn(PoolError) -> !,
    ) -> Result<Self, PoolError> {
        let core = Arc::new(Core::start(backend, config, on_fatal)?);
        let supervisor = thread::Builder::new()
            .name("worker-pool".into())
            .spawn({
                let core = Arc::clone(&core);
                move || core.supervise()
            })
            .map_err(|error| {
                core.shutdown();
                PoolError::Launcher(format!("cannot start pool supervisor: {error}"))
            })?;
        Ok(Self {
            core,
            supervisor: Some(supervisor),
        })
    }
}

impl<B: Backend> Drop for Handle<B> {
    fn drop(&mut self) {
        self.core.shutdown();
        if let Some(supervisor) = self.supervisor.take()
            && supervisor.join().is_err()
        {
            tracing::error!(dependency = "worker", "pool supervisor panicked");
        }
    }
}

/// Exclusive use of one worker; dropping it returns or retires the worker.
pub(crate) struct Leased<'p, B: Backend> {
    core: &'p Core<B>,
    id: WorkerId,
    worker: Option<B::Worker>,
}

impl<B: Backend> Leased<'_, B> {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, PoolError> {
        let worker = self
            .worker
            .as_mut()
            .expect("leases hold a worker until dropped");
        worker.exchange(request).map_err(|error| {
            if worker.failure().is_some() {
                PoolError::Worker(error)
            } else {
                PoolError::Request(error)
            }
        })
    }

    fn fail(mut self) {
        tracing::error!(dependency = "worker", worker = %self.id, "pooled worker response rejected");
        if let Some(worker) = self.worker.as_mut() {
            worker.close(ConnectionError::Protocol);
        }
    }
}

impl<B: Backend> Drop for Leased<'_, B> {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.core.release(self.id, worker);
        }
    }
}

#[cfg(test)]
mod tests;
