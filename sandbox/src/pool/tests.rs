//! Pool state machine against an in-memory backend; the launcher is covered by process tests.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::*;

/// Request bytes selecting fake worker behavior.
const CRASH: &[u8] = &[0xff];
const SLOW: &[u8] = &[0xfe];

#[derive(Default)]
struct Fake {
    spawned: AtomicUsize,
    /// The next this many launches fail.
    failing_spawns: AtomicUsize,
    reaped: AtomicUsize,
    /// Liveness switches of every launched worker, by launch order.
    alive: Mutex<Vec<Arc<AtomicBool>>>,
    /// Concurrent slow requests, and the most seen at once.
    in_flight: AtomicUsize,
    peak: AtomicUsize,
}

struct FakeWorker {
    fake: Arc<Fake>,
    alive: Arc<AtomicBool>,
    failure: Option<ConnectionError>,
}

impl Endpoint for FakeWorker {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, ConnectionError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if request.is_empty() {
            return Err(ConnectionError::InvalidRequest);
        }
        if request == CRASH || !self.alive.load(Ordering::SeqCst) {
            let error = io::Error::from(io::ErrorKind::UnexpectedEof);
            self.close(ConnectionError::Transport(Arc::new(error)));
            return Err(self.failure.clone().unwrap());
        }
        if request == SLOW {
            // Waits for the other slow requests, up to a bound, so overlap is deterministic.
            let in_flight = self.fake.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.fake.peak.fetch_max(in_flight, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(1);
            while self.fake.peak.load(Ordering::SeqCst) < 3 && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            self.fake.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
        Ok(request.to_vec())
    }

    fn failure(&self) -> Option<&ConnectionError> {
        self.failure.as_ref()
    }

    fn close(&mut self, error: ConnectionError) {
        self.failure.get_or_insert(error);
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

impl Backend for Arc<Fake> {
    type Worker = FakeWorker;

    fn spawn(&self, _slot: usize) -> Result<(FakeWorker, Vec<u8>), PoolError> {
        if self
            .failing_spawns
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(PoolError::Launch("fixture launch failure".into()));
        }
        self.spawned.fetch_add(1, Ordering::SeqCst);
        let alive = Arc::new(AtomicBool::new(true));
        lock(&self.alive).push(Arc::clone(&alive));
        Ok((
            FakeWorker {
                fake: Arc::clone(self),
                alive,
                failure: None,
            },
            b"ready".to_vec(),
        ))
    }

    fn kill(&self, worker: FakeWorker) -> Result<(), PoolError> {
        worker.alive.store(false, Ordering::SeqCst);
        self.reaped.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn unexpected_fatal(error: PoolError) -> ! {
    panic!("unexpected fatal pool error: {error}");
}

fn config(size: usize, mode: PoolMode) -> PoolConfig {
    PoolConfig {
        size,
        mode,
        acquire_timeout: Duration::from_millis(200),
        health_interval: Duration::from_millis(10),
        restart: RestartPolicy {
            initial_backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(20),
            max_failures: 10,
            window: Duration::from_secs(60),
        },
        ready: |ready| ready == b"ready",
    }
}

fn start(fake: &Arc<Fake>, config: PoolConfig) -> Handle<Arc<Fake>> {
    Handle::start(Arc::clone(fake), config, unexpected_fatal).unwrap()
}

/// Polls until `done` holds, failing after two seconds.
fn eventually(mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !done() {
        assert!(Instant::now() < deadline, "condition not reached");
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn requests_use_every_worker_in_parallel() {
    let fake = Arc::new(Fake::default());
    let pool = start(&fake, config(3, PoolMode::Supervised));
    thread::scope(|scope| {
        for _ in 0..3 {
            scope.spawn(|| {
                let mut lease = pool.core.acquire().unwrap();
                assert_eq!(lease.exchange(SLOW).unwrap(), SLOW);
            });
        }
    });
    assert_eq!(fake.peak.load(Ordering::SeqCst), 3);
    assert_eq!(pool.core.status().idle, 3);
}

#[test]
fn requests_are_shed_when_every_worker_stays_busy() {
    let fake = Arc::new(Fake::default());
    let pool = start(&fake, config(2, PoolMode::Supervised));
    let _first = pool.core.acquire().unwrap();
    let second = pool.core.acquire().unwrap();
    let started = Instant::now();
    assert!(matches!(pool.core.acquire(), Err(PoolError::Busy)));
    assert!(started.elapsed() >= Duration::from_millis(200));

    // A returned worker wakes a waiting request.
    thread::scope(|scope| {
        let waiter = scope.spawn(|| pool.core.acquire().map(|lease| lease.id));
        thread::sleep(Duration::from_millis(20));
        let id = second.id;
        drop(second);
        assert_eq!(waiter.join().unwrap().unwrap(), id);
    });
}

#[test]
fn failed_workers_are_retired_and_replaced() {
    let fake = Arc::new(Fake::default());
    let pool = start(&fake, config(2, PoolMode::Supervised));
    let mut lease = pool.core.acquire().unwrap();
    let id = lease.id;
    assert!(matches!(lease.exchange(&[]), Err(PoolError::Request(_))));
    assert!(matches!(lease.exchange(CRASH), Err(PoolError::Worker(_))));
    assert!(matches!(lease.exchange(b"x"), Err(PoolError::Worker(_))));
    drop(lease);

    eventually(|| pool.core.status().is_full());
    assert!(!pool.core.workers().contains(&id));
    assert_eq!(fake.spawned.load(Ordering::SeqCst), 3);
    assert_eq!(fake.reaped.load(Ordering::SeqCst), 1);
    assert_eq!(pool.core.status().recent_failures, 1);
}

#[test]
fn rejected_responses_retire_the_worker() {
    let fake = Arc::new(Fake::default());
    let pool = start(&fake, config(1, PoolMode::Supervised));
    let mut lease = pool.core.acquire().unwrap();
    let id = lease.id;
    assert_eq!(lease.exchange(b"x").unwrap(), b"x");
    lease.fail();
    eventually(|| pool.core.status().is_full());
    assert_ne!(pool.core.workers(), [id]);
    assert_eq!(pool.core.status().recent_failures, 1);
}

#[test]
fn killed_workers_are_replaced_without_counting_as_failures() {
    let fake = Arc::new(Fake::default());
    let pool = start(&fake, config(2, PoolMode::Supervised));
    let idle = pool.core.workers()[0];
    pool.core.kill(idle).unwrap();
    assert!(matches!(
        pool.core.kill(idle),
        Err(PoolError::UnknownWorker)
    ));

    // A busy worker finishes its request first.
    let mut lease = pool.core.acquire().unwrap();
    let busy = lease.id;
    pool.core.kill(busy).unwrap();
    assert_eq!(lease.exchange(b"x").unwrap(), b"x");
    drop(lease);

    eventually(|| {
        let workers = pool.core.workers();
        workers.len() == 2 && !workers.contains(&idle) && !workers.contains(&busy)
    });
    assert_eq!(fake.reaped.load(Ordering::SeqCst), 2);
    assert_eq!(pool.core.status().recent_failures, 0);
}

#[test]
fn idle_exits_are_found_by_the_health_check() {
    let fake = Arc::new(Fake::default());
    let pool = start(&fake, config(2, PoolMode::Supervised));
    lock(&fake.alive)[1].store(false, Ordering::SeqCst);
    eventually(|| fake.spawned.load(Ordering::SeqCst) == 3 && pool.core.status().is_full());
    assert_eq!(pool.core.status().recent_failures, 1);
}

#[test]
fn manual_pools_shrink_and_regrow_only_on_request() {
    let fake = Arc::new(Fake::default());
    let pool = start(&fake, config(2, PoolMode::Manual));
    assert!(matches!(pool.core.spawn(), Err(PoolError::Full)));

    pool.core.kill(pool.core.workers()[0]).unwrap();
    let mut lease = pool.core.acquire().unwrap();
    assert!(lease.exchange(CRASH).is_err());
    drop(lease);
    thread::sleep(Duration::from_millis(50));
    let status = pool.core.status();
    assert_eq!((status.idle, status.busy, status.starting), (0, 0, 0));
    assert!(matches!(pool.core.acquire(), Err(PoolError::Busy)));

    let first = pool.core.spawn().unwrap();
    let second = pool.core.spawn().unwrap();
    assert_ne!(first, second);
    assert!(pool.core.status().is_full());
    assert!(matches!(pool.core.spawn(), Err(PoolError::Full)));

    fake.failing_spawns.store(1, Ordering::SeqCst);
    pool.core.kill(first).unwrap();
    assert!(matches!(pool.core.spawn(), Err(PoolError::Launch(_))));
    assert!(pool.core.spawn().is_ok());
}

#[test]
fn replacement_launch_failures_back_off_and_retry() {
    let fake = Arc::new(Fake::default());
    let pool = start(&fake, config(1, PoolMode::Supervised));
    fake.failing_spawns.store(2, Ordering::SeqCst);
    let lease = pool.core.acquire().unwrap();
    lease.fail();
    eventually(|| pool.core.status().is_full());
    // One worker failure plus two failed launches.
    assert_eq!(pool.core.status().recent_failures, 3);
}

static CRASH_LOOP: AtomicUsize = AtomicUsize::new(0);

fn crash_loop_fatal(error: PoolError) -> ! {
    let PoolError::CrashLoop { failures } = error else {
        panic!("unexpected fatal pool error: {error}");
    };
    CRASH_LOOP.store(failures, Ordering::SeqCst);
    // Stands in for exiting the enclave.
    loop {
        thread::park();
    }
}

#[test]
fn a_crash_loop_is_fatal() {
    let fake = Arc::new(Fake::default());
    let mut config = config(1, PoolMode::Supervised);
    config.restart.max_failures = 2;
    let pool = Handle::start(Arc::clone(&fake), config, crash_loop_fatal).unwrap();
    for _ in 0..2 {
        let mut lease = pool.core.acquire().unwrap();
        assert!(lease.exchange(CRASH).is_err());
    }
    thread::spawn({
        let core = Arc::clone(&pool.core);
        move || {
            if let Ok(mut lease) = core.acquire() {
                let _ = lease.exchange(CRASH);
            }
        }
    });
    eventually(|| CRASH_LOOP.load(Ordering::SeqCst) == 3);
    // A parked fatal handler holds the pool; never join it.
    std::mem::forget(pool);
}

#[test]
fn start_fails_cleanly_on_invalid_configuration_or_launch() {
    let fake = Arc::new(Fake::default());
    for config in [
        config(0, PoolMode::Supervised),
        config(MAX_POOL_SIZE + 1, PoolMode::Supervised),
        PoolConfig {
            acquire_timeout: Duration::ZERO,
            ..config(1, PoolMode::Manual)
        },
        PoolConfig {
            restart: RestartPolicy {
                max_failures: 0,
                ..RestartPolicy::default()
            },
            ..config(1, PoolMode::Manual)
        },
    ] {
        assert!(matches!(
            Handle::start(Arc::clone(&fake), config, unexpected_fatal),
            Err(PoolError::InvalidConfig(_))
        ));
    }
    assert_eq!(fake.spawned.load(Ordering::SeqCst), 0);

    // Two launches succeed, the third fails: both started workers are reaped.
    struct ThirdFails(Arc<Fake>);
    impl Backend for ThirdFails {
        type Worker = FakeWorker;
        fn spawn(&self, slot: usize) -> Result<(FakeWorker, Vec<u8>), PoolError> {
            if slot == 2 {
                return Err(PoolError::Launch("third".into()));
            }
            self.0.spawn(slot)
        }
        fn kill(&self, worker: FakeWorker) -> Result<(), PoolError> {
            self.0.kill(worker)
        }
    }
    assert!(matches!(
        Handle::start(
            ThirdFails(Arc::clone(&fake)),
            config(3, PoolMode::Supervised),
            unexpected_fatal
        ),
        Err(PoolError::Launch(_))
    ));
    assert_eq!(fake.reaped.load(Ordering::SeqCst), 2);

    let mut rejecting = config(1, PoolMode::Supervised);
    rejecting.ready = |ready| ready == b"other";
    assert!(matches!(
        Handle::start(Arc::clone(&fake), rejecting, unexpected_fatal),
        Err(PoolError::Launch(_))
    ));
    assert_eq!(fake.reaped.load(Ordering::SeqCst), 3);
}

#[test]
fn backoff_grows_with_recent_failures_up_to_its_ceiling() {
    let policy = RestartPolicy::default();
    assert_eq!(policy.delay(0), Duration::ZERO);
    for failures in [1, 2, 5, 20, usize::MAX] {
        let ceiling = policy
            .initial_backoff
            .saturating_mul(1 << (failures - 1).min(16))
            .min(policy.max_backoff);
        let delay = policy.delay(failures);
        assert!(
            delay >= ceiling / 2 && delay <= ceiling,
            "{failures}: {delay:?}"
        );
    }
}
