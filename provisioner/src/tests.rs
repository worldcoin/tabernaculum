use std::{
    cell::{Cell, RefCell},
    future::pending,
    path::PathBuf,
    time::Duration,
};

use anyhow::{Result, anyhow};
use tokio::{sync::oneshot, time};

use super::{config::Config, run_lifecycle};

fn config(ready_file: PathBuf) -> Config {
    Config {
        eif: PathBuf::from("unused.eif"),
        ready_file,
        artifact_uri: "unused".into(),
        artifact_sha256: "0".repeat(64),
        executable_name: "unused-worker".into(),
        debug_mode: false,
        cid: 16,
        cpus: 2,
        memory_mib: 6144,
        bootstrap_timeout: Duration::from_secs(10),
        io_timeout: Duration::from_secs(1),
        poll_interval: Duration::from_secs(1),
    }
}

struct RecordDrop<'a>(&'a Cell<bool>);

impl Drop for RecordDrop<'_> {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

#[tokio::test(start_paused = true)]
async fn readiness_waits_for_initialization_after_bootstrap() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().join("ready"));
    let events = RefCell::new(Vec::new());
    let (started_tx, started_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();

    let lifecycle = run_lifecycle(
        &config,
        async {
            events.borrow_mut().push("bootstrap");
            Ok(())
        },
        |cid| {
            assert_eq!(cid, config.cid);
            assert_eq!(*events.borrow(), ["bootstrap"]);
            events.borrow_mut().push("initialize");
            async {
                started_tx.send(()).unwrap();
                finish_rx.await.unwrap();
                Ok(())
            }
        },
        async {
            assert_eq!(std::fs::read(&config.ready_file).unwrap(), b"ready\n");
            events.borrow_mut().push("monitor");
            Ok(())
        },
        pending(),
        async {
            assert!(!config.ready_file.exists());
            events.borrow_mut().push("cleanup");
            Ok(())
        },
    );
    let observe = async {
        started_rx.await.unwrap();
        assert!(!config.ready_file.exists());
        assert_eq!(*events.borrow(), ["bootstrap", "initialize"]);
        finish_tx.send(()).unwrap();
    };

    let (result, ()) = tokio::join!(lifecycle, observe);
    result.unwrap();
    assert!(!config.ready_file.exists());
    assert_eq!(
        *events.borrow(),
        ["bootstrap", "initialize", "monitor", "cleanup"]
    );
}

#[tokio::test(start_paused = true)]
async fn rejected_initialization_cleans_up_without_becoming_ready() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().join("ready"));
    let monitor_called = Cell::new(false);
    let cleanup_count = Cell::new(0);

    let error = run_lifecycle(
        &config,
        async { Ok(()) },
        |_| async { Err(anyhow!("release rejected")) },
        async {
            monitor_called.set(true);
            Ok(())
        },
        pending(),
        async {
            assert!(!config.ready_file.exists());
            cleanup_count.set(cleanup_count.get() + 1);
            Ok(())
        },
    )
    .await
    .unwrap_err();

    let error = format!("{error:#}");
    assert!(
        error.contains("application initialization failed"),
        "{error}"
    );
    assert!(error.contains("release rejected"), "{error}");
    assert!(!monitor_called.get());
    assert_eq!(cleanup_count.get(), 1);
    assert!(!config.ready_file.exists());
}

#[tokio::test(start_paused = true)]
async fn initialization_uses_remaining_bootstrap_deadline_and_is_cancelled() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().join("ready"));
    let initialize_dropped = Cell::new(false);
    let monitor_called = Cell::new(false);
    let cleanup_count = Cell::new(0);
    let (started_tx, started_rx) = oneshot::channel();
    let started_at = time::Instant::now();

    let lifecycle = run_lifecycle(
        &config,
        async {
            time::sleep(Duration::from_secs(4)).await;
            Ok(())
        },
        |_| async {
            let _drop = RecordDrop(&initialize_dropped);
            started_tx.send(()).unwrap();
            pending::<Result<()>>().await
        },
        async {
            monitor_called.set(true);
            Ok(())
        },
        pending(),
        async {
            assert!(initialize_dropped.get());
            assert!(!config.ready_file.exists());
            cleanup_count.set(cleanup_count.get() + 1);
            Ok(())
        },
    );
    let observe = async {
        started_rx.await.unwrap();
        assert!(!config.ready_file.exists());
        assert_eq!(started_at.elapsed(), Duration::from_secs(4));
        time::advance(Duration::from_secs(6)).await;
    };

    let (result, ()) = tokio::join!(lifecycle, observe);
    let error = format!("{:#}", result.unwrap_err());
    assert!(
        error.contains("provisioner bootstrap deadline exceeded"),
        "{error}"
    );
    assert_eq!(started_at.elapsed(), config.bootstrap_timeout);
    assert!(initialize_dropped.get());
    assert!(!monitor_called.get());
    assert_eq!(cleanup_count.get(), 1);
    assert!(!config.ready_file.exists());
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_pending_initialization_and_cleans_up() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().join("ready"));
    let initialize_dropped = Cell::new(false);
    let monitor_called = Cell::new(false);
    let cleanup_count = Cell::new(0);
    let (started_tx, started_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let lifecycle = run_lifecycle(
        &config,
        async { Ok(()) },
        |_| async {
            let _drop = RecordDrop(&initialize_dropped);
            started_tx.send(()).unwrap();
            pending::<Result<()>>().await
        },
        async {
            monitor_called.set(true);
            Ok(())
        },
        async { shutdown_rx.await.unwrap() },
        async {
            assert!(initialize_dropped.get());
            assert!(!config.ready_file.exists());
            cleanup_count.set(cleanup_count.get() + 1);
            Ok(())
        },
    );
    let observe = async {
        started_rx.await.unwrap();
        assert!(!config.ready_file.exists());
        shutdown_tx.send(()).unwrap();
    };

    let (result, ()) = tokio::join!(lifecycle, observe);
    result.unwrap();
    assert!(initialize_dropped.get());
    assert!(!monitor_called.get());
    assert_eq!(cleanup_count.get(), 1);
    assert!(!config.ready_file.exists());
}

#[tokio::test(start_paused = true)]
async fn bootstrap_failure_skips_initialization_and_still_cleans_up() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().join("ready"));
    let initialize_called = Cell::new(false);
    let monitor_called = Cell::new(false);
    let cleanup_count = Cell::new(0);

    let error = run_lifecycle(
        &config,
        async { Err(anyhow!("bundle rejected")) },
        |_| {
            initialize_called.set(true);
            async { Ok(()) }
        },
        async {
            monitor_called.set(true);
            Ok(())
        },
        pending(),
        async {
            assert!(!config.ready_file.exists());
            cleanup_count.set(cleanup_count.get() + 1);
            Ok(())
        },
    )
    .await
    .unwrap_err();

    assert!(format!("{error:#}").contains("bundle rejected"));
    assert!(!initialize_called.get());
    assert!(!monitor_called.get());
    assert_eq!(cleanup_count.get(), 1);
    assert!(!config.ready_file.exists());
}

#[tokio::test(start_paused = true)]
async fn each_run_initializes_before_publishing_readiness() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path().join("ready"));
    let initialize_count = Cell::new(0);
    let cleanup_count = Cell::new(0);

    for expected_count in 1..=2 {
        run_lifecycle(
            &config,
            async { Ok(()) },
            |_| async {
                assert!(!config.ready_file.exists());
                initialize_count.set(initialize_count.get() + 1);
                Ok(())
            },
            async {
                assert_eq!(initialize_count.get(), expected_count);
                assert_eq!(std::fs::read(&config.ready_file).unwrap(), b"ready\n");
                Ok(())
            },
            pending(),
            async {
                assert!(!config.ready_file.exists());
                cleanup_count.set(cleanup_count.get() + 1);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert!(!config.ready_file.exists());
    }

    assert_eq!(initialize_count.get(), 2);
    assert_eq!(cleanup_count.get(), 2);
}
