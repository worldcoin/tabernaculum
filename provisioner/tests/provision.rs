use std::{path::PathBuf, time::Duration};

use tabernaculum_bundle::host::Error;
use tabernaculum_provisioner::{ProvisionOptions, provision};

#[tokio::test]
async fn invalid_options_are_rejected_before_opening_the_executable() {
    // An empty path would fail preparation. Invalid options must be rejected first, without
    // touching the artifact or attempting to connect to a reserved CID.
    for (enclave_cid, io_timeout) in (0..=3)
        .map(|cid| (cid, Duration::from_secs(120)))
        .chain([(16, Duration::ZERO), (16, Duration::from_secs(901))])
    {
        let error = provision(ProvisionOptions {
            executable: PathBuf::new(),
            enclave_cid,
            io_timeout,
        })
        .await
        .unwrap_err();
        assert!(error.downcast_ref::<Error>().is_none());
        assert!(
            error
                .to_string()
                .contains(if enclave_cid <= 3 { "CID" } else { "timeout" })
        );
    }
}

#[tokio::test]
async fn unusable_executables_are_rejected_before_connecting() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("empty");
    tokio::fs::write(&executable, []).await.unwrap();
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&executable, &link).unwrap();

    for path in [executable, link, directory.path().to_path_buf()] {
        let error = provision(ProvisionOptions {
            executable: path,
            enclave_cid: 16,
            io_timeout: Duration::from_secs(120),
        })
        .await
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<Error>(),
            Some(Error::InvalidBundle)
        ));
    }
}
