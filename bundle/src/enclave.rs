//! Enclave-side bootstrap: accept one bundle from the parent before any threads exist.

use std::{
    fs::{self, File},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::Path,
    time::Duration,
};

use crate::{BOOTSTRAP_PORT, BootstrapConfig, Error, VerifiedRuntime};

/// Nitro uses CID 3 for the parent EC2 instance.
pub const PARENT_CID: u32 = 3;
/// Staging on the executable root filesystem; Nitro mounts `/tmp` noexec.
pub const STAGING_DIR: &str = "/worker-runtime";

/// The verified runtime and the still unacknowledged transfer.
pub struct Bootstrap {
    runtime: VerifiedRuntime,
    provisioner: vsock::VsockStream,
}

impl Bootstrap {
    /// The verified executable and its sandbox root.
    #[must_use]
    pub fn runtime(&self) -> &VerifiedRuntime {
        &self.runtime
    }

    /// Acknowledges a ready worker and closes bootstrap for this boot. The returned runtime
    /// must outlive the worker.
    ///
    /// # Errors
    /// Returns an error on a write timeout, write failure or shutdown failure.
    pub fn acknowledge(mut self) -> Result<VerifiedRuntime, Error> {
        self.provisioner.write_all(&[0])?;
        self.provisioner.shutdown(std::net::Shutdown::Both)?;
        Ok(self.runtime)
    }
}

/// Accepts one size-bounded bundle from the parent on [`BOOTSTRAP_PORT`], then closes the
/// listener. Call while the process is single-threaded.
///
/// Socket timeouts bound each read and write after accept. The provisioner bounds total
/// startup, including accept, and tears down the enclave on failure.
///
/// # Errors
/// Returns an error for invalid limits, unusable staging, a non-parent peer, transport
/// failure, or a bundle that fails verification.
pub fn accept(config: &BootstrapConfig, staging: &Path) -> Result<Bootstrap, Error> {
    config.validate()?;
    prepare_staging(staging)?;

    let listener = vsock::VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, BOOTSTRAP_PORT)?;
    let (mut provisioner, peer) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    };
    drop(listener);
    if peer.cid() != PARENT_CID {
        return Err(Error::NotParent);
    }

    let timeout = Some(Duration::from_secs(config.provisioning_io_timeout_seconds));
    provisioner.set_read_timeout(timeout)?;
    provisioner.set_write_timeout(timeout)?;
    let runtime = crate::receive(&mut provisioner, config.max_bundle_bytes, staging)?;

    Ok(Bootstrap {
        runtime,
        provisioner,
    })
}

/// Staging must be a real root-owned directory on a writable mount without `noexec`.
fn prepare_staging(staging: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(staging)?;
    if !metadata.is_dir() || metadata.uid() != 0 {
        return Err(Error::UnusableStaging);
    }

    let directory = File::open(staging)?;
    // SAFETY: fstatvfs writes only this initialized buffer for a live directory descriptor.
    let mut filesystem: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), &raw mut filesystem) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if filesystem.f_flag & (libc::ST_NOEXEC | libc::ST_RDONLY) != 0 {
        return Err(Error::UnusableStaging);
    }

    // Nix normalizes directory modes; restore private write access before receiving bytes.
    fs::set_permissions(staging, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::{Error, prepare_staging};

    #[test]
    fn staging_rejects_missing_paths_files_symlinks_and_foreign_owners() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            prepare_staging(&directory.path().join("missing")),
            Err(Error::Io(_))
        ));

        let file = directory.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(matches!(
            prepare_staging(&file),
            Err(Error::UnusableStaging)
        ));

        let link = directory.path().join("link");
        std::os::unix::fs::symlink(directory.path(), &link).unwrap();
        assert!(matches!(
            prepare_staging(&link),
            Err(Error::UnusableStaging)
        ));

        if directory.path().metadata().unwrap().uid() != 0 {
            assert!(matches!(
                prepare_staging(directory.path()),
                Err(Error::UnusableStaging)
            ));
        }
    }
}
