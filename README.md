# tabernaculum

Sandboxed worker runtime for AWS Nitro enclaves, shared by [flamingo](https://github.com/worldcoin/flamingo) and [biometrics-tee](https://github.com/worldcoin/biometrics-tee).

A closed worker executable reaches the enclave once at boot, is verified, and runs under Minijail with a seccomp policy. The enclave talks to it over a framed socket and enforces its output contract.

| Crate | Purpose |
|---|---|
| `tabernaculum-bundle` | Bundle format and verification; enclave-side bootstrap (`enclave` feature) and host-side provisioning (`host` feature) over vsock |
| `tabernaculum` | Minijail jail and seccomp policy, worker lifecycle, framed request/response connection (Linux x86_64) |
| `tabernaculum-provisioner` | Sideloading library with explicit options; standalone sidecar that fetches the worker from S3 and owns the enclave lifecycle |

Workers start from the reviewed seccomp policy in `sandbox/worker.policy`. An enclave adjusts single entries in code; the launch, IPC and process-creation entries are locked:

```rust
static POLICY: LazyLock<Policy> = LazyLock::new(|| Policy::default_worker().allow("sched_setaffinity", "1"));
```

Deploy repos build their provisioner image on the published base, pinned by digest, and add their EIF:

```dockerfile
FROM ghcr.io/worldcoin/tabernaculum-provisioner:<matching-tag>@sha256:…
COPY enclave.eif /home/enclave.eif
```

Each `v*` tag publishes the image; the run summary shows its digest. Consumers pin a git tag until the API settles.

## Programmatic provisioning

Applications with their own enclave lifecycle can call `provision` with a local executable:

```rust
use std::{path::PathBuf, time::Duration};
use tabernaculum_provisioner::{ProvisionOptions, provision};

async fn sideload(worker_path: PathBuf, enclave_cid: u32) -> anyhow::Result<()> {
    provision(ProvisionOptions {
        executable: worker_path,
        enclave_cid,
        io_timeout: Duration::from_secs(120),
    }).await
}
```

The caller downloads, verifies and extracts its artifact if necessary, and launches the enclave.
`provision` generates transfer metadata from the executable, sends it over vsock and waits for
worker initialization acknowledgement. Keep the executable available and unchanged through that
call. The library takes all configuration through arguments and owns no enclave lifecycle,
signal handlers or readiness files.

After acknowledgement, Flamingo's provisioner can load its release manifest over Pontifex and
check application health before publishing readiness. Its server may still be starting, so the
caller owns those connection retries. The caller also owns the overall bootstrap deadline and
must terminate the enclave on failure or cancellation. Dropping `provision` closes its transfer
socket. `io_timeout` bounds connection retries and individual socket operations, not total startup.

The standalone binary retains its existing environment configuration and lifecycle: download and
verify the archive, inspect the executable, launch the enclave, sideload the worker, mark readiness,
monitor Nitro state, and clean up on failure or shutdown. These modules remain private to the
binary. Custom images must copy their own provisioner executable and override `ENTRYPOINT`.

## Bootstrap format compatibility

This checkout uses manifest version **4**, containing only `manifest_version`, `sha384` and `size`.
The diagnostic `release_id` has been removed from the wire format, `Manifest`, `VerifiedRuntime`
and the lower-level `Bundle::prepare` argument list. Preparation now takes only an executable path.
Executable size limits and SHA-384 transfer integrity checks remain unchanged. Artifact authenticity
remains the deployment's responsibility; the standalone binary still verifies its archive checksum.

Version 4 is incompatible with version 3 (used by `v0.1.0`): old receivers require `release_id`, and
new receivers reject both older versions and unknown fields. Update the provisioner image and the
enclave's Tabernaculum dependency together, rebuild the EIF, and deploy a matching pair. Existing
tracks can retain their matching older pair. Consumers must remove any use of `runtime.release_id`
from diagnostics; Flamingo's WIP release manifest and `release_hash` are separate and unchanged.
