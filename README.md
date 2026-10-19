# tabernaculum

Sandboxed worker runtime for AWS Nitro enclaves, shared by [flamingo](https://github.com/worldcoin/flamingo) and [biometrics-tee](https://github.com/worldcoin/biometrics-tee).

A closed worker executable reaches the enclave once at boot, is verified, and runs under Minijail with a seccomp policy. The enclave talks to it over a framed socket and enforces its output contract.

| Crate | Purpose |
|---|---|
| `tabernaculum-bundle` | Bundle format and verification; enclave-side bootstrap (`enclave` feature) and host-side provisioning (`host` feature) over vsock |
| `tabernaculum` | Minijail jail and seccomp policy, worker lifecycle, framed request/response connection (Linux x86_64) |
| `tabernaculum-provisioner` | Host lifecycle library and sidecar: fetches the worker bundle from S3, starts the enclave and provisions the worker |

Workers start from the reviewed seccomp policy in `sandbox/worker.policy`. An enclave adjusts single entries in code; the launch, IPC and process-creation entries are locked:

```rust
static POLICY: LazyLock<Policy> = LazyLock::new(|| Policy::default_worker().allow("sched_setaffinity", "1"));
```

Deploy repos build their provisioner image on the published base, pinned by digest, and add their EIF:

```dockerfile
FROM ghcr.io/worldcoin/tabernaculum-provisioner:v0.1.0@sha256:…
COPY enclave.eif /home/enclave.eif
```

Each `v*` tag publishes the image; the run summary shows its digest. Consumers pin a git tag until the API settles.

## Application initialization

Applications that need additional enclave configuration before readiness can depend on
`tabernaculum-provisioner` and call `run` from their own Linux executable:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tabernaculum_provisioner::run(|cid| async move {
        load_application_configuration(cid).await?;
        wait_for_application_health(cid).await
    }).await
}
```

The two application functions above represent the caller's own protocol. For example,
Flamingo can load its release manifest over Pontifex and then check release-aware health.
Tabernaculum does not interpret that manifest or depend on the application transport.

The callback runs once, after the bundle acknowledgement and before the ready file is
written. The application's RPC server may still be starting: the callback owns connection
retries and application health checks. Download, worker startup and application initialization
share `BOOTSTRAP_TIMEOUT_SECONDS`; a rejected configuration should return an error.
After initialization, the provisioner checks that its enclave is still running before
publishing readiness. Ongoing monitoring remains a Nitro running-state check.

The library uses the same environment settings as the binary and owns SIGTERM/SIGINT handling,
readiness cleanup and termination of its enclave. The callback must be cancellation-safe:
a timeout or shutdown drops it before cleanup. Do not detach initialization tasks or block
the executor. Drive `run` to completion; dropping or aborting it bypasses asynchronous cleanup.
Initialize logging in the application, and run only one provisioner lifecycle per process.

The existing binary supplies a no-op callback. Custom images can continue to use the provisioner
base for its system dependencies, but must copy their executable and override `ENTRYPOINT`.
Every new enclave lifecycle invokes initialization again; no bootstrap wire-format change is needed.
