# tabernaculum

Sandboxed worker runtime for AWS Nitro enclaves, shared by [flamingo](https://github.com/worldcoin/flamingo) and [biometrics-tee](https://github.com/worldcoin/biometrics-tee).

A closed worker executable reaches the enclave once at boot, is verified, and runs under Minijail with a seccomp policy. The enclave talks to it over a framed socket and enforces its output contract.

| Crate | Purpose |
|---|---|
| `tabernaculum-bundle` | Bundle format and verification; enclave-side bootstrap (`enclave` feature) and host-side provisioning (`host` feature) over vsock |

Consumers pin a git tag until the API settles.
