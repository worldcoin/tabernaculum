//! Nitro debug-mode detection, which gates forwarding worker output into enclave logs.

use aws_nitro_enclaves_nsm_api::{
    api::{AttestationDoc, Request, Response},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use serde_cbor::Value;

/// Proof that this enclave runs in Nitro debug mode. Its PCRs are zeroed, so it cannot pass
/// attestation for a released image, and the host can already read its console.
#[derive(Debug)]
pub struct DebugEnclave(());

impl DebugEnclave {
    /// Asks the Nitro Secure Module whether every PCR in a fresh attestation is zeroed.
    /// Returns `None` for a measured enclave.
    ///
    /// # Errors
    /// Returns an error when the NSM is unavailable or its attestation cannot be read.
    pub fn detect() -> Result<Option<Self>, DebugEnclaveError> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(DebugEnclaveError::Unavailable);
        }
        let response = nsm_process_request(
            fd,
            Request::Attestation {
                user_data: None,
                nonce: None,
                public_key: None,
            },
        );
        nsm_exit(fd);
        let document = match response {
            Response::Attestation { document } => document,
            Response::Error(code) => return Err(DebugEnclaveError::Nsm(format!("{code:?}"))),
            _ => return Err(DebugEnclaveError::Malformed),
        };
        Ok(has_zeroed_measurements(&payload(&document)?).then_some(Self(())))
    }

    /// Skips detection for this crate's process tests; absent from release builds.
    #[cfg(all(feature = "test-worker", debug_assertions))]
    #[doc(hidden)]
    #[must_use]
    pub fn assume_for_tests() -> Self {
        Self(())
    }
}

/// Where the worker's stdout and stderr go.
#[derive(Debug, Default)]
pub enum WorkerOutput {
    /// `/dev/null`; the only choice for a measured enclave.
    #[default]
    Discard,
    /// Each line becomes a `tabernaculum::worker` tracing event in the enclave.
    Forward(DebugEnclave),
}

impl WorkerOutput {
    /// Forwards in a debug enclave and discards otherwise, so one image serves both modes.
    ///
    /// # Errors
    /// Returns an error when debug mode cannot be determined.
    pub fn forward_if_debug() -> Result<Self, DebugEnclaveError> {
        Ok(match DebugEnclave::detect()? {
            Some(enclave) => Self::Forward(enclave),
            None => {
                tracing::warn!(
                    dependency = "worker",
                    "worker output forwarding needs a debug enclave; discarding output"
                );
                Self::Discard
            }
        })
    }
}

/// Debug mode could not be determined, so worker output must stay discarded.
#[derive(Debug, thiserror::Error)]
pub enum DebugEnclaveError {
    /// `/dev/nsm` is missing or cannot be opened.
    #[error("Nitro Secure Module is unavailable")]
    Unavailable,
    /// The NSM rejected the attestation request.
    #[error("Nitro Secure Module attestation failed: {0}")]
    Nsm(String),
    /// The attestation is not a COSE_Sign1 attestation document.
    #[error("malformed Nitro attestation document")]
    Malformed,
}

/// Extracts the unverified payload; the local NSM device is trusted, so no signature check.
fn payload(document: &[u8]) -> Result<AttestationDoc, DebugEnclaveError> {
    let value =
        serde_cbor::from_slice::<Value>(document).map_err(|_| DebugEnclaveError::Malformed)?;
    let value = match value {
        Value::Tag(18, inner) => *inner,
        value => value,
    };
    match value {
        Value::Array(parts) if parts.len() == 4 => match &parts[2] {
            Value::Bytes(payload) => {
                AttestationDoc::from_binary(payload).map_err(|_| DebugEnclaveError::Malformed)
            }
            _ => Err(DebugEnclaveError::Malformed),
        },
        _ => Err(DebugEnclaveError::Malformed),
    }
}

/// Same rule as Flamingo's attestation check: a debug enclave zeroes every PCR.
fn has_zeroed_measurements(document: &AttestationDoc) -> bool {
    !document.pcrs.is_empty()
        && document
            .pcrs
            .values()
            .all(|pcr| pcr.iter().all(|&byte| byte == 0))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aws_nitro_enclaves_nsm_api::api::Digest;

    use super::*;

    fn cose(pcrs: BTreeMap<usize, Vec<u8>>, tagged: bool) -> Vec<u8> {
        let document = AttestationDoc::new(
            "i-test-enc0".into(),
            Digest::SHA384,
            0,
            pcrs,
            vec![1],
            vec![vec![2]],
            None,
            None,
            None,
        );
        let sign1 = Value::Array(vec![
            Value::Bytes(vec![0xa0]),
            Value::Map(BTreeMap::new()),
            Value::Bytes(document.to_binary()),
            Value::Bytes(vec![0; 96]),
        ]);
        let sign1 = if tagged {
            Value::Tag(18, Box::new(sign1))
        } else {
            sign1
        };
        serde_cbor::to_vec(&sign1).unwrap()
    }

    #[test]
    fn only_fully_zeroed_measurements_count_as_debug_mode() {
        let zeroed: BTreeMap<_, _> = (0..16).map(|index| (index, vec![0; 48])).collect();
        let mut measured = zeroed.clone();
        measured.insert(0, vec![1; 48]);
        for tagged in [false, true] {
            assert!(has_zeroed_measurements(
                &payload(&cose(zeroed.clone(), tagged)).unwrap()
            ));
            assert!(!has_zeroed_measurements(
                &payload(&cose(measured.clone(), tagged)).unwrap()
            ));
        }
        assert!(!has_zeroed_measurements(
            &payload(&cose(BTreeMap::new(), false)).unwrap()
        ));
    }

    #[test]
    fn malformed_attestations_are_rejected() {
        for document in [
            vec![],
            serde_cbor::to_vec(&Value::Array(vec![Value::Null; 4])).unwrap(),
            serde_cbor::to_vec(&Value::Bytes(vec![1, 2])).unwrap(),
        ] {
            assert!(matches!(
                payload(&document),
                Err(DebugEnclaveError::Malformed)
            ));
        }
    }

    #[test]
    fn detection_fails_closed_without_an_nsm() {
        if !std::path::Path::new("/dev/nsm").exists() {
            assert!(matches!(
                WorkerOutput::forward_if_debug(),
                Err(DebugEnclaveError::Unavailable)
            ));
        }
    }
}
