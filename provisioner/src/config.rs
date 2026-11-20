use std::{env, path::PathBuf, time::Duration};

use anyhow::{Context, Result, ensure};

pub struct Config {
    pub eif: PathBuf,
    pub ready_file: PathBuf,
    pub artifact_uri: String,
    pub artifact_sha256: String,
    pub executable_name: String,
    pub debug_mode: bool,
    pub cid: u32,
    pub cpus: u32,
    pub memory_mib: u32,
    pub bootstrap_timeout: Duration,
    pub io_timeout: Duration,
    pub poll_interval: Duration,
    pub application_config: Option<serde_json::Value>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let artifact_uri = required("BUNDLE_ARTIFACT_URI")?;
        let artifact_sha256 = required("BUNDLE_ARTIFACT_SHA256")?;
        let executable_name = setting("BUNDLE_EXECUTABLE", "biometric-engines-worker");
        ensure!(
            !executable_name.is_empty()
                && executable_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && !executable_name.starts_with('.'),
            "BUNDLE_EXECUTABLE must be a plain file name"
        );

        let cid = number("ENCLAVE_CID", 16)?;
        ensure!(cid > 3, "enclave CID must be greater than 3");

        let io_timeout = u64::from(number("PROVISIONING_IO_TIMEOUT_SECONDS", 120)?);
        ensure!(
            io_timeout <= 900,
            "provisioning I/O timeout exceeds 900 seconds"
        );

        Ok(Self {
            eif: setting("EIF_PATH", "/home/enclave.eif").into(),
            ready_file: ready_file(),
            artifact_uri,
            artifact_sha256,
            executable_name,
            debug_mode: setting("ENCLAVE_DEBUG_MODE", "false")
                .parse()
                .context("ENCLAVE_DEBUG_MODE must be true or false")?,
            cid,
            cpus: number("ENCLAVE_CPU_COUNT", 2)?,
            memory_mib: number("ENCLAVE_MEMORY_SIZE", 6144)?,
            bootstrap_timeout: Duration::from_secs(
                number("BOOTSTRAP_TIMEOUT_SECONDS", 300)?.into(),
            ),
            io_timeout: Duration::from_secs(io_timeout),
            poll_interval: Duration::from_secs(number("POLL_SECONDS", 2)?.into()),
            application_config: match env::var("ENCLAVE_APPLICATION_CONFIG") {
                Ok(value) => {
                    Some(application_config(&value).context("invalid ENCLAVE_APPLICATION_CONFIG")?)
                }
                Err(env::VarError::NotPresent) => None,
                Err(env::VarError::NotUnicode(_)) => {
                    anyhow::bail!("ENCLAVE_APPLICATION_CONFIG must be UTF-8")
                }
            },
        })
    }
}

fn application_config(value: &str) -> Result<serde_json::Value> {
    ensure!(
        value.len() <= tabernaculum_bundle::MAX_APPLICATION_CONFIG_BYTES,
        "application configuration exceeds 16 KiB"
    );
    let config: serde_json::Value = serde_json::from_str(value).context("invalid JSON")?;
    ensure!(
        !config.is_null(),
        "application configuration must not be null"
    );
    Ok(config)
}

pub fn ready_file() -> PathBuf {
    setting("BUNDLE_READY_FILE", "/run/tabernaculum/ready").into()
}

fn required(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("missing {name}"))?;
    ensure!(!value.is_empty(), "{name} must not be empty");
    Ok(value)
}

fn setting(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn number(name: &str, default: u32) -> Result<u32> {
    let value = setting(name, &default.to_string())
        .parse::<u32>()
        .with_context(|| format!("invalid {name}"))?;
    ensure!(value > 0, "{name} must be positive");

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::application_config;

    #[test]
    fn application_configuration_requires_bounded_non_null_json() {
        assert_eq!(
            application_config(r#"{"environment":"stage"}"#).unwrap(),
            serde_json::json!({"environment": "stage"})
        );
        for invalid in ["", "null", "{", "not JSON"] {
            assert!(application_config(invalid).is_err());
        }
        let oversized =
            serde_json::to_string(&"x".repeat(tabernaculum_bundle::MAX_APPLICATION_CONFIG_BYTES))
                .unwrap();
        assert!(application_config(&oversized).is_err());
    }
}
