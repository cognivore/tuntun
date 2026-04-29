//! `SecretPort` adapter that shells out to `rageveil`.
//!
//! `rageveil` is a git+age-backed password manager with a CLI shape near-
//! identical to `passveil` — `show <path>`, `insert <path> --batch`, `list`,
//! `sync`. We use `--batch` on insert so the laptop daemon can store
//! generated keys without an interactive prompt.

use async_trait::async_trait;

use crate::adapters::process::TokioProcess;
use tuntun_core::{Error, ProcessPort, ProcessSpec, Result, SecretKey, SecretPort, SecretValue};

/// Binary name on `$PATH`. Splitting it out keeps tests honest if we ever want
/// to point at a stand-in.
const RAGEVEIL_BIN: &str = "rageveil";

#[derive(Debug)]
pub struct RageveilSecrets {
    process: TokioProcess,
}

impl Default for RageveilSecrets {
    fn default() -> Self {
        Self::new()
    }
}

impl RageveilSecrets {
    pub fn new() -> Self {
        Self {
            process: TokioProcess,
        }
    }
}

#[async_trait]
impl SecretPort for RageveilSecrets {
    async fn load(&self, key: &SecretKey) -> Result<SecretValue> {
        let spec = ProcessSpec::new(RAGEVEIL_BIN)
            .arg("show")
            .arg(key.as_str());
        let exit = self.process.run_to_completion(&spec).await?;
        if !exit.is_success() {
            return Err(Error::port(
                RAGEVEIL_BIN,
                format!(
                    "load `{}`: exit {:?}: {}",
                    key,
                    exit.code,
                    String::from_utf8_lossy(&exit.stderr).trim()
                ),
            ));
        }
        // Trim a single trailing newline (rageveil emits one).
        let mut bytes = exit.stdout;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        Ok(SecretValue::from_bytes(bytes))
    }

    async fn store(&self, key: &SecretKey, value: &SecretValue) -> Result<()> {
        let spec = ProcessSpec::new(RAGEVEIL_BIN)
            .arg("insert")
            .arg(key.as_str())
            .arg("--batch")
            .stdin_input(value.expose_bytes().to_vec());
        let exit = self.process.run_to_completion(&spec).await?;
        if !exit.is_success() {
            return Err(Error::port(
                RAGEVEIL_BIN,
                format!(
                    "store `{}`: exit {:?}: {}",
                    key,
                    exit.code,
                    String::from_utf8_lossy(&exit.stderr).trim()
                ),
            ));
        }
        Ok(())
    }

    async fn exists(&self, key: &SecretKey) -> Result<bool> {
        let spec = ProcessSpec::new(RAGEVEIL_BIN)
            .arg("show")
            .arg(key.as_str());
        let exit = self.process.run_to_completion(&spec).await?;
        Ok(exit.is_success())
    }
}
