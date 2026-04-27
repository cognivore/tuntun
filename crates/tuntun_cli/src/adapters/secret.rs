//! `SecretPort` adapter that shells out to `passveil`.
//!
//! The orim project uses the same `passveil show <key>` pattern for Porkbun
//! credentials. Layout matches `~/Github/orim/scripts/lib.sh:110-117`.

use async_trait::async_trait;

use crate::adapters::process::TokioProcess;
use tuntun_core::{Error, ProcessPort, ProcessSpec, Result, SecretKey, SecretPort, SecretValue};

#[derive(Debug)]
pub struct PassveilSecrets {
    process: TokioProcess,
}

impl Default for PassveilSecrets {
    fn default() -> Self {
        Self::new()
    }
}

impl PassveilSecrets {
    pub fn new() -> Self {
        Self {
            process: TokioProcess,
        }
    }
}

#[async_trait]
impl SecretPort for PassveilSecrets {
    async fn load(&self, key: &SecretKey) -> Result<SecretValue> {
        let spec = ProcessSpec::new("passveil")
            .arg("show")
            .arg(key.as_str());
        let exit = self.process.run_to_completion(&spec).await?;
        if !exit.is_success() {
            return Err(Error::port(
                "passveil",
                format!(
                    "load `{}`: exit {:?}: {}",
                    key,
                    exit.code,
                    String::from_utf8_lossy(&exit.stderr).trim()
                ),
            ));
        }
        // Trim a single trailing newline (passveil emits one).
        let mut bytes = exit.stdout;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        Ok(SecretValue::from_bytes(bytes))
    }

    async fn store(&self, key: &SecretKey, value: &SecretValue) -> Result<()> {
        let spec = ProcessSpec::new("passveil")
            .arg("insert")
            .arg(key.as_str())
            .stdin_input(value.expose_bytes().to_vec());
        let exit = self.process.run_to_completion(&spec).await?;
        if !exit.is_success() {
            return Err(Error::port(
                "passveil",
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
        let spec = ProcessSpec::new("passveil")
            .arg("show")
            .arg(key.as_str());
        let exit = self.process.run_to_completion(&spec).await?;
        Ok(exit.is_success())
    }
}
