//! `SecretPort` adapter for the server side.
//!
//! Reads systemd `LoadCredential` directory (`$CREDENTIALS_DIRECTORY/<name>`)
//! and falls back to a path on the filesystem otherwise.

use std::path::PathBuf;

use async_trait::async_trait;

use tuntun_core::{Error, Result, SecretKey, SecretPort, SecretValue};

#[derive(Debug, Default)]
pub struct CredentialDirSecrets;

impl CredentialDirSecrets {
    fn resolve(key: &SecretKey) -> Option<PathBuf> {
        let dir = std::env::var("CREDENTIALS_DIRECTORY").ok()?;
        // The systemd LoadCredential names have already been written to
        // disk; we map our SecretKey path-style names ("tuntun/foo") onto
        // the credential names ("tuntun-foo") for filesystem safety.
        let cred_name = key.as_str().replace('/', "-");
        Some(PathBuf::from(dir).join(cred_name))
    }
}

#[async_trait]
impl SecretPort for CredentialDirSecrets {
    async fn load(&self, key: &SecretKey) -> Result<SecretValue> {
        let path = Self::resolve(key)
            .ok_or_else(|| Error::not_found("secret", key.as_str()))?;
        let mut bytes = tokio::fs::read(&path).await.map_err(|e| {
            Error::port(
                "credential-dir",
                format!("read {}: {e}", path.display()),
            )
        })?;
        // Strip a single trailing CR/LF pair. Operators routinely write
        // secrets via `cat > file`, which appends a newline. PEM payloads
        // (signing keys, certs) handle the trailing newline themselves; flat
        // tokens (Porkbun keys, Argon2id PHC) do not, and JSON-serializing a
        // trailing `\n` produces an "Invalid API key" from Porkbun.
        while matches!(bytes.last(), Some(&(b'\n' | b'\r'))) {
            bytes.pop();
        }
        Ok(SecretValue::from_bytes(bytes))
    }

    async fn store(&self, _key: &SecretKey, _value: &SecretValue) -> Result<()> {
        Err(Error::port(
            "credential-dir",
            "credential directory is read-only at runtime",
        ))
    }

    async fn exists(&self, key: &SecretKey) -> Result<bool> {
        let Some(path) = Self::resolve(key) else {
            return Ok(false);
        };
        Ok(tokio::fs::metadata(&path).await.is_ok())
    }
}
