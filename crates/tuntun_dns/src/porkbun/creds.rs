//! Porkbun API credentials.

use std::fmt;

use tuntun_core::SecretValue;

/// Porkbun API credentials.
///
/// Both fields are stored as [`SecretValue`], which redacts in `Debug` and
/// zeroizes on drop. The struct itself also implements a redacted `Debug` so
/// accidental `tracing::debug!("{creds:?}")` cannot leak.
#[derive(Clone)]
pub struct PorkbunCreds {
    pub api_key: SecretValue,
    pub secret_key: SecretValue,
}

impl PorkbunCreds {
    pub fn new(api_key: SecretValue, secret_key: SecretValue) -> Self {
        Self {
            api_key,
            secret_key,
        }
    }

    /// Build a `PorkbunCreds` from plain strings. Convenience for tests and
    /// for callers loading credentials from a `passveil` payload that has
    /// already been parsed into two strings.
    pub fn from_strings(api_key: impl Into<String>, secret_key: impl Into<String>) -> Self {
        Self {
            api_key: SecretValue::from_string(api_key.into()),
            secret_key: SecretValue::from_string(secret_key.into()),
        }
    }

    /// Borrow the api key as a UTF-8 string. Returns an error if the secret
    /// bytes are not valid UTF-8 (Porkbun keys are ASCII, so this is purely
    /// defensive).
    pub fn api_key_str(&self) -> Result<&str, std::str::Utf8Error> {
        self.api_key.expose_str()
    }

    /// Borrow the secret api key as a UTF-8 string.
    pub fn secret_key_str(&self) -> Result<&str, std::str::Utf8Error> {
        self.secret_key.expose_str()
    }
}

impl fmt::Debug for PorkbunCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PorkbunCreds")
            .field("api_key", &self.api_key)
            .field("secret_key", &self.secret_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_both_fields() {
        let creds = PorkbunCreds::from_strings("pk1_visible", "sk1_visible");
        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("pk1_visible"));
        assert!(!dbg.contains("sk1_visible"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn exposes_keys_for_serialization() {
        let creds = PorkbunCreds::from_strings("k", "s");
        assert_eq!(creds.api_key_str().unwrap(), "k");
        assert_eq!(creds.secret_key_str().unwrap(), "s");
    }
}
