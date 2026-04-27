//! Errors that can arise while parsing or validating a [`crate::ProjectSpec`].
//!
//! Parsing is a pure function over a `serde_json::Value` (or its string
//! representation). The only ways to fail are:
//!
//! - The JSON does not match the expected shape ([`ConfigError::Json`]).
//! - A required field is missing ([`ConfigError::MissingField`]). This is
//!   reserved for cases the validator detects after deserialization; the
//!   serde layer typically reports its own missing-field errors via
//!   [`ConfigError::Json`].
//! - The set of services is empty ([`ConfigError::EmptyServices`]).
//! - A semantic invariant is violated ([`ConfigError::Validation`]):
//!   duplicate subdomains, duplicate local ports, malformed health-check
//!   path, or out-of-range expected status.

use thiserror::Error;

/// Reasons [`crate::parse::parse_project_spec_from_json`] (or its string
/// shim) may refuse to produce a [`crate::ProjectSpec`].
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Underlying JSON deserialization failed: the value did not match the
    /// expected schema, an id failed validation, or the JSON itself was
    /// malformed.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// A semantic invariant was violated after deserialization. The string
    /// describes the specific rule that was broken.
    #[error("validation failed: {0}")]
    Validation(String),

    /// A required field was absent. The serde layer normally surfaces this
    /// as [`ConfigError::Json`]; this variant exists so the validator can
    /// report post-deserialization missing fields with a stable name.
    #[error("missing required field: {field}")]
    MissingField {
        /// The name of the missing field.
        field: &'static str,
    },

    /// The `services` map was present but empty. A project with no services
    /// has nothing to tunnel and is rejected up-front.
    #[error("services map must contain at least one entry")]
    EmptyServices,
}
