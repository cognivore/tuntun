//! Pure entry points for converting JSON into a validated
//! [`crate::ProjectSpec`].
//!
//! The CLI binary calls `nix eval --json -f tuntun.nix` and feeds the
//! resulting JSON through one of these functions. No I/O happens here:
//! the caller supplies the bytes (or pre-parsed [`serde_json::Value`]).

use crate::error::ConfigError;
use crate::model::ProjectSpec;

/// Parse a [`ProjectSpec`] from a pre-decoded [`serde_json::Value`] and
/// run [`ProjectSpec::validate`] on the result.
pub fn parse_project_spec_from_json(value: &serde_json::Value) -> Result<ProjectSpec, ConfigError> {
    let spec: ProjectSpec = serde_json::from_value(value.clone())?;
    spec.validate()?;
    Ok(spec)
}

/// Parse a [`ProjectSpec`] from a JSON string and run
/// [`ProjectSpec::validate`] on the result.
pub fn parse_project_spec_from_str(s: &str) -> Result<ProjectSpec, ConfigError> {
    let spec: ProjectSpec = serde_json::from_str(s)?;
    spec.validate()?;
    Ok(spec)
}
