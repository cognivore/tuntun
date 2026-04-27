//! `tuntun_config` -- schema for the per-project `tuntun.nix` configuration.
//!
//! This crate performs **zero I/O**. It defines the typed Rust shape that
//! the JSON output of `nix eval --json -f tuntun.nix` deserializes into,
//! plus pure validation logic.
//!
//! See the workspace `CLAUDE.md` for the canonical example of `tuntun.nix`.
//!
//! Public modules:
//!
//! - [`model`] -- the [`ProjectSpec`], [`ServiceSpec`], [`AuthPolicy`],
//!   [`HealthCheckSpec`] types.
//! - [`error`] -- the [`ConfigError`] variants.
//! - [`parse`] -- pure entry points
//!   ([`parse::parse_project_spec_from_json`],
//!   [`parse::parse_project_spec_from_str`]) that combine deserialization
//!   with validation.

pub mod error;
pub mod model;
pub mod parse;

pub use crate::error::ConfigError;
pub use crate::model::{AuthPolicy, HealthCheckSpec, ProjectSpec, ServiceSpec};
pub use crate::parse::{parse_project_spec_from_json, parse_project_spec_from_str};
