//! `tuntun_core` -- domain types and port traits for the tuntun system.
//!
//! This crate performs **zero I/O**. It defines:
//!
//! - Validated newtype identifiers via [`define_id!`] and [`define_numeric_id!`]
//! - Domain value types (`HttpRequest`, `DnsRecord`, `Timestamp`, ...)
//! - Async port traits (`HttpPort`, `DnsPort`, `ClockPort`, `SecretPort`,
//!   `ProcessPort`, `FsPort`)
//! - A unified [`Error`] / [`Result`] alias
//! - Mock implementations of every port behind [`testing`]
//!
//! See the workspace root `CLAUDE.md` for the full architectural contract.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod crypto;
pub mod dns;
pub mod error;
pub mod http;
pub mod id;
pub mod ids;
pub mod ports;
pub mod process;
pub mod secret;
pub mod testing;
pub mod time;

pub use crate::crypto::{Ed25519PublicKey, Ed25519Signature, Fingerprint, Nonce};
pub use crate::dns::{DnsRecord, DnsRecordContent, DnsRecordKind, DnsRecordSpec};
pub use crate::error::{Error, Result};
pub use crate::http::{HttpHeader, HttpMethod, HttpRequest, HttpResponse, HttpStatus, HttpUrl};
pub use crate::id::IdError;
pub use crate::ids::{
    DnsRecordId, Domain, Fqdn, LocalPort, ProjectId, SecretKey, ServiceName, ServicePort,
    Subdomain, TenantId, Ttl, TunnelClientId,
};
pub use crate::ports::{
    ClockPort, DnsPort, FsPort, HttpPort, ProcessPort, SecretPort,
};
pub use crate::process::{ProcessExit, ProcessExitCode, ProcessSignal, ProcessSpec};
pub use crate::secret::SecretValue;
pub use crate::time::{Duration, Instant, Timestamp};
