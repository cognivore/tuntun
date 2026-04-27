//! `tuntun_dns` -- typed Porkbun JSON API client logic.
//!
//! This crate performs **zero I/O**. It contains:
//!
//! - Pure request builders that emit [`tuntun_core::HttpRequest`] values for the
//!   Porkbun JSON API (`https://api.porkbun.com/api/json/v3`).
//! - Pure response parsers that decode raw [`tuntun_core::HttpResponse`] bytes
//!   into typed [`tuntun_core::DnsRecord`] values.
//! - A [`porkbun::PorkbunDns`] adapter that implements
//!   [`tuntun_core::DnsPort`] generically over an injected
//!   [`tuntun_core::HttpPort`]. The adapter contains no I/O of its own — the
//!   only thing performing real network work is the `HttpPort` impl supplied by
//!   the binary crate.
//! - A pure [`reconcile::plan_dns_reconciliation`] planner that turns a desired
//!   set of [`tuntun_core::DnsRecordSpec`] plus an observed set of
//!   [`tuntun_core::DnsRecord`] into a list of [`reconcile::DnsAction`]s.
//!
//! See the workspace `CLAUDE.md`, rules 1, 2, 3 and 7, for the architectural
//! contract this crate must satisfy.

pub mod error;
pub mod porkbun;
pub mod reconcile;

pub use crate::error::DnsError;
pub use crate::porkbun::{PorkbunCreds, PorkbunDns, PORKBUN_API_BASE};
pub use crate::reconcile::{plan_dns_reconciliation, DnsAction};
