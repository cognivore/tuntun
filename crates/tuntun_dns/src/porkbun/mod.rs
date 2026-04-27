//! Porkbun JSON API integration: typed credentials, request builders, response
//! parsers, and a generic [`PorkbunDns`] adapter that implements
//! [`tuntun_core::DnsPort`] over any [`tuntun_core::HttpPort`].
//!
//! The Porkbun JSON API authenticates by including `apikey` and `secretapikey`
//! fields in the JSON body of every request — there are no auth headers.
//! Successful responses carry `{"status": "SUCCESS", ...}`; failures carry
//! `{"status": "ERROR", "message": "..."}`. We treat a non-2xx HTTP status or a
//! JSON-level `status: "ERROR"` as a failure regardless of HTTP code.
//!
//! All public functions in this module are pure (no I/O) except the methods
//! on [`PorkbunDns`], which call out through an injected `HttpPort`.

mod adapter;
mod creds;
mod request;
mod response;
mod wire;

pub use adapter::PorkbunDns;
pub use creds::PorkbunCreds;

/// Base URL for Porkbun's JSON API. All endpoints are appended to this prefix.
pub const PORKBUN_API_BASE: &str = "https://api.porkbun.com/api/json/v3";

// Re-exported for callers that want to drive the wire protocol manually
// (e.g. additional record types not yet covered by the adapter, or tests).
pub use request::{
    build_create_request, build_delete_request, build_list_request, build_update_request,
};
pub use response::{parse_create_response, parse_list_response, parse_status_response};
