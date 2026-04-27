//! Wire-format types for the Porkbun JSON API.
//!
//! These types exist purely to serialize request bodies and to deserialize
//! response bodies. They are crate-internal — public functions never accept or
//! return them, only the typed [`tuntun_core`] domain values.

use serde::{Deserialize, Serialize};

/// The auth fields embedded in every Porkbun request body.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AuthFields<'a> {
    pub apikey: &'a str,
    pub secretapikey: &'a str,
}

/// `POST /dns/create/{domain}` body.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CreateBody<'a> {
    pub apikey: &'a str,
    pub secretapikey: &'a str,
    pub name: &'a str,
    #[serde(rename = "type")]
    pub kind: &'a str,
    pub content: &'a str,
    /// TTL is sent as a string; Porkbun accepts both but the orim shell uses
    /// strings, and the official `pkb-go` client emits strings. We follow.
    pub ttl: String,
}

/// `POST /dns/editByNameType/{domain}/{type}/{subdomain}` body.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct EditBody<'a> {
    pub apikey: &'a str,
    pub secretapikey: &'a str,
    pub content: &'a str,
    pub ttl: String,
}

// ---------------------------------------------------------------------------

/// Common envelope: every Porkbun response carries a `status` field.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct StatusEnvelope {
    pub status: String,
    #[serde(default)]
    pub message: Option<String>,
}

/// `POST /dns/create/{domain}` response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CreateResponse {
    pub status: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub id: Option<serde_json::Number>,
}

/// `POST /dns/retrieveByNameType/...` response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ListResponse {
    pub status: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub records: Vec<RawRecord>,
}

/// One record inside a list/retrieve response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawRecord {
    pub id: serde_json::Value,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub content: String,
    pub ttl: serde_json::Value,
    #[serde(default)]
    #[allow(dead_code)]
    pub prio: Option<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    pub notes: Option<String>,
}

/// Status string Porkbun returns on success.
pub(crate) const STATUS_SUCCESS: &str = "SUCCESS";
