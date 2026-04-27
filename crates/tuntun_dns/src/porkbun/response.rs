//! Pure response parsers: raw [`HttpResponse`] -> typed [`DnsRecord`] etc.
//!
//! Each parser performs the same general flow:
//!
//! 1. If the HTTP status is non-2xx, return [`DnsError::HttpStatus`].
//! 2. Decode the body as JSON into a wire envelope.
//! 3. If `status != "SUCCESS"`, return [`DnsError::Api`] with the message.
//! 4. Otherwise convert the wire-format payload into typed
//!    [`tuntun_core`] domain values.

use std::net::Ipv4Addr;
use std::str::FromStr;

use tuntun_core::{
    DnsRecord, DnsRecordContent, DnsRecordId, DnsRecordKind, Domain, Fqdn, HttpResponse, Subdomain,
    Ttl,
};

use crate::error::DnsError;

use super::wire::{CreateResponse, ListResponse, RawRecord, StatusEnvelope, STATUS_SUCCESS};

fn check_http_status(resp: &HttpResponse) -> Result<(), DnsError> {
    if resp.status.is_success() {
        return Ok(());
    }
    let body = resp.body_as_str().unwrap_or("<non-utf8 body>").to_string();
    Err(DnsError::HttpStatus {
        status: resp.status.0,
        body,
    })
}

fn decode_json<'a, T: serde::de::Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, DnsError> {
    serde_json::from_slice(bytes).map_err(|e| DnsError::decode(e.to_string()))
}

fn check_status_string(status: &str, message: Option<&str>) -> Result<(), DnsError> {
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        let msg = message.map_or_else(|| format!("status={status}"), str::to_string);
        Err(DnsError::Api(msg))
    }
}

/// Parse a generic Porkbun status response (used for edit / delete endpoints).
pub fn parse_status_response(resp: &HttpResponse) -> Result<(), DnsError> {
    check_http_status(resp)?;
    let env: StatusEnvelope = decode_json(&resp.body)?;
    check_status_string(&env.status, env.message.as_deref())
}

/// Parse a `POST /dns/create/{domain}` response and return the new record id.
pub fn parse_create_response(resp: &HttpResponse) -> Result<DnsRecordId, DnsError> {
    check_http_status(resp)?;
    let body: CreateResponse = decode_json(&resp.body)?;
    check_status_string(&body.status, body.message.as_deref())?;
    let id_num = body
        .id
        .ok_or_else(|| DnsError::decode("create response missing id field"))?;
    let id_str = id_num.to_string();
    DnsRecordId::new(id_str.clone()).map_err(|e| DnsError::invalid_field("id", e.to_string()))
}

/// Parse a `POST /dns/retrieveByNameType/...` response into typed records.
///
/// `apex` is the domain whose records were queried; Porkbun returns the bare
/// subdomain in `name` and we re-attach the apex to construct each record.
pub fn parse_list_response(resp: &HttpResponse, apex: &Domain) -> Result<Vec<DnsRecord>, DnsError> {
    check_http_status(resp)?;
    let body: ListResponse = decode_json(&resp.body)?;
    check_status_string(&body.status, body.message.as_deref())?;

    let mut out = Vec::with_capacity(body.records.len());
    for raw in &body.records {
        if let Some(rec) = record_from_raw(apex, raw)? {
            out.push(rec);
        }
    }
    Ok(out)
}

fn record_from_raw(apex: &Domain, raw: &RawRecord) -> Result<Option<DnsRecord>, DnsError> {
    let id_str = json_id_to_string(&raw.id)?;
    let id = DnsRecordId::new(id_str)
        .map_err(|e| DnsError::invalid_field("id", e.to_string()))?;

    let kind = parse_kind(&raw.kind)?;
    // Porkbun also returns root records (where `name` equals the apex) and
    // multi-label subdomains. We currently only model single-label subdomains
    // because that is what tuntun reconciles. Skip anything else so callers
    // get a clean view of just the records they are about to upsert.
    let bare = bare_subdomain(&raw.name, apex);
    let Some(bare) = bare else {
        return Ok(None);
    };
    let name = Subdomain::new(bare)
        .map_err(|e| DnsError::invalid_field("name", e.to_string()))?;

    let ttl_u32 = parse_ttl(&raw.ttl)?;
    let ttl = Ttl::new(ttl_u32).map_err(|e| DnsError::invalid_field("ttl", e.to_string()))?;
    let content = parse_content(kind, &raw.content)?;

    Ok(Some(DnsRecord {
        id,
        apex: apex.clone(),
        name,
        ttl,
        content,
    }))
}

fn json_id_to_string(v: &serde_json::Value) -> Result<String, DnsError> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        other => Err(DnsError::decode(format!("unexpected id type: {other}"))),
    }
}

fn parse_ttl(v: &serde_json::Value) -> Result<u32, DnsError> {
    match v {
        serde_json::Value::String(s) => s
            .parse::<u32>()
            .map_err(|e| DnsError::invalid_field("ttl", e.to_string())),
        serde_json::Value::Number(n) => n
            .as_u64()
            .and_then(|x| u32::try_from(x).ok())
            .ok_or_else(|| DnsError::invalid_field("ttl", format!("not u32: {n}"))),
        other => Err(DnsError::invalid_field("ttl", format!("type: {other}"))),
    }
}

fn parse_kind(s: &str) -> Result<DnsRecordKind, DnsError> {
    match s {
        "A" => Ok(DnsRecordKind::A),
        "CNAME" => Ok(DnsRecordKind::Cname),
        "TXT" => Ok(DnsRecordKind::Txt),
        other => Err(DnsError::invalid_field("type", format!("unsupported: {other}"))),
    }
}

fn parse_content(kind: DnsRecordKind, content: &str) -> Result<DnsRecordContent, DnsError> {
    match kind {
        DnsRecordKind::A => {
            let ip = Ipv4Addr::from_str(content)
                .map_err(|e| DnsError::invalid_field("content", format!("not ipv4: {e}")))?;
            Ok(DnsRecordContent::A { ip })
        }
        DnsRecordKind::Cname => {
            // Porkbun stores CNAME targets with or without a trailing dot;
            // strip it before validating so the FQDN newtype's domain check
            // accepts the value.
            let trimmed = content.trim_end_matches('.');
            let target = Fqdn::new(trimmed)
                .map_err(|e| DnsError::invalid_field("content", e.to_string()))?;
            Ok(DnsRecordContent::Cname { target })
        }
        DnsRecordKind::Txt => Ok(DnsRecordContent::Txt {
            value: content.to_string(),
        }),
    }
}

/// Compute the bare subdomain label, given Porkbun's `name` field plus our
/// known apex. Returns `None` if `name` denotes the apex itself or contains
/// multiple labels (e.g. `foo.bar.example.com` has bare `foo.bar` which is
/// not a single DNS label and not modelled in `tuntun_core`'s `Subdomain`).
///
/// Porkbun's `name` is sometimes the bare label (`"blog"`), sometimes the
/// full FQDN (`"blog.example.com"`). Both are accepted.
fn bare_subdomain(name: &str, apex: &Domain) -> Option<String> {
    let apex_str = apex.as_str();
    let candidate: &str = if name == apex_str {
        // root record — not a subdomain
        return None;
    } else if let Some(stripped) = name
        .strip_suffix(apex_str)
        .and_then(|s| s.strip_suffix('.'))
    {
        stripped
    } else {
        name
    };
    if candidate.is_empty() || candidate.contains('.') {
        return None;
    }
    Some(candidate.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tuntun_core::HttpStatus;

    use super::*;

    fn http_ok(body: &serde_json::Value) -> HttpResponse {
        HttpResponse::new(HttpStatus(200), serde_json::to_vec(body).unwrap())
    }

    fn apex() -> Domain {
        Domain::new("memorici.de").unwrap()
    }

    #[test]
    fn parse_status_success() {
        let resp = http_ok(&json!({"status": "SUCCESS"}));
        parse_status_response(&resp).unwrap();
    }

    #[test]
    fn parse_status_api_error() {
        let resp = http_ok(&json!({"status": "ERROR", "message": "bad credentials"}));
        let err = parse_status_response(&resp).unwrap_err();
        assert!(matches!(err, DnsError::Api(ref m) if m.contains("bad credentials")));
    }

    #[test]
    fn parse_status_http_error() {
        let resp = HttpResponse::new(HttpStatus(503), b"oops".to_vec());
        let err = parse_status_response(&resp).unwrap_err();
        assert!(matches!(
            err,
            DnsError::HttpStatus { status: 503, .. }
        ));
    }

    #[test]
    fn parse_create_returns_id() {
        let resp = http_ok(&json!({"status": "SUCCESS", "id": 123_456}));
        let id = parse_create_response(&resp).unwrap();
        assert_eq!(id.as_str(), "123456");
    }

    #[test]
    fn parse_create_missing_id_is_decode_error() {
        let resp = http_ok(&json!({"status": "SUCCESS"}));
        let err = parse_create_response(&resp).unwrap_err();
        assert!(matches!(err, DnsError::Decode(_)));
    }

    #[test]
    fn parse_create_api_error() {
        let resp = http_ok(&json!({"status": "ERROR", "message": "duplicate"}));
        let err = parse_create_response(&resp).unwrap_err();
        assert!(matches!(err, DnsError::Api(_)));
    }

    #[test]
    fn parse_list_a_record() {
        let resp = http_ok(&json!({
            "status": "SUCCESS",
            "records": [
                {
                    "id": "777",
                    "name": "blog.memorici.de",
                    "type": "A",
                    "content": "1.2.3.4",
                    "ttl": "60",
                    "prio": "0",
                    "notes": ""
                }
            ]
        }));
        let recs = parse_list_response(&resp, &apex()).unwrap();
        assert_eq!(recs.len(), 1);
        let rec = &recs[0];
        assert_eq!(rec.id.as_str(), "777");
        assert_eq!(rec.name.as_str(), "blog");
        assert_eq!(rec.ttl.value(), 60);
        assert_eq!(
            rec.content,
            DnsRecordContent::A {
                ip: Ipv4Addr::new(1, 2, 3, 4)
            }
        );
    }

    #[test]
    fn parse_list_cname_strips_trailing_dot() {
        let resp = http_ok(&json!({
            "status": "SUCCESS",
            "records": [
                {
                    "id": 9,
                    "name": "api",
                    "type": "CNAME",
                    "content": "edge.memorici.de.",
                    "ttl": 300
                }
            ]
        }));
        let recs = parse_list_response(&resp, &apex()).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].content,
            DnsRecordContent::Cname {
                target: Fqdn::new("edge.memorici.de").unwrap()
            }
        );
    }

    #[test]
    fn parse_list_skips_apex_record() {
        let resp = http_ok(&json!({
            "status": "SUCCESS",
            "records": [
                {
                    "id": "1",
                    "name": "memorici.de",
                    "type": "A",
                    "content": "1.2.3.4",
                    "ttl": "60"
                }
            ]
        }));
        let recs = parse_list_response(&resp, &apex()).unwrap();
        assert!(recs.is_empty());
    }

    #[test]
    fn parse_list_skips_multi_label() {
        let resp = http_ok(&json!({
            "status": "SUCCESS",
            "records": [
                {
                    "id": "1",
                    "name": "foo.bar.memorici.de",
                    "type": "A",
                    "content": "1.2.3.4",
                    "ttl": "60"
                }
            ]
        }));
        let recs = parse_list_response(&resp, &apex()).unwrap();
        assert!(recs.is_empty());
    }

    #[test]
    fn parse_list_invalid_ip_is_field_error() {
        let resp = http_ok(&json!({
            "status": "SUCCESS",
            "records": [
                {
                    "id": "1",
                    "name": "blog",
                    "type": "A",
                    "content": "not-an-ip",
                    "ttl": "60"
                }
            ]
        }));
        let err = parse_list_response(&resp, &apex()).unwrap_err();
        assert!(matches!(err, DnsError::InvalidField { field: "content", .. }));
    }
}
