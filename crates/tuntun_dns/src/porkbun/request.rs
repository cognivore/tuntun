//! Pure builders that turn typed inputs into [`HttpRequest`] values for the
//! Porkbun JSON API. No I/O, no clocks, no randomness.

use tuntun_core::{
    DnsName, DnsRecordKind, DnsRecordSpec, Domain, HttpMethod, HttpRequest, HttpUrl, Ttl,
};

use crate::error::DnsError;

use super::creds::PorkbunCreds;
use super::wire::{AuthFields, CreateBody, EditBody};
use super::PORKBUN_API_BASE;

fn url(path: &str) -> Result<HttpUrl, DnsError> {
    HttpUrl::new(format!("{PORKBUN_API_BASE}{path}"))
        .map_err(|e| DnsError::invalid_field("url", e.to_string()))
}

fn json_body(value: &impl serde::Serialize) -> Result<Vec<u8>, DnsError> {
    serde_json::to_vec(value)
        .map_err(|e| DnsError::invalid_field("request_body", e.to_string()))
}

fn kind_str(kind: DnsRecordKind) -> &'static str {
    match kind {
        DnsRecordKind::A => "A",
        DnsRecordKind::Cname => "CNAME",
        DnsRecordKind::Txt => "TXT",
    }
}

fn extract_auth(creds: &PorkbunCreds) -> Result<(&str, &str), DnsError> {
    let api = creds
        .api_key_str()
        .map_err(|e| DnsError::invalid_field("api_key", e.to_string()))?;
    let secret = creds
        .secret_key_str()
        .map_err(|e| DnsError::invalid_field("secret_key", e.to_string()))?;
    Ok((api, secret))
}

/// Build a `POST /dns/retrieveByNameType/{domain}/{type}/{subdomain}` request.
pub fn build_list_request(
    creds: &PorkbunCreds,
    domain: &Domain,
    name: &DnsName,
    kind: DnsRecordKind,
) -> Result<HttpRequest, DnsError> {
    let (apikey, secretapikey) = extract_auth(creds)?;
    let path = format!(
        "/dns/retrieveByNameType/{domain}/{kind}/{name}",
        domain = domain.as_str(),
        kind = kind_str(kind),
        name = name.as_str(),
    );
    let body = json_body(&AuthFields {
        apikey,
        secretapikey,
    })?;
    Ok(HttpRequest::new(HttpMethod::Post, url(&path)?)
        .with_header("Content-Type", "application/json")
        .with_body(body))
}

/// Build a `POST /dns/create/{domain}` request from a typed [`DnsRecordSpec`].
pub fn build_create_request(
    creds: &PorkbunCreds,
    spec: &DnsRecordSpec,
) -> Result<HttpRequest, DnsError> {
    let (apikey, secretapikey) = extract_auth(creds)?;
    let path = format!("/dns/create/{}", spec.apex.as_str());
    let kind = kind_str(spec.content.kind());
    let content = spec.content.wire_value();
    let body = json_body(&CreateBody {
        apikey,
        secretapikey,
        name: spec.name.as_str(),
        kind,
        content: &content,
        ttl: ttl_to_string(spec.ttl),
    })?;
    Ok(HttpRequest::new(HttpMethod::Post, url(&path)?)
        .with_header("Content-Type", "application/json")
        .with_body(body))
}

/// Build a `POST /dns/editByNameType/{domain}/{type}/{subdomain}` request.
pub fn build_update_request(
    creds: &PorkbunCreds,
    spec: &DnsRecordSpec,
) -> Result<HttpRequest, DnsError> {
    let (apikey, secretapikey) = extract_auth(creds)?;
    let kind = kind_str(spec.content.kind());
    let path = format!(
        "/dns/editByNameType/{domain}/{kind}/{name}",
        domain = spec.apex.as_str(),
        name = spec.name.as_str(),
    );
    let content = spec.content.wire_value();
    let body = json_body(&EditBody {
        apikey,
        secretapikey,
        content: &content,
        ttl: ttl_to_string(spec.ttl),
    })?;
    Ok(HttpRequest::new(HttpMethod::Post, url(&path)?)
        .with_header("Content-Type", "application/json")
        .with_body(body))
}

/// Build a `POST /dns/deleteByNameType/{domain}/{type}/{subdomain}` request.
pub fn build_delete_request(
    creds: &PorkbunCreds,
    domain: &Domain,
    name: &DnsName,
    kind: DnsRecordKind,
) -> Result<HttpRequest, DnsError> {
    let (apikey, secretapikey) = extract_auth(creds)?;
    let path = format!(
        "/dns/deleteByNameType/{domain}/{kind}/{name}",
        domain = domain.as_str(),
        kind = kind_str(kind),
        name = name.as_str(),
    );
    let body = json_body(&AuthFields {
        apikey,
        secretapikey,
    })?;
    Ok(HttpRequest::new(HttpMethod::Post, url(&path)?)
        .with_header("Content-Type", "application/json")
        .with_body(body))
}

fn ttl_to_string(ttl: Ttl) -> String {
    ttl.value().to_string()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use serde_json::Value;
    use tuntun_core::{DnsRecordContent, Fqdn};

    use super::*;

    fn creds() -> PorkbunCreds {
        PorkbunCreds::from_strings("pk-key", "sk-key")
    }

    fn parse_body(req: &HttpRequest) -> Value {
        serde_json::from_slice(&req.body).unwrap()
    }

    #[test]
    fn list_request_path_includes_domain_kind_name() {
        let req = build_list_request(
            &creds(),
            &Domain::new("example.com").unwrap(),
            &DnsName::new("blog").unwrap(),
            DnsRecordKind::A,
        )
        .unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert!(req.url.as_str().ends_with("/dns/retrieveByNameType/example.com/A/blog"));
        let body = parse_body(&req);
        assert_eq!(body["apikey"], "pk-key");
        assert_eq!(body["secretapikey"], "sk-key");
        assert!(req
            .header_map()
            .get("Content-Type")
            .copied()
            .is_some_and(|v| v.eq_ignore_ascii_case("application/json")));
    }

    #[test]
    fn create_request_serializes_a_record() {
        let spec = DnsRecordSpec {
            apex: Domain::new("memorici.de").unwrap(),
            name: DnsName::new("blog").unwrap(),
            ttl: Ttl::new(60).unwrap(),
            content: DnsRecordContent::A {
                ip: Ipv4Addr::new(203, 0, 113, 9),
            },
        };
        let req = build_create_request(&creds(), &spec).unwrap();
        assert!(req.url.as_str().ends_with("/dns/create/memorici.de"));
        let body = parse_body(&req);
        assert_eq!(body["name"], "blog");
        assert_eq!(body["type"], "A");
        assert_eq!(body["content"], "203.0.113.9");
        assert_eq!(body["ttl"], "60");
    }

    #[test]
    fn create_request_serializes_cname() {
        let spec = DnsRecordSpec {
            apex: Domain::new("memorici.de").unwrap(),
            name: DnsName::new("api").unwrap(),
            ttl: Ttl::new(300).unwrap(),
            content: DnsRecordContent::Cname {
                target: Fqdn::new("edge.memorici.de").unwrap(),
            },
        };
        let req = build_create_request(&creds(), &spec).unwrap();
        let body = parse_body(&req);
        assert_eq!(body["type"], "CNAME");
        assert_eq!(body["content"], "edge.memorici.de");
        assert_eq!(body["ttl"], "300");
    }

    #[test]
    fn update_request_omits_name_field() {
        let spec = DnsRecordSpec {
            apex: Domain::new("memorici.de").unwrap(),
            name: DnsName::new("blog").unwrap(),
            ttl: Ttl::new(120).unwrap(),
            content: DnsRecordContent::A {
                ip: Ipv4Addr::new(1, 2, 3, 4),
            },
        };
        let req = build_update_request(&creds(), &spec).unwrap();
        assert!(req.url.as_str().ends_with("/dns/editByNameType/memorici.de/A/blog"));
        let body = parse_body(&req);
        assert!(body.get("name").is_none());
        assert_eq!(body["content"], "1.2.3.4");
        assert_eq!(body["ttl"], "120");
    }

    #[test]
    fn delete_request_only_carries_auth() {
        let req = build_delete_request(
            &creds(),
            &Domain::new("memorici.de").unwrap(),
            &DnsName::new("blog").unwrap(),
            DnsRecordKind::Cname,
        )
        .unwrap();
        assert!(req
            .url
            .as_str()
            .ends_with("/dns/deleteByNameType/memorici.de/CNAME/blog"));
        let body = parse_body(&req);
        assert_eq!(body["apikey"], "pk-key");
        assert_eq!(body["secretapikey"], "sk-key");
        assert!(body.get("content").is_none());
    }
}
