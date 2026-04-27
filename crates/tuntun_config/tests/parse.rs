//! Integration tests for the `tuntun_config` schema and validator.

use tuntun_config::{
    parse_project_spec_from_json, parse_project_spec_from_str, AuthPolicy, ConfigError,
    ProjectSpec,
};

/// The canonical example from CLAUDE.md.
const CANONICAL_JSON: &str = r#"{
    "tenant": "memorici-de",
    "domain": "memorici.de",
    "services": {
        "blog": {
            "subdomain": "blog",
            "localPort": 4000,
            "auth": "tenant",
            "healthCheck": { "path": "/_health" }
        }
    }
}"#;

#[test]
fn parses_canonical_example() {
    let spec = parse_project_spec_from_str(CANONICAL_JSON).expect("canonical example must parse");
    assert_eq!(spec.tenant.as_str(), "memorici-de");
    assert_eq!(spec.domain.as_str(), "memorici.de");
    assert!(spec.project.is_none());
    assert_eq!(spec.services.len(), 1);
    let blog = spec
        .services
        .get(&"blog".parse().expect("valid service name"))
        .expect("blog service present");
    assert_eq!(blog.subdomain.as_str(), "blog");
    assert_eq!(blog.local_port.value(), 4000);
    assert_eq!(blog.auth, AuthPolicy::Tenant);
    let hc = blog
        .health_check
        .as_ref()
        .expect("health check present");
    assert_eq!(hc.path, "/_health");
    assert_eq!(hc.expected_status, None);
    assert_eq!(hc.timeout_seconds, 5);
}

#[test]
fn parses_via_serde_json_value() {
    let value: serde_json::Value =
        serde_json::from_str(CANONICAL_JSON).expect("canonical example is valid JSON");
    let spec = parse_project_spec_from_json(&value).expect("value must parse");
    assert_eq!(spec.tenant.as_str(), "memorici-de");
}

#[test]
fn auth_defaults_to_tenant_when_omitted() {
    let json = r#"{
        "tenant": "memorici-de",
        "domain": "memorici.de",
        "services": {
            "blog": { "subdomain": "blog", "localPort": 4000 }
        }
    }"#;
    let spec = parse_project_spec_from_str(json).expect("must parse without auth field");
    let blog = spec
        .services
        .get(&"blog".parse().expect("valid service name"))
        .expect("blog service present");
    assert_eq!(blog.auth, AuthPolicy::Tenant);
}

#[test]
fn rejects_duplicate_subdomains() {
    let json = r#"{
        "tenant": "memorici-de",
        "domain": "memorici.de",
        "services": {
            "blog":  { "subdomain": "shared", "localPort": 4000 },
            "wiki":  { "subdomain": "shared", "localPort": 4001 }
        }
    }"#;
    let err = parse_project_spec_from_str(json).expect_err("duplicate subdomain must fail");
    match err {
        ConfigError::Validation(msg) => assert!(
            msg.contains("duplicate subdomain"),
            "unexpected validation message: {msg}"
        ),
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[test]
fn rejects_duplicate_local_ports() {
    let json = r#"{
        "tenant": "memorici-de",
        "domain": "memorici.de",
        "services": {
            "blog":  { "subdomain": "blog", "localPort": 4000 },
            "wiki":  { "subdomain": "wiki", "localPort": 4000 }
        }
    }"#;
    let err = parse_project_spec_from_str(json).expect_err("duplicate port must fail");
    match err {
        ConfigError::Validation(msg) => assert!(
            msg.contains("duplicate local port"),
            "unexpected validation message: {msg}"
        ),
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[test]
fn rejects_empty_services_map() {
    let json = r#"{
        "tenant": "memorici-de",
        "domain": "memorici.de",
        "services": {}
    }"#;
    let err = parse_project_spec_from_str(json).expect_err("empty services must fail");
    assert!(matches!(err, ConfigError::EmptyServices));
}

#[test]
fn rejects_health_check_path_without_leading_slash() {
    let json = r#"{
        "tenant": "memorici-de",
        "domain": "memorici.de",
        "services": {
            "blog": {
                "subdomain": "blog",
                "localPort": 4000,
                "healthCheck": { "path": "_health" }
            }
        }
    }"#;
    let err = parse_project_spec_from_str(json).expect_err("bad health path must fail");
    match err {
        ConfigError::Validation(msg) => assert!(
            msg.contains("must start with '/'"),
            "unexpected validation message: {msg}"
        ),
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[test]
fn rejects_health_check_expected_status_out_of_range() {
    let json = r#"{
        "tenant": "memorici-de",
        "domain": "memorici.de",
        "services": {
            "blog": {
                "subdomain": "blog",
                "localPort": 4000,
                "healthCheck": { "path": "/_health", "expectedStatus": 700 }
            }
        }
    }"#;
    let err = parse_project_spec_from_str(json).expect_err("bad status must fail");
    match err {
        ConfigError::Validation(msg) => assert!(
            msg.contains("expectedStatus"),
            "unexpected validation message: {msg}"
        ),
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[test]
fn round_trips_via_json() {
    let spec = parse_project_spec_from_str(CANONICAL_JSON).expect("parses");
    let serialized = serde_json::to_string(&spec).expect("serializes");
    let again: ProjectSpec =
        serde_json::from_str(&serialized).expect("re-parses serialized form");
    again.validate().expect("re-parsed value is still valid");
    assert_eq!(spec, again);
}

#[test]
fn parses_explicit_project_name_and_extras() {
    let json = r#"{
        "tenant": "memorici-de",
        "domain": "memorici.de",
        "project": "main-site",
        "services": {
            "api": {
                "subdomain": "api",
                "localPort": 8080,
                "auth": "public",
                "healthCheck": {
                    "path": "/healthz",
                    "expectedStatus": 200,
                    "timeoutSeconds": 10
                }
            }
        }
    }"#;
    let spec = parse_project_spec_from_str(json).expect("must parse");
    assert_eq!(
        spec.project.as_ref().map(tuntun_core::ProjectId::as_str),
        Some("main-site")
    );
    let api = spec
        .services
        .get(&"api".parse().expect("valid service name"))
        .expect("api service present");
    assert_eq!(api.auth, AuthPolicy::Public);
    let hc = api.health_check.as_ref().expect("hc present");
    assert_eq!(hc.expected_status, Some(200));
    assert_eq!(hc.timeout_seconds, 10);
}
