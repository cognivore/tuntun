//! Integration tests for the [`PorkbunDns`] adapter, driven via the
//! `tuntun_core::testing::MockHttp` port. No real network is involved.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;

use serde_json::json;
use tuntun_core::testing::MockHttp;
use tuntun_core::{
    DnsName, DnsPort, DnsRecordContent, DnsRecordKind, DnsRecordSpec, Domain, Fqdn, HttpMethod,
    Ttl,
};
use tuntun_dns::{PorkbunCreds, PorkbunDns};

fn make_adapter() -> PorkbunDns<MockHttp> {
    PorkbunDns::new(MockHttp::new(), PorkbunCreds::from_strings("pk", "sk"))
}

fn apex() -> Domain {
    Domain::new("memorici.de").unwrap()
}

#[tokio::test]
async fn create_a_record_round_trip() {
    let adapter = make_adapter();
    adapter
        .http()
        .push_json_response(200, &json!({"status": "SUCCESS", "id": 42}));

    let spec = DnsRecordSpec {
        apex: apex(),
        name: DnsName::new("blog").unwrap(),
        ttl: Ttl::new(60).unwrap(),
        content: DnsRecordContent::A {
            ip: Ipv4Addr::new(203, 0, 113, 9),
        },
    };
    let id = adapter.create_record(&spec).await.unwrap();
    assert_eq!(id.as_str(), "42");

    let req = adapter.http().last_request().expect("recorded request");
    assert_eq!(req.method, HttpMethod::Post);
    assert!(req.url.as_str().ends_with("/dns/create/memorici.de"));
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body["name"], "blog");
    assert_eq!(body["type"], "A");
    assert_eq!(body["content"], "203.0.113.9");
    assert_eq!(body["ttl"], "60");
    assert_eq!(body["apikey"], "pk");
    assert_eq!(body["secretapikey"], "sk");
}

#[tokio::test]
async fn create_cname_record() {
    let adapter = make_adapter();
    adapter
        .http()
        .push_json_response(200, &json!({"status": "SUCCESS", "id": 7}));

    let spec = DnsRecordSpec {
        apex: apex(),
        name: DnsName::new("api").unwrap(),
        ttl: Ttl::new(300).unwrap(),
        content: DnsRecordContent::Cname {
            target: Fqdn::new("edge.memorici.de").unwrap(),
        },
    };
    let id = adapter.create_record(&spec).await.unwrap();
    assert_eq!(id.as_str(), "7");

    let req = adapter.http().last_request().unwrap();
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body["type"], "CNAME");
    assert_eq!(body["content"], "edge.memorici.de");
}

#[tokio::test]
async fn update_record_calls_edit_endpoint() {
    let adapter = make_adapter();
    adapter
        .http()
        .push_json_response(200, &json!({"status": "SUCCESS"}));

    let spec = DnsRecordSpec {
        apex: apex(),
        name: DnsName::new("blog").unwrap(),
        ttl: Ttl::new(120).unwrap(),
        content: DnsRecordContent::A {
            ip: Ipv4Addr::new(1, 2, 3, 4),
        },
    };
    adapter.update_record(&spec).await.unwrap();

    let req = adapter.http().last_request().unwrap();
    assert!(req
        .url
        .as_str()
        .ends_with("/dns/editByNameType/memorici.de/A/blog"));
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert!(body.get("name").is_none());
    assert_eq!(body["content"], "1.2.3.4");
    assert_eq!(body["ttl"], "120");
}

#[tokio::test]
async fn delete_record_calls_delete_endpoint() {
    let adapter = make_adapter();
    adapter
        .http()
        .push_json_response(200, &json!({"status": "SUCCESS"}));

    adapter
        .delete_record(
            &apex(),
            &DnsName::new("blog").unwrap(),
            DnsRecordKind::Cname,
        )
        .await
        .unwrap();

    let req = adapter.http().last_request().unwrap();
    assert!(req
        .url
        .as_str()
        .ends_with("/dns/deleteByNameType/memorici.de/CNAME/blog"));
}

#[tokio::test]
async fn api_error_status_is_upstream_error() {
    let adapter = make_adapter();
    adapter.http().push_json_response(
        200,
        &json!({"status": "ERROR", "message": "invalid api key"}),
    );

    let spec = DnsRecordSpec {
        apex: apex(),
        name: DnsName::new("blog").unwrap(),
        ttl: Ttl::new(60).unwrap(),
        content: DnsRecordContent::A {
            ip: Ipv4Addr::new(1, 2, 3, 4),
        },
    };
    let err = adapter.create_record(&spec).await.unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("porkbun"), "{s}");
    assert!(s.contains("invalid api key"), "{s}");
}

#[tokio::test]
async fn http_5xx_is_upstream_error() {
    let adapter = make_adapter();
    adapter
        .http()
        .push_response(tuntun_core::HttpResponse::new(
            tuntun_core::HttpStatus(503),
            b"unavailable".to_vec(),
        ));

    let err = adapter
        .delete_record(
            &apex(),
            &DnsName::new("blog").unwrap(),
            DnsRecordKind::A,
        )
        .await
        .unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("503"), "{s}");
}

#[tokio::test]
async fn list_records_for_decodes_records() {
    let adapter = make_adapter();
    adapter.http().push_json_response(
        200,
        &json!({
            "status": "SUCCESS",
            "records": [
                {
                    "id": "111",
                    "name": "blog.memorici.de",
                    "type": "A",
                    "content": "203.0.113.9",
                    "ttl": "60"
                }
            ]
        }),
    );

    let recs = adapter
        .list_records_for(
            &apex(),
            &DnsName::new("blog").unwrap(),
            DnsRecordKind::A,
        )
        .await
        .unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].id.as_str(), "111");
    assert_eq!(recs[0].name.as_str(), "blog");
    assert_eq!(recs[0].ttl.value(), 60);
}

#[tokio::test]
async fn list_records_top_level_method_is_unsupported() {
    let adapter = make_adapter();
    let err = adapter.list_records(&apex()).await.unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("dns"), "{s}");
}
