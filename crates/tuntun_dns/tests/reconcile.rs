//! End-to-end integration test that drives the [`PorkbunDns`] adapter through
//! a complete reconcile cycle using a [`MockHttp`] queue.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;

use serde_json::json;
use tuntun_core::testing::MockHttp;
use tuntun_core::{
    DnsPort, DnsRecord, DnsRecordContent, DnsRecordId, DnsRecordKind, DnsRecordSpec, Domain,
    Subdomain, Ttl,
};
use tuntun_dns::{plan_dns_reconciliation, DnsAction, PorkbunCreds, PorkbunDns};

fn apex() -> Domain {
    Domain::new("memorici.de").unwrap()
}

fn spec(name: &str, ip: [u8; 4]) -> DnsRecordSpec {
    DnsRecordSpec {
        apex: apex(),
        name: Subdomain::new(name).unwrap(),
        ttl: Ttl::new(60).unwrap(),
        content: DnsRecordContent::A {
            ip: Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
        },
    }
}

fn observed(id: &str, name: &str, ip: [u8; 4]) -> DnsRecord {
    DnsRecord {
        id: DnsRecordId::new(id).unwrap(),
        apex: apex(),
        name: Subdomain::new(name).unwrap(),
        ttl: Ttl::new(60).unwrap(),
        content: DnsRecordContent::A {
            ip: Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
        },
    }
}

#[tokio::test]
async fn plan_then_execute_creates_updates_deletes() {
    let desired = vec![spec("blog", [1, 2, 3, 4]), spec("api", [9, 9, 9, 9])];
    let observed_set = vec![
        observed("rec-blog", "blog", [1, 2, 3, 4]),  // matches -> NoOp
        observed("rec-api", "api", [1, 2, 3, 4]),    // mismatch -> Update
        observed("rec-stale", "stale", [7, 7, 7, 7]), // unwanted -> Delete
    ];
    let plan = plan_dns_reconciliation(&desired, &observed_set);
    assert_eq!(plan.len(), 3);

    let mut creates = 0_usize;
    let mut updates = 0_usize;
    let mut deletes = 0_usize;
    let mut noops = 0_usize;

    let adapter = PorkbunDns::new(MockHttp::new(), PorkbunCreds::from_strings("pk", "sk"));

    for action in &plan {
        match action {
            DnsAction::Create(_) => {
                adapter
                    .http()
                    .push_json_response(200, &json!({"status": "SUCCESS", "id": 1}));
            }
            DnsAction::Update(_) | DnsAction::Delete { .. } => {
                adapter
                    .http()
                    .push_json_response(200, &json!({"status": "SUCCESS"}));
            }
            DnsAction::NoOp(_) => {}
        }
    }

    for action in plan {
        match action {
            DnsAction::Create(s) => {
                adapter.create_record(&s).await.unwrap();
                creates += 1;
            }
            DnsAction::Update(s) => {
                adapter.update_record(&s).await.unwrap();
                updates += 1;
            }
            DnsAction::Delete { domain, name, kind } => {
                adapter.delete_record(&domain, &name, kind).await.unwrap();
                deletes += 1;
            }
            DnsAction::NoOp(_) => {
                noops += 1;
            }
        }
    }

    assert_eq!(creates, 0); // both desired records existed observed-side
    assert_eq!(updates, 1);
    assert_eq!(deletes, 1);
    assert_eq!(noops, 1);

    // Adapter should have made exactly 2 HTTP calls (1 update + 1 delete).
    assert_eq!(adapter.http().requests().len(), 2);
    let urls: Vec<String> = adapter
        .http()
        .requests()
        .iter()
        .map(|r| r.url.as_str().to_string())
        .collect();
    assert!(urls.iter().any(|u| u.contains("editByNameType")));
    assert!(urls.iter().any(|u| u.contains("deleteByNameType")));
}

#[tokio::test]
async fn delete_only_when_observed_is_extra() {
    // Desired is empty, observed has one stale record -> single delete.
    let plan = plan_dns_reconciliation(&[], &[observed("rec-x", "x", [1, 2, 3, 4])]);
    assert!(matches!(plan.as_slice(), [DnsAction::Delete { .. }]));

    let adapter = PorkbunDns::new(MockHttp::new(), PorkbunCreds::from_strings("pk", "sk"));
    adapter
        .http()
        .push_json_response(200, &json!({"status": "SUCCESS"}));

    if let DnsAction::Delete { domain, name, kind } = &plan[0] {
        adapter.delete_record(domain, name, *kind).await.unwrap();
    }
    assert_eq!(adapter.http().requests().len(), 1);
}

#[tokio::test]
async fn create_when_observed_empty() {
    let desired = vec![spec("blog", [1, 2, 3, 4])];
    let plan = plan_dns_reconciliation(&desired, &[]);
    assert!(matches!(plan.as_slice(), [DnsAction::Create(_)]));

    let adapter = PorkbunDns::new(MockHttp::new(), PorkbunCreds::from_strings("pk", "sk"));
    adapter
        .http()
        .push_json_response(200, &json!({"status": "SUCCESS", "id": 99}));

    if let DnsAction::Create(s) = &plan[0] {
        let id = adapter.create_record(s).await.unwrap();
        assert_eq!(id.as_str(), "99");
    }
}

#[tokio::test]
async fn cname_kind_is_distinct_from_a() {
    use tuntun_core::Fqdn;

    let desired = vec![DnsRecordSpec {
        apex: apex(),
        name: Subdomain::new("api").unwrap(),
        ttl: Ttl::new(60).unwrap(),
        content: DnsRecordContent::Cname {
            target: Fqdn::new("edge.memorici.de").unwrap(),
        },
    }];
    let observed_set = vec![DnsRecord {
        id: DnsRecordId::new("rec-a").unwrap(),
        apex: apex(),
        name: Subdomain::new("api").unwrap(),
        ttl: Ttl::new(60).unwrap(),
        content: DnsRecordContent::A {
            ip: Ipv4Addr::new(1, 2, 3, 4),
        },
    }];
    // Different kinds -> Create the CNAME and Delete the A.
    let plan = plan_dns_reconciliation(&desired, &observed_set);
    assert_eq!(plan.len(), 2);
    assert!(matches!(plan[0], DnsAction::Create(_)));
    assert!(matches!(
        plan[1],
        DnsAction::Delete { kind: DnsRecordKind::A, .. }
    ));
}
