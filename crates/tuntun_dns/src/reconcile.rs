//! Pure DNS reconciliation planner.
//!
//! The orim shell uses upsert-style logic where every "ensure this record
//! exists with this content" call either edits in place or creates. This crate
//! exposes that policy as an explicit, testable plan: given the desired set of
//! [`DnsRecordSpec`] and an observed set of [`DnsRecord`] (typically obtained
//! via [`PorkbunDns::list_records_for`]), produce a list of typed
//! [`DnsAction`] values that the caller can then dispatch through a
//! [`DnsPort`].
//!
//! The planner is deterministic and total: every desired record produces
//! exactly one action (`Create`, `Update`, or `NoOp`), and every observed
//! record that has no matching desired record produces a `Delete`.
//!
//! [`PorkbunDns::list_records_for`]: crate::porkbun::PorkbunDns::list_records_for

use std::collections::{HashMap, HashSet};

use tuntun_core::{DnsName, DnsRecord, DnsRecordKind, DnsRecordSpec, Domain};

/// One step in a reconciliation plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAction {
    /// Record does not exist on the provider — create it.
    Create(DnsRecordSpec),
    /// Record exists with the same `(apex, name, kind)` but has a different
    /// content or TTL — update it in place.
    Update(DnsRecordSpec),
    /// Record exists on the provider but is not in the desired set — delete it.
    Delete {
        domain: Domain,
        name: DnsName,
        kind: DnsRecordKind,
    },
    /// Record already matches the spec; nothing to do. Emitted so callers can
    /// log/audit a complete plan instead of silently dropping rows.
    NoOp(DnsRecordSpec),
}

/// Compute the actions required to reconcile `observed` into `desired`.
///
/// Records are matched by `(apex, name, kind)`. The TTL and content are
/// compared via [`DnsRecord::matches`]; a mismatch on either field yields an
/// [`DnsAction::Update`].
///
/// The output ordering is stable: `Create`, `Update`, and `NoOp` actions
/// appear in the input order of `desired`. `Delete`s are appended afterwards,
/// in the order in which the corresponding records appeared in `observed`.
/// This makes the plan easy to compare in tests.
#[must_use]
pub fn plan_dns_reconciliation(
    desired: &[DnsRecordSpec],
    observed: &[DnsRecord],
) -> Vec<DnsAction> {
    type Key = (Domain, DnsName, DnsRecordKind);

    fn record_key(rec: &DnsRecord) -> Key {
        (rec.apex.clone(), rec.name.clone(), rec.content.kind())
    }

    fn spec_key(spec: &DnsRecordSpec) -> Key {
        (spec.apex.clone(), spec.name.clone(), spec.content.kind())
    }

    // Index observed records by key for O(N+M) matching.
    let mut observed_index: HashMap<Key, &DnsRecord> = HashMap::with_capacity(observed.len());
    for rec in observed {
        observed_index.insert(record_key(rec), rec);
    }

    let mut plan = Vec::with_capacity(desired.len());
    let mut consumed: HashSet<Key> = HashSet::with_capacity(desired.len());

    for spec in desired {
        let key = spec_key(spec);
        match observed_index.get(&key) {
            None => plan.push(DnsAction::Create(spec.clone())),
            Some(rec) if rec.matches(spec) => plan.push(DnsAction::NoOp(spec.clone())),
            Some(_) => plan.push(DnsAction::Update(spec.clone())),
        }
        consumed.insert(key);
    }

    for rec in observed {
        let key = record_key(rec);
        if consumed.contains(&key) {
            continue;
        }
        let (domain, name, kind) = key;
        plan.push(DnsAction::Delete { domain, name, kind });
    }

    plan
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tuntun_core::{DnsRecord, DnsRecordContent, DnsRecordId, Fqdn, Ttl};

    use super::*;

    fn apex() -> Domain {
        Domain::new("memorici.de").unwrap()
    }

    fn spec_a(name: &str, ip: [u8; 4], ttl: u32) -> DnsRecordSpec {
        DnsRecordSpec {
            apex: apex(),
            name: DnsName::new(name).unwrap(),
            ttl: Ttl::new(ttl).unwrap(),
            content: DnsRecordContent::A {
                ip: Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            },
        }
    }

    fn observed_a(id: &str, name: &str, ip: [u8; 4], ttl: u32) -> DnsRecord {
        DnsRecord {
            id: DnsRecordId::new(id).unwrap(),
            apex: apex(),
            name: DnsName::new(name).unwrap(),
            ttl: Ttl::new(ttl).unwrap(),
            content: DnsRecordContent::A {
                ip: Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            },
        }
    }

    #[test]
    fn empty_inputs_produce_empty_plan() {
        let plan = plan_dns_reconciliation(&[], &[]);
        assert!(plan.is_empty());
    }

    #[test]
    fn missing_record_is_created() {
        let want = vec![spec_a("blog", [1, 2, 3, 4], 60)];
        let plan = plan_dns_reconciliation(&want, &[]);
        assert_eq!(plan, vec![DnsAction::Create(want[0].clone())]);
    }

    #[test]
    fn matching_record_is_noop() {
        let want = vec![spec_a("blog", [1, 2, 3, 4], 60)];
        let have = vec![observed_a("rec-1", "blog", [1, 2, 3, 4], 60)];
        let plan = plan_dns_reconciliation(&want, &have);
        assert_eq!(plan, vec![DnsAction::NoOp(want[0].clone())]);
    }

    #[test]
    fn content_mismatch_is_update() {
        let want = vec![spec_a("blog", [9, 9, 9, 9], 60)];
        let have = vec![observed_a("rec-1", "blog", [1, 2, 3, 4], 60)];
        let plan = plan_dns_reconciliation(&want, &have);
        assert_eq!(plan, vec![DnsAction::Update(want[0].clone())]);
    }

    #[test]
    fn ttl_mismatch_is_update() {
        let want = vec![spec_a("blog", [1, 2, 3, 4], 300)];
        let have = vec![observed_a("rec-1", "blog", [1, 2, 3, 4], 60)];
        let plan = plan_dns_reconciliation(&want, &have);
        assert_eq!(plan, vec![DnsAction::Update(want[0].clone())]);
    }

    #[test]
    fn unwanted_observed_record_is_deleted() {
        let want: Vec<DnsRecordSpec> = vec![];
        let have = vec![observed_a("rec-1", "stale", [1, 2, 3, 4], 60)];
        let plan = plan_dns_reconciliation(&want, &have);
        assert_eq!(
            plan,
            vec![DnsAction::Delete {
                domain: apex(),
                name: DnsName::new("stale").unwrap(),
                kind: DnsRecordKind::A,
            }]
        );
    }

    #[test]
    fn different_kinds_are_independent() {
        // Same name, different type — both are independent records.
        let want = vec![
            spec_a("api", [1, 2, 3, 4], 60),
            DnsRecordSpec {
                apex: apex(),
                name: DnsName::new("api").unwrap(),
                ttl: Ttl::new(60).unwrap(),
                content: DnsRecordContent::Cname {
                    target: Fqdn::new("edge.memorici.de").unwrap(),
                },
            },
        ];
        let have: Vec<DnsRecord> = vec![];
        let plan = plan_dns_reconciliation(&want, &have);
        assert_eq!(plan.len(), 2);
        assert!(matches!(plan[0], DnsAction::Create(_)));
        assert!(matches!(plan[1], DnsAction::Create(_)));
    }

    #[test]
    fn mixed_plan_has_create_update_noop_delete() {
        let want = vec![
            spec_a("blog", [1, 2, 3, 4], 60),     // matches obs1 -> NoOp
            spec_a("api", [9, 9, 9, 9], 60),      // mismatch ip -> Update
            spec_a("status", [5, 5, 5, 5], 60),   // not present -> Create
        ];
        let have = vec![
            observed_a("rec-blog", "blog", [1, 2, 3, 4], 60),
            observed_a("rec-api", "api", [1, 2, 3, 4], 60),
            observed_a("rec-stale", "stale", [7, 7, 7, 7], 60),
        ];
        let plan = plan_dns_reconciliation(&want, &have);

        assert!(matches!(plan[0], DnsAction::NoOp(ref s) if s.name.as_str() == "blog"));
        assert!(matches!(plan[1], DnsAction::Update(ref s) if s.name.as_str() == "api"));
        assert!(matches!(plan[2], DnsAction::Create(ref s) if s.name.as_str() == "status"));
        assert!(matches!(
            plan[3],
            DnsAction::Delete { ref name, .. } if name.as_str() == "stale"
        ));
    }
}
