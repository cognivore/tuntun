//! DNS record value types exchanged at the `DnsPort` boundary.
//!
//! Record content is strongly typed by record kind (A → IPv4 address,
//! CNAME → FQDN, TXT → free-form). Untyped strings are not accepted across
//! the port — the `DnsPort` adapter converts to/from provider-specific wire
//! formats internally.

use std::fmt;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::ids::{DnsName, DnsRecordId, Domain, Fqdn, Ttl};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordKind {
    A,
    Cname,
    Txt,
}

impl fmt::Display for DnsRecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DnsRecordKind::A => "A",
            DnsRecordKind::Cname => "CNAME",
            DnsRecordKind::Txt => "TXT",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "UPPERCASE")]
pub enum DnsRecordContent {
    A { ip: Ipv4Addr },
    Cname { target: Fqdn },
    Txt { value: String },
}

impl DnsRecordContent {
    pub fn kind(&self) -> DnsRecordKind {
        match self {
            DnsRecordContent::A { .. } => DnsRecordKind::A,
            DnsRecordContent::Cname { .. } => DnsRecordKind::Cname,
            DnsRecordContent::Txt { .. } => DnsRecordKind::Txt,
        }
    }

    /// Wire string used by most DNS APIs (the `content` field on Porkbun's API).
    #[must_use]
    pub fn wire_value(&self) -> String {
        match self {
            DnsRecordContent::A { ip } => ip.to_string(),
            DnsRecordContent::Cname { target } => target.to_string(),
            DnsRecordContent::Txt { value } => value.clone(),
        }
    }
}

/// A desired DNS record (no provider id yet — used as input for upsert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecordSpec {
    pub apex: Domain,
    pub name: DnsName,
    pub ttl: Ttl,
    pub content: DnsRecordContent,
}

/// An observed DNS record returned by the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: DnsRecordId,
    pub apex: Domain,
    pub name: DnsName,
    pub ttl: Ttl,
    pub content: DnsRecordContent,
}

impl DnsRecord {
    /// Does this observed record already match the desired spec?
    pub fn matches(&self, spec: &DnsRecordSpec) -> bool {
        self.apex == spec.apex
            && self.name == spec.name
            && self.ttl == spec.ttl
            && self.content == spec.content
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_kinds() {
        let a = DnsRecordContent::A {
            ip: Ipv4Addr::new(203, 0, 113, 1),
        };
        assert_eq!(a.kind(), DnsRecordKind::A);
        assert_eq!(a.wire_value(), "203.0.113.1");

        let c = DnsRecordContent::Cname {
            target: Fqdn::new("edge.example.com").unwrap(),
        };
        assert_eq!(c.kind(), DnsRecordKind::Cname);
        assert_eq!(c.wire_value(), "edge.example.com");
    }

    #[test]
    fn record_match() {
        let spec = DnsRecordSpec {
            apex: Domain::new("example.com").unwrap(),
            name: DnsName::new("blog").unwrap(),
            ttl: Ttl::new(60).unwrap(),
            content: DnsRecordContent::A {
                ip: Ipv4Addr::new(1, 2, 3, 4),
            },
        };
        let observed = DnsRecord {
            id: DnsRecordId::new("rec-1").unwrap(),
            apex: spec.apex.clone(),
            name: spec.name.clone(),
            ttl: spec.ttl,
            content: spec.content.clone(),
        };
        assert!(observed.matches(&spec));
    }
}
