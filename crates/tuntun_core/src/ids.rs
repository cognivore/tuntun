//! Validated identifier types used throughout the workspace.

use crate::id::{
    validate_dns_label, validate_dns_name, validate_domain, validate_secret_key, validate_slug,
};
use crate::{define_id, define_numeric_id};

define_id!(
    /// Logical tenant the projects belong to. Lowercase alnum + hyphen, 1..=64.
    pub TenantId,
    validate = validate_slug,
);

define_id!(
    /// Per-tenant project name. Lowercase alnum + hyphen, 1..=64.
    pub ProjectId,
    validate = validate_slug,
);

define_id!(
    /// Logical service name within a project (e.g., "blog", "api").
    pub ServiceName,
    validate = validate_slug,
);

define_id!(
    /// A single DNS label — 1..=63 chars, lowercase alnum + hyphen.
    pub Subdomain,
    validate = validate_dns_label,
);

define_id!(
    /// A DNS name fragment used as the `name` of a record, relative to its
    /// apex. Permits multi-label values (e.g., `blog.sweater`) and a literal
    /// `*` as the leftmost label for wildcards (e.g., `*.sweater`).
    pub DnsName,
    validate = validate_dns_name,
);

define_id!(
    /// A fully-qualified domain name.
    pub Domain,
    validate = validate_domain,
);

define_id!(
    /// A fully-qualified hostname (e.g., "blog.memorici.de").
    pub Fqdn,
    validate = validate_domain,
);

define_id!(
    /// Identifier returned by the DNS provider for an existing record.
    /// Opaque — we never parse it, only echo it back.
    pub DnsRecordId,
);

define_id!(
    /// Opaque tunnel-client identifier issued by the server on connect.
    pub TunnelClientId,
);

define_id!(
    /// rageveil-style secret key path (e.g., "tuntun/tunnel-private-key").
    pub SecretKey,
    validate = validate_secret_key,
);

define_numeric_id!(
    /// TCP/UDP port for a service running on the laptop.
    pub LocalPort, u16, min = 1u16,
);

define_numeric_id!(
    /// TCP/UDP port allocated server-side for a tunneled project.
    pub ServicePort, u16, min = 1u16,
);

define_numeric_id!(
    /// DNS TTL in seconds. Porkbun minimum is 60, but we allow shorter values
    /// for testing where the API returns an explicit error.
    pub Ttl, u32, min = 1u32,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_id_round_trip() {
        let t = TenantId::new("memorici-de").unwrap();
        assert_eq!(t.as_str(), "memorici-de");
        assert_eq!(t.to_string(), "memorici-de");
    }

    #[test]
    fn tenant_id_rejects_uppercase() {
        assert!(TenantId::new("Memorici-De").is_err());
    }

    #[test]
    fn subdomain_rejects_too_long() {
        assert!(Subdomain::new("a".repeat(64)).is_err());
        assert!(Subdomain::new("a".repeat(63)).is_ok());
    }

    #[test]
    fn service_port_rejects_zero() {
        assert!(ServicePort::new(0).is_err());
        assert!(ServicePort::new(1).is_ok());
        assert!(ServicePort::new(u16::MAX).is_ok());
    }

    #[test]
    fn ttl_rejects_zero() {
        assert!(Ttl::new(0).is_err());
        assert!(Ttl::new(1).is_ok());
    }

    #[test]
    fn serde_round_trip() {
        let t = TenantId::new("jm").unwrap();
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"jm\"");
        let back: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn serde_rejects_invalid() {
        let bad = serde_json::from_str::<TenantId>("\"NOPE\"");
        assert!(bad.is_err());
    }
}
