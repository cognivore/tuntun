//! Input model for the Caddyfile renderer.
//!
//! The renderer accepts a single [`CaddyInput`] value and emits a complete
//! Caddyfile string. All shapes here are plain data — no I/O, no traits.

use serde::{Deserialize, Serialize};
use tuntun_core::{Fqdn, ServicePort};

/// Top-level renderer input. One of these produces exactly one Caddyfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaddyInput {
    /// Global block: admin endpoint, ACME email, log destination.
    pub global: GlobalConfig,
    /// Forward-auth endpoint that gates tenant-protected services.
    pub auth_endpoint: AuthEndpointConfig,
    /// The login site (e.g. `auth.memorici.de`) that hosts the login flow.
    pub login_site: LoginSiteConfig,
    /// Per-service sites. Order is preserved verbatim in the output.
    pub services: Vec<ServiceSite>,
}

/// Global block configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// `admin` directive listen address, e.g. `127.0.0.1:2019`.
    pub admin_listen: String,
    /// ACME registration email.
    pub email: String,
    /// Path Caddy should write its JSON access log to.
    pub log_path: String,
}

/// `tuntun_server`'s forward-auth verification endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthEndpointConfig {
    /// Upstream `host:port` Caddy contacts for `forward_auth`. The renderer
    /// also appends the `/verify` URI for tenant-gated sites.
    pub upstream: String,
}

/// Login site published at a tenant's login FQDN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginSiteConfig {
    /// Public FQDN, e.g. `auth.memorici.de`.
    pub fqdn: Fqdn,
    /// Upstream `host:port` for `tuntun_server`'s login HTTP endpoint.
    pub upstream: String,
}

/// One published service site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSite {
    /// Public FQDN, e.g. `blog.memorici.de`.
    pub fqdn: Fqdn,
    /// Loopback port the local tunnel listener exposes the service on.
    pub upstream_port: ServicePort,
    /// How (or whether) Caddy should gate access at the edge.
    pub auth_policy: AuthPolicy,
    /// Optional health-check path. When set, the rendered `reverse_proxy`
    /// block contains `health_uri <path>` and a default
    /// `health_interval 30s`.
    pub health_check_path: Option<String>,
}

/// Edge auth policy for a published service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthPolicy {
    /// Tenant-protected: emit `forward_auth` before `reverse_proxy`.
    Tenant,
    /// Public: no edge auth (e.g., a public API).
    Public,
    /// No edge auth (e.g., a service authenticated entirely upstream).
    /// Currently emits the same Caddy directives as [`AuthPolicy::Public`];
    /// the variants differ in higher layers.
    None,
}
