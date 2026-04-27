//! Typed schema for a `tuntun.nix` project configuration.
//!
//! These types deserialize directly from the JSON that
//! `nix eval --json -f tuntun.nix` produces. They use validated
//! identifier newtypes from [`tuntun_core`] so that out-of-shape
//! values are rejected at deserialization time.
//!
//! Validation that cannot be expressed at the type level
//! (uniqueness, cross-field constraints) lives in
//! [`ProjectSpec::validate`].

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tuntun_core::{Domain, LocalPort, ProjectId, ServiceName, Subdomain, TenantId};

use crate::error::ConfigError;

/// Top-level schema of `tuntun.nix`.
///
/// ```ignore
/// {
///   "tenant": "memorici-de",
///   "domain": "memorici.de",
///   "services": {
///     "blog": { "subdomain": "blog", "localPort": 4000, ... }
///   }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectSpec {
    /// Logical tenant the project belongs to (e.g., `memorici-de`).
    pub tenant: TenantId,

    /// Apex domain under which the services' subdomains live
    /// (e.g., `memorici.de`).
    pub domain: Domain,

    /// Optional explicit project name. When absent, the CLI defaults to the
    /// current working directory's name.
    #[serde(default)]
    pub project: Option<ProjectId>,

    /// Map of service-local-name → [`ServiceSpec`]. Must be non-empty.
    pub services: BTreeMap<ServiceName, ServiceSpec>,
}

/// Per-service configuration.
///
/// JSON field names use camelCase (`localPort`, `healthCheck`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    /// DNS label this service is exposed under, joined to the project's
    /// [`ProjectSpec::domain`] to form the public FQDN.
    pub subdomain: Subdomain,

    /// TCP port on the laptop that the local service listens on. The tunnel
    /// client forwards traffic to this port.
    pub local_port: LocalPort,

    /// Authentication policy for inbound requests; defaults to
    /// [`AuthPolicy::Tenant`] when omitted.
    #[serde(default = "AuthPolicy::default")]
    pub auth: AuthPolicy,

    /// Optional health-check probe configuration.
    #[serde(default)]
    pub health_check: Option<HealthCheckSpec>,
}

/// Authentication policy for a tunneled service.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthPolicy {
    /// Only authenticated tenant members may reach the service.
    #[default]
    Tenant,
    /// Anyone on the public internet may reach the service.
    Public,
    /// No auth gate; reserved for explicit opt-out (treated like
    /// [`AuthPolicy::Public`] but distinguishable in policy decisions).
    None,
}

/// Health-check probe configuration for a service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckSpec {
    /// Path component of the URL to probe (must start with `/`).
    pub path: String,

    /// Optional expected HTTP status (any value in `100..600`). When
    /// absent, the probe accepts any 2xx response.
    #[serde(default)]
    pub expected_status: Option<u16>,

    /// Probe timeout, in seconds. Defaults to 5.
    #[serde(default = "default_health_timeout")]
    pub timeout_seconds: u32,
}

/// Default health-check timeout in seconds.
fn default_health_timeout() -> u32 {
    5
}

impl ProjectSpec {
    /// Verify cross-field invariants that cannot be expressed at the type
    /// level:
    ///
    /// - At least one service is configured.
    /// - Subdomains are unique across services.
    /// - Local ports are unique across services.
    /// - Each health-check `path` begins with `/`.
    /// - Each health-check `expected_status`, if set, lies in `100..600`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.services.is_empty() {
            return Err(ConfigError::EmptyServices);
        }

        let mut seen_subdomains: BTreeSet<&str> = BTreeSet::new();
        let mut seen_ports: BTreeSet<u16> = BTreeSet::new();

        for (name, svc) in &self.services {
            let sub = svc.subdomain.as_str();
            if !seen_subdomains.insert(sub) {
                return Err(ConfigError::Validation(format!(
                    "duplicate subdomain {sub:?} (service {name})"
                )));
            }

            let port = svc.local_port.value();
            if !seen_ports.insert(port) {
                return Err(ConfigError::Validation(format!(
                    "duplicate local port {port} (service {name})"
                )));
            }

            if let Some(hc) = &svc.health_check {
                if !hc.path.starts_with('/') {
                    return Err(ConfigError::Validation(format!(
                        "health-check path {path:?} for service {name} must start with '/'",
                        path = hc.path,
                    )));
                }
                if let Some(status) = hc.expected_status {
                    if !(100..600).contains(&status) {
                        return Err(ConfigError::Validation(format!(
                            "health-check expectedStatus {status} for service {name} \
                             must be in 100..600"
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_policy_default_is_tenant() {
        assert_eq!(AuthPolicy::default(), AuthPolicy::Tenant);
    }

    #[test]
    fn default_health_timeout_is_five_seconds() {
        assert_eq!(default_health_timeout(), 5);
    }
}
