//! Pure Caddyfile rendering.
//!
//! [`render_caddyfile`] takes a fully-typed [`CaddyInput`] and emits the
//! Caddyfile text the supervising binary will write to disk. No I/O is
//! performed here; this module only manipulates `String` buffers.

use std::collections::HashSet;
use std::fmt::Write as _;

use crate::error::CaddyError;
use crate::model::{AuthPolicy, CaddyInput, ServiceSite};

/// Indentation unit used throughout the Caddyfile. Keep this consistent so
/// the output is whitespace-stable across runs.
const INDENT: &str = "    ";

/// Default health check probe interval emitted alongside `health_uri`.
const HEALTH_INTERVAL: &str = "30s";

/// Render a [`CaddyInput`] into a Caddyfile string.
///
/// # Errors
///
/// Returns [`CaddyError::DuplicateFqdn`] if any two services share the same
/// FQDN.
pub fn render_caddyfile(input: &CaddyInput) -> Result<String, CaddyError> {
    validate_unique_fqdns(&input.services)?;

    let mut out = String::new();

    render_global_block(&mut out, input);
    render_login_site(&mut out, input);
    for service in &input.services {
        render_service_site(&mut out, input, service);
    }

    Ok(out)
}

fn validate_unique_fqdns(services: &[ServiceSite]) -> Result<(), CaddyError> {
    let mut seen: HashSet<&str> = HashSet::with_capacity(services.len());
    for s in services {
        let fqdn = s.fqdn.as_str();
        if !seen.insert(fqdn) {
            return Err(CaddyError::DuplicateFqdn {
                fqdn: fqdn.to_owned(),
            });
        }
    }
    Ok(())
}

fn render_global_block(out: &mut String, input: &CaddyInput) {
    let admin = &input.global.admin_listen;
    let email = &input.global.email;
    let log_path = &input.global.log_path;

    out.push_str("{\n");
    let _ = writeln!(out, "{INDENT}admin {admin}");
    let _ = writeln!(out, "{INDENT}email {email}");
    let _ = writeln!(out, "{INDENT}log {{");
    let _ = writeln!(out, "{INDENT}{INDENT}output file {log_path}");
    let _ = writeln!(out, "{INDENT}{INDENT}format json");
    let _ = writeln!(out, "{INDENT}}}");
    out.push_str("}\n");
}

fn render_login_site(out: &mut String, input: &CaddyInput) {
    let fqdn = input.login_site.fqdn.as_str();
    let upstream = &input.login_site.upstream;

    out.push('\n');
    out.push_str("# Login site (always public — tenant guests log in here).\n");
    let _ = writeln!(out, "{fqdn} {{");
    let _ = writeln!(out, "{INDENT}reverse_proxy {upstream}");
    out.push_str("}\n");
}

fn render_service_site(out: &mut String, input: &CaddyInput, service: &ServiceSite) {
    let fqdn = service.fqdn.as_str();
    let upstream_port = service.upstream_port.value();

    out.push('\n');
    match service.auth_policy {
        AuthPolicy::Tenant => {
            out.push_str("# Service site with tenant auth.\n");
        }
        AuthPolicy::Public => {
            out.push_str("# Service site, public bypass.\n");
        }
        AuthPolicy::None => {
            out.push_str("# Service site, no edge auth.\n");
        }
    }

    let _ = writeln!(out, "{fqdn} {{");

    if matches!(service.auth_policy, AuthPolicy::Tenant) {
        let auth_upstream = &input.auth_endpoint.upstream;
        let _ = writeln!(out, "{INDENT}forward_auth {auth_upstream} {{");
        let _ = writeln!(out, "{INDENT}{INDENT}uri /verify");
        let _ = writeln!(
            out,
            "{INDENT}{INDENT}copy_headers X-Tuntun-Tenant X-Tuntun-Subject"
        );
        let _ = writeln!(out, "{INDENT}}}");
    }

    match &service.health_check_path {
        Some(path) => {
            let _ = writeln!(out, "{INDENT}reverse_proxy 127.0.0.1:{upstream_port} {{");
            let _ = writeln!(out, "{INDENT}{INDENT}health_uri {path}");
            let _ = writeln!(
                out,
                "{INDENT}{INDENT}health_interval {HEALTH_INTERVAL}"
            );
            let _ = writeln!(out, "{INDENT}}}");
        }
        None => {
            let _ = writeln!(out, "{INDENT}reverse_proxy 127.0.0.1:{upstream_port}");
        }
    }

    out.push_str("}\n");
}

// ---------------------------------------------------------------------------
// `validate_with_caddy_fmt` is intentionally not implemented here. It would
// require shelling out to the `caddy` binary, which is I/O — forbidden in
// this crate. The supervising binary may run `caddy fmt` itself.
// ---------------------------------------------------------------------------
// pub fn validate_with_caddy_fmt(_caddyfile: &str) -> Result<(), CaddyError> {
//     unimplemented!("I/O — perform in tuntun_server, not in tuntun_caddy");
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuthEndpointConfig, GlobalConfig, LoginSiteConfig};
    use tuntun_core::{Fqdn, ServicePort};

    fn sample_global() -> GlobalConfig {
        GlobalConfig {
            admin_listen: "127.0.0.1:2019".into(),
            email: "ops@memorici.de".into(),
            log_path: "/var/lib/tuntun/caddy.log".into(),
        }
    }

    fn sample_auth() -> AuthEndpointConfig {
        AuthEndpointConfig {
            upstream: "127.0.0.1:7081".into(),
        }
    }

    fn sample_login() -> LoginSiteConfig {
        LoginSiteConfig {
            fqdn: Fqdn::new("auth.memorici.de").expect("valid fqdn"),
            upstream: "127.0.0.1:7090".into(),
        }
    }

    fn empty_input() -> CaddyInput {
        CaddyInput {
            global: sample_global(),
            auth_endpoint: sample_auth(),
            login_site: sample_login(),
            services: vec![],
        }
    }

    #[test]
    fn empty_input_emits_global_and_login_only() {
        let out = render_caddyfile(&empty_input()).expect("render");
        assert!(out.starts_with("{\n"));
        assert!(out.contains("admin 127.0.0.1:2019"));
        assert!(out.contains("email ops@memorici.de"));
        assert!(out.contains("output file /var/lib/tuntun/caddy.log"));
        assert!(out.contains("format json"));
        assert!(out.contains("auth.memorici.de {"));
        assert!(out.contains("reverse_proxy 127.0.0.1:7090"));
        // No service sites yet.
        assert!(!out.contains("forward_auth"));
    }

    #[test]
    fn public_service_has_no_forward_auth() {
        let mut input = empty_input();
        input.services.push(ServiceSite {
            fqdn: Fqdn::new("api.memorici.de").expect("valid fqdn"),
            upstream_port: ServicePort::new(9002).expect("valid port"),
            auth_policy: AuthPolicy::Public,
            health_check_path: None,
        });
        let out = render_caddyfile(&input).expect("render");
        assert!(out.contains("api.memorici.de {"));
        assert!(out.contains("reverse_proxy 127.0.0.1:9002"));
        assert!(!out.contains("forward_auth"));
    }

    #[test]
    fn auth_policy_none_has_no_forward_auth() {
        let mut input = empty_input();
        input.services.push(ServiceSite {
            fqdn: Fqdn::new("internal.memorici.de").expect("valid fqdn"),
            upstream_port: ServicePort::new(9003).expect("valid port"),
            auth_policy: AuthPolicy::None,
            health_check_path: None,
        });
        let out = render_caddyfile(&input).expect("render");
        assert!(!out.contains("forward_auth"));
    }

    #[test]
    fn tenant_service_has_forward_auth_with_correct_upstream() {
        let mut input = empty_input();
        input.services.push(ServiceSite {
            fqdn: Fqdn::new("blog.memorici.de").expect("valid fqdn"),
            upstream_port: ServicePort::new(9001).expect("valid port"),
            auth_policy: AuthPolicy::Tenant,
            health_check_path: None,
        });
        let out = render_caddyfile(&input).expect("render");
        assert!(out.contains("blog.memorici.de {"));
        assert!(out.contains("forward_auth 127.0.0.1:7081 {"));
        assert!(out.contains("uri /verify"));
        assert!(out.contains("copy_headers X-Tuntun-Tenant X-Tuntun-Subject"));
        assert!(out.contains("reverse_proxy 127.0.0.1:9001"));
        // forward_auth must come before reverse_proxy.
        let fa = out.find("forward_auth").expect("present");
        let rp = out.find("reverse_proxy 127.0.0.1:9001").expect("present");
        assert!(fa < rp, "forward_auth should appear before reverse_proxy");
    }

    #[test]
    fn duplicate_fqdns_rejected() {
        let mut input = empty_input();
        let fqdn = Fqdn::new("blog.memorici.de").expect("valid fqdn");
        input.services.push(ServiceSite {
            fqdn: fqdn.clone(),
            upstream_port: ServicePort::new(9001).expect("valid port"),
            auth_policy: AuthPolicy::Public,
            health_check_path: None,
        });
        input.services.push(ServiceSite {
            fqdn: fqdn.clone(),
            upstream_port: ServicePort::new(9002).expect("valid port"),
            auth_policy: AuthPolicy::Tenant,
            health_check_path: None,
        });
        let err = render_caddyfile(&input).expect_err("duplicate must fail");
        assert_eq!(
            err,
            CaddyError::DuplicateFqdn {
                fqdn: "blog.memorici.de".into(),
            }
        );
    }

    #[test]
    fn health_check_round_trip() {
        let mut input = empty_input();
        input.services.push(ServiceSite {
            fqdn: Fqdn::new("svc.memorici.de").expect("valid fqdn"),
            upstream_port: ServicePort::new(9100).expect("valid port"),
            auth_policy: AuthPolicy::Public,
            health_check_path: Some("/_health".into()),
        });
        let out = render_caddyfile(&input).expect("render");
        assert!(out.contains("reverse_proxy 127.0.0.1:9100 {"));
        assert!(out.contains("health_uri /_health"));
        assert!(out.contains("health_interval 30s"));
    }

    #[test]
    fn deterministic_across_calls() {
        let mut input = empty_input();
        input.services.push(ServiceSite {
            fqdn: Fqdn::new("blog.memorici.de").expect("valid fqdn"),
            upstream_port: ServicePort::new(9001).expect("valid port"),
            auth_policy: AuthPolicy::Tenant,
            health_check_path: None,
        });
        input.services.push(ServiceSite {
            fqdn: Fqdn::new("api.memorici.de").expect("valid fqdn"),
            upstream_port: ServicePort::new(9002).expect("valid port"),
            auth_policy: AuthPolicy::Public,
            health_check_path: Some("/healthz".into()),
        });
        let a = render_caddyfile(&input).expect("render a");
        let b = render_caddyfile(&input).expect("render b");
        assert_eq!(a, b);
    }

    #[test]
    fn snapshot_representative_input() {
        let input = CaddyInput {
            global: sample_global(),
            auth_endpoint: sample_auth(),
            login_site: sample_login(),
            services: vec![
                ServiceSite {
                    fqdn: Fqdn::new("blog.memorici.de").expect("valid fqdn"),
                    upstream_port: ServicePort::new(9001).expect("valid port"),
                    auth_policy: AuthPolicy::Tenant,
                    health_check_path: None,
                },
                ServiceSite {
                    fqdn: Fqdn::new("api.memorici.de").expect("valid fqdn"),
                    upstream_port: ServicePort::new(9002).expect("valid port"),
                    auth_policy: AuthPolicy::Public,
                    health_check_path: None,
                },
            ],
        };
        let out = render_caddyfile(&input).expect("render");
        let expected = "\
{
    admin 127.0.0.1:2019
    email ops@memorici.de
    log {
        output file /var/lib/tuntun/caddy.log
        format json
    }
}

# Login site (always public — tenant guests log in here).
auth.memorici.de {
    reverse_proxy 127.0.0.1:7090
}

# Service site with tenant auth.
blog.memorici.de {
    forward_auth 127.0.0.1:7081 {
        uri /verify
        copy_headers X-Tuntun-Tenant X-Tuntun-Subject
    }
    reverse_proxy 127.0.0.1:9001
}

# Service site, public bypass.
api.memorici.de {
    reverse_proxy 127.0.0.1:9002
}
";
        assert_eq!(out, expected);
    }
}
