#!/usr/bin/env rust-script
//! End-to-end smoke test against a live tuntun deployment. No editing of
//! any consumer project's `tuntun.nix` — the test reads each service's
//! declared `auth` and adapts:
//!
//! - `auth = "public"` services: GET `https://<sub>.<tenant>.<domain>/`,
//!   expect 200. Proves the full proxy/tunnel chain end-to-end without
//!   touching auth at all.
//! - `auth = "tenant"` services: log in via `auth.<tenant>.<domain>/login`
//!   using the password from rageveil at `tuntun/tenant/<id>/password`
//!   (CSRF double-submit), then GET the service URL with the session cookie
//!   and expect 200. Proves `forward_auth`, the per-tenant cookie scope,
//!   and the tunnel together.
//!
//! If the project has no `auth = "public"` service, the public path is
//! skipped — declare one if you want that surface tested. There is no
//! "publicSite" special case; `auth = "public"` IS the opt-in.
//!
//! Usage from a project that has a `tuntun.nix`:
//!
//!     rust-script -f scripts/smoke-test.rs
//!
//! IMPORTANT: re-run with `-f` after editing — without it, the cached
//! binary is executed and edits are silently ignored.
//!
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "blocking", "cookies"] }
//! serde_json = "1"
//! ```

use anyhow::{anyhow, bail, Context, Result};
use std::process::Command;
use std::time::Duration;

fn main() -> Result<()> {
    let spec = load_project_spec().context("load tuntun.nix")?;

    let domain = spec["domain"]
        .as_str()
        .ok_or_else(|| anyhow!("domain missing in tuntun.nix"))?;
    let tenant = spec["tenant"]
        .as_str()
        .ok_or_else(|| anyhow!("tenant missing in tuntun.nix"))?;
    let services = spec["services"]
        .as_object()
        .ok_or_else(|| anyhow!("services missing in tuntun.nix"))?;

    let mut failures = 0;

    // We only need the tenant password if the project declares any
    // `auth = "tenant"` services. Skip the rageveil call otherwise so a
    // public-only project doesn't require any secret material.
    let any_tenant_gated = services
        .values()
        .any(|s| s.get("auth").and_then(|v| v.as_str()).unwrap_or("tenant") == "tenant");
    let tenant_password = if any_tenant_gated {
        match rageveil_show(&format!("tuntun/tenant/{tenant}/password")) {
            Ok(p) => p,
            Err(e) => {
                // Without the password, we can only verify the auth gate
                // *redirects* — that's still a useful signal.
                println!(
                    "[WARN] no rageveil entry for tuntun/tenant/{tenant}/password ({e}); \
                     falling back to redirect-only checks"
                );
                String::new()
            }
        }
    } else {
        String::new()
    };

    let session_cookie = if tenant_password.is_empty() {
        None
    } else {
        match login(domain, tenant, &tenant_password) {
            Ok(cookie) => {
                println!("[ok ] login        -> auth.{tenant}.{domain}/login (200)");
                Some(cookie)
            }
            Err(e) => {
                println!("[FAIL] login       -> auth.{tenant}.{domain}/login ({e})");
                failures += 1;
                None
            }
        }
    };

    let auth_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    for (name, svc) in services {
        let sub = svc["subdomain"]
            .as_str()
            .ok_or_else(|| anyhow!("service {name}: subdomain missing"))?;
        let auth = svc.get("auth").and_then(|v| v.as_str()).unwrap_or("tenant");
        let url = format!("https://{sub}.{tenant}.{domain}/");

        let mut req = auth_client.get(&url);
        if auth == "tenant" {
            if let Some(c) = &session_cookie {
                req = req.header("Cookie", c);
            }
        }

        match req.send() {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let acceptable = match (auth, session_cookie.is_some()) {
                    // Authed tenant request → expect 200.
                    ("tenant", true) => status == 200,
                    // No password available → expect a 303 to /login.
                    ("tenant", false) => status == 303,
                    // Public service → expect 200.
                    ("public", _) => status == 200,
                    _ => false,
                };
                if acceptable {
                    println!("[ok ] {name:>10} -> {url} ({status}, auth={auth})");
                } else {
                    println!(
                        "[FAIL] {name:>10} -> {url} ({status}, auth={auth}, authed={})",
                        session_cookie.is_some()
                    );
                    failures += 1;
                }
            }
            Err(e) => {
                println!("[ERR ] {name:>10} -> {url} ({e})");
                failures += 1;
            }
        }
    }

    if failures > 0 {
        eprintln!("\n{failures} smoke-test failure(s)");
        std::process::exit(1);
    }
    println!("\nall checks green");
    Ok(())
}

fn load_project_spec() -> Result<serde_json::Value> {
    // Where to source `tuntun.lib` from. In order of preference:
    //   1. $TUNTUN_FLAKE — explicit override (path or flake ref).
    //   2. `.` if the current dir is itself the tuntun checkout
    //      (i.e. has a flake.nix that exposes `lib.mkProject`).
    //   3. `../.` — the historical default, where the smoke test is run
    //      from a downstream project whose parent is the tuntun checkout.
    let flake_ref = std::env::var("TUNTUN_FLAKE").ok().unwrap_or_else(|| {
        if std::path::Path::new("./flake.nix").exists()
            && std::path::Path::new("./crates/tuntun_core").exists()
        {
            "./.".to_string()
        } else {
            "../.".to_string()
        }
    });
    let expr = format!(
        "builtins.toJSON ((import ./tuntun.nix) {{ tuntun = (builtins.getFlake (toString {flake_ref})).lib; }})"
    );
    let out = Command::new("nix")
        .args(["eval", "--raw", "--impure", "--expr", &expr])
        .output()
        .context("nix eval")?;
    if !out.status.success() {
        bail!(
            "nix eval failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    serde_json::from_slice(&out.stdout).context("parse tuntun.nix output as JSON")
}

fn rageveil_show(key: &str) -> Result<String> {
    let out = Command::new("rageveil")
        .args(["show", key])
        .output()
        .context("rageveil show")?;
    if !out.status.success() {
        bail!(
            "rageveil show {key} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// POST `auth.<tenant>.<domain>/login` with the CSRF token from the GET
/// form. Return the `Cookie` header value to send on subsequent requests.
fn login(domain: &str, tenant: &str, password: &str) -> Result<String> {
    let login_url = format!("https://auth.{tenant}.{domain}/login");
    // Manual cookie handling because we need to inspect Set-Cookie pairs and
    // pass the same cookie back on the POST + downstream GETs. reqwest's
    // cookie store would also work but this is easier to read.
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let get_resp = client.get(&login_url).send().context("GET /login")?;
    if !get_resp.status().is_success() {
        bail!("GET /login: status {}", get_resp.status());
    }
    let csrf_cookie = extract_set_cookie(&get_resp, "tuntun_csrf")
        .ok_or_else(|| anyhow!("GET /login: no tuntun_csrf Set-Cookie"))?;
    let body = get_resp.text().context("read /login body")?;
    let csrf_token = extract_form_value(&body, "_csrf")
        .ok_or_else(|| anyhow!("GET /login: no _csrf form field"))?;

    // POST credentials. The server's POST /login validates the double-submit
    // (cookie value == form value), the password, and issues a Set-Cookie
    // for `tuntun_session` plus a 303 to `?redirect=`.
    let post_resp = client
        .post(&login_url)
        .header(
            "Cookie",
            format!("tuntun_csrf={}", csrf_cookie),
        )
        .form(&[
            ("password", password),
            ("_csrf", csrf_token.as_str()),
            ("redirect", "/"),
        ])
        .send()
        .context("POST /login")?;

    let status = post_resp.status().as_u16();
    if status != 303 {
        bail!("POST /login: expected 303, got {status}");
    }
    let session = extract_set_cookie(&post_resp, "tuntun_session")
        .ok_or_else(|| anyhow!("POST /login: no tuntun_session Set-Cookie"))?;

    Ok(format!("tuntun_session={}", session))
}

fn extract_set_cookie(resp: &reqwest::blocking::Response, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    for header in resp.headers().get_all("set-cookie") {
        let s = header.to_str().ok()?;
        if let Some(rest) = s.strip_prefix(&prefix) {
            return Some(rest.split(';').next()?.to_string());
        }
    }
    None
}

fn extract_form_value(body: &str, name: &str) -> Option<String> {
    // <input ... name="<name>" value="<value>"> — order can be either way.
    let needle_a = format!(r#"name="{name}""#);
    let pos = body.find(&needle_a)?;
    let line_end = body[pos..]
        .find('>')
        .map(|i| pos + i)
        .unwrap_or(body.len());
    let line = &body[pos..line_end];
    let value_pos = line.find(r#"value=""#)?;
    let after = &line[value_pos + r#"value=""#.len()..];
    let close = after.find('"')?;
    Some(after[..close].to_string())
}
