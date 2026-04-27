#!/usr/bin/env rust-script
//! End-to-end smoke test against a live tuntun deployment.
//!
//! Reads the local `tuntun.nix`, asks the CLI to register, then issues an
//! HTTP request against each declared `https://<subdomain>.<domain>/`.
//! Prints a green tick or a red cross per service; exits non-zero on the
//! first failure.
//!
//! IMPORTANT: re-run with `rust-script -f scripts/smoke-test.rs` after
//! editing — without `-f`, the cached binary executes and your edits are
//! silently ignored.
//!
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "blocking"] }
//! serde_json = "1"
//! ```

use anyhow::{anyhow, Context, Result};
use std::process::Command;
use std::time::Duration;

fn main() -> Result<()> {
    let spec_json = Command::new("nix")
        .args([
            "eval", "--raw", "--impure",
            "--expr",
            "builtins.toJSON ((import ./tuntun.nix) { tuntun = (builtins.getFlake (toString ../.)).lib; })",
        ])
        .output()
        .context("nix eval")?;
    if !spec_json.status.success() {
        return Err(anyhow!(
            "nix eval failed: {}",
            String::from_utf8_lossy(&spec_json.stderr)
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&spec_json.stdout)
        .context("parse tuntun.nix output as JSON")?;

    let domain = v["domain"]
        .as_str()
        .ok_or_else(|| anyhow!("domain missing"))?;
    let services = v["services"]
        .as_object()
        .ok_or_else(|| anyhow!("services missing"))?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let mut failures = 0;
    for (name, svc) in services {
        let sub = svc["subdomain"]
            .as_str()
            .ok_or_else(|| anyhow!("service {name}: subdomain missing"))?;
        let url = format!("https://{sub}.{domain}/");
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 401 => {
                // 401 is expected for tenant-protected sites without a session
                println!("[ok ] {name:>10} -> {url} ({})", resp.status());
            }
            Ok(resp) => {
                println!("[FAIL] {name:>10} -> {url} ({})", resp.status());
                failures += 1;
            }
            Err(e) => {
                println!("[ERR ] {name:>10} -> {url} ({e})");
                failures += 1;
            }
        }
    }

    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}
