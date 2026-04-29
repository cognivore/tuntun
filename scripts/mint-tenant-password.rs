#!/usr/bin/env rust-script
//! Mint a fresh random password for a tenant, store it in rageveil at
//! `tuntun/tenant/<id>/password`, and emit the Argon2id PHC hash to stdout
//! (suitable for shipping to the server's `passwordHashFile`).
//!
//! Argon2id parameters match CLAUDE.md §5: m_cost = 19_456 KiB, t_cost = 2,
//! p_cost = 1. These match OWASP 2024 guidance and what the server's auth
//! verifier expects.
//!
//! Usage:
//!     rust-script -f scripts/mint-tenant-password.rs <tenant-id>
//!
//! IMPORTANT: After editing this script, re-run with `-f` or rust-script will
//! execute the cached binary and silently ignore your edits.
//!
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! argon2 = { version = "0.5", features = ["password-hash", "std"] }
//! base64 = "0.22"
//! rand = "0.8"
//! ```

use anyhow::{Context, Result, bail};
use argon2::{Argon2, Algorithm, Version, Params};
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use rand::RngCore;
use std::io::Write;
use std::process::{Command, Stdio};

fn main() -> Result<()> {
    let tenant = std::env::args().nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: mint-tenant-password.rs <tenant-id>"))?;

    let mut raw = [0u8; 24];
    OsRng.fill_bytes(&mut raw);
    let password: String = base64_url(&raw);

    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(19_456, 2, 1, None)
        .context("invalid argon2 params")?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?
        .to_string();

    let key = format!("tuntun/tenant/{tenant}/password");
    let mut child = Command::new("rageveil")
        .args(["insert", &key, "--batch"])
        .stdin(Stdio::piped())
        .spawn()
        .context("spawn rageveil insert")?;
    child.stdin.as_mut().expect("piped stdin").write_all(password.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        bail!("rageveil insert failed: {status}");
    }

    eprintln!("Wrote {key} (random password, base64-url, {} chars).", password.len());
    eprintln!("PHC hash follows on stdout — ship it to the server's passwordHashFile.");
    println!("{hash}");
    Ok(())
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(bytes)
}
