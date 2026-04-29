//! `tuntun blessings` — list the bastion keys this tenant has authorized.
//!
//! Pretty-prints whatever the server has in
//! `<state_dir>/tenants/<tenant>/bless.keys`. Each line is one key:
//! algorithm, an SHA-256 fingerprint of the wire-format public-key body
//! (matching `ssh-keygen -lf` shape), and the bless label.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use tuntun_core::TenantId;
use tuntun_proto::{BlessingEntry, ControlFrame, ListBlessingsFrame};

use crate::config::DaemonConfig;
use crate::tunnel::oneshot::OneShotSession;

pub async fn run(config: Option<&Path>) -> Result<()> {
    let cfg = Arc::new(DaemonConfig::load(config).await?);
    let tenant = TenantId::new(cfg.default_tenant.clone())
        .map_err(|e| anyhow!("invalid default_tenant: {e}"))?;

    let mut session = OneShotSession::open(&cfg, &tenant, "blessings").await?;
    session
        .send(&ControlFrame::ListBlessings(ListBlessingsFrame::default()))
        .await?;
    let entries = match session.recv().await? {
        ControlFrame::BlessingsList(l) => l.entries,
        other => bail!("expected BlessingsList, got {other:?}"),
    };
    session.close();

    if entries.is_empty() {
        println!("no blessings for tenant {tenant}");
        return Ok(());
    }

    println!("blessings for tenant {tenant} ({n}):", n = entries.len());
    for entry in &entries {
        println!(
            "  {algo:<11}  {fp}  {label}",
            algo = entry.algorithm,
            fp = fingerprint_for_display(entry),
            label = entry.label,
        );
    }
    Ok(())
}

fn fingerprint_for_display(entry: &BlessingEntry) -> String {
    // OpenSSH-style: SHA256:<base64-no-pad>(sha256(wire-bytes)).
    // We have only the body the server parsed out of the .pub file, which
    // for ssh-ed25519 is the same wire-bytes ssh-keygen hashes, so this
    // matches `ssh-keygen -lf` output for that key type. Other algorithms
    // would carry their own wire encoding here; if we ever bless non-ed25519
    // keys, we'll teach the server to ship the canonical wire bytes too.
    use base64::engine::general_purpose::STANDARD;
    let body = match STANDARD.decode(entry.public_key_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return format!("invalid-base64:{}", entry.public_key_b64),
    };
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let digest = hasher.finalize();
    format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
}
