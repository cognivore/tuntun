//! Authorize an existing device key without transferring private material.
use std::path::Path;

use anyhow::{ensure, Context, Result};
use tuntun_core::{Ed25519PublicKey, TenantId};
use tuntun_proto::{BlessKeyFrame, ControlFrame};

use crate::{config::DaemonConfig, tunnel::oneshot::OneShotSession};

#[derive(Debug, thiserror::Error)]
#[error("invalid public SSH key: {0}")]
struct PublicKeyError(ssh_key::Error);

pub async fn run(path: &Path, label: &str, config: Option<&Path>) -> Result<()> {
    ensure!(
        !label.is_empty()
            && label.len() <= 64
            && label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.@".contains(&c)),
        "label must be 1–64 letters, digits, -, _, ., or @"
    );
    let cfg = DaemonConfig::load(config).await?;
    let tenant = TenantId::new(cfg.default_tenant.clone()).context("tenant")?;
    let text = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read public key {}", path.display()))?;
    ensure!(
        text.len() <= 4096 && text.trim().lines().count() == 1,
        "expected one public SSH key"
    );
    let key = ssh_key::PublicKey::from_openssh(text.trim()).map_err(PublicKeyError)?;
    let raw = key
        .key_data()
        .ed25519()
        .context("only Ed25519 keys are supported")?
        .0;
    let label = format!("tuntun-bless-{tenant}-{label}");
    let line = format!(
        "ssh-ed25519 {} {label}\n",
        super::bless::encode_openssh_ed25519_public(&raw)
    );
    super::bless::append_local_authorized_key(&label, &line).await?;
    let mut session = OneShotSession::open(&cfg, &tenant, "authorize").await?;
    session
        .send(&ControlFrame::BlessKey(BlessKeyFrame {
            public_key: Ed25519PublicKey::from_bytes(raw),
            label,
        }))
        .await?;
    match session.recv().await? {
        ControlFrame::BlessKeyAck(ack) if ack.ok => {},
        other => anyhow::bail!("local SSH key installed, but bastion authorization failed: {other:?}; retry the same command"),
    }
    println!(
        "Authorized {} for ssh://{}@ssh.{tenant}.{} (requires the bastion SSH configuration)",
        key.fingerprint(ssh_key::HashAlg::Sha256),
        std::env::var("USER")?,
        super::bless::resolve_domain(&cfg)?
    );
    Ok(())
}
