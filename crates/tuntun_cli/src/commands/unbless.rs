//! `tuntun unbless <user@host>` — revoke a previously-blessed bastion key.
//!
//! Matches by canonical label (`tuntun-bless-<tenant>-<target>`). The
//! server walks `<state_dir>/tenants/<tenant>/bless.keys`, drops every
//! line whose comment field matches that label, and rewrites the file
//! atomically. The remote machine still has its private key file on
//! disk; that's harmless once the server no longer accepts it.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};

use tuntun_core::TenantId;
use tuntun_proto::{ControlFrame, UnblessKeyFrame};

use crate::config::DaemonConfig;
use crate::tunnel::oneshot::OneShotSession;

pub async fn run(target: &str, config: Option<&Path>) -> Result<()> {
    parse_target(target)?;
    let cfg = Arc::new(DaemonConfig::load(config).await?);
    let tenant = TenantId::new(cfg.default_tenant.clone())
        .map_err(|e| anyhow!("invalid default_tenant: {e}"))?;

    let label = format!("tuntun-bless-{tenant}-{target}");

    let mut session = OneShotSession::open(&cfg, &tenant, "unbless").await?;
    session
        .send(&ControlFrame::UnblessKey(UnblessKeyFrame {
            label: label.clone(),
        }))
        .await?;
    let removed = match session.recv().await? {
        ControlFrame::UnblessKeyAck(a) if a.ok => a.removed,
        ControlFrame::UnblessKeyAck(a) => {
            bail!("server rejected unbless: {}", a.message.unwrap_or_default())
        }
        other => bail!("expected UnblessKeyAck, got {other:?}"),
    };
    session.close();

    if removed == 0 {
        println!("no blessing matched {label:?} — nothing to remove");
    } else {
        println!("unblessed {target} for tenant {tenant}: removed {removed} key(s)");
    }
    Ok(())
}

fn parse_target(s: &str) -> Result<()> {
    let (user, host) = s
        .split_once('@')
        .ok_or_else(|| anyhow!("target must be `user@host`, got {s:?}"))?;
    if user.is_empty() || host.is_empty() {
        bail!("target must be `user@host`, got {s:?}");
    }
    Ok(())
}
