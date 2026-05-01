//! `tuntun unbless <user@host>` — revoke a previously-blessed bastion key.
//!
//! Two halves, mirroring `bless`:
//!
//! 1. Server-side: matches by canonical label (`tuntun-bless-<tenant>-<target>`).
//!    The server walks `<state_dir>/tenants/<tenant>/bless.keys`, drops every
//!    line whose comment field matches that label, and rewrites the file
//!    atomically.
//! 2. Remote-side: SSH into `<user@host>` and remove the key files
//!    (`~/.ssh/tuntun_<tenant>_ed25519{,.pub}`) plus the matching `Host`
//!    block in `~/.ssh/tuntun.config`. If `tuntun.config` ends up with no
//!    Host blocks, it's removed too.
//!
//! Remote cleanup is best-effort: if `ssh` to the target fails (host gone,
//! key rotation, no network), we still succeed — the server-side revocation
//! is what actually disables access. We just warn so the user knows there
//! may be stale files lying around.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::AsyncWriteExt;

use tuntun_core::TenantId;
use tuntun_proto::{ControlFrame, UnblessKeyFrame};

use crate::commands::bless::resolve_domain;
use crate::config::DaemonConfig;
use crate::tunnel::oneshot::OneShotSession;

pub async fn run(target: &str, config: Option<&Path>) -> Result<()> {
    parse_target(target)?;
    let cfg = Arc::new(DaemonConfig::load(config).await?);
    let tenant = TenantId::new(cfg.default_tenant.clone())
        .map_err(|e| anyhow!("invalid default_tenant: {e}"))?;
    let domain = resolve_domain(&cfg)?;

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
        println!("no blessing matched {label:?} — nothing to remove server-side");
    } else {
        println!("unblessed {target} for tenant {tenant}: removed {removed} key(s) server-side");
    }

    // Best-effort cleanup of files left on the remote by `bless`.
    if let Err(e) = cleanup_on_remote(target, &tenant, &domain).await {
        eprintln!(
            "tuntun: warning — could not clean up files on {target}: {e:#}\n\
             the server-side revocation has succeeded; remove these by hand if you care:\n  \
             ~/.ssh/tuntun_{tenant}_ed25519\n  \
             ~/.ssh/tuntun_{tenant}_ed25519.pub\n  \
             the `Host ssh.{tenant}.{domain}` block in ~/.ssh/tuntun.config"
        );
    }

    Ok(())
}

async fn cleanup_on_remote(target: &str, tenant: &TenantId, domain: &str) -> Result<()> {
    let key_basename = format!("tuntun_{}_ed25519", tenant.as_str());
    let host_alias = format!("ssh.{tenant}.{domain}");

    // Walk `~/.ssh/tuntun.config` with awk: drop the Host block whose first
    // line is `Host <host_alias>` and continues until the next `Host ` line
    // or EOF. If the resulting file has no Host blocks left, remove it
    // entirely. We deliberately leave the `Include ~/.ssh/tuntun.config`
    // entry in `~/.ssh/config` alone — it's harmless when the file is
    // absent, and a future `bless` will recreate the file.
    let script = format!(
        r#"set -eu
rm -f ~/.ssh/{key_basename} ~/.ssh/{key_basename}.pub
if [ -f ~/.ssh/tuntun.config ]; then
  awk -v h='Host {host_alias}' '
    BEGIN {{ skip = 0 }}
    $0 == h {{ skip = 1; next }}
    skip && /^Host / {{ skip = 0 }}
    !skip {{ print }}
  ' ~/.ssh/tuntun.config > ~/.ssh/tuntun.config.tmp
  if grep -q '^Host ' ~/.ssh/tuntun.config.tmp; then
    mv ~/.ssh/tuntun.config.tmp ~/.ssh/tuntun.config
    chmod 600 ~/.ssh/tuntun.config
  else
    rm -f ~/.ssh/tuntun.config.tmp ~/.ssh/tuntun.config
  fi
fi
echo "tuntun: unblessed cleanup for {host_alias}"
"#,
    );

    let mut child = tokio::process::Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg(target)
        .arg("bash -s")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn ssh {target}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .await
            .context("write cleanup script to ssh stdin")?;
    }
    let status = child.wait().await.context("wait ssh")?;
    if !status.success() {
        bail!("ssh {target} failed: exit {status}");
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
