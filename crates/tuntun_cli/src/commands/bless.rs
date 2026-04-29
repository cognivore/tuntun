//! `tuntun bless <user@host>` — install a per-tenant bastion key onto a
//! remote machine.
//!
//! Flow:
//!
//! 1. Generate a fresh ed25519 keypair locally (ephemeral; we don't keep
//!    a copy — the remote owns it now, the server will accept it via
//!    `bless.keys`, the laptop never needs to know it again).
//! 2. Open a one-shot tunnel session to `tuntun-server`, authenticated via
//!    the same ed25519 tunnel key the daemon uses (loaded from rageveil).
//!    Send a `BlessKey` control frame with the new public key + a
//!    `user@host` label, await the `BlessKeyAck`.
//! 3. SSH to `<user@host>` and install:
//!    - `~/.ssh/tuntun_<tenant>_ed25519` (mode 0600) — the private half.
//!    - `~/.ssh/tuntun_<tenant>_ed25519.pub` (mode 0644) — the public half.
//!    - A `Host ssh.<tenant>.<domain>` block in `~/.ssh/tuntun.config`,
//!      idempotent.
//!    - An `Include ~/.ssh/tuntun.config` line in `~/.ssh/config`,
//!      idempotent.
//!
//! Idempotency: re-running `bless` for the same `<user@host>` mints a
//! new key, ships it, and authorizes it. The old key remains in
//! `bless.keys` until you remove it via `tuntun unbless <user@host>`.
//! That's deliberate — overlapping keys during rotation should not
//! suddenly break in-flight SSH.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use tokio::io::AsyncWriteExt;

use tuntun_core::{Ed25519PublicKey, TenantId};
use tuntun_proto::{BlessKeyFrame, ControlFrame};

use crate::config::DaemonConfig;
use crate::tunnel::oneshot::OneShotSession;

pub async fn run(target: &str, config: Option<&Path>) -> Result<()> {
    let (_user, _host) = parse_target(target)?;
    let cfg = Arc::new(DaemonConfig::load(config).await?);
    let tenant = TenantId::new(cfg.default_tenant.clone())
        .map_err(|e| anyhow!("invalid default_tenant: {e}"))?;
    let domain = resolve_domain(&cfg)?;

    // 1. Mint a fresh ed25519 keypair. Lives on the stack; we ship it via
    // SCP and let the local copy drop at end of scope. The server will
    // know the public half via BlessKey; the remote will have the private.
    let bless_signing = SigningKey::generate(&mut rand::rngs::OsRng);
    let bless_pub = bless_signing.verifying_key();
    let bless_pub_wire = Ed25519PublicKey::from_bytes(bless_pub.to_bytes());
    let bless_pem = bless_signing
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow!("encode bless key as PKCS#8 PEM: {e}"))?;
    let openssh_b64 = encode_openssh_ed25519_public(&bless_pub.to_bytes());
    let label = format!("tuntun-bless-{tenant}-{target}");
    let openssh_line = format!("ssh-ed25519 {openssh_b64} {label}\n");

    // 2. One-shot tunnel session: authenticate, send BlessKey, get ack.
    let mut session = OneShotSession::open(&cfg, &tenant, "bless").await?;
    session
        .send(&ControlFrame::BlessKey(BlessKeyFrame {
            public_key: bless_pub_wire,
            label: label.clone(),
        }))
        .await?;
    match session.recv().await? {
        ControlFrame::BlessKeyAck(a) if a.ok => {}
        ControlFrame::BlessKeyAck(a) => {
            bail!("server rejected bless: {}", a.message.unwrap_or_default())
        }
        other => bail!("expected BlessKeyAck, got {other:?}"),
    }
    session.close();

    // 3. SSH to the remote and drop the files.
    install_on_remote(target, &tenant, &domain, bless_pem.as_str(), &openssh_line).await?;

    println!("blessed {target} for tenant {tenant}: ssh ssh.{tenant}.{domain}");
    Ok(())
}

fn parse_target(s: &str) -> Result<(&str, &str)> {
    let (user, host) = s
        .split_once('@')
        .ok_or_else(|| anyhow!("target must be `user@host`, got {s:?}"))?;
    if user.is_empty() || host.is_empty() {
        bail!("target must be `user@host`, got {s:?}");
    }
    Ok((user, host))
}

/// Explicit `server_domain` from cli.toml wins; otherwise best-effort
/// derive from the server_host. The latter only works when server_host
/// is a real DNS name (`edge.fere.me:7000`), not an IP.
pub(crate) fn resolve_domain(cfg: &DaemonConfig) -> Result<String> {
    if cfg.server_domain.is_empty() {
        derive_domain_from_server_host(&cfg.server_host).ok_or_else(|| {
            anyhow!(
                "no server_domain in cli.toml and can't derive from server_host {} \
                 (set `server_domain = \"<apex>\"` to fix)",
                cfg.server_host
            )
        })
    } else {
        Ok(cfg.server_domain.clone())
    }
}

/// `cfg.server_host` is `host:port` of the tunnel acceptor (e.g.
/// `edge.fere.me:7000` or just `18.171.39.154:7000`). The "domain" we
/// publish services under is whatever the server believes its `domain`
/// is — but the laptop daemon doesn't carry that today. For now we infer
/// from the server hostname when it's a real DNS name (strip the leading
/// `edge.` / `tunnel.` / etc. label), and fall back to None when it's an IP.
fn derive_domain_from_server_host(server_host: &str) -> Option<String> {
    let host = server_host.split(':').next()?;
    if host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 3 {
        Some(labels[1..].join("."))
    } else {
        Some(host.to_string())
    }
}

async fn install_on_remote(
    target: &str,
    tenant: &TenantId,
    domain: &str,
    private_pem: &str,
    public_openssh_line: &str,
) -> Result<()> {
    let key_basename = format!("tuntun_{}_ed25519", tenant.as_str());
    let host_alias = format!("ssh.{tenant}.{domain}");

    // The remote receives this bash heredoc, runs it. It writes the key
    // material with strict permissions, appends a Host block to
    // `~/.ssh/tuntun.config` if not already present, and prepends an
    // `Include ~/.ssh/tuntun.config` line to `~/.ssh/config` if missing.
    // We use `awk` checks so re-running for the same tenant is a no-op
    // on the config files (the key material is overwritten, since the
    // private key is fresh each time).
    let script = format!(
        r#"set -eu
mkdir -p ~/.ssh
chmod 700 ~/.ssh
umask 077

cat > ~/.ssh/{key_basename} <<'__TUNTUN_PRIV_EOF__'
{private_pem}__TUNTUN_PRIV_EOF__
chmod 600 ~/.ssh/{key_basename}

cat > ~/.ssh/{key_basename}.pub <<'__TUNTUN_PUB_EOF__'
{public_openssh_line}__TUNTUN_PUB_EOF__
chmod 644 ~/.ssh/{key_basename}.pub

touch ~/.ssh/tuntun.config
chmod 600 ~/.ssh/tuntun.config
if ! awk -v h='Host {host_alias}' '$0==h {{found=1}} END {{exit !found}}' ~/.ssh/tuntun.config; then
cat >> ~/.ssh/tuntun.config <<'__TUNTUN_CFG_EOF__'

Host {host_alias}
    User tuntun
    Port 2222
    IdentityFile ~/.ssh/{key_basename}
    IdentitiesOnly yes
__TUNTUN_CFG_EOF__
fi

touch ~/.ssh/config
chmod 600 ~/.ssh/config
if ! grep -qF 'Include ~/.ssh/tuntun.config' ~/.ssh/config; then
  printf 'Include ~/.ssh/tuntun.config\n%s' "$(cat ~/.ssh/config)" > ~/.ssh/config.tmp
  mv ~/.ssh/config.tmp ~/.ssh/config
  chmod 600 ~/.ssh/config
fi
echo "tuntun: blessed for {host_alias}"
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
            .context("write install script to ssh stdin")?;
    }
    let status = child.wait().await.context("wait ssh")?;
    if !status.success() {
        bail!("ssh {target} failed: exit {status}");
    }
    Ok(())
}

fn encode_openssh_ed25519_public(raw: &[u8; 32]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let alg = b"ssh-ed25519";
    let mut buf = Vec::with_capacity(4 + alg.len() + 4 + 32);
    buf.extend_from_slice(&u32::try_from(alg.len()).unwrap_or(0).to_be_bytes());
    buf.extend_from_slice(alg);
    buf.extend_from_slice(&32u32.to_be_bytes());
    buf.extend_from_slice(raw);
    STANDARD.encode(&buf)
}
