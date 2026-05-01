//! `tuntun bless <user@host>` — install a per-tenant bastion key onto a
//! remote machine.
//!
//! Flow:
//!
//! 1. Generate a fresh ed25519 keypair locally (ephemeral; the laptop holds
//!    it just long enough to ship the private half to the remote and authorize
//!    the public half on both ends).
//! 2. Open a one-shot tunnel session to `tuntun-server`, authenticated via
//!    the same ed25519 tunnel key the daemon uses (loaded from rageveil).
//!    Send a `BlessKey` control frame with the new public key + a
//!    `user@host` label, await the `BlessKeyAck`. The server appends the
//!    public key to `bless.keys`; the bastion's `AuthorizedKeysCommand`
//!    wraps every line with a `command="tuntun-server tcp-forward …"` clause
//!    so the key can only drive the bastion byte-pipe.
//! 3. Append the public key (no forced command) to the laptop's own
//!    `~/.ssh/authorized_keys`, tagged with the bless label so `unbless` can
//!    remove it. The laptop side of the SSH session — a normal sshd login —
//!    needs an authorized key independent of the bastion; this is it.
//! 4. SSH to `<user@host>` and install:
//!    - `~/.ssh/tuntun_<tenant>_ed25519` (mode 0600) — the private half.
//!    - `~/.ssh/tuntun_<tenant>_ed25519.pub` (mode 0644) — the public half.
//!    - A `Host ssh.<tenant>.<domain>` block + a private bastion-jump alias
//!      in `~/.ssh/tuntun.config`, idempotent. The destination block uses
//!      `ProxyCommand` so the user's outer ssh negotiates SSH end-to-end with
//!      the laptop's sshd; the bastion jump is a dumb byte pipe.
//!    - An `Include ~/.ssh/tuntun.config` line in `~/.ssh/config`,
//!      idempotent.
//!
//! Idempotency: re-running `bless` for the same `<user@host>` mints a
//! new key, ships it, and authorizes it. The old key remains in
//! `bless.keys` (and in the laptop's `authorized_keys`) until you remove it
//! via `tuntun unbless <user@host>`. That's deliberate — overlapping keys
//! during rotation should not suddenly break in-flight SSH.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey, KeypairData};
use ssh_key::{LineEnding, PrivateKey};
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

    // The remote-side Host block needs to know which user on the laptop the
    // inner SSH session should log in as. We use whoever is running tuntun
    // — the same person who'll be sshing back to themselves later.
    let laptop_user = std::env::var("USER").map_err(|_| {
        anyhow!("USER env var not set; cannot determine the laptop user for the bless config")
    })?;
    if laptop_user.is_empty() {
        bail!("USER env var is empty; cannot determine the laptop user for the bless config");
    }

    // 1. Mint a fresh ed25519 keypair. Lives on the stack; we ship it via
    // SCP and let the local copy drop at end of scope. The server will
    // know the public half via BlessKey; the remote will have the private.
    let bless_signing = SigningKey::generate(&mut rand::rngs::OsRng);
    let bless_pub = bless_signing.verifying_key();
    let bless_pub_wire = Ed25519PublicKey::from_bytes(bless_pub.to_bytes());
    let label = format!("tuntun-bless-{tenant}-{target}");
    // OpenSSH cannot reliably load PKCS#8 PEM private keys for ed25519 —
    // ssh-keygen reports "invalid format" and the auth signing step fails
    // silently. Encode in OpenSSH's own format instead, which is what
    // ssh-keygen produces by default for ed25519.
    let bless_keypair = Ed25519Keypair {
        public: ssh_key::public::Ed25519PublicKey(bless_pub.to_bytes()),
        private: Ed25519PrivateKey::from_bytes(&bless_signing.to_bytes()),
    };
    let bless_private = PrivateKey::new(KeypairData::Ed25519(bless_keypair), label.clone())
        .map_err(|e| anyhow!("build OpenSSH private key: {e}"))?;
    let bless_pem = bless_private
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow!("encode bless key as OpenSSH PEM: {e}"))?;
    let openssh_b64 = encode_openssh_ed25519_public(&bless_pub.to_bytes());
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

    // 3. Authorize the same key on the laptop's local sshd. The bastion only
    // proxies bytes; the inner SSH session is terminated by the laptop's own
    // sshd, which needs to recognise the client key. Without this step,
    // `ssh ssh.<tenant>.<domain>` from the remote would proxy through the
    // bastion just to be rejected by the laptop with "Permission denied".
    append_local_authorized_key(&label, &openssh_line)
        .await
        .context("authorize bless key on laptop's sshd")?;

    // 4. SSH to the remote and drop the files.
    install_on_remote(
        target,
        &tenant,
        &domain,
        &laptop_user,
        bless_pem.as_str(),
        &openssh_line,
    )
    .await?;

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
    laptop_user: &str,
    private_pem: &str,
    public_openssh_line: &str,
) -> Result<()> {
    let key_basename = format!("tuntun_{}_ed25519", tenant.as_str());
    let host_alias = format!("ssh.{tenant}.{domain}");
    // Private alias used as a ProxyCommand stepping stone. Distinct from
    // `host_alias` so the inner ssh invocation doesn't recursively match
    // the outer `Host ssh.<tenant>.<domain>` block. Both names are covered
    // by the `*.<tenant>.<domain>` wildcard A record on Porkbun.
    let bastion_alias = format!("_tuntun_bastion_{tenant}");

    // The remote receives this bash heredoc, runs it. It writes the key
    // material with strict permissions, appends two Host blocks to
    // `~/.ssh/tuntun.config` if not already present (one for the destination
    // — used by the human as `ssh ssh.<tenant>.<domain>` — and one for the
    // bastion jump, invoked via ProxyCommand from the first), and prepends
    // an `Include ~/.ssh/tuntun.config` line to `~/.ssh/config` if missing.
    // We use `awk` checks so re-running for the same tenant is a no-op
    // on the config files (the key material is overwritten, since the
    // private key is fresh each time).
    //
    // Why ProxyCommand: the bastion sshd's `command="tuntun-server tcp-forward
    // <tenant>",no-pty,…` forced command pumps stdin/stdout to a unix socket
    // that's bridged through the tunnel into the laptop's local sshd. The
    // outer ssh client must therefore speak SSH protocol *through* that pipe
    // (so it negotiates directly with the laptop's sshd, preserving end-to-end
    // SSH crypto). Connecting to the bastion directly would make the outer
    // ssh treat the bastion as the SSH endpoint — which is exactly what fails
    // with "PTY allocation request failed on channel 0".
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
    HostName {host_alias}
    User {laptop_user}
    ProxyCommand ssh -T {bastion_alias}
    IdentityFile ~/.ssh/{key_basename}
    IdentitiesOnly yes

Host {bastion_alias}
    HostName {host_alias}
    Port 2222
    User tuntun
    IdentityFile ~/.ssh/{key_basename}
    IdentitiesOnly yes
    RequestTTY no
    ServerAliveInterval 30
    ServerAliveCountMax 3
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

/// Append the bless pubkey to the laptop's `~/.ssh/authorized_keys`, tagged
/// with the bless label so `unbless` can locate and remove it. Idempotent:
/// any existing line containing the same label is left in place.
///
/// We deliberately do not add a `command="..."` restriction here. The
/// equivalent restriction lives only at the bastion — that's its whole
/// purpose. The laptop endpoint is a normal interactive sshd login.
async fn append_local_authorized_key(label: &str, openssh_line: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME env var not set"))?;
    let ssh_dir = std::path::Path::new(&home).join(".ssh");
    tokio::fs::create_dir_all(&ssh_dir)
        .await
        .with_context(|| format!("create {}", ssh_dir.display()))?;
    // Tighten ssh dir perms if it was just created world-readable; harmless
    // if already 0700.
    let _ = tokio::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).await;

    let auth_path = ssh_dir.join("authorized_keys");
    let existing = match tokio::fs::read_to_string(&auth_path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(anyhow::Error::from(e))
                .with_context(|| format!("read {}", auth_path.display()));
        }
    };

    if existing.lines().any(|l| l.contains(label)) {
        return Ok(());
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(openssh_line);

    tokio::fs::write(&auth_path, updated.as_bytes())
        .await
        .with_context(|| format!("write {}", auth_path.display()))?;
    tokio::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o600))
        .await
        .with_context(|| format!("chmod 600 {}", auth_path.display()))?;
    Ok(())
}
