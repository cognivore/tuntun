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
//! `bless.keys` until you explicitly remove it (a future `tuntun unbless`).
//! That's deliberate — overlapping keys during rotation should not
//! suddenly break in-flight SSH.

use std::future::poll_fn;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config as YamuxConfig, Connection as YamuxConnection, Mode};

use tuntun_auth::tunnel_auth::build_challenge_message;
use tuntun_core::{
    Ed25519PublicKey, Ed25519Signature, Fingerprint, SecretKey, SecretPort, TenantId,
    TunnelClientId,
};
use tuntun_proto::{
    encode_frame, AuthResponseFrame, BlessKeyFrame, ControlFrame, FrameBuffer, HelloFrame,
    RegisterFrame, PROTOCOL_VERSION,
};

use crate::adapters::secret::RageveilSecrets;
use crate::config::DaemonConfig;
use crate::tls::build_pinned_client_config;

const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn run(target: &str, config: Option<&Path>) -> Result<()> {
    let (_user, _host) = parse_target(target)?;
    let cfg = Arc::new(DaemonConfig::load(config).await?);
    let tenant = TenantId::new(cfg.default_tenant.clone())
        .map_err(|e| anyhow!("invalid default_tenant: {e}"))?;
    // Explicit `server_domain` from cli.toml wins; otherwise best-effort
    // derive from the server_host. The latter only works when server_host
    // is a real DNS name (`edge.fere.me:7000`), not an IP.
    let domain = if cfg.server_domain.is_empty() {
        derive_domain_from_server_host(&cfg.server_host).ok_or_else(|| {
            anyhow!(
                "no server_domain in cli.toml and can't derive from server_host {} \
                 (set `server_domain = \"<apex>\"` to fix)",
                cfg.server_host
            )
        })?
    } else {
        cfg.server_domain.clone()
    };

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
    let openssh_line =
        format!("ssh-ed25519 {openssh_b64} tuntun-bless-{tenant}-{target}\n");

    // 2. One-shot tunnel session: authenticate, send BlessKey, get ack.
    register_with_server(&cfg, &tenant, bless_pub_wire, target.to_string()).await?;

    // 3. SSH to the remote and drop the files.
    install_on_remote(target, &tenant, &domain, bless_pem.as_str(), &openssh_line).await?;

    println!(
        "blessed {target} for tenant {tenant}: ssh ssh.{tenant}.{domain}"
    );
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

/// `cfg.server_host` is `host:port` of the tunnel acceptor (e.g.
/// `edge.fere.me:7000` or just `18.171.39.154:7000`). The "domain" we
/// publish services under is whatever the server believes its `domain`
/// is — but the laptop daemon doesn't carry that today. For now we infer
/// from the server hostname when it's a real DNS name (strip the leading
/// `edge.` / `tunnel.` / etc. label), and fall back to passing the host
/// as-is when it's an IP.
fn derive_domain_from_server_host(server_host: &str) -> Option<String> {
    let host = server_host.split(':').next()?;
    if host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok() {
        // No way to derive a useful domain from an IP — caller should
        // have a `serverDomain` knob, which the home-manager module
        // already exposes via `services.tuntun-cli.bastion.serverDomain`.
        // Until that lands in `cli.toml`, hardcode `fere.me` won't do.
        // Surface the shortcoming honestly.
        return None;
    }
    // Best-effort: if the host has at least three labels, drop the first
    // (e.g. `edge.fere.me` → `fere.me`); otherwise return the whole host.
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 3 {
        Some(labels[1..].join("."))
    } else {
        Some(host.to_string())
    }
}

async fn register_with_server(
    cfg: &DaemonConfig,
    tenant: &TenantId,
    bless_pub: Ed25519PublicKey,
    label: String,
) -> Result<()> {
    // ----- Load the laptop's tunnel signing key from rageveil. -----
    let secrets = RageveilSecrets::new();
    let key_name = SecretKey::new(cfg.private_key_secret_name.clone())
        .map_err(|e| anyhow!("invalid private_key_secret_name: {e}"))?;
    let value = secrets
        .load(&key_name)
        .await
        .context("load tunnel private key from rageveil")?;
    let pem = std::str::from_utf8(value.expose_bytes()).context("private key not utf-8")?;
    let signing_key = SigningKey::from_pkcs8_pem(pem)
        .map_err(|e| anyhow!("parse tunnel private PKCS#8 PEM: {e}"))?;

    let fingerprint = Fingerprint::from_hex(&cfg.server_pubkey_fingerprint)
        .map_err(|e| anyhow!("parse server fingerprint: {e}"))?;
    let tls_config = Arc::new(build_pinned_client_config(fingerprint));
    let connector = TlsConnector::from(tls_config);

    // ----- TCP + TLS + yamux. -----
    let tcp = tokio::net::TcpStream::connect(&cfg.server_host)
        .await
        .with_context(|| format!("connect to {}", cfg.server_host))?;
    let server_name =
        ServerName::try_from("tuntun.invalid").map_err(|e| anyhow!("server name: {e}"))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| anyhow!("tls connect: {e}"))?;

    let mut yamux_conn = YamuxConnection::new(tls.compat(), YamuxConfig::default(), Mode::Client);

    // Open the control stream BEFORE moving the connection into a driver
    // task — same single-owner pattern the daemon uses. The Stream is
    // independent after it's been opened; the driver just keeps the
    // Connection's I/O loop turning so reads/writes flush.
    let control_stream = poll_fn(|cx| std::pin::Pin::new(&mut yamux_conn).poll_new_outbound(cx))
        .await
        .map_err(|e| anyhow!("yamux open control stream: {e}"))?;
    let mut control = control_stream.compat();

    let driver = tokio::spawn(async move {
        let mut conn = yamux_conn;
        loop {
            let res =
                poll_fn(|cx| std::pin::Pin::new(&mut conn).poll_next_inbound(cx)).await;
            // Bless is a one-shot client; we don't expect inbound streams
            // beyond the control stream we already opened. Drop anything
            // we get and treat any error or EOF as session end.
            let Some(Ok(stream)) = res else { break };
            drop(stream);
        }
    });

    // ----- Hello / Welcome. -----
    let client_id = TunnelClientId::new(format!("bless-{}", tenant.as_str()))
        .map_err(|e| anyhow!("derive client id: {e}"))?;
    let hello = ControlFrame::Hello(HelloFrame {
        protocol_version: PROTOCOL_VERSION,
        client_id,
        tenant: tenant.clone(),
        software_version: format!("tuntun-bless/{SOFTWARE_VERSION}"),
    });
    write_frame(&mut control, &hello).await?;
    expect_welcome(&mut control).await?;

    // ----- Auth: receive challenge, sign, send response, receive result. -----
    let challenge = match read_one_frame(&mut control).await? {
        ControlFrame::AuthChallenge(c) => c,
        other => bail!("expected AuthChallenge, got {other:?}"),
    };
    let message = build_challenge_message(&challenge.nonce, tenant);
    let sig: Signature = signing_key.sign(&message);
    let response = ControlFrame::AuthResponse(AuthResponseFrame {
        signature: Ed25519Signature(sig.to_bytes()),
        public_key: Ed25519PublicKey::from_bytes(signing_key.verifying_key().to_bytes()),
    });
    write_frame(&mut control, &response).await?;
    match read_one_frame(&mut control).await? {
        ControlFrame::AuthResult(r) => {
            if !r.ok {
                bail!("auth denied: {}", r.message.unwrap_or_default());
            }
        }
        other => bail!("expected AuthResult, got {other:?}"),
    }

    // ----- Empty Register so the server's protocol expectation is satisfied
    // (it requires Register after auth). We register zero services. -----
    let register = ControlFrame::Register(RegisterFrame { projects: vec![] });
    write_frame(&mut control, &register).await?;
    match read_one_frame(&mut control).await? {
        ControlFrame::Registered(_) => {}
        other => bail!("expected Registered, got {other:?}"),
    }

    // ----- BlessKey + ack. -----
    let bless = ControlFrame::BlessKey(BlessKeyFrame {
        public_key: bless_pub,
        label,
    });
    write_frame(&mut control, &bless).await?;
    match read_one_frame(&mut control).await? {
        ControlFrame::BlessKeyAck(a) if a.ok => {}
        ControlFrame::BlessKeyAck(a) => {
            bail!("server rejected bless: {}", a.message.unwrap_or_default())
        }
        other => bail!("expected BlessKeyAck, got {other:?}"),
    }

    driver.abort();
    Ok(())
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

async fn write_frame<S>(s: &mut S, frame: &ControlFrame) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let bytes = encode_frame(frame).map_err(|e| anyhow!("encode frame: {e}"))?;
    s.write_all(&bytes).await.map_err(|e| anyhow!("write: {e}"))?;
    s.flush().await.map_err(|e| anyhow!("flush: {e}"))?;
    Ok(())
}

async fn read_one_frame<S>(s: &mut S) -> Result<ControlFrame>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = FrameBuffer::new();
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) => bail!("unexpected EOF on control stream"),
            Ok(n) => {
                buf.push(&chunk[..n]);
                match buf.try_pop_frame() {
                    Ok(Some(frame)) => return Ok(frame),
                    Ok(None) => continue,
                    Err(e) => bail!("frame decode: {e}"),
                }
            }
            Err(e) => bail!("read: {e}"),
        }
    }
}

async fn expect_welcome<S>(s: &mut S) -> Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    match read_one_frame(s).await? {
        ControlFrame::Welcome(w) if w.protocol_version == PROTOCOL_VERSION => Ok(()),
        ControlFrame::Welcome(w) => bail!(
            "server protocol version {} != ours {PROTOCOL_VERSION}",
            w.protocol_version
        ),
        other => bail!("expected Welcome, got {other:?}"),
    }
}
