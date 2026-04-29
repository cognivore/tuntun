//! One-shot authenticated control session.
//!
//! `bless`, `unbless`, and `blessings` all do the same dance — TCP→TLS→yamux,
//! open a single control stream, Hello/Welcome, sign the auth challenge with
//! the laptop's tunnel key, send an empty Register so the server's protocol
//! state machine is satisfied, then exchange one or two further frames and
//! drop the connection. This module factors that prelude out so the
//! subcommands only contain their own request/response logic.
//!
//! The session runs the yamux Connection on a background driver task to keep
//! its outbound queue flushing (yamux 0.13 only flushes on poll_next_inbound).
//! `close()` aborts that driver. The control stream is owned by the session
//! struct after `open()` returns, exposed via [`Self::send`] and [`Self::recv`].

use std::future::poll_fn;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config as YamuxConfig, Connection as YamuxConnection, Mode};

use tuntun_auth::tunnel_auth::build_challenge_message;
use tuntun_core::{
    Ed25519PublicKey, Ed25519Signature, Fingerprint, SecretKey, SecretPort, TenantId,
    TunnelClientId,
};
use tuntun_proto::{
    encode_frame, AuthResponseFrame, ControlFrame, FrameBuffer, HelloFrame, RegisterFrame,
    PROTOCOL_VERSION,
};

use crate::adapters::secret::RageveilSecrets;
use crate::config::DaemonConfig;
use crate::tls::build_pinned_client_config;

const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

type ControlStream = Compat<yamux::Stream>;

pub struct OneShotSession {
    control: ControlStream,
    /// Persistent decode buffer. The server frequently coalesces multiple
    /// frames into a single TLS write (e.g. Welcome + AuthChallenge sent
    /// back-to-back), so a single read() can return more than one frame's
    /// bytes. Keeping the buffer across recv() calls means the leftover
    /// bytes from one frame are available for the next, instead of being
    /// silently dropped — which would manifest as a hang on the next read.
    inbox: FrameBuffer,
    driver: JoinHandle<()>,
}

impl OneShotSession {
    /// Open a fresh tunnel session, run Hello/Welcome + auth + empty Register,
    /// and return the session ready for caller-specific frames.
    ///
    /// `client_label` is mixed into the [`TunnelClientId`] so server-side
    /// logs can tell `bless`, `unbless`, etc. apart.
    pub async fn open(
        cfg: &DaemonConfig,
        tenant: &TenantId,
        client_label: &str,
    ) -> Result<Self> {
        let signing_key = load_signing_key(cfg).await?;
        let tls = connect_tls(cfg).await?;
        let mut yamux_conn =
            YamuxConnection::new(tls.compat(), YamuxConfig::default(), Mode::Client);

        let stream = poll_fn(|cx| std::pin::Pin::new(&mut yamux_conn).poll_new_outbound(cx))
            .await
            .map_err(|e| anyhow!("yamux open control stream: {e}"))?;
        let mut control = stream.compat();
        let mut inbox = FrameBuffer::new();

        let driver = tokio::spawn(async move {
            let mut conn = yamux_conn;
            loop {
                let res =
                    poll_fn(|cx| std::pin::Pin::new(&mut conn).poll_next_inbound(cx)).await;
                let Some(Ok(stream)) = res else { break };
                drop(stream);
            }
        });

        // Hello / Welcome.
        let client_id = TunnelClientId::new(format!("{client_label}-{}", tenant.as_str()))
            .map_err(|e| anyhow!("derive client id: {e}"))?;
        let hello = ControlFrame::Hello(HelloFrame {
            protocol_version: PROTOCOL_VERSION,
            client_id,
            tenant: tenant.clone(),
            software_version: format!("tuntun-{client_label}/{SOFTWARE_VERSION}"),
        });
        write_frame(&mut control, &hello).await?;
        match read_one_frame(&mut control, &mut inbox).await? {
            ControlFrame::Welcome(w) if w.protocol_version == PROTOCOL_VERSION => {}
            ControlFrame::Welcome(w) => bail!(
                "server protocol version {} != ours {PROTOCOL_VERSION}",
                w.protocol_version
            ),
            other => bail!("expected Welcome, got {other:?}"),
        }

        // Auth: receive challenge, sign, send response, receive result.
        let challenge = match read_one_frame(&mut control, &mut inbox).await? {
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
        match read_one_frame(&mut control, &mut inbox).await? {
            ControlFrame::AuthResult(r) => {
                if !r.ok {
                    bail!("auth denied: {}", r.message.unwrap_or_default());
                }
            }
            other => bail!("expected AuthResult, got {other:?}"),
        }

        // Empty Register so the server's protocol state machine advances.
        let register = ControlFrame::Register(RegisterFrame { projects: vec![] });
        write_frame(&mut control, &register).await?;
        match read_one_frame(&mut control, &mut inbox).await? {
            ControlFrame::Registered(_) => {}
            other => bail!("expected Registered, got {other:?}"),
        }

        Ok(Self {
            control,
            inbox,
            driver,
        })
    }

    pub async fn send(&mut self, frame: &ControlFrame) -> Result<()> {
        write_frame(&mut self.control, frame).await
    }

    pub async fn recv(&mut self) -> Result<ControlFrame> {
        read_one_frame(&mut self.control, &mut self.inbox).await
    }

    pub fn close(self) {
        self.driver.abort();
    }
}

async fn load_signing_key(cfg: &DaemonConfig) -> Result<SigningKey> {
    let secrets = RageveilSecrets::new();
    let key_name = SecretKey::new(cfg.private_key_secret_name.clone())
        .map_err(|e| anyhow!("invalid private_key_secret_name: {e}"))?;
    let value = secrets
        .load(&key_name)
        .await
        .context("load tunnel private key from rageveil")?;
    let pem = std::str::from_utf8(value.expose_bytes()).context("private key not utf-8")?;
    SigningKey::from_pkcs8_pem(pem).map_err(|e| anyhow!("parse tunnel private PKCS#8 PEM: {e}"))
}

async fn connect_tls(cfg: &DaemonConfig) -> Result<TlsStream<tokio::net::TcpStream>> {
    let fingerprint = Fingerprint::from_hex(&cfg.server_pubkey_fingerprint)
        .map_err(|e| anyhow!("parse server fingerprint: {e}"))?;
    let tls_config = Arc::new(build_pinned_client_config(fingerprint));
    let connector = TlsConnector::from(tls_config);

    let tcp = tokio::net::TcpStream::connect(&cfg.server_host)
        .await
        .with_context(|| format!("connect to {}", cfg.server_host))?;
    let server_name =
        ServerName::try_from("tuntun.invalid").map_err(|e| anyhow!("server name: {e}"))?;
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| anyhow!("tls connect: {e}"))
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

async fn read_one_frame<S>(s: &mut S, inbox: &mut FrameBuffer) -> Result<ControlFrame>
where
    S: tokio::io::AsyncRead + Unpin,
{
    // First check if a complete frame is already buffered from a previous
    // read that pulled in more than one frame's worth of bytes.
    match inbox.try_pop_frame() {
        Ok(Some(frame)) => return Ok(frame),
        Ok(None) => {}
        Err(e) => bail!("frame decode: {e}"),
    }
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) => bail!("unexpected EOF on control stream"),
            Ok(n) => {
                inbox.push(&chunk[..n]);
                match inbox.try_pop_frame() {
                    Ok(Some(frame)) => return Ok(frame),
                    Ok(None) => continue,
                    Err(e) => bail!("frame decode: {e}"),
                }
            }
            Err(e) => bail!("read: {e}"),
        }
    }
}
