//! TLS + yamux tunnel client.
//!
//! Connects to the configured server, completes ed25519 challenge-response
//! authentication, and multiplexes per-service streams over yamux.

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tuntun_config::ProjectSpec;
use yamux::{Config as YamuxConfig, Connection as YamuxConnection, Mode};

use tuntun_auth::tunnel_auth::build_challenge_message;
use tuntun_core::{
    Ed25519PublicKey, Ed25519Signature, Fingerprint, LocalPort, ProjectId, SecretKey, SecretPort,
    ServiceName, TenantId, TunnelClientId,
};
use tuntun_proto::{
    encode_frame, AuthResponseFrame, BuiltinService, ControlFrame, FrameBuffer, HelloFrame,
    ProjectRegistration, RegisterFrame, ServiceRegistration, PROTOCOL_VERSION,
};

use crate::adapters::secret::RageveilSecrets;
use crate::config::DaemonConfig;
use crate::tls::build_pinned_client_config;
use crate::tunnel::reconnect::BackoffState;

const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Map a yamux stream id to the local port it should be forwarded to.
type StreamRouting = BTreeMap<u32, LocalPort>;

/// Snapshot of the projects the daemon should advertise to the server.
#[derive(Debug, Clone, Default)]
pub struct ProjectsSnapshot {
    pub projects: Vec<ProjectSpec>,
}

#[derive(Debug)]
pub struct TunnelClient {
    config: Arc<DaemonConfig>,
    state_dir: PathBuf,
    projects: Arc<tokio::sync::RwLock<ProjectsSnapshot>>,
}

impl TunnelClient {
    pub fn new(config: Arc<DaemonConfig>) -> Self {
        let state_dir = config.state_dir.clone();
        Self {
            config,
            state_dir,
            projects: Arc::new(tokio::sync::RwLock::new(ProjectsSnapshot::default())),
        }
    }

    pub fn projects_handle(&self) -> Arc<tokio::sync::RwLock<ProjectsSnapshot>> {
        self.projects.clone()
    }

    /// Replace the daemon's project list. Currently invoked only at startup;
    /// future Unix-socket IPC will call this on each `tuntun register`.
    pub async fn update_projects(&self, snapshot: ProjectsSnapshot) {
        let mut guard = self.projects.write().await;
        *guard = snapshot;
    }

    /// Run the long-lived client loop. Returns only on fatal error
    /// (configuration parse failure, signing-key load failure).
    pub async fn run_forever(self: Arc<Self>) -> Result<()> {
        ensure_state_dir(&self.state_dir).await?;

        let signing_key = self.load_signing_key().await?;
        let fingerprint = Fingerprint::from_hex(&self.config.server_pubkey_fingerprint)
            .map_err(|e| anyhow!("parse server fingerprint: {e}"))?;
        let tls_config = Arc::new(build_pinned_client_config(fingerprint));
        let connector = TlsConnector::from(tls_config);

        let tenant = TenantId::new(self.config.default_tenant.clone())
            .map_err(|e| anyhow!("invalid default_tenant: {e}"))?;

        let mut backoff = BackoffState::new();
        loop {
            match self
                .run_session(&signing_key, &connector, &tenant)
                .await
            {
                Ok(()) => {
                    tracing::info!("session ended cleanly; reconnecting");
                    backoff.reset();
                }
                Err(e) => {
                    let delay = backoff.next_delay(rand::random::<f64>);
                    tracing::warn!(
                        "session error: {e:#}; reconnecting in {}ms",
                        delay.as_millis()
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    async fn load_signing_key(&self) -> Result<SigningKey> {
        let secrets = RageveilSecrets::new();
        let key_name = SecretKey::new(self.config.private_key_secret_name.clone())
            .map_err(|e| anyhow!("invalid private_key_secret_name: {e}"))?;
        let value = secrets
            .load(&key_name)
            .await
            .context("load tunnel private key from rageveil")?;
        let pem = std::str::from_utf8(value.expose_bytes())
            .context("private key is not utf-8")?;
        SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| anyhow!("parse PEM (regenerate with scripts/regen-client-keys.rs?): {e}"))
    }

    async fn run_session(
        &self,
        signing_key: &SigningKey,
        connector: &TlsConnector,
        tenant: &TenantId,
    ) -> Result<()> {
        // 1. TCP connect.
        let tcp = tokio::net::TcpStream::connect(&self.config.server_host)
            .await
            .with_context(|| format!("connect to {}", self.config.server_host))?;

        // 2. TLS handshake. Server name doesn't matter for our pinned
        // verifier; pass a placeholder so rustls is happy.
        let server_name = ServerName::try_from("tuntun.invalid")
            .map_err(|e| anyhow!("server name: {e}"))?;
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| anyhow!("tls connect: {e}"))?;

        // 3. Yamux client. We open the single outbound (control) stream
        // *before* moving the Connection into the driver task, so the driver
        // can own it exclusively and `poll_next_inbound` it forever. The
        // resulting Stream has its own buffer and does not require the
        // Connection to read/write — but the Connection must keep being
        // polled, otherwise nothing flows.
        let mut yamux_conn =
            YamuxConnection::new(tls_stream.compat(), YamuxConfig::default(), Mode::Client);

        // 4. Open the control stream (first outbound stream).
        let control_stream =
            poll_fn(|cx| std::pin::Pin::new(&mut yamux_conn).poll_new_outbound(cx))
                .await
                .map_err(|e| anyhow!("yamux open control stream: {e}"))?;
        let mut control = control_stream.compat();

        // Spawn the driver — it owns yamux_conn outright and pumps inbound
        // streams. From here on the handshake task uses only `control`,
        // which is independent of `yamux_conn`'s ownership.
        let routing: Arc<Mutex<StreamRouting>> = Arc::new(Mutex::new(StreamRouting::new()));
        let ssh_local_port = LocalPort::new(self.config.ssh_local_port)
            .map_err(|e| anyhow!("ssh_local_port {}: {e}", self.config.ssh_local_port))?;
        let routing_for_acceptor = routing.clone();
        let acceptor = tokio::spawn(async move {
            let mut conn = yamux_conn;
            loop {
                let res = poll_fn(|cx| {
                    std::pin::Pin::new(&mut conn).poll_next_inbound(cx)
                })
                .await;
                match res {
                    None => break,
                    Some(Ok(stream)) => {
                        let id = stream.id().val();
                        let port = wait_for_routing(&routing_for_acceptor, id).await;
                        match port {
                            Some(p) => {
                                tokio::spawn(async move {
                                    if let Err(e) = pump_stream_to_local(stream, p).await {
                                        tracing::debug!("stream {id}: {e}");
                                    }
                                });
                            }
                            None => {
                                tracing::warn!(
                                    "no routing entry for inbound yamux stream id={id}"
                                );
                                drop(stream);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        tracing::debug!("yamux accept: {e}");
                        break;
                    }
                }
            }
        });

        // 5. Send Hello.
        let client_id_str =
            format!("laptop-{}", &self.config.default_tenant);
        let client_id = TunnelClientId::new(client_id_str.clone())
            .map_err(|e| anyhow!("derive client id: {e}"))?;
        let hello = ControlFrame::Hello(HelloFrame {
            protocol_version: PROTOCOL_VERSION,
            client_id: client_id.clone(),
            tenant: tenant.clone(),
            software_version: SOFTWARE_VERSION.to_string(),
        });
        write_frame(&mut control, &hello).await?;

        // 6. Receive Welcome.
        let welcome = read_one_frame(&mut control).await?;
        let ControlFrame::Welcome(welcome) = welcome else {
            return Err(anyhow!("expected Welcome, got {welcome:?}"));
        };
        if welcome.protocol_version != PROTOCOL_VERSION {
            return Err(anyhow!(
                "server protocol version {} != ours {}",
                welcome.protocol_version,
                PROTOCOL_VERSION
            ));
        }

        // 7. Receive AuthChallenge. (Some server flows expect the client to
        // first send AuthRequest; we send one defensively, then read the
        // challenge — the server may also push the challenge unsolicited.)
        // For the simple flow specified in CLAUDE.md the server sends the
        // challenge directly after Welcome.
        let challenge_or_req = read_one_frame(&mut control).await?;
        let challenge = match challenge_or_req {
            ControlFrame::AuthChallenge(c) => c,
            other => return Err(anyhow!("expected AuthChallenge, got {other:?}")),
        };

        // 8. Sign and send AuthResponse.
        let message = build_challenge_message(&challenge.nonce, tenant);
        let sig: Signature = signing_key.sign(&message);
        let response = ControlFrame::AuthResponse(AuthResponseFrame {
            signature: Ed25519Signature(sig.to_bytes()),
            public_key: Ed25519PublicKey::from_bytes(signing_key.verifying_key().to_bytes()),
        });
        write_frame(&mut control, &response).await?;

        // 9. Receive AuthResult.
        let auth_result = read_one_frame(&mut control).await?;
        let ControlFrame::AuthResult(auth_result) = auth_result else {
            return Err(anyhow!("expected AuthResult, got {auth_result:?}"));
        };
        if !auth_result.ok {
            return Err(anyhow!(
                "auth denied: {}",
                auth_result.message.unwrap_or_default()
            ));
        }
        tracing::info!("tunnel authenticated as {tenant}");

        // 10. Build and send Register.
        let snapshot = self.projects.read().await.clone();
        let (register_frame, routing_seed) = build_register_frame(&snapshot)?;
        let register = ControlFrame::Register(register_frame);
        write_frame(&mut control, &register).await?;

        // 11. Receive Registered.
        let registered = read_one_frame(&mut control).await?;
        let ControlFrame::Registered(registered) = registered else {
            return Err(anyhow!("expected Registered, got {registered:?}"));
        };
        tracing::info!(
            "registered {} services with server",
            registered.allocations.len()
        );

        // 12. Run the control loop. The yamux acceptor was already spawned
        // before the handshake; once Register completes the server is free
        // to open new inbound streams and the acceptor will pick them up
        // and pair each with a routing entry.
        let control_loop_result =
            run_control_loop(&mut control, routing_seed, ssh_local_port, routing.clone()).await;

        // Make sure the acceptor doesn't hold onto yamux past disconnect.
        acceptor.abort();

        control_loop_result
    }
}

async fn ensure_state_dir(path: &std::path::Path) -> Result<()> {
    tokio::fs::create_dir_all(path)
        .await
        .with_context(|| format!("mkdir {}", path.display()))?;
    Ok(())
}

fn build_register_frame(
    snapshot: &ProjectsSnapshot,
) -> Result<(RegisterFrame, BTreeMap<(ProjectId, ServiceName), LocalPort>)> {
    let mut projects: Vec<ProjectRegistration> = Vec::new();
    let mut local_routing: BTreeMap<(ProjectId, ServiceName), LocalPort> = BTreeMap::new();

    for spec in &snapshot.projects {
        let project_id: ProjectId = match spec.project.clone() {
            Some(p) => p,
            None => ProjectId::new(spec.tenant.as_str().to_string())
                .map_err(|e| anyhow!("derive project id: {e}"))?,
        };

        let mut svcs: Vec<ServiceRegistration> = Vec::with_capacity(spec.services.len());
        for (svc_name, svc_spec) in &spec.services {
            let auth_policy = match svc_spec.auth {
                tuntun_config::AuthPolicy::Tenant => tuntun_proto::AuthPolicy::Tenant,
                tuntun_config::AuthPolicy::Public => tuntun_proto::AuthPolicy::Public,
            };
            let health = svc_spec.health_check.as_ref().map(|h| {
                tuntun_proto::HealthCheckSpec {
                    path: h.path.clone(),
                    expected_status: h.expected_status,
                    timeout_seconds: h.timeout_seconds,
                }
            });
            svcs.push(ServiceRegistration {
                service: svc_name.clone(),
                subdomain: svc_spec.subdomain.clone(),
                auth_policy,
                health_check: health,
            });
            local_routing.insert(
                (project_id.clone(), svc_name.clone()),
                svc_spec.local_port,
            );
        }
        projects.push(ProjectRegistration {
            project: project_id,
            services: svcs,
        });
    }

    Ok((RegisterFrame { projects }, local_routing))
}

async fn run_control_loop<S>(
    control: &mut S,
    local_routing: BTreeMap<(ProjectId, ServiceName), LocalPort>,
    ssh_local_port: LocalPort,
    routing: Arc<Mutex<StreamRouting>>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let frame = match read_one_frame_opt(control).await? {
            Some(f) => f,
            None => return Ok(()),
        };
        match frame {
            ControlFrame::StreamOpen(open) => {
                let key = (open.project.clone(), open.service.clone());
                if let Some(port) = local_routing.get(&key) {
                    let mut r = routing.lock().await;
                    r.insert(open.stream_id, *port);
                } else {
                    tracing::warn!(
                        "StreamOpen for unknown service {}/{}",
                        open.project,
                        open.service
                    );
                }
            }
            ControlFrame::StreamOpenBuiltin(open) => match open.kind {
                BuiltinService::Ssh => {
                    let mut r = routing.lock().await;
                    r.insert(open.stream_id, ssh_local_port);
                    tracing::debug!(
                        "builtin ssh stream {} -> 127.0.0.1:{}",
                        open.stream_id,
                        ssh_local_port.value()
                    );
                }
            },
            ControlFrame::Ping(p) => {
                let pong = ControlFrame::Pong(tuntun_proto::PongFrame { nonce: p.nonce });
                write_frame(control, &pong).await?;
            }
            ControlFrame::Pong(_) => { /* swallow */ }
            ControlFrame::StreamData(_) | ControlFrame::StreamClose(_) => {
                // Stream data is carried in-band on yamux streams; these
                // out-of-band frames are not expected in the current flow.
                tracing::debug!("ignoring StreamData/Close on control channel");
            }
            ControlFrame::Error(e) => {
                tracing::warn!("server error: {} ({:?})", e.message, e.code);
            }
            other => {
                tracing::debug!("ignoring inbound control frame: {other:?}");
            }
        }
    }
}

async fn wait_for_routing(
    routing: &Arc<Mutex<StreamRouting>>,
    stream_id: u32,
) -> Option<LocalPort> {
    // Poll the routing map for up to ~2s. The StreamOpen frame and the
    // inbound yamux stream race; the frame is small so it usually arrives
    // first, but we allow a brief retry window.
    use std::time::Duration;
    for _ in 0..200 {
        {
            let map = routing.lock().await;
            if let Some(port) = map.get(&stream_id).copied() {
                return Some(port);
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    None
}

async fn pump_stream_to_local(yamux_stream: yamux::Stream, port: LocalPort) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port.value());
    let tcp = tokio::net::TcpStream::connect(&addr)
        .await
        .with_context(|| format!("connect local {addr}"))?;
    let mut yamux = yamux_stream.compat();
    let mut tcp = tcp;
    let _ = tokio::io::copy_bidirectional(&mut yamux, &mut tcp)
        .await
        .map_err(|e| anyhow!("pump: {e}"))?;
    Ok(())
}

async fn read_one_frame<S>(s: &mut S) -> Result<ControlFrame>
where
    S: tokio::io::AsyncRead + Unpin,
{
    match read_one_frame_opt(s).await? {
        Some(f) => Ok(f),
        None => Err(anyhow!("unexpected EOF on control stream")),
    }
}

async fn read_one_frame_opt<S>(s: &mut S) -> Result<Option<ControlFrame>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = FrameBuffer::new();
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) => {
                if buf.is_empty() {
                    return Ok(None);
                }
                return Err(anyhow!("EOF mid-frame"));
            }
            Ok(n) => {
                buf.push(&chunk[..n]);
                match buf.try_pop_frame() {
                    Ok(Some(frame)) => return Ok(Some(frame)),
                    Ok(None) => continue,
                    Err(e) => return Err(anyhow!("frame decode: {e}")),
                }
            }
            Err(e) => return Err(anyhow!("read: {e}")),
        }
    }
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

