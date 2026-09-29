//! TLS + yamux tunnel client.
//!
//! Connects to the configured server, completes ed25519 challenge-response
//! authentication, and multiplexes per-service streams over yamux.

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::task::AbortOnDropHandle;
use tuntun_config::ProjectSpec;
use tuntun_proto::heartbeat::Heartbeat;
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

/// Stream-routing state shared between the control loop (writer) and the
/// yamux acceptor (reader). The `Notify` lets the acceptor block until a
/// matching `StreamOpen` arrives, instead of busy-polling. It's wrapped
/// in an `Arc` so the acceptor can clone it out from under the lock and
/// await on it without holding the routing mutex.
#[derive(Debug, Default)]
struct StreamRouting {
    map: BTreeMap<u32, LocalPort>,
    notify: Arc<Notify>,
}

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
    /// Fires whenever `projects` is replaced. The active `run_session`
    /// selects on this and returns when it changes, so the next iteration
    /// of `run_forever` re-registers with the new spec — without needing
    /// to wait for the old session to die naturally.
    projects_changed: Arc<Notify>,
}

impl TunnelClient {
    pub fn new(config: Arc<DaemonConfig>) -> Self {
        let state_dir = config.state_dir.clone();
        Self {
            config,
            state_dir,
            projects: Arc::new(tokio::sync::RwLock::new(ProjectsSnapshot::default())),
            projects_changed: Arc::new(Notify::new()),
        }
    }

    pub fn projects_handle(&self) -> Arc<tokio::sync::RwLock<ProjectsSnapshot>> {
        self.projects.clone()
    }

    /// Replace the daemon's project list. The active session is woken so
    /// it tears down and re-registers with the new spec on next iteration.
    pub async fn update_projects(&self, snapshot: ProjectsSnapshot) {
        let mut guard = self.projects.write().await;
        *guard = snapshot;
        drop(guard);
        // notify_waiters wakes every current await on .notified(); future
        // calls are not pre-armed (which is fine — we just need to wake the
        // single live session).
        self.projects_changed.notify_one();
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
                .run_session(&signing_key, &connector, &tenant, &mut backoff)
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
        let pem = std::str::from_utf8(value.expose_bytes()).context("private key is not utf-8")?;
        SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| anyhow!("parse PEM (regenerate with scripts/regen-client-keys.rs?): {e}"))
    }

    async fn run_session(
        &self,
        signing_key: &SigningKey,
        connector: &TlsConnector,
        tenant: &TenantId,
        backoff: &mut BackoffState,
    ) -> Result<()> {
        // 1. TCP connect.
        let tcp = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(&self.config.server_host),
        )
        .await
        .context("TCP connect timed out")?
        .with_context(|| format!("connect to {}", self.config.server_host))?;

        // 2. TLS handshake. Server name doesn't matter for our pinned
        // verifier; pass a placeholder so rustls is happy.
        let server_name =
            ServerName::try_from("tuntun.invalid").map_err(|e| anyhow!("server name: {e}"))?;
        let tls_stream =
            tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
                .await
                .context("TLS handshake timed out")?
                .context("TLS handshake")?;

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
        // Persistent decode buffer threaded through every read on `control`.
        // A single TLS read can carry more than one frame (the server pipes
        // Welcome + AuthChallenge back-to-back, etc.); keeping leftover
        // bytes between reads is the difference between progress and a hang.
        let mut control_inbox = FrameBuffer::new();

        // Spawn the driver — it owns yamux_conn outright and pumps inbound
        // streams. From here on the handshake task uses only `control`,
        // which is independent of `yamux_conn`'s ownership.
        let routing: Arc<Mutex<StreamRouting>> = Arc::new(Mutex::new(StreamRouting::default()));
        let ssh_local_port = LocalPort::new(self.config.ssh_local_port)
            .map_err(|e| anyhow!("ssh_local_port {}: {e}", self.config.ssh_local_port))?;
        let routing_for_acceptor = routing.clone();
        let mut acceptor = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut conn = yamux_conn;
            let mut streams = JoinSet::new();
            loop {
                tokio::select! {
                    completed = streams.join_next(), if !streams.is_empty() => {
                        completed.context("stream task set unexpectedly empty")?
                            .context("stream task panicked")?;
                    }
                    res = poll_fn(|cx| conn.poll_next_inbound(cx)) => match res {
                        Some(Ok(stream)) => {
                            anyhow::ensure!(streams.len() < 256, "too many inbound tunnel streams");
                            let routing = routing_for_acceptor.clone();
                            streams.spawn(async move {
                                let id = stream.id().val();
                                if let Some(port) = wait_for_routing(&routing, id).await {
                                    if let Err(e) = pump_stream_to_local(stream, port).await {
                                        tracing::debug!(stream_id = id, error = ?e, "local stream ended");
                                    }
                                } else {
                                    tracing::warn!(stream_id = id, "stream routing timed out");
                                }
                            });
                        }
                        Some(Err(e)) => return Err(anyhow::Error::new(e).context("yamux driver")),
                        None => return Err(anyhow!("yamux connection closed")),
                    }
                }
            }
        }));

        // 5. Send Hello.
        let client_id_str = if self.config.client_id.is_empty() {
            format!("laptop-{}", self.config.default_tenant)
        } else {
            self.config.client_id.clone()
        };
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
        let welcome = read_one_frame(&mut control, &mut control_inbox).await?;
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
        let challenge_or_req = read_one_frame(&mut control, &mut control_inbox).await?;
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
        let auth_result = read_one_frame(&mut control, &mut control_inbox).await?;
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
        // Consume any pending notification BEFORE reading the snapshot. A later
        // change retains a permit and forces another registration.
        let _ = tokio::time::timeout(Duration::ZERO, self.projects_changed.notified()).await;
        let snapshot = self.projects.read().await.clone();
        let (register_frame, routing_seed) = build_register_frame(&snapshot)?;
        let register = ControlFrame::Register(register_frame);
        write_frame(&mut control, &register).await?;

        // 11. Receive Registered.
        let registered = read_one_frame(&mut control, &mut control_inbox).await?;
        let ControlFrame::Registered(registered) = registered else {
            return Err(anyhow!("expected Registered, got {registered:?}"));
        };
        backoff.reset();
        tracing::info!(
            "registered {} services with server",
            registered.allocations.len()
        );

        // 12. Run the control loop. The yamux acceptor was already spawned
        // before the handshake; once Register completes the server is free
        // to open new inbound streams and the acceptor will pick them up
        // and pair each with a routing entry.
        //
        // We race the loop against `projects_changed` so a `tuntun register
        // <new>` triggers a clean reconnect that picks up the fresh spec —
        // without it the daemon only re-registers on its own boot.
        let projects_changed = self.projects_changed.clone();
        let control_loop_result = tokio::select! {
            r = run_control_loop(
                &mut control,
                &mut control_inbox,
                routing_seed,
                ssh_local_port,
                routing.clone(),
            ) => r,
            result = &mut acceptor => {
                result.context("tunnel driver task panicked")?
            }
            () = projects_changed.notified() => {
                tracing::info!("projects snapshot changed; tearing down session to re-register");
                Ok(())
            }
        };

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
            let health = svc_spec
                .health_check
                .as_ref()
                .map(|h| tuntun_proto::HealthCheckSpec {
                    path: h.path.clone(),
                    expected_status: h.expected_status,
                    timeout_seconds: h.timeout_seconds,
                });
            svcs.push(ServiceRegistration {
                service: svc_name.clone(),
                subdomain: svc_spec.subdomain.clone(),
                auth_policy,
                health_check: health,
            });
            local_routing.insert((project_id.clone(), svc_name.clone()), svc_spec.local_port);
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
    inbox: &mut FrameBuffer,
    local_routing: BTreeMap<(ProjectId, ServiceName), LocalPort>,
    ssh_local_port: LocalPort,
    routing: Arc<Mutex<StreamRouting>>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let started = tokio::time::Instant::now();
    let mut heartbeat = Heartbeat::new(rand::random());
    loop {
        let received = tokio::select! {
            () = tokio::time::sleep_until(started + heartbeat.deadline()) => {
                if let Some(ping) = heartbeat.poll(started.elapsed())? {
                    write_frame(control, &ControlFrame::Ping(ping)).await?;
                }
                continue;
            }
            frame = read_one_frame_opt(control, inbox) => frame?,
        };
        let frame = match received {
            Some(f) => f,
            None => return Err(anyhow!("server closed control stream")),
        };
        match frame {
            ControlFrame::StreamOpen(open) => {
                let key = (open.project.clone(), open.service.clone());
                if let Some(port) = local_routing.get(&key) {
                    let mut r = routing.lock().await;
                    anyhow::ensure!(r.map.len() < 256, "too many pending stream routes");
                    anyhow::ensure!(
                        r.map.insert(open.stream_id, *port).is_none(),
                        "duplicate stream route {}",
                        open.stream_id
                    );
                    r.notify.notify_waiters();
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
                    anyhow::ensure!(r.map.len() < 256, "too many pending stream routes");
                    anyhow::ensure!(
                        r.map.insert(open.stream_id, ssh_local_port).is_none(),
                        "duplicate stream route {}",
                        open.stream_id
                    );
                    r.notify.notify_waiters();
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
            ControlFrame::Pong(pong) => heartbeat.on_pong(pong.nonce),
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let notify = routing.lock().await.notify.clone();
    loop {
        // Register before checking the map, so an insertion cannot be lost
        // between the check and awaiting notification.
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(port) = routing.lock().await.map.remove(&stream_id) {
            return Some(port);
        }
        tokio::time::timeout_at(deadline, notified).await.ok()?;
    }
}

async fn pump_stream_to_local(yamux_stream: yamux::Stream, port: LocalPort) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port.value());
    let tcp = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .context("local connection timed out")?
    .with_context(|| format!("connect local {addr}"))?;
    let mut yamux = yamux_stream.compat();
    let mut tcp = tcp;
    let _ = tokio::io::copy_bidirectional(&mut yamux, &mut tcp)
        .await
        .map_err(|e| anyhow!("pump: {e}"))?;
    Ok(())
}

async fn read_one_frame<S>(s: &mut S, inbox: &mut FrameBuffer) -> Result<ControlFrame>
where
    S: tokio::io::AsyncRead + Unpin,
{
    match tokio::time::timeout(Duration::from_secs(10), read_one_frame_opt(s, inbox))
        .await
        .context("control handshake timed out")??
    {
        Some(f) => Ok(f),
        None => Err(anyhow!("unexpected EOF on control stream")),
    }
}

/// Read one frame, sharing a persistent `inbox` across calls. A single TLS
/// read can return more than one frame's bytes when the server coalesces
/// writes (Welcome + AuthChallenge are sent back-to-back, for instance), so
/// the inbox preserves leftover bytes after a frame is popped — otherwise
/// the next read silently waits forever for bytes that already arrived.
async fn read_one_frame_opt<S>(s: &mut S, inbox: &mut FrameBuffer) -> Result<Option<ControlFrame>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    match inbox.try_pop_frame() {
        Ok(Some(frame)) => return Ok(Some(frame)),
        Ok(None) => {}
        Err(e) => return Err(anyhow::Error::new(e).context("frame decode")),
    }
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) => {
                if inbox.is_empty() {
                    return Ok(None);
                }
                return Err(anyhow!("EOF mid-frame"));
            }
            Ok(n) => {
                inbox.push(&chunk[..n]);
                match inbox.try_pop_frame() {
                    Ok(Some(frame)) => return Ok(Some(frame)),
                    Ok(None) => continue,
                    Err(e) => return Err(anyhow::Error::new(e).context("frame decode")),
                }
            }
            Err(e) => return Err(anyhow::Error::new(e).context("control read")),
        }
    }
}

async fn write_frame<S>(s: &mut S, frame: &ControlFrame) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let bytes = encode_frame(frame).context("encode frame")?;
    tokio::time::timeout(Duration::from_secs(5), async {
        s.write_all(&bytes).await.context("control write")?;
        s.flush().await.context("control flush")
    })
    .await
    .context("control write timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_is_abandoned_with_heartbeat_evidence() {
        let (mut control, _silent_peer) = tokio::io::duplex(4096);
        let result = tokio::time::timeout(
            Duration::from_secs(51),
            run_control_loop(
                &mut control,
                &mut FrameBuffer::new(),
                BTreeMap::new(),
                LocalPort::new(22).expect("SSH port"),
                Arc::new(Mutex::new(StreamRouting::default())),
            ),
        )
        .await
        .expect("client detects loss within 50 seconds")
        .expect_err("silent peer is dead");
        assert_eq!(
            result
                .downcast_ref::<tuntun_proto::heartbeat::HeartbeatTimeout>()
                .expect("original heartbeat evidence retained")
                .missed,
            3
        );
    }

    #[tokio::test]
    async fn a_route_is_consumed_once_even_when_it_arrives_after_the_stream() {
        let routing = Arc::new(Mutex::new(StreamRouting::default()));
        let waiter_routing = routing.clone();
        let waiter = tokio::spawn(async move { wait_for_routing(&waiter_routing, 2).await });
        tokio::task::yield_now().await;
        let port = LocalPort::new(22).expect("SSH port");
        {
            let mut state = routing.lock().await;
            state.map.insert(2, port);
            state.notify.notify_waiters();
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("no missed wakeup")
                .expect("waiter"),
            Some(port)
        );
        assert!(routing.lock().await.map.is_empty());
    }
}
