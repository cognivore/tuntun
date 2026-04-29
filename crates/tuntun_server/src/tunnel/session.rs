//! Per-tunnel-client session.
//!
//! After acceptance, this task:
//!
//! 1. Negotiates TLS (server cert pinned by clients via fingerprint).
//! 2. Opens a yamux server-side multiplexer; the very first inbound stream is
//!    treated as the control stream.
//! 3. Reads a `Hello` frame on the control stream, validates the protocol
//!    version, replies with `Welcome`.
//! 4. Generates a 32-byte challenge nonce, sends `AuthChallenge`, reads
//!    `AuthResponse`, verifies via `tuntun_auth::verify_tunnel_signature`
//!    against the tenant's authorized_keys.
//! 5. Reads `Register`, allocates server-side ports for each service, inserts
//!    them into the `Registry`, replies with `Registered`, triggers a
//!    Caddyfile re-render via the supervisor.
//! 6. Spawns one public TCP listener per registered service.
//! 7. For every public connection, opens a fresh yamux outbound stream,
//!    emits a `StreamOpen` control frame so the client can match it to a
//!    service, and bidirectionally pipes bytes between Caddy and the client.

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::VerifyingKey;
use rand::rngs::OsRng;
use rand::RngCore as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config as YamuxConfig, Connection as YamuxConnection, Mode};

use tuntun_auth::tunnel_auth::verify_tunnel_signature;
use tuntun_caddy::{
    AuthEndpointConfig, AuthPolicy as CaddyAuthPolicy, CaddyInput, GlobalConfig, LoginSiteConfig,
    ServiceSite,
};
use tuntun_core::{
    Ed25519PublicKey, Fqdn, Nonce, ProjectId, ServiceName, ServicePort, TenantId,
};
use tuntun_proto::{
    encode_frame, AuthChallengeFrame, AuthPolicy as ProtoAuthPolicy, AuthResultFrame,
    BlessKeyAckFrame, BlessingEntry, BlessingsListFrame, ControlFrame, FrameBuffer, PongFrame,
    RegisteredFrame, ServiceAllocation, UnblessKeyAckFrame, WelcomeFrame, PROTOCOL_VERSION,
};

use crate::caddy_supervisor::CaddySupervisor;
use crate::config::{ServerConfig, TenantsFileEntry};
use crate::registry::{ClientRecord, ProjectRecord, Registry, ServiceRecord};
use crate::tls::TlsAcceptorHandle;
use crate::tunnel::per_service_listener::{
    build_stream_open, build_stream_open_builtin, pump_stream, run_listener, OpenStreamRequest,
    OpenStreamSubject,
};

const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn handle_connection(
    sock: tokio::net::TcpStream,
    peer: SocketAddr,
    registry: Arc<Registry>,
    config: Arc<ServerConfig>,
    supervisor: Arc<CaddySupervisor>,
    tls: Arc<TlsAcceptorHandle>,
) -> Result<()> {
    // 1. TLS accept.
    let tls_stream = tls
        .acceptor
        .accept(sock)
        .await
        .with_context(|| format!("tls accept from {peer}"))?;

    // 2. Yamux server connection. We give exclusive ownership to a single
    // driver task that interleaves three things in one `poll_fn`:
    //   - polling for inbound streams (drives the connection),
    //   - polling for `OpenOutbound` requests on a channel (lets the
    //     `stream_opener` ask for new outbound streams without contending
    //     for a lock),
    //   - polling for `poll_new_outbound` itself when an open is in flight.
    // Wrapping the connection in `Arc<Mutex>` deadlocks: the lock must be
    // held while awaiting an inbound, but that blocks anyone wanting to
    // open an outbound. Single-owner + a command channel sidesteps that.
    let mut yamux_conn =
        YamuxConnection::new(tls_stream.compat(), YamuxConfig::default(), Mode::Server);

    // 3. The first inbound stream is the control stream. We poll it once
    // here so the rest of the session can read/write on it — and *then*
    // move the Connection into the driver task.
    let control_stream =
        poll_fn(|cx| std::pin::Pin::new(&mut yamux_conn).poll_next_inbound(cx))
            .await
            .ok_or_else(|| anyhow!("client closed before opening control stream"))?
            .map_err(|e| anyhow!("yamux control stream accept: {e}"))?;
    let mut control = control_stream.compat();

    // Channel into the driver: stream_opener tasks send `OpenOutboundCmd`
    // and receive a freshly-allocated yamux Stream back via a oneshot.
    let (open_tx, mut open_rx) = mpsc::channel::<OpenOutboundCmd>(64);

    let driver = tokio::spawn(async move {
        let mut conn = yamux_conn;
        // Yamux 0.13 only flushes queued outbound writes when the Connection
        // is polled. With nothing else poking it, control-stream frames
        // (e.g., StreamOpen) and freshly-pumped service bytes sit on the
        // queue until the next inbound event arrives — easily 30s in idle
        // HTTP flows. A 10 ms tick keeps the driver in motion so writes
        // flush within a frame's RTT.
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            // poll_fn lets us poll the open-command channel, a tick, and the
            // inbound-stream side using the same `&mut conn`, in sequence
            // within a single closure call. Whichever is ready first wins.
            let event: DriverEvent = poll_fn(|cx| {
                if let Poll::Ready(req_opt) = open_rx.poll_recv(cx) {
                    return Poll::Ready(DriverEvent::OpenCmd(req_opt));
                }
                if tick.poll_tick(cx).is_ready() {
                    return Poll::Ready(DriverEvent::Tick);
                }
                match std::pin::Pin::new(&mut conn).poll_next_inbound(cx) {
                    Poll::Ready(r) => Poll::Ready(DriverEvent::Inbound(r)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            match event {
                // Both `OpenCmd(None)` (the channel closed because the
                // session is tearing down) and `Inbound(None)` (yamux saw
                // EOF) mean the same thing: stop driving.
                DriverEvent::OpenCmd(None) | DriverEvent::Inbound(None) => break,
                DriverEvent::OpenCmd(Some(cmd)) => {
                    let res = poll_fn(|cx| {
                        std::pin::Pin::new(&mut conn).poll_new_outbound(cx)
                    })
                    .await;
                    let _ = cmd.reply.send(
                        res.map_err(|e| anyhow!("yamux open_outbound: {e}")),
                    );
                }
                DriverEvent::Tick => {
                    // Loop body exists purely so the next iteration's
                    // poll_next_inbound runs, which drives the connection's
                    // I/O state machine and flushes any queued writes.
                }
                DriverEvent::Inbound(Some(Ok(stream))) => {
                    tracing::debug!(
                        "ignoring extra inbound yamux stream id={}",
                        stream.id()
                    );
                    drop(stream);
                }
                DriverEvent::Inbound(Some(Err(e))) => {
                    tracing::debug!("yamux driver: inbound error: {e}");
                    break;
                }
            }
        }
    });

    // Persistent decode buffer for the control stream. Keeping leftover
    // bytes between read_one_frame calls prevents losing the second frame
    // when the client coalesces two frames into one TLS write.
    let mut control_inbox = FrameBuffer::new();

    // 4. Receive Hello.
    let hello = read_one_frame(&mut control, &mut control_inbox).await?;
    let ControlFrame::Hello(hello) = hello else {
        return Err(anyhow!("expected Hello, got {hello:?}"));
    };
    if hello.protocol_version != PROTOCOL_VERSION {
        return Err(anyhow!(
            "unsupported protocol version: client {} vs server {}",
            hello.protocol_version,
            PROTOCOL_VERSION
        ));
    }
    let tenant = hello.tenant.clone();
    let client_id = hello.client_id.clone();

    // Reply Welcome.
    let welcome = ControlFrame::Welcome(WelcomeFrame {
        protocol_version: PROTOCOL_VERSION,
        server_id: format!("tuntun-server-{}", config.domain),
        software_version: SOFTWARE_VERSION.to_string(),
    });
    write_frame(&mut control, &welcome).await?;

    // 5. Auth challenge/response.
    let nonce = generate_nonce();
    let challenge = ControlFrame::AuthChallenge(AuthChallengeFrame { nonce });
    write_frame(&mut control, &challenge).await?;

    let response = read_one_frame(&mut control, &mut control_inbox).await?;
    let ControlFrame::AuthResponse(response) = response else {
        return Err(anyhow!("expected AuthResponse, got {response:?}"));
    };

    let authorized_keys = load_tenant_authorized_keys(&config, &tenant).await?;
    let verify_result =
        verify_tunnel_signature(&authorized_keys, &nonce, &tenant, &response.signature);

    let auth_ok = verify_result.is_ok();
    let result_frame = ControlFrame::AuthResult(AuthResultFrame {
        ok: auth_ok,
        message: if auth_ok {
            None
        } else {
            Some("authentication failed".to_string())
        },
    });
    write_frame(&mut control, &result_frame).await?;

    if !auth_ok {
        return Err(anyhow!(
            "tunnel auth failed for tenant {tenant} from {peer}"
        ));
    }
    tracing::info!(
        "tunnel client {client_id} authenticated for tenant {tenant} from {peer}"
    );

    // 6. Register frame.
    let register_frame = read_one_frame(&mut control, &mut control_inbox).await?;
    let ControlFrame::Register(register) = register_frame else {
        return Err(anyhow!("expected Register, got {register_frame:?}"));
    };

    // Allocate ports and build records.
    let mut allocations: Vec<ServiceAllocation> = Vec::new();
    let mut projects: BTreeMap<ProjectId, ProjectRecord> = BTreeMap::new();
    for proj in &register.projects {
        let mut svc_records: BTreeMap<ServiceName, ServiceRecord> = BTreeMap::new();
        for svc in &proj.services {
            let port: ServicePort = registry.allocate_port().await;
            // Schema: <subdomain>.<tenant>.<domain> — the tenant is part of
            // the public hostname, so two tenants on the same server can each
            // declare a service called "blog" without conflict.
            let fqdn_str = format!(
                "{}.{}.{}",
                svc.subdomain.as_str(),
                tenant.as_str(),
                config.domain
            );
            let fqdn = Fqdn::new(fqdn_str.clone())
                .map_err(|e| anyhow!("derive fqdn {fqdn_str}: {e}"))?;

            allocations.push(ServiceAllocation {
                project: proj.project.clone(),
                service: svc.service.clone(),
                public_fqdn: fqdn.clone(),
                server_internal_port: port,
            });

            svc_records.insert(
                svc.service.clone(),
                ServiceRecord {
                    service: svc.service.clone(),
                    fqdn,
                    server_port: port,
                    auth_policy: svc.auth_policy,
                    health_check: svc.health_check.clone(),
                },
            );
        }
        projects.insert(
            proj.project.clone(),
            ProjectRecord {
                project: proj.project.clone(),
                services: svc_records,
            },
        );
    }

    // Outbound control-frame channel: any task that wants to write a frame
    // to the client sends it here; the writer task drains it.
    let (control_tx, control_rx) = mpsc::channel::<ControlFrame>(64);

    // Stream-open requests channel — used both by the per-service public TCP
    // listeners spawned below and by the global SSH bastion side-car (via
    // [`ClientRecord::stream_tx`] looked up by tenant).
    let (stream_tx, stream_rx) = mpsc::channel::<OpenStreamRequest>(64);

    let client_record = ClientRecord {
        client_id: client_id.clone(),
        tenant: tenant.clone(),
        control_tx: control_tx.clone(),
        stream_tx: stream_tx.clone(),
        projects: projects.clone(),
    };
    registry.upsert_client(client_record).await;

    // Reply Registered.
    let registered = ControlFrame::Registered(RegisteredFrame {
        allocations: allocations.clone(),
    });
    write_frame(&mut control, &registered).await?;

    // 7. Trigger Caddyfile re-render with the union of all currently
    // registered services across all clients.
    if let Err(e) = render_and_reload_caddy(&supervisor, &config, &registry).await {
        tracing::warn!("caddy reload failed: {e:#}");
    }

    // 8. Spin up one public listener per service.
    for proj in projects.values() {
        for svc in proj.services.values() {
            let pid = proj.project.clone();
            let sname = svc.service.clone();
            let sport = svc.server_port;
            let tx = stream_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = run_listener(pid.clone(), sname.clone(), sport, tx).await {
                    tracing::warn!("public listener {pid}/{sname}: {e:#}");
                }
            });
        }
    }
    // The session keeps a clone of `stream_tx` alive (via the registry) so the
    // SSH bastion can dispatch builtin requests after the per-service
    // listeners have exited. Drop the local handle so the channel closes when
    // both the listeners *and* the registry entry are gone.
    drop(stream_tx);

    // 10. Stream-opener loop: for each public connection, ask the driver
    // (via the open_tx channel) to allocate an outbound yamux stream, send
    // a StreamOpen control frame, and pump bytes.
    let opener = tokio::spawn(stream_opener(
        open_tx.clone(),
        stream_rx,
        control_tx.clone(),
    ));

    // 11. Control IO: writer drains control_rx → control stream; reader
    // handles inbound Ping / Deregister / BlessKey frames.
    let writer_result = control_loop(
        &mut control,
        &mut control_inbox,
        control_rx,
        control_tx,
        tenant.clone(),
        config.state_dir.clone(),
    )
    .await;
    if let Err(e) = writer_result {
        tracing::info!("control loop ended for {client_id}: {e:#}");
    }

    // 12. Tear down.
    registry.drop_client(&client_id).await;
    if let Err(e) = render_and_reload_caddy(&supervisor, &config, &registry).await {
        tracing::warn!("caddy reload after disconnect: {e:#}");
    }

    opener.abort();
    driver.abort();
    Ok(())
}

/// Driver event surfaced by the single `poll_fn` inside the driver task.
enum DriverEvent {
    /// An open-outbound command from the stream_opener task (or the channel
    /// closed, in which case the inner Option is `None`).
    OpenCmd(Option<OpenOutboundCmd>),
    /// Periodic tick — forces another iteration so the connection is polled
    /// and any queued outbound writes get flushed.
    Tick,
    /// Yamux yielded an inbound stream (or the connection ended).
    Inbound(Option<Result<yamux::Stream, yamux::ConnectionError>>),
}

/// Request from the stream-opener task to the driver: please allocate a
/// new outbound yamux stream and send it back.
struct OpenOutboundCmd {
    reply: oneshot::Sender<Result<yamux::Stream>>,
}

async fn stream_opener(
    open_tx: mpsc::Sender<OpenOutboundCmd>,
    mut stream_rx: mpsc::Receiver<OpenStreamRequest>,
    control_tx: mpsc::Sender<ControlFrame>,
) {
    while let Some(req) = stream_rx.recv().await {
        let (reply_tx, reply_rx) = oneshot::channel();
        if open_tx
            .send(OpenOutboundCmd { reply: reply_tx })
            .await
            .is_err()
        {
            let _ = req.ack.send(Err(anyhow!("yamux driver gone")));
            continue;
        }
        let outbound = match reply_rx.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let _ = req.ack.send(Err(e));
                continue;
            }
            Err(_) => {
                let _ = req.ack.send(Err(anyhow!("yamux driver dropped reply")));
                continue;
            }
        };
        let stream_id = outbound.id().val();

        let (frame, log_label) = match &req.subject {
            OpenStreamSubject::Service { project, service } => (
                build_stream_open(stream_id, project, service),
                format!("{project}/{service}"),
            ),
            OpenStreamSubject::Builtin(kind) => (
                build_stream_open_builtin(stream_id, *kind),
                format!("builtin:{kind:?}"),
            ),
        };
        if control_tx.send(frame).await.is_err() {
            let _ = req.ack.send(Err(anyhow!("control channel closed")));
            continue;
        }

        let ack = req.ack;
        let inbound = req.inbound;
        tokio::spawn(async move {
            match pump_stream(outbound, inbound).await {
                Ok((up, down)) => {
                    tracing::debug!(
                        "stream {log_label} closed; up={up} down={down}"
                    );
                    let _ = ack.send(Ok(()));
                }
                Err(e) => {
                    tracing::debug!("stream {log_label} pump: {e}");
                    let _ = ack.send(Err(anyhow!("pump: {e}")));
                }
            }
        });
    }
    tracing::debug!("stream opener exiting (no more public connections)");
}

async fn control_loop<S>(
    control: &mut S,
    inbox: &mut FrameBuffer,
    mut control_rx: mpsc::Receiver<ControlFrame>,
    control_tx: mpsc::Sender<ControlFrame>,
    tenant: TenantId,
    state_dir: std::path::PathBuf,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    drop(control_tx); // we keep the writer side via control_rx; tx is unused here
    loop {
        tokio::select! {
            biased;
            outbound = control_rx.recv() => {
                match outbound {
                    Some(frame) => write_frame(control, &frame).await?,
                    None => return Ok(()),
                }
            }
            inbound = read_one_frame_opt(control, inbox) => {
                match inbound? {
                    Some(ControlFrame::Ping(p)) => {
                        let pong = ControlFrame::Pong(PongFrame { nonce: p.nonce });
                        write_frame(control, &pong).await?;
                    }
                    Some(ControlFrame::Deregister(_)) => {
                        tracing::info!("client deregister received");
                        return Ok(());
                    }
                    Some(ControlFrame::BlessKey(req)) => {
                        let ack = match append_blessed_key(&state_dir, &tenant, &req).await {
                            Ok(()) => {
                                tracing::info!(
                                    "blessed key for tenant {tenant}: {label}",
                                    label = req.label
                                );
                                BlessKeyAckFrame { ok: true, message: None }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "bless append failed for tenant {tenant}: {e:#}"
                                );
                                BlessKeyAckFrame {
                                    ok: false,
                                    message: Some(format!("{e:#}")),
                                }
                            }
                        };
                        write_frame(control, &ControlFrame::BlessKeyAck(ack)).await?;
                    }
                    Some(ControlFrame::UnblessKey(req)) => {
                        let ack = match remove_blessed_keys_by_label(
                            &state_dir, &tenant, &req.label,
                        )
                        .await
                        {
                            Ok(removed) => {
                                tracing::info!(
                                    "unblessed {removed} key(s) for tenant {tenant} \
                                     matching label {label:?}",
                                    label = req.label,
                                );
                                UnblessKeyAckFrame {
                                    ok: true,
                                    removed,
                                    message: None,
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "unbless failed for tenant {tenant}: {e:#}"
                                );
                                UnblessKeyAckFrame {
                                    ok: false,
                                    removed: 0,
                                    message: Some(format!("{e:#}")),
                                }
                            }
                        };
                        write_frame(control, &ControlFrame::UnblessKeyAck(ack)).await?;
                    }
                    Some(ControlFrame::ListBlessings(_)) => {
                        let entries = read_blessings(&state_dir, &tenant).await
                            .unwrap_or_else(|e| {
                                tracing::warn!(
                                    "list blessings failed for tenant {tenant}: {e:#}"
                                );
                                Vec::new()
                            });
                        write_frame(
                            control,
                            &ControlFrame::BlessingsList(BlessingsListFrame { entries }),
                        )
                        .await?;
                    }
                    Some(other) => {
                        tracing::debug!("ignoring inbound control frame: {other:?}");
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

/// Append `req.public_key` (in OpenSSH `ssh-ed25519 <b64> <label>` form) to
/// `<state_dir>/tenants/<tenant>/bless.keys`, creating the directory and
/// file as needed with mode 0750/0640. The bastion's
/// `AuthorizedKeysCommand` reads this on every SSH attempt — no daemon
/// reload, no NixOS rebuild. Idempotent: a key already present is a no-op.
async fn append_blessed_key(
    state_dir: &std::path::Path,
    tenant: &TenantId,
    req: &tuntun_proto::BlessKeyFrame,
) -> Result<()> {
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use base64::Engine as _;

    // Sanitize the label: strip CR/LF and the comment-terminator boundary,
    // and bound the length. The label is operator-supplied via the protocol
    // and lands verbatim in an `authorized_keys`-style line where a
    // newline would split it into a SECOND key entry.
    let label: String = req
        .label
        .chars()
        .filter(|c| *c != '\n' && *c != '\r')
        .take(128)
        .collect();

    let pubkey_b64 = STANDARD_NO_PAD.encode(req.public_key.0);
    // Rebuild the OpenSSH wire-format public key body: a single SSH string
    // containing the algorithm name, then a single SSH string with the
    // 32-byte raw key, all base64-encoded standard (with padding).
    let openssh_b64 = encode_openssh_ed25519_public(&req.public_key.0);
    let line = format!("ssh-ed25519 {openssh_b64} {label}\n");

    let dir = state_dir.join("tenants").join(tenant.as_str());
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("mkdir {}", dir.display()))?;
    let path = dir.join("bless.keys");

    // Idempotency check.
    if let Ok(existing) = tokio::fs::read_to_string(&path).await {
        let key_marker = format!("ssh-ed25519 {openssh_b64} ");
        if existing.lines().any(|l| l.starts_with(&key_marker)) {
            tracing::debug!("bless: key already present in {}", path.display());
            // Different label → still no-op for now; first-write wins.
            // (`tuntun unbless` will manage replacement later.)
            let _ = pubkey_b64; // silence unused
            return Ok(());
        }
    }

    let mut opts = tokio::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    opts.mode(0o640);
    let mut f = opts
        .open(&path)
        .await
        .with_context(|| format!("open append {}", path.display()))?;
    use tokio::io::AsyncWriteExt as _;
    f.write_all(line.as_bytes())
        .await
        .with_context(|| format!("write {}", path.display()))?;
    f.flush().await?;
    Ok(())
}

/// Encode a raw 32-byte ed25519 public key as the body of an `authorized_keys`
/// `ssh-ed25519 <body>` line: SSH-string-encoded `"ssh-ed25519"` followed by
/// the SSH-string-encoded raw key, the whole thing standard-base64.
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

/// Read every entry from `<state_dir>/tenants/<tenant>/bless.keys` and
/// return it parsed. Lines are split on whitespace into three fields —
/// algorithm, base64-body, label (which may be empty). Lines that don't
/// have at least two fields are skipped silently; comment lines (`# …`)
/// and blank lines are dropped. A missing file is treated as "no
/// blessings" and yields an empty Vec.
async fn read_blessings(
    state_dir: &std::path::Path,
    tenant: &TenantId,
) -> Result<Vec<BlessingEntry>> {
    let path = state_dir
        .join("tenants")
        .join(tenant.as_str())
        .join("bless.keys");
    let text = match tokio::fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow!("read {}: {e}", path.display())),
    };
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, char::is_whitespace);
        let alg = match parts.next() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let body = match parts.next() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let label = parts.next().unwrap_or("").trim().to_string();
        out.push(BlessingEntry {
            algorithm: alg,
            public_key_b64: body,
            label,
        });
    }
    Ok(out)
}

/// Atomically rewrite `bless.keys`, dropping any line whose label exactly
/// matches `target_label` (after the same CR/LF + length sanitization that
/// `append_blessed_key` applied at insertion time, so an unbless will hit
/// what a bless previously wrote). Returns the number of lines removed.
async fn remove_blessed_keys_by_label(
    state_dir: &std::path::Path,
    tenant: &TenantId,
    target_label: &str,
) -> Result<u32> {
    let path = state_dir
        .join("tenants")
        .join(tenant.as_str())
        .join("bless.keys");
    let text = match tokio::fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(anyhow!("read {}: {e}", path.display())),
    };
    let canonical: String = target_label
        .chars()
        .filter(|c| *c != '\n' && *c != '\r')
        .take(128)
        .collect();

    let mut removed: u32 = 0;
    let mut kept = String::with_capacity(text.len());
    for raw in text.split_inclusive('\n') {
        // Re-derive the label from each line for comparison.
        let line = raw.trim_end_matches(['\n', '\r']);
        if line.is_empty() || line.starts_with('#') {
            kept.push_str(raw);
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, char::is_whitespace).collect();
        let line_label = parts.get(2).map_or("", |s| s.trim());
        if line_label == canonical {
            removed = removed.saturating_add(1);
        } else {
            kept.push_str(raw);
        }
    }

    if removed == 0 {
        return Ok(0);
    }

    // Write atomically via a sibling temp file + rename so we don't leave
    // a partial file if the daemon crashes mid-write.
    let tmp = path.with_extension("keys.tmp");
    let mut opts = tokio::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o640);
    let mut f = opts
        .open(&tmp)
        .await
        .with_context(|| format!("open temp {}", tmp.display()))?;
    use tokio::io::AsyncWriteExt as _;
    f.write_all(kept.as_bytes())
        .await
        .with_context(|| format!("write {}", tmp.display()))?;
    f.flush().await?;
    drop(f);
    tokio::fs::rename(&tmp, &path)
        .await
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(removed)
}

fn generate_nonce() -> Nonce {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    Nonce::from_bytes(buf)
}

async fn read_one_frame<S>(s: &mut S, inbox: &mut FrameBuffer) -> Result<ControlFrame>
where
    S: tokio::io::AsyncRead + Unpin,
{
    match read_one_frame_opt(s, inbox).await? {
        Some(f) => Ok(f),
        None => Err(anyhow!("unexpected EOF on control stream")),
    }
}

/// Read one frame; returns `Ok(None)` on clean EOF before any bytes.
///
/// The `inbox` is shared across calls so leftover bytes from a previous
/// read (when one TLS read carried more than one frame) are preserved.
/// Without that, frames coalesced on the wire would silently disappear
/// after the first one is popped.
async fn read_one_frame_opt<S>(
    s: &mut S,
    inbox: &mut FrameBuffer,
) -> Result<Option<ControlFrame>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    match inbox.try_pop_frame() {
        Ok(Some(frame)) => return Ok(Some(frame)),
        Ok(None) => {}
        Err(e) => return Err(anyhow!("frame decode: {e}")),
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

async fn load_tenant_authorized_keys(
    cfg: &ServerConfig,
    tenant: &TenantId,
) -> Result<Vec<Ed25519PublicKey>> {
    let tenants = cfg
        .load_tenants()
        .await
        .with_context(|| format!("load tenants for {tenant}"))?;
    let entry: &TenantsFileEntry = tenants
        .0
        .get(tenant.as_str())
        .ok_or_else(|| anyhow!("tenant {tenant} not configured"))?;

    let mut out = Vec::with_capacity(entry.authorized_keys.len());
    for line in &entry.authorized_keys {
        let pk = Ed25519PublicKey::from_authorized_keys_line(line)
            .map_err(|e| anyhow!("authorized_keys line for {tenant}: {e}"))?;
        let _ = VerifyingKey::from_bytes(&pk.0)
            .map_err(|e| anyhow!("authorized key for {tenant} not on curve: {e}"))?;
        out.push(pk);
    }
    Ok(out)
}

async fn render_and_reload_caddy(
    supervisor: &CaddySupervisor,
    cfg: &ServerConfig,
    registry: &Arc<Registry>,
) -> Result<()> {
    let services = registry.snapshot_services().await;
    let mut sites: Vec<ServiceSite> = Vec::with_capacity(services.len());
    for svc in services {
        let auth = match svc.auth_policy {
            ProtoAuthPolicy::Tenant => CaddyAuthPolicy::Tenant,
            ProtoAuthPolicy::Public => CaddyAuthPolicy::Public,
        };
        let health_path = svc.health_check.as_ref().map(|h| h.path.clone());
        sites.push(ServiceSite {
            fqdn: svc.fqdn,
            upstream_port: svc.server_port,
            auth_policy: auth,
            health_check_path: health_path,
        });
    }

    // One login site per configured tenant, served at
    // `auth.<tenant>.<domain>`. The upstream is shared (a single internal
    // HTTP service that reads `Host` to figure out which tenant the request
    // belongs to) — this matches the per-tenant cookie scope (`Domain=
    // .<tenant>.<domain>`), which a single apex `auth.<domain>` could not
    // produce because browsers reject Set-Cookie attempting to scope to a
    // domain that is not a parent of the request URL.
    let tenants = cfg
        .load_tenants()
        .await
        .map_err(|e| anyhow!("load tenants for caddy render: {e:#}"))?;
    let mut login_sites: Vec<LoginSiteConfig> = Vec::with_capacity(tenants.0.len());
    for tenant_name in tenants.0.keys() {
        let fqdn_str = format!("auth.{tenant_name}.{}", cfg.domain);
        let fqdn = Fqdn::new(fqdn_str.clone())
            .map_err(|e| anyhow!("derive login fqdn {fqdn_str}: {e}"))?;
        login_sites.push(LoginSiteConfig {
            fqdn,
            upstream: cfg.login_listen.clone(),
        });
    }

    let input = CaddyInput {
        global: GlobalConfig {
            admin_listen: cfg.caddy_admin.clone(),
            email: cfg.acme_email.clone(),
            log_path: cfg.caddy_log.display().to_string(),
        },
        auth_endpoint: AuthEndpointConfig {
            upstream: cfg.auth_listen.clone(),
        },
        login_sites,
        services: sites,
    };
    supervisor.render_and_reload(&input).await
}
