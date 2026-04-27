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

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::VerifyingKey;
use rand::rngs::OsRng;
use rand::RngCore as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
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
    ControlFrame, FrameBuffer, PongFrame, RegisteredFrame, ServiceAllocation, WelcomeFrame,
    PROTOCOL_VERSION,
};

use crate::caddy_supervisor::CaddySupervisor;
use crate::config::{ServerConfig, TenantsFileEntry};
use crate::registry::{ClientRecord, ProjectRecord, Registry, ServiceRecord};
use crate::tls::TlsAcceptorHandle;
use crate::tunnel::per_service_listener::{
    build_stream_open, pump_stream, run_listener, OpenStreamRequest,
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

    // 2. Yamux server connection. Wrap the tokio TLS stream so it implements
    // futures-io.
    let mut yamux_conn =
        YamuxConnection::new(tls_stream.compat(), YamuxConfig::default(), Mode::Server);

    // 3. The first inbound stream is the control stream.
    let control_stream = poll_fn(|cx| std::pin::Pin::new(&mut yamux_conn).poll_next_inbound(cx))
        .await
        .ok_or_else(|| anyhow!("client closed before opening control stream"))?
        .map_err(|e| anyhow!("yamux control stream accept: {e}"))?;
    let mut control = control_stream.compat();

    // 4. Receive Hello.
    let hello = read_one_frame(&mut control).await?;
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

    let response = read_one_frame(&mut control).await?;
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
    let register_frame = read_one_frame(&mut control).await?;
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
            let fqdn_str = format!("{}.{}", svc.subdomain.as_str(), config.domain);
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

    let client_record = ClientRecord {
        client_id: client_id.clone(),
        tenant: tenant.clone(),
        control_tx: control_tx.clone(),
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
    let (stream_tx, stream_rx) = mpsc::channel::<OpenStreamRequest>(64);
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
    drop(stream_tx); // listeners hold the only senders

    let yamux_arc = Arc::new(Mutex::new(yamux_conn));

    // 9. Inbound-stream driver: drain unexpected client-initiated streams to
    // keep the yamux state machine progressing. Returns when the connection
    // shuts down.
    let driver_yamux = yamux_arc.clone();
    let driver = tokio::spawn(async move {
        loop {
            let mut conn = driver_yamux.lock().await;
            let res = poll_fn(|cx| std::pin::Pin::new(&mut *conn).poll_next_inbound(cx)).await;
            drop(conn);
            match res {
                None => break,
                Some(Ok(stream)) => {
                    tracing::debug!("ignoring extra inbound yamux stream id={}", stream.id());
                    drop(stream);
                }
                Some(Err(e)) => {
                    tracing::debug!("yamux driver: inbound error: {e}");
                    break;
                }
            }
        }
    });

    // 10. Stream-opener loop: for each public connection, open an outbound
    // yamux stream, send a StreamOpen control frame, and pump bytes.
    let opener = tokio::spawn(stream_opener(
        yamux_arc.clone(),
        stream_rx,
        control_tx.clone(),
    ));

    // 11. Control IO: writer drains control_rx → control stream; reader
    // handles inbound Ping/Deregister frames.
    let writer_result = control_loop(&mut control, control_rx, control_tx).await;
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

async fn stream_opener(
    yamux_arc: Arc<Mutex<YamuxConnection<tokio_util::compat::Compat<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>>>>,
    mut stream_rx: mpsc::Receiver<OpenStreamRequest>,
    control_tx: mpsc::Sender<ControlFrame>,
) {
    while let Some(req) = stream_rx.recv().await {
        let mut conn = yamux_arc.lock().await;
        let outbound = match poll_fn(|cx| {
            std::pin::Pin::new(&mut *conn).poll_new_outbound(cx)
        })
        .await
        {
            Ok(s) => s,
            Err(e) => {
                let _ = req.ack.send(Err(anyhow!("yamux open_outbound: {e}")));
                continue;
            }
        };
        let stream_id = outbound.id().val();
        drop(conn);

        let frame = build_stream_open(stream_id, &req.project, &req.service);
        if control_tx.send(frame).await.is_err() {
            let _ = req.ack.send(Err(anyhow!("control channel closed")));
            continue;
        }

        let svc_for_log = req.service.clone();
        let proj_for_log = req.project.clone();
        let ack = req.ack;
        let tcp = req.tcp;
        tokio::spawn(async move {
            match pump_stream(outbound, tcp).await {
                Ok((up, down)) => {
                    tracing::debug!(
                        "stream {proj_for_log}/{svc_for_log} closed; up={up} down={down}"
                    );
                    let _ = ack.send(Ok(()));
                }
                Err(e) => {
                    tracing::debug!("stream {proj_for_log}/{svc_for_log} pump: {e}");
                    let _ = ack.send(Err(anyhow!("pump: {e}")));
                }
            }
        });
    }
    tracing::debug!("stream opener exiting (no more public connections)");
}

async fn control_loop<S>(
    control: &mut S,
    mut control_rx: mpsc::Receiver<ControlFrame>,
    control_tx: mpsc::Sender<ControlFrame>,
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
            inbound = read_one_frame_opt(control) => {
                match inbound? {
                    Some(ControlFrame::Ping(p)) => {
                        let pong = ControlFrame::Pong(PongFrame { nonce: p.nonce });
                        write_frame(control, &pong).await?;
                    }
                    Some(ControlFrame::Deregister(_)) => {
                        tracing::info!("client deregister received");
                        return Ok(());
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

fn generate_nonce() -> Nonce {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    Nonce::from_bytes(buf)
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

/// Read one frame; returns `Ok(None)` on clean EOF before any bytes.
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
            ProtoAuthPolicy::None => CaddyAuthPolicy::None,
        };
        let health_path = svc.health_check.as_ref().map(|h| h.path.clone());
        sites.push(ServiceSite {
            fqdn: svc.fqdn,
            upstream_port: svc.server_port,
            auth_policy: auth,
            health_check_path: health_path,
        });
    }

    let login_fqdn = Fqdn::new(format!("auth.{}", cfg.domain))
        .map_err(|e| anyhow!("derive login fqdn: {e}"))?;
    let input = CaddyInput {
        global: GlobalConfig {
            admin_listen: cfg.caddy_admin.clone(),
            email: cfg.acme_email.clone(),
            log_path: cfg.caddy_log.display().to_string(),
        },
        auth_endpoint: AuthEndpointConfig {
            upstream: cfg.auth_listen.clone(),
        },
        login_site: LoginSiteConfig {
            fqdn: login_fqdn,
            upstream: cfg.login_listen.clone(),
        },
        services: sites,
    };
    supervisor.render_and_reload(&input).await
}
