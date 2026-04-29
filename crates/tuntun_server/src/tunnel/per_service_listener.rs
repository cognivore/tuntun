//! Per-service public TCP listener and shared open-stream plumbing.
//!
//! Each registered tenant-declared service has a server-side TCP port that
//! Caddy proxies public traffic to. When a TCP connection arrives, the
//! listener task asks the owning tunnel session (via [`OpenStreamRequest`])
//! to allocate a fresh yamux outbound stream, send the matching control
//! frame, and pipe bytes between the public connection and the yamux stream.
//!
//! The same machinery is also used by the SSH bastion side-car: an inbound
//! unix-socket connection from the bastion `ForceCommand` is wrapped as an
//! [`OpenStreamRequest`] with [`OpenStreamSubject::Builtin`] and dispatched
//! through the same per-session opener task. That keeps yamux ownership
//! local to the session.

use std::io;
use std::net::SocketAddr;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use yamux::Stream as YamuxStream;

use tuntun_core::{ProjectId, ServiceName, ServicePort};
use tuntun_proto::{BuiltinService, ControlFrame, StreamOpenBuiltinFrame, StreamOpenFrame};

/// Trait alias for "a bidirectional byte stream we can pump through a yamux
/// stream". Implemented automatically for `tokio::net::TcpStream`,
/// `tokio::net::UnixStream`, and any other duplex transport.
pub(crate) trait DuplexStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> DuplexStream for T {}

/// Which kind of yamux stream the requester wants opened.
pub(crate) enum OpenStreamSubject {
    /// A tenant-declared service registered via `tuntun.nix`.
    Service {
        project: ProjectId,
        service: ServiceName,
    },
    /// A server-managed side-car (e.g., the SSH bastion).
    Builtin(BuiltinService),
}

/// Request sent to a session's stream-opener task to create a new outbound
/// yamux stream and pipe bytes between an inbound transport and that stream.
pub(crate) struct OpenStreamRequest {
    pub subject: OpenStreamSubject,
    pub inbound: Box<dyn DuplexStream>,
    /// Replier — we tell the requester whether the stream open ultimately
    /// succeeded so it can log meaningfully.
    pub ack: oneshot::Sender<Result<()>>,
}

/// Run the per-service public TCP listener. The listener exits when `tx` is
/// closed (i.e., the owning session has dropped).
pub async fn run_listener(
    project: ProjectId,
    service: ServiceName,
    server_port: ServicePort,
    tx: mpsc::Sender<OpenStreamRequest>,
) -> Result<()> {
    let addr: SocketAddr =
        format!("127.0.0.1:{}", server_port.value()).parse().map_err(
            |e| anyhow!("parse listen addr 127.0.0.1:{}: {e}", server_port.value()),
        )?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind public listener for service {service} on {addr}"))?;
    tracing::info!(
        "service {project}/{service} listening on {addr}"
    );

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("public accept on {addr}: {e}");
                continue;
            }
        };
        tracing::debug!("public connection on {addr} from {peer}");

        let (ack_tx, ack_rx) = oneshot::channel();
        let request = OpenStreamRequest {
            subject: OpenStreamSubject::Service {
                project: project.clone(),
                service: service.clone(),
            },
            inbound: Box::new(sock),
            ack: ack_tx,
        };
        if tx.send(request).await.is_err() {
            tracing::info!(
                "service {service} listener exiting: session closed"
            );
            return Ok(());
        }

        // We don't await the ack here — we move on to the next connection so
        // multiple in-flight streams can pile up. The session's task pumps
        // each one to completion in the background.
        let svc_log = service.clone();
        tokio::spawn(async move {
            match ack_rx.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!("stream {svc_log}: {e:#}"),
                Err(_) => tracing::debug!("stream {svc_log}: ack dropped"),
            }
        });
    }
}

/// Pump bytes between a yamux stream and an inbound duplex transport. Used by
/// the session task once the matching control frame has been emitted.
pub(crate) async fn pump_stream<S>(
    yamux_stream: YamuxStream,
    mut inbound: S,
) -> io::Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut yamux = yamux_stream.compat();
    tokio::io::copy_bidirectional(&mut yamux, &mut inbound).await
}

/// Helper: build a [`StreamOpenFrame`] for a tenant-declared service stream.
pub(crate) fn build_stream_open(
    stream_id: u32,
    project: &ProjectId,
    service: &ServiceName,
) -> ControlFrame {
    ControlFrame::StreamOpen(StreamOpenFrame {
        stream_id,
        project: project.clone(),
        service: service.clone(),
    })
}

/// Helper: build a [`StreamOpenBuiltinFrame`] for a side-car stream.
pub(crate) fn build_stream_open_builtin(
    stream_id: u32,
    kind: BuiltinService,
) -> ControlFrame {
    ControlFrame::StreamOpenBuiltin(StreamOpenBuiltinFrame { stream_id, kind })
}
