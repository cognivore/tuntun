//! Per-service public TCP listener.
//!
//! Each registered service has a server-side port that Caddy proxies public
//! traffic to. When a TCP connection arrives on that port, this task asks the
//! owning tunnel session to allocate a fresh yamux outbound stream, sends a
//! `StreamOpen` control frame so the client knows which service the stream
//! belongs to, and bidirectionally pipes bytes between the public TCP socket
//! and the yamux stream.

use std::io;
use std::net::SocketAddr;

use anyhow::{anyhow, Context, Result};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use yamux::Stream as YamuxStream;

use tuntun_core::{ProjectId, ServiceName, ServicePort};
use tuntun_proto::{ControlFrame, StreamOpenFrame};

/// Request sent to the session's stream-opener task to create a new outbound
/// yamux stream and forward bytes over it.
pub(crate) struct OpenStreamRequest {
    pub project: ProjectId,
    pub service: ServiceName,
    pub tcp: tokio::net::TcpStream,
    /// Replier — we tell the listener whether the stream open ultimately
    /// succeeded so it can log meaningfully.
    pub ack: oneshot::Sender<Result<()>>,
}

/// Run the per-service listener. The listener exits when `tx` is closed (i.e.
/// the owning session has dropped).
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
            project: project.clone(),
            service: service.clone(),
            tcp: sock,
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

/// Pump bytes between a yamux stream and a TCP connection. Used by the
/// session task once the control-plane `StreamOpen` frame has been emitted.
pub(crate) async fn pump_stream(
    yamux_stream: YamuxStream,
    tcp: tokio::net::TcpStream,
) -> io::Result<(u64, u64)> {
    let mut yamux = yamux_stream.compat();
    let mut tcp = tcp;
    tokio::io::copy_bidirectional(&mut yamux, &mut tcp).await
}

/// Helper: build a StreamOpenFrame from the components.
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
