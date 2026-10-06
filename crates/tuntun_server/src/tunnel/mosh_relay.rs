//! Mosh side-car: relay a tenant's public UDP ports into its tunnel.
//!
//! mosh runs its session over UDP, which the TCP bastion cannot carry. For
//! each port in a tenant's `moshPorts` range the server binds a public UDP
//! socket. The first datagram that arrives while no relay stream is open asks
//! the tenant's session for a [`BuiltinService::Mosh`] stream, exactly as the
//! SSH bastion asks for [`BuiltinService::Ssh`]. The session pumps that
//! stream to one end of an in-memory duplex; this module frames datagrams on
//! the other end with [`tuntun_proto::datagram`]. The laptop's daemon
//! exchanges them with `mosh-server` on `127.0.0.1:<same port>`.
//!
//! Replies go to the address that sent the most recent datagram, so a
//! roaming mosh client is followed the way a NAT would follow it. mosh
//! authenticates and encrypts every datagram end to end, so the relay never
//! needs to inspect them; a spoofed datagram can at worst divert replies
//! until the real client's next packet (mosh sends at least every 3 s).
//!
//! When the tunnel session ends, its pump drops the duplex. The next datagram
//! then opens a stream on whichever session is current, which is why a mosh
//! session survives a tunnel reconnect.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;

use tuntun_core::{MoshPort, TenantId};
use tuntun_proto::{encode_datagram, BuiltinService, DatagramBuffer, MAX_DATAGRAM_LEN};

use crate::config::MoshPortRange;
use crate::registry::Registry;
use crate::tunnel::per_service_listener::{OpenStreamRequest, OpenStreamSubject};

/// Capacity of the in-memory pipe between a UDP port and its tunnel stream.
const DUPLEX_CAPACITY: usize = 64 * 1024;

/// A write into the tunnel that stalls this long abandons the relay stream;
/// the next datagram opens a fresh one.
const UPLINK_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Bind every port of `range` and relay it into `tenant`'s tunnel. Returns
/// only on a socket failure, which the caller treats as fatal.
pub async fn run_tenant(
    tenant: TenantId,
    range: MoshPortRange,
    registry: Arc<Registry>,
) -> Result<()> {
    let mut ports = JoinSet::new();
    for port in range.ports() {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port.value()))
            .await
            .with_context(|| format!("bind mosh UDP port {port} for tenant {tenant}"))?;
        ports.spawn(run_port(
            tenant.clone(),
            port,
            Arc::new(socket),
            registry.clone(),
        ));
    }
    tracing::info!("mosh relay for tenant {tenant} on UDP {range}");
    ports
        .join_next()
        .await
        .context("mosh relay has no ports")?
        .context("mosh relay port panicked")??;
    Err(anyhow!("mosh relay port exited unexpectedly"))
}

/// The tunnel end of one UDP port: the duplex half we write datagrams into,
/// and the task that sends the laptop's replies back out of the socket.
struct Uplink {
    writer: WriteHalf<DuplexStream>,
    downlink: AbortOnDropHandle<()>,
}

impl Uplink {
    fn is_closed(&self) -> bool {
        self.downlink.is_finished()
    }

    async fn send(&mut self, datagram: &[u8]) -> Result<()> {
        let framed = encode_datagram(datagram).context("frame datagram")?;
        tokio::time::timeout(UPLINK_WRITE_TIMEOUT, async {
            self.writer.write_all(&framed).await?;
            self.writer.flush().await
        })
        .await
        .context("tunnel write timed out")?
        .context("tunnel write")
    }
}

async fn run_port(
    tenant: TenantId,
    port: MoshPort,
    socket: Arc<UdpSocket>,
    registry: Arc<Registry>,
) -> Result<()> {
    let (peer_tx, peer_rx) = watch::channel(None);
    let mut uplink: Option<Uplink> = None;
    // A waiting mosh client retries for as long as the laptop is offline;
    // report the outage once rather than once per datagram.
    let mut dropping = false;
    let mut buf = vec![0u8; MAX_DATAGRAM_LEN];
    loop {
        let (len, from) = socket
            .recv_from(&mut buf)
            .await
            .with_context(|| format!("receive on mosh UDP port {port}"))?;
        peer_tx.send_replace(Some(from));
        if uplink.as_ref().is_some_and(Uplink::is_closed) {
            uplink = None;
        }
        if uplink.is_none() {
            match open_uplink(&tenant, port, &registry, socket.clone(), peer_rx.clone()).await {
                Ok(opened) => {
                    uplink = Some(opened);
                    dropping = false;
                }
                Err(e) => {
                    if !dropping {
                        tracing::debug!(
                            "mosh {tenant}:{port}: dropping datagrams from {from}: {e:#}"
                        );
                        dropping = true;
                    }
                    continue;
                }
            }
        }
        if let Some(open) = uplink.as_mut() {
            if let Err(e) = open.send(&buf[..len]).await {
                tracing::debug!("mosh {tenant}:{port}: relay stream lost: {e:#}");
                uplink = None;
            }
        }
    }
}

async fn open_uplink(
    tenant: &TenantId,
    port: MoshPort,
    registry: &Arc<Registry>,
    socket: Arc<UdpSocket>,
    peer: watch::Receiver<Option<SocketAddr>>,
) -> Result<Uplink> {
    let client = registry
        .lookup_by_tenant(tenant)
        .await
        .ok_or_else(|| anyhow!("no tunnel connected for tenant {tenant}"))?;
    let (ours, theirs) = tokio::io::duplex(DUPLEX_CAPACITY);
    // The session reports the stream's outcome only once it ends; the
    // closed duplex already tells us that, so the receiver is unused.
    let (ack, _ack_rx) = oneshot::channel();
    client
        .stream_tx
        .try_send(OpenStreamRequest {
            subject: OpenStreamSubject::Builtin(BuiltinService::Mosh { port }),
            inbound: Box::new(theirs),
            ack,
        })
        .map_err(|_| anyhow!("tenant {tenant} session is closed or saturated"))?;
    tracing::debug!("mosh {tenant}:{port}: opened relay stream");
    let (reader, writer) = tokio::io::split(ours);
    let downlink = AbortOnDropHandle::new(tokio::spawn(run_downlink(reader, socket, peer, port)));
    Ok(Uplink { writer, downlink })
}

/// Send each datagram the laptop returns to the latest client address,
/// until the tunnel stream closes.
async fn run_downlink(
    mut reader: ReadHalf<DuplexStream>,
    socket: Arc<UdpSocket>,
    peer: watch::Receiver<Option<SocketAddr>>,
    port: MoshPort,
) {
    let mut inbox = DatagramBuffer::new();
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        while let Some(datagram) = inbox.try_pop() {
            let to = *peer.borrow();
            if let Some(to) = to {
                // UDP is lossy by contract; mosh retransmits.
                if let Err(e) = socket.send_to(&datagram, to).await {
                    tracing::debug!("mosh port {port}: send to {to}: {e}");
                }
            }
        }
        match reader.read(&mut chunk).await {
            Ok(0) => return,
            Ok(n) => inbox.push(&chunk[..n]),
            Err(e) => {
                tracing::debug!("mosh port {port}: relay stream read: {e}");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;
    use tuntun_core::TunnelClientId;

    use super::*;
    use crate::registry::ClientRecord;

    fn client_for(tenant: &TenantId) -> (ClientRecord, mpsc::Receiver<OpenStreamRequest>) {
        let (stream_tx, stream_rx) = mpsc::channel(4);
        let record = ClientRecord {
            client_id: TunnelClientId::new(format!("laptop-{tenant}")).expect("client id"),
            tenant: tenant.clone(),
            stream_tx,
            cancelled: CancellationToken::new(),
            projects: BTreeMap::new(),
        };
        (record, stream_rx)
    }

    async fn next_stream(
        rx: &mut mpsc::Receiver<OpenStreamRequest>,
    ) -> Box<dyn crate::tunnel::per_service_listener::DuplexStream> {
        let request = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("stream requested in time")
            .expect("session open");
        assert!(matches!(
            request.subject,
            OpenStreamSubject::Builtin(BuiltinService::Mosh { port }) if port.value() == 60_000
        ));
        request.inbound
    }

    async fn read_datagram(
        stream: &mut Box<dyn crate::tunnel::per_service_listener::DuplexStream>,
    ) -> Vec<u8> {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.expect("length");
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut body).await.expect("body");
        body
    }

    /// A datagram crosses into the tunnel, the reply returns to the sender,
    /// and once the session drops the stream the next datagram reopens it on
    /// the current session.
    #[tokio::test]
    async fn datagrams_round_trip_and_survive_a_session_replacement() {
        let tenant = TenantId::new("alice").expect("tenant");
        let registry = Arc::new(Registry::new());
        let (first, mut first_rx) = client_for(&tenant);
        registry.upsert_client(first.clone()).await;

        let socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind"),
        );
        let relay_addr = socket.local_addr().expect("relay address");
        let port = MoshPort::new(60_000).expect("port");
        let _relay = AbortOnDropHandle::new(tokio::spawn(run_port(
            tenant.clone(),
            port,
            socket,
            registry.clone(),
        )));

        let mosh_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("client");
        mosh_client.connect(relay_addr).await.expect("connect");
        mosh_client.send(b"hello").await.expect("send");
        let mut stream = next_stream(&mut first_rx).await;
        assert_eq!(read_datagram(&mut stream).await, b"hello");

        stream
            .write_all(&encode_datagram(b"world").expect("frame"))
            .await
            .expect("reply");
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), mosh_client.recv(&mut buf))
            .await
            .expect("reply in time")
            .expect("recv");
        assert_eq!(&buf[..n], b"world");

        // The tunnel reconnects: the old session drops its pump, a new
        // session takes over the tenant.
        drop(stream);
        let (second, mut second_rx) = client_for(&tenant);
        registry.upsert_client(second).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        mosh_client
            .send(b"again")
            .await
            .expect("send after reconnect");
        let mut stream = next_stream(&mut second_rx).await;
        assert_eq!(read_datagram(&mut stream).await, b"again");
        assert!(first_rx.try_recv().is_err(), "stale session got no stream");
    }

    #[tokio::test]
    async fn datagrams_without_a_tunnel_are_dropped_not_fatal() {
        let tenant = TenantId::new("bob").expect("tenant");
        let registry = Arc::new(Registry::new());
        let socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind"),
        );
        let relay_addr = socket.local_addr().expect("relay address");
        let relay = tokio::spawn(run_port(
            tenant.clone(),
            MoshPort::new(60_000).expect("port"),
            socket,
            registry.clone(),
        ));
        let mosh_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("client");
        mosh_client
            .send_to(b"lost", relay_addr)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (record, mut rx) = client_for(&tenant);
        registry.upsert_client(record).await;
        mosh_client
            .send_to(b"kept", relay_addr)
            .await
            .expect("send");
        let mut stream = next_stream(&mut rx).await;
        assert_eq!(read_datagram(&mut stream).await, b"kept");
        assert!(!relay.is_finished());
        relay.abort();
    }
}
