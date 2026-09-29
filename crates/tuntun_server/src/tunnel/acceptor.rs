//! TLS + yamux tunnel acceptor.
//!
//! Listens on `tunnel_listen`, terminates rustls, performs the ed25519
//! challenge-response (using `tuntun_auth::tunnel_auth::*`), validates the
//! client's public key against the server's authorized-keys set, then hands
//! the multiplexed connection off to a per-client session task.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::caddy_supervisor::CaddySupervisor;
use crate::config::ServerConfig;
use crate::registry::Registry;
use crate::tls::TlsAcceptorHandle;

#[derive(Debug)]
pub struct Acceptor {
    config: Arc<ServerConfig>,
    registry: Arc<Registry>,
    supervisor: Arc<CaddySupervisor>,
    tls: Arc<TlsAcceptorHandle>,
}

impl Acceptor {
    pub fn new(
        config: Arc<ServerConfig>,
        registry: Arc<Registry>,
        supervisor: Arc<CaddySupervisor>,
        tls: Arc<TlsAcceptorHandle>,
    ) -> Self {
        Self {
            config,
            registry,
            supervisor,
            tls,
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        let addr: SocketAddr = self
            .config
            .tunnel_listen
            .parse()
            .with_context(|| format!("parse tunnel_listen {}", self.config.tunnel_listen))?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("tunnel acceptor listening on {addr}");
        let slots = Arc::new(tokio::sync::Semaphore::new(128));

        loop {
            match listener.accept().await {
                Ok((sock, peer)) => {
                    let Ok(slot) = slots.clone().try_acquire_owned() else {
                        tracing::warn!(%peer, "tunnel session capacity reached");
                        continue;
                    };
                    tracing::info!("tunnel client connected from {peer}");
                    let registry = self.registry.clone();
                    let config = self.config.clone();
                    let supervisor = self.supervisor.clone();
                    let tls = self.tls.clone();
                    tokio::spawn(async move {
                        let _slot = slot;
                        if let Err(e) = super::session::handle_connection(
                            sock, peer, registry, config, supervisor, tls,
                        )
                        .await
                        {
                            tracing::warn!("session {peer} ended: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    return Err(e).context("tunnel accept failed");
                }
            }
        }
    }
}
