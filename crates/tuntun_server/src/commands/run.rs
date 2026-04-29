//! `tuntun-server run` -- the long-running daemon entry point.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;

use tuntun_core::SecretKey;
use tuntun_core::SecretPort;
use tuntun_dns::{PorkbunCreds, PorkbunDns};

use crate::adapters::http::ReqwestHttp;
use crate::adapters::secret::CredentialDirSecrets;
use crate::auth_endpoint::AuthState;
use crate::caddy_supervisor::CaddySupervisor;
use crate::config::ServerConfig;
use crate::dns_reconciler::Reconciler;
use crate::registry::Registry;
use crate::tls::load_or_generate;
use crate::tunnel::acceptor::Acceptor;
use crate::tunnel::bastion;

pub async fn run(config: Option<&Path>) -> Result<()> {
    let cfg = Arc::new(ServerConfig::load(config).await?);
    tracing::info!(
        "tuntun-server starting (domain={}, tunnel={})",
        cfg.domain,
        cfg.tunnel_listen
    );

    // Wire adapters.
    let http = Arc::new(ReqwestHttp::new()?);
    let secrets = CredentialDirSecrets;
    let registry = Arc::new(Registry::new(20_000));
    let supervisor = Arc::new(CaddySupervisor::new(cfg.clone()));

    // Load Porkbun creds via the credential-directory adapter.
    let porkbun_api = secrets
        .load(&SecretKey::new("porkbun-api-key").context("invalid secret key")?)
        .await?;
    let porkbun_secret = secrets
        .load(&SecretKey::new("porkbun-secret-key").context("invalid secret key")?)
        .await?;
    let creds = PorkbunCreds::new(porkbun_api, porkbun_secret);
    let dns = Arc::new(PorkbunDns::new(http.clone(), creds));

    // Load (or generate) TLS material.
    let tls_material = load_or_generate(&cfg).await?;
    let tls_handle = Arc::new(tls_material.into_acceptor()?);

    // Load the server's session-token signing key. The path comes from a
    // systemd LoadCredential, materialized into ${CREDENTIALS_DIRECTORY}/
    // server-signing-key. We refuse to start without it — silently
    // auto-generating would invalidate every issued session on every restart
    // that lost the file, which is the kind of thing you'd rather find out
    // about loudly.
    let signing_key = Arc::new(load_signing_key(&secrets).await?);

    // Boot Caddy.
    supervisor.launch().await?;

    // Auth endpoint (axum). The same router handles both `/verify` (called
    // by Caddy's `forward_auth` from the inside) and `/login` / `/logout`
    // (proxied through Caddy from the per-tenant `auth.<tenant>.<domain>`
    // sites). We bind both `auth_listen` and `login_listen` so the same
    // routes are reachable on either port — the upstreams in the Caddyfile
    // point at the right one for each role.
    let auth_state = Arc::new(AuthState::new(cfg.clone(), signing_key));
    let auth_listen = cfg.auth_listen.clone();
    let login_listen = cfg.login_listen.clone();
    let auth_state_a = auth_state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::auth_endpoint::serve(&auth_listen, auth_state_a).await {
            tracing::error!("auth endpoint (auth_listen): {e:#}");
        }
    });
    if login_listen != cfg.auth_listen {
        let auth_state_b = auth_state.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::auth_endpoint::serve(&login_listen, auth_state_b).await {
                tracing::error!("auth endpoint (login_listen): {e:#}");
            }
        });
    }

    // DNS reconciler.
    let reconciler = Arc::new(Reconciler::new(cfg.clone(), registry.clone(), dns));
    tokio::spawn(async move {
        if let Err(e) = reconciler.run_forever().await {
            tracing::error!("dns reconciler: {e:#}");
        }
    });

    // SSH bastion side-car. The bastion sshd's `ForceCommand` helper
    // (`tuntun-server tcp-forward <tenant>`) connects to this unix socket;
    // the listener routes the connection to the right tenant's tunnel via
    // the registry and a [`StreamOpenBuiltinFrame`].
    let bastion_socket = cfg.bastion_socket.clone();
    let bastion_registry = registry.clone();
    tokio::spawn(async move {
        if let Err(e) = bastion::run_listener(bastion_socket, bastion_registry).await {
            tracing::error!("ssh bastion: {e:#}");
        }
    });

    // Tunnel acceptor.
    let acceptor = Arc::new(Acceptor::new(
        cfg.clone(),
        registry.clone(),
        supervisor,
        tls_handle,
    ));
    acceptor.run().await
}

async fn load_signing_key(secrets: &CredentialDirSecrets) -> Result<SigningKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    let key = SecretKey::new("server-signing-key").context("invalid secret key")?;
    let value = secrets
        .load(&key)
        .await
        .context("load server-signing-key from systemd CREDENTIALS_DIRECTORY (configure services.tuntun-server.serverSigningKeyFile)")?;
    let pem = std::str::from_utf8(value.expose_bytes())
        .context("server-signing-key is not utf-8 PEM")?;
    SigningKey::from_pkcs8_pem(pem).map_err(|e| anyhow::anyhow!("parse signing key: {e}"))
}
