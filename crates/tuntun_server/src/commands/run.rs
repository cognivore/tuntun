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

    // Load (or generate) the server's session-token signing key.
    let signing_key = Arc::new(load_or_generate_signing_key(&cfg).await?);

    // Boot Caddy.
    supervisor.launch().await?;

    // Auth endpoint (axum).
    let auth_state = Arc::new(AuthState::new(cfg.clone(), signing_key));
    let auth_listen = cfg.auth_listen.clone();
    let auth_state_for_serve = auth_state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::auth_endpoint::serve(&auth_listen, auth_state_for_serve).await {
            tracing::error!("auth endpoint: {e:#}");
        }
    });

    // DNS reconciler.
    let reconciler = Arc::new(Reconciler::new(cfg.clone(), registry.clone(), dns));
    tokio::spawn(async move {
        if let Err(e) = reconciler.run_forever().await {
            tracing::error!("dns reconciler: {e:#}");
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

async fn load_or_generate_signing_key(cfg: &ServerConfig) -> Result<SigningKey> {
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};

    let path = cfg.state_dir.join("server-signing-key.pem");
    if let Ok(bytes) = tokio::fs::read(&path).await {
        let pem =
            std::str::from_utf8(&bytes).context("server-signing-key.pem is not utf-8")?;
        let sk = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| anyhow::anyhow!("parse signing key: {e}"))?;
        tracing::info!("loaded server signing key from {}", path.display());
        return Ok(sk);
    }

    tokio::fs::create_dir_all(&cfg.state_dir)
        .await
        .with_context(|| format!("mkdir {}", cfg.state_dir.display()))?;

    let mut csprng = rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut csprng);
    let pem = sk
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("encode signing key as PKCS8 PEM: {e}"))?;
    tokio::fs::write(&path, pem.as_bytes())
        .await
        .with_context(|| format!("write {}", path.display()))?;
    tracing::warn!(
        "generated new server signing key at {} (back this up)",
        path.display()
    );
    Ok(sk)
}
