use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use tuntun_core::{SecretKey, SecretPort};
use tuntun_dns::{PorkbunCreds, PorkbunDns};

use crate::adapters::http::ReqwestHttp;
use crate::adapters::secret::CredentialDirSecrets;
use crate::config::ServerConfig;
use crate::dns_reconciler::Reconciler;
use crate::registry::Registry;

pub async fn run(config: Option<&Path>) -> Result<()> {
    let cfg = Arc::new(ServerConfig::load(config).await?);
    let http = Arc::new(ReqwestHttp::new()?);
    let secrets = CredentialDirSecrets;
    let api = secrets
        .load(&SecretKey::new("porkbun-api-key").context("api key id")?)
        .await?;
    let sec = secrets
        .load(&SecretKey::new("porkbun-secret-key").context("secret key id")?)
        .await?;
    let dns = Arc::new(PorkbunDns::new(http, PorkbunCreds::new(api, sec)));

    let registry = Arc::new(Registry::new(20_000));
    let reconciler = Reconciler::new(cfg, registry, dns);
    reconciler.reconcile_once().await
}
