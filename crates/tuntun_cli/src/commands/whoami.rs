use std::path::Path;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::SigningKey;

use tuntun_core::{SecretKey, SecretPort};

use crate::adapters::secret::PassveilSecrets;
use crate::config::DaemonConfig;

pub async fn run(config: Option<&Path>) -> Result<()> {
    let cfg = DaemonConfig::load(config).await?;
    let key_name = SecretKey::new(cfg.private_key_secret_name.clone())
        .map_err(|e| anyhow::anyhow!("invalid private_key_secret_name: {e}"))?;

    let secrets = PassveilSecrets::new();
    let value = secrets
        .load(&key_name)
        .await
        .context("load tunnel private key from passveil")?;

    let pem = std::str::from_utf8(value.expose_bytes())
        .context("private key is not utf-8")?;
    let signing = SigningKey::from_pkcs8_pem(pem)
        .context("parse PEM (regenerate with scripts/regen-client-keys.rs?)")?;
    let pub_b64 = STANDARD_NO_PAD.encode(signing.verifying_key().to_bytes());

    println!("ed25519:{pub_b64}");
    Ok(())
}
