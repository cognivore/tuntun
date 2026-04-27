//! TLS bootstrap for the tunnel acceptor.
//!
//! The server uses a self-signed certificate that clients pin by SHA-256
//! fingerprint. On first start we generate a fresh keypair via `rcgen`, write
//! the cert and key to `<state_dir>/server.{crt,key}`, log the fingerprint so
//! the operator can transcribe it onto each laptop, and reuse them on
//! subsequent boots.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, PrivateKeyDer};
use rustls::ServerConfig as RustlsServerConfig;
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;

use tuntun_core::Fingerprint;

use crate::config::ServerConfig;

/// On-disk filenames inside `state_dir`.
const CERT_FILE: &str = "server.crt";
const KEY_FILE: &str = "server.key";

/// Materials returned by [`load_or_generate`].
#[derive(Debug)]
pub struct TlsMaterial {
    pub cert_der: Vec<u8>,
    pub key_der_pkcs8: Vec<u8>,
    pub fingerprint: Fingerprint,
}

impl TlsMaterial {
    /// Build a [`TlsAcceptorHandle`] from these materials.
    pub fn into_acceptor(self) -> Result<TlsAcceptorHandle> {
        let cert = CertificateDer::from(self.cert_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der_pkcs8));

        let config = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| anyhow!("rustls server config: {e}"))?;
        Ok(TlsAcceptorHandle {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            fingerprint: self.fingerprint,
        })
    }
}

/// Handle to the TLS acceptor plus its public-key fingerprint, for sharing
/// across tasks via `Arc`.
pub struct TlsAcceptorHandle {
    pub acceptor: TlsAcceptor,
    pub fingerprint: Fingerprint,
}

impl std::fmt::Debug for TlsAcceptorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptorHandle")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

/// Load the server's TLS material, generating it on first run.
///
/// SAN entries default to the server's domain plus `localhost`. Clients
/// already bypass hostname verification (they pin by SHA-256), so the SANs
/// are mostly cosmetic — but we still want to produce a syntactically valid
/// certificate.
pub async fn load_or_generate(cfg: &ServerConfig) -> Result<TlsMaterial> {
    let state_dir = &cfg.state_dir;
    tokio::fs::create_dir_all(state_dir)
        .await
        .with_context(|| format!("create state dir {}", state_dir.display()))?;

    let cert_path = state_dir.join(CERT_FILE);
    let key_path = state_dir.join(KEY_FILE);

    if tokio::fs::metadata(&cert_path).await.is_ok()
        && tokio::fs::metadata(&key_path).await.is_ok()
    {
        load_existing(&cert_path, &key_path).await
    } else {
        generate_new(&cert_path, &key_path, &cfg.domain).await
    }
}

async fn load_existing(cert_path: &Path, key_path: &Path) -> Result<TlsMaterial> {
    let cert_pem = tokio::fs::read(cert_path)
        .await
        .with_context(|| format!("read cert {}", cert_path.display()))?;
    let key_pem = tokio::fs::read(key_path)
        .await
        .with_context(|| format!("read key {}", key_path.display()))?;

    let cert_der = pem_to_der(&cert_pem, "CERTIFICATE")
        .with_context(|| format!("parse cert PEM at {}", cert_path.display()))?;
    let key_der = pem_to_der(&key_pem, "PRIVATE KEY")
        .with_context(|| format!("parse key PEM at {}", key_path.display()))?;

    let fingerprint = compute_fingerprint(&cert_der);
    tracing::info!(
        "server TLS loaded; pin this on each laptop: {}",
        fingerprint.to_hex_with_prefix()
    );
    Ok(TlsMaterial {
        cert_der,
        key_der_pkcs8: key_der,
        fingerprint,
    })
}

async fn generate_new(cert_path: &PathBuf, key_path: &PathBuf, domain: &str) -> Result<TlsMaterial> {
    let sans: Vec<String> = vec![domain.to_string(), "localhost".to_string()];
    let ck = rcgen::generate_simple_self_signed(sans)
        .map_err(|e| anyhow!("rcgen generate: {e}"))?;

    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();

    atomic_write(cert_path, cert_pem.as_bytes()).await?;
    atomic_write(key_path, key_pem.as_bytes()).await?;

    let cert_der = ck.cert.der().to_vec();
    let key_der = ck.key_pair.serialize_der();

    let fingerprint = compute_fingerprint(&cert_der);
    tracing::warn!(
        "generated new self-signed server cert; pin on each laptop: {}",
        fingerprint.to_hex_with_prefix()
    );
    Ok(TlsMaterial {
        cert_der,
        key_der_pkcs8: key_der,
        fingerprint,
    })
}

fn compute_fingerprint(der: &[u8]) -> Fingerprint {
    let mut hasher = Sha256::new();
    hasher.update(der);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Fingerprint(out)
}

/// Extract the first PEM block matching `tag` and return its DER bytes.
fn pem_to_der(pem_bytes: &[u8], tag: &str) -> Result<Vec<u8>> {
    let s = std::str::from_utf8(pem_bytes).context("pem is not utf-8")?;
    let begin = format!("-----BEGIN {tag}-----");
    let end = format!("-----END {tag}-----");
    let after_begin = s
        .find(&begin)
        .ok_or_else(|| anyhow!("missing {begin}"))?
        + begin.len();
    let end_idx = s[after_begin..]
        .find(&end)
        .ok_or_else(|| anyhow!("missing {end}"))?
        + after_begin;
    let body: String = s[after_begin..end_idx]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD
        .decode(body.as_bytes())
        .map_err(|e| anyhow!("base64 decode {tag}: {e}"))
}

async fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}
