//! Client-side TLS configuration with SHA-256 server-cert pinning.
//!
//! The server uses a self-signed certificate. Each laptop is configured with
//! the cert's SHA-256 fingerprint; this module builds a `rustls::ClientConfig`
//! whose verifier accepts ANY chain so long as the leaf certificate's DER
//! bytes hash to the pinned fingerprint. Constant-time comparison via
//! `subtle`.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use tuntun_core::Fingerprint;

/// Verifier that pins by SHA-256 fingerprint of the leaf certificate's DER
/// bytes.
#[derive(Debug)]
pub struct PinnedFingerprintVerifier {
    pub expected: Fingerprint,
}

impl PinnedFingerprintVerifier {
    pub fn new(expected: Fingerprint) -> Self {
        Self { expected }
    }

    fn matches(&self, leaf_der: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(leaf_der);
        let actual = hasher.finalize();
        // Constant-time compare.
        actual.as_slice().ct_eq(&self.expected.0).into()
    }
}

impl ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.matches(end_entity.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate fingerprint mismatch".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a [`ClientConfig`] that pins the server cert by `fingerprint`.
pub fn build_pinned_client_config(fingerprint: Fingerprint) -> ClientConfig {
    let verifier = Arc::new(PinnedFingerprintVerifier::new(fingerprint));
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_same_bytes() {
        let der = [0xABu8; 32];
        let mut hasher = Sha256::new();
        hasher.update(der);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        let v = PinnedFingerprintVerifier::new(Fingerprint(bytes));
        assert!(v.matches(&der));
    }

    #[test]
    fn rejects_different_bytes() {
        let der_a = [0xABu8; 32];
        let der_b = [0xCDu8; 32];
        let mut hasher = Sha256::new();
        hasher.update(der_a);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        let v = PinnedFingerprintVerifier::new(Fingerprint(bytes));
        assert!(!v.matches(&der_b));
    }

    #[derive(Debug)]
    struct CertificateResolver(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for CertificateResolver {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    async fn handshake(forged: bool, version: &'static rustls::SupportedProtocolVersion) -> bool {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let legitimate =
            rcgen::generate_simple_self_signed(vec!["tuntun.invalid".into()]).expect("certificate");
        let impostor = rcgen::generate_simple_self_signed(vec!["tuntun.invalid".into()])
            .expect("impostor certificate");
        let digest: [u8; 32] = Sha256::digest(legitimate.cert.der()).into();
        let key = if forged {
            &impostor.key_pair
        } else {
            &legitimate.key_pair
        };
        let signing_key = rustls::crypto::ring::sign::any_supported_type(
            &rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .expect("signing key");
        // A custom resolver lets an adversary present the pinned public
        // certificate while signing with a different private key.
        let certificate =
            rustls::sign::CertifiedKey::new(vec![legitimate.cert.der().clone()], signing_key);
        let server = rustls::ServerConfig::builder_with_protocol_versions(&[version])
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(CertificateResolver(Arc::new(certificate))));
        let client = build_pinned_client_config(Fingerprint(digest));
        let (client_io, server_io) = tokio::io::duplex(16_384);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let (connected, _) = tokio::join!(
            connector.connect(
                ServerName::try_from("tuntun.invalid").expect("server name"),
                client_io
            ),
            acceptor.accept(server_io),
        );
        connected.is_ok()
    }

    #[tokio::test]
    async fn pinned_certificate_still_requires_its_private_key() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            assert!(
                handshake(false, version).await,
                "legitimate server connects"
            );
            assert!(
                !handshake(true, version).await,
                "forged handshake must fail"
            );
        }
    }
}
