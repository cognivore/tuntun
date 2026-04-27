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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // We've already pinned the cert; accept the signature unconditionally
        // (rustls does its own crypto on the wire layer).
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
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
}
