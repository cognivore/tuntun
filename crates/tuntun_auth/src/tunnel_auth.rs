//! Tunnel-client challenge-response authentication.
//!
//! Protocol:
//! 1. Server generates a 32-byte random [`Nonce`] (via `OsRng` in the binary)
//!    and sends it to the client along with the expected [`TenantId`].
//! 2. Client signs `domain_separator || nonce || tenant_id_bytes` with its
//!    long-term Ed25519 signing key and returns the signature.
//! 3. Server iterates over the per-tenant `authorized_keys` set and accepts
//!    the connection if any of those public keys validates the signature.
//!
//! The domain separator (`b"tuntun-tunnel-auth-v1\0"`) ensures that a client
//! signature over a tunnel challenge cannot be replayed as a signature over a
//! session token, a TLS handshake transcript, or any other message family.
//!
//! The verifier walks the entire authorized-keys list even after a match, so
//! the time taken is constant in the size of the set (modulo Ed25519's own
//! per-call variance).

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;
use tuntun_core::{Ed25519PublicKey, Ed25519Signature, Error as CoreError, Nonce, TenantId};

/// Domain separator for tunnel-client challenge signatures.
pub const TUNNEL_DOMAIN_SEPARATOR: &[u8] = b"tuntun-tunnel-auth-v1\0";

#[derive(Debug, Error)]
pub enum TunnelAuthError {
    #[error("tunnel auth: no authorized key matched")]
    NoMatchingKey,
    #[error("tunnel auth: invalid public key in authorized_keys")]
    InvalidAuthorizedKey,
}

impl From<TunnelAuthError> for CoreError {
    fn from(value: TunnelAuthError) -> Self {
        CoreError::auth(value.to_string())
    }
}

/// Build the exact byte sequence that is signed during tunnel handshake.
///
/// Used by both the client (to produce the signature) and the server (to
/// verify). Pure, no I/O.
pub fn build_challenge_message(nonce: &Nonce, tenant: &TenantId) -> Vec<u8> {
    let tenant_bytes = tenant.as_str().as_bytes();
    let mut buf =
        Vec::with_capacity(TUNNEL_DOMAIN_SEPARATOR.len() + nonce.0.len() + tenant_bytes.len());
    buf.extend_from_slice(TUNNEL_DOMAIN_SEPARATOR);
    buf.extend_from_slice(&nonce.0);
    buf.extend_from_slice(tenant_bytes);
    buf
}

/// Verify a tunnel client's challenge response against a set of authorized
/// public keys.
///
/// On success, returns a reference to the public key that matched. The verifier
/// continues to iterate after a match so its runtime is constant in the size
/// of the authorized set (give or take Ed25519's own per-call variance).
///
/// Returns [`TunnelAuthError::NoMatchingKey`] if no key in the set produced a
/// valid signature. Returns [`TunnelAuthError::InvalidAuthorizedKey`] if any
/// authorized-keys entry is structurally invalid (not a point on the curve).
pub fn verify_tunnel_signature<'a>(
    authorized_keys: &'a [Ed25519PublicKey],
    nonce: &Nonce,
    tenant: &TenantId,
    signature: &Ed25519Signature,
) -> Result<&'a Ed25519PublicKey, TunnelAuthError> {
    let message = build_challenge_message(nonce, tenant);
    let sig = Signature::from_bytes(&signature.0);

    let mut matched: Option<&Ed25519PublicKey> = None;
    for candidate in authorized_keys {
        let vk = VerifyingKey::from_bytes(&candidate.0)
            .map_err(|_| TunnelAuthError::InvalidAuthorizedKey)?;
        if vk.verify_strict(&message, &sig).is_ok() && matched.is_none() {
            matched = Some(candidate);
            // Don't break — keep walking so timing is constant in the set size.
        }
    }
    matched.ok_or(TunnelAuthError::NoMatchingKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn tenant() -> TenantId {
        TenantId::new("jm").expect("tenant")
    }

    fn nonce(byte: u8) -> Nonce {
        Nonce::from_bytes([byte; 32])
    }

    fn pubkey_from(sk: &SigningKey) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes(sk.verifying_key().to_bytes())
    }

    fn sign_challenge(sk: &SigningKey, n: &Nonce, t: &TenantId) -> Ed25519Signature {
        let msg = build_challenge_message(n, t);
        let sig: Signature = sk.sign(&msg);
        Ed25519Signature(sig.to_bytes())
    }

    #[test]
    fn challenge_message_layout() {
        let n = nonce(0xAA);
        let t = tenant();
        let msg = build_challenge_message(&n, &t);
        assert!(msg.starts_with(TUNNEL_DOMAIN_SEPARATOR));
        let after_dom = &msg[TUNNEL_DOMAIN_SEPARATOR.len()..];
        assert_eq!(&after_dom[..32], &n.0);
        assert_eq!(&after_dom[32..], t.as_str().as_bytes());
    }

    #[test]
    fn verify_accepts_authorized_key() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let n = nonce(0x11);
        let t = tenant();
        let sig = sign_challenge(&sk, &n, &t);
        let keys = [pubkey_from(&sk)];
        let matched = verify_tunnel_signature(&keys, &n, &t, &sig).expect("verify");
        assert_eq!(*matched, keys[0]);
    }

    #[test]
    fn verify_returns_correct_key_among_many() {
        let sk_a = SigningKey::from_bytes(&[1u8; 32]);
        let sk_b = SigningKey::from_bytes(&[2u8; 32]);
        let sk_c = SigningKey::from_bytes(&[3u8; 32]);
        let n = nonce(0x22);
        let t = tenant();
        let sig = sign_challenge(&sk_b, &n, &t);
        let keys = [pubkey_from(&sk_a), pubkey_from(&sk_b), pubkey_from(&sk_c)];
        let matched = verify_tunnel_signature(&keys, &n, &t, &sig).expect("verify");
        assert_eq!(*matched, keys[1]);
    }

    #[test]
    fn verify_rejects_unauthorized_key() {
        let sk_signer = SigningKey::from_bytes(&[1u8; 32]);
        let sk_other = SigningKey::from_bytes(&[2u8; 32]);
        let n = nonce(0x33);
        let t = tenant();
        let sig = sign_challenge(&sk_signer, &n, &t);
        let keys = [pubkey_from(&sk_other)];
        let err = verify_tunnel_signature(&keys, &n, &t, &sig).unwrap_err();
        assert!(matches!(err, TunnelAuthError::NoMatchingKey));
    }

    #[test]
    fn verify_rejects_empty_authorized_set() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let n = nonce(0x44);
        let t = tenant();
        let sig = sign_challenge(&sk, &n, &t);
        let err = verify_tunnel_signature(&[], &n, &t, &sig).unwrap_err();
        assert!(matches!(err, TunnelAuthError::NoMatchingKey));
    }

    #[test]
    fn verify_rejects_wrong_tenant() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let n = nonce(0x55);
        let t_signed = TenantId::new("alpha").expect("alpha");
        let t_check = TenantId::new("beta").expect("beta");
        let sig = sign_challenge(&sk, &n, &t_signed);
        let keys = [pubkey_from(&sk)];
        let err = verify_tunnel_signature(&keys, &n, &t_check, &sig).unwrap_err();
        assert!(matches!(err, TunnelAuthError::NoMatchingKey));
    }

    #[test]
    fn verify_rejects_wrong_nonce() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let n_signed = nonce(0xAA);
        let n_check = nonce(0xBB);
        let t = tenant();
        let sig = sign_challenge(&sk, &n_signed, &t);
        let keys = [pubkey_from(&sk)];
        let err = verify_tunnel_signature(&keys, &n_check, &t, &sig).unwrap_err();
        assert!(matches!(err, TunnelAuthError::NoMatchingKey));
    }

    #[test]
    fn verify_rejects_signature_with_wrong_domain_separator() {
        // Sign without the domain separator at all.
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let n = nonce(0x66);
        let t = tenant();
        let mut bare_msg = Vec::new();
        bare_msg.extend_from_slice(&n.0);
        bare_msg.extend_from_slice(t.as_str().as_bytes());
        let sig: Signature = sk.sign(&bare_msg);
        let sig_wrap = Ed25519Signature(sig.to_bytes());
        let keys = [pubkey_from(&sk)];
        let err = verify_tunnel_signature(&keys, &n, &t, &sig_wrap).unwrap_err();
        assert!(matches!(err, TunnelAuthError::NoMatchingKey));
    }

    #[test]
    fn verify_rejects_invalid_authorized_key_bytes() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let n = nonce(0x77);
        let t = tenant();
        let sig = sign_challenge(&sk, &n, &t);
        // 0xDD repeated 32 times fails Edwards point decompression.
        let bogus = Ed25519PublicKey::from_bytes([0xDDu8; 32]);
        let keys = [bogus];
        let err = verify_tunnel_signature(&keys, &n, &t, &sig).unwrap_err();
        assert!(matches!(err, TunnelAuthError::InvalidAuthorizedKey));
    }

    #[test]
    fn challenge_messages_with_different_inputs_differ() {
        let t = tenant();
        let m1 = build_challenge_message(&nonce(0x01), &t);
        let m2 = build_challenge_message(&nonce(0x02), &t);
        assert_ne!(m1, m2);
        let t2 = TenantId::new("other").expect("other");
        let m3 = build_challenge_message(&nonce(0x01), &t2);
        assert_ne!(m1, m3);
    }
}
