//! Ed25519-signed session token envelopes.
//!
//! Wire format:
//! ```text
//! base64url_no_pad(payload_bytes) ++ "." ++ base64url_no_pad(signature_bytes)
//! ```
//!
//! `payload_bytes` is the postcard-serialized [`SessionTokenPayload`]. Before
//! signing, we prepend a 1-byte zero-terminated domain separator
//! (`b"tuntun-session-v1\0"`) to defeat cross-protocol attacks: a signature
//! over a session token can never be confused with a signature over a tunnel
//! challenge or any other message family.
//!
//! Signing is deterministic (Ed25519 RFC 8032 nonces), so the same payload
//! always produces the same token under the same key. Verification is constant
//! time relative to signature validity — `ed25519-dalek::verify_strict`
//! handles that internally.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tuntun_core::{Error as CoreError, Nonce, TenantId, Timestamp};

/// Domain separator for session-token signatures. The trailing NUL keeps it
/// disjoint from any longer message that happens to start with the same bytes.
pub const SESSION_DOMAIN_SEPARATOR: &[u8] = b"tuntun-session-v1\0";

/// Plaintext payload signed inside a session token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTokenPayload {
    pub tenant: TenantId,
    pub label: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub nonce: Nonce,
}

/// Wire-format signed session token: `payload.signature`, both base64url-no-pad.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedSessionToken(String);

impl SignedSessionToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// Wrap a raw string as a session token. The contents are not validated
    /// here — call [`verify_session_token`] before trusting them.
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session token: postcard serialization: {0}")]
    Postcard(String),
    #[error("session token: malformed wire format")]
    MalformedWire,
    #[error("session token: invalid base64")]
    InvalidBase64,
    #[error("session token: invalid signature length")]
    InvalidSignatureLength,
    #[error("session token: signature verification failed")]
    BadSignature,
    #[error("session token: expired (now={now}, expires_at={expires_at})")]
    Expired { now: i64, expires_at: i64 },
    #[error("session token: issued in the future (now={now}, issued_at={issued_at})")]
    IssuedInFuture { now: i64, issued_at: i64 },
    #[error("session token: invalid temporal range (issued_at={issued_at} > expires_at={expires_at})")]
    BadRange { issued_at: i64, expires_at: i64 },
}

impl From<SessionError> for CoreError {
    fn from(value: SessionError) -> Self {
        CoreError::auth(value.to_string())
    }
}

fn encode_payload(payload: &SessionTokenPayload) -> Result<Vec<u8>, SessionError> {
    postcard::to_allocvec(payload).map_err(|e| SessionError::Postcard(e.to_string()))
}

fn decode_payload(bytes: &[u8]) -> Result<SessionTokenPayload, SessionError> {
    postcard::from_bytes(bytes).map_err(|e| SessionError::Postcard(e.to_string()))
}

fn sign_input(payload_bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SESSION_DOMAIN_SEPARATOR.len() + payload_bytes.len());
    buf.extend_from_slice(SESSION_DOMAIN_SEPARATOR);
    buf.extend_from_slice(payload_bytes);
    buf
}

/// Sign a session-token payload deterministically.
///
/// Errors only if the payload fails to serialize via postcard. Ed25519 signing
/// itself cannot fail for a 32-byte signing key on bounded-length input.
pub fn sign_session_token(
    key: &SigningKey,
    payload: &SessionTokenPayload,
) -> Result<SignedSessionToken, SessionError> {
    let payload_bytes = encode_payload(payload)?;
    let sig: Signature = key.sign(&sign_input(&payload_bytes));
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(SignedSessionToken(format!("{payload_b64}.{sig_b64}")))
}

/// Verify a signed session token: signature, expiry, and temporal sanity.
///
/// Returns the parsed payload on success. The signature check uses
/// `verify_strict`, which rejects the malleable encoding described in
/// [RFC 8032 §5.1.7].
///
/// `now` comes from the caller's `ClockPort`. We refuse tokens whose
/// `expires_at <= now` and whose `issued_at > now`. Tokens with
/// `issued_at > expires_at` are rejected as malformed.
pub fn verify_session_token(
    verifying_key: &VerifyingKey,
    token: &SignedSessionToken,
    now: Timestamp,
) -> Result<SessionTokenPayload, SessionError> {
    let (payload_b64, sig_b64) = token
        .as_str()
        .split_once('.')
        .ok_or(SessionError::MalformedWire)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| SessionError::InvalidBase64)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| SessionError::InvalidBase64)?;

    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(SessionError::InvalidSignatureLength);
    }
    let mut sig_array = [0u8; SIGNATURE_LENGTH];
    sig_array.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_array);

    verifying_key
        .verify_strict(&sign_input(&payload_bytes), &sig)
        .map_err(|_| SessionError::BadSignature)?;

    let payload = decode_payload(&payload_bytes)?;

    if payload.issued_at.seconds > payload.expires_at.seconds {
        return Err(SessionError::BadRange {
            issued_at: payload.issued_at.seconds,
            expires_at: payload.expires_at.seconds,
        });
    }
    if now.seconds < payload.issued_at.seconds {
        return Err(SessionError::IssuedInFuture {
            now: now.seconds,
            issued_at: payload.issued_at.seconds,
        });
    }
    if now.seconds >= payload.expires_at.seconds {
        return Err(SessionError::Expired {
            now: now.seconds,
            expires_at: payload.expires_at.seconds,
        });
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sample_payload() -> SessionTokenPayload {
        SessionTokenPayload {
            tenant: TenantId::new("jm").expect("tenant"),
            label: "laptop".to_string(),
            issued_at: Timestamp::from_seconds(1_000),
            expires_at: Timestamp::from_seconds(2_000),
            nonce: Nonce::from_bytes([9u8; 32]),
        }
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let sk = fixed_signing_key();
        let payload = sample_payload();
        let token = sign_session_token(&sk, &payload).expect("sign");
        let got = verify_session_token(&sk.verifying_key(), &token, Timestamp::from_seconds(1_500))
            .expect("verify");
        assert_eq!(got, payload);
    }

    #[test]
    fn signing_is_deterministic() {
        let sk = fixed_signing_key();
        let payload = sample_payload();
        let a = sign_session_token(&sk, &payload).expect("a");
        let b = sign_session_token(&sk, &payload).expect("b");
        assert_eq!(a, b);
    }

    #[test]
    fn token_has_two_dot_separated_segments() {
        let sk = fixed_signing_key();
        let payload = sample_payload();
        let token = sign_session_token(&sk, &payload).expect("sign");
        let parts: Vec<&str> = token.as_str().split('.').collect();
        assert_eq!(parts.len(), 2);
        assert!(!parts[0].is_empty());
        assert!(!parts[1].is_empty());
    }

    #[test]
    fn verify_rejects_expired_token() {
        let sk = fixed_signing_key();
        let payload = sample_payload();
        let token = sign_session_token(&sk, &payload).expect("sign");
        let err =
            verify_session_token(&sk.verifying_key(), &token, Timestamp::from_seconds(2_000))
                .unwrap_err();
        assert!(matches!(err, SessionError::Expired { .. }));
    }

    #[test]
    fn verify_rejects_token_at_exact_expiry() {
        let sk = fixed_signing_key();
        let payload = sample_payload();
        let token = sign_session_token(&sk, &payload).expect("sign");
        // expires_at is exclusive: now == expires_at must fail.
        let err =
            verify_session_token(&sk.verifying_key(), &token, Timestamp::from_seconds(2_000))
                .unwrap_err();
        assert!(matches!(err, SessionError::Expired { .. }));
    }

    #[test]
    fn verify_accepts_token_one_second_before_expiry() {
        let sk = fixed_signing_key();
        let payload = sample_payload();
        let token = sign_session_token(&sk, &payload).expect("sign");
        verify_session_token(&sk.verifying_key(), &token, Timestamp::from_seconds(1_999))
            .expect("just under expiry");
    }

    #[test]
    fn verify_rejects_token_issued_in_future() {
        let sk = fixed_signing_key();
        let payload = sample_payload();
        let token = sign_session_token(&sk, &payload).expect("sign");
        let err = verify_session_token(&sk.verifying_key(), &token, Timestamp::from_seconds(500))
            .unwrap_err();
        assert!(matches!(err, SessionError::IssuedInFuture { .. }));
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let sk = fixed_signing_key();
        let payload = sample_payload();
        let token = sign_session_token(&sk, &payload).expect("sign");
        // Flip the last char of the signature segment to corrupt it.
        let s = token.as_str();
        let mut bytes = s.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let corrupted =
            SignedSessionToken(String::from_utf8(bytes).expect("ascii"));
        let err = verify_session_token(
            &sk.verifying_key(),
            &corrupted,
            Timestamp::from_seconds(1_500),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SessionError::BadSignature | SessionError::InvalidSignatureLength
        ));
    }

    #[test]
    fn verify_rejects_signature_from_different_key() {
        let sk_a = fixed_signing_key();
        let sk_b = SigningKey::from_bytes(&[8u8; 32]);
        let payload = sample_payload();
        let token = sign_session_token(&sk_a, &payload).expect("sign");
        let err =
            verify_session_token(&sk_b.verifying_key(), &token, Timestamp::from_seconds(1_500))
                .unwrap_err();
        assert!(matches!(err, SessionError::BadSignature));
    }

    #[test]
    fn verify_rejects_malformed_wire() {
        let sk = fixed_signing_key();
        let bad = SignedSessionToken("nodothere".to_string());
        let err =
            verify_session_token(&sk.verifying_key(), &bad, Timestamp::from_seconds(1_500))
                .unwrap_err();
        assert!(matches!(err, SessionError::MalformedWire));
    }

    #[test]
    fn verify_rejects_invalid_base64() {
        let sk = fixed_signing_key();
        let bad = SignedSessionToken("!!!.???".to_string());
        let err =
            verify_session_token(&sk.verifying_key(), &bad, Timestamp::from_seconds(1_500))
                .unwrap_err();
        assert!(matches!(err, SessionError::InvalidBase64));
    }

    #[test]
    fn verify_rejects_signature_with_wrong_length() {
        let sk = fixed_signing_key();
        let payload = sample_payload();
        let payload_bytes = encode_payload(&payload).expect("encode");
        // Build a token whose signature segment decodes to <64 bytes.
        let token = SignedSessionToken(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload_bytes),
            URL_SAFE_NO_PAD.encode([0u8; 16])
        ));
        let err =
            verify_session_token(&sk.verifying_key(), &token, Timestamp::from_seconds(1_500))
                .unwrap_err();
        assert!(matches!(err, SessionError::InvalidSignatureLength));
    }

    #[test]
    fn verify_rejects_token_signed_for_different_domain() {
        // Construct a token whose signature is computed without the session
        // domain separator. It must fail verification: this exercises the
        // domain-separation guarantee.
        let sk = fixed_signing_key();
        let payload = sample_payload();
        let payload_bytes = encode_payload(&payload).expect("encode");
        let sig: Signature = sk.sign(&payload_bytes); // no domain separator!
        let token = SignedSessionToken(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload_bytes),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        ));
        let err =
            verify_session_token(&sk.verifying_key(), &token, Timestamp::from_seconds(1_500))
                .unwrap_err();
        assert!(matches!(err, SessionError::BadSignature));
    }

    #[test]
    fn payload_with_different_tenant_changes_signature() {
        let sk = fixed_signing_key();
        let mut a = sample_payload();
        let mut b = sample_payload();
        a.tenant = TenantId::new("alpha").expect("alpha");
        b.tenant = TenantId::new("beta").expect("beta");
        let ta = sign_session_token(&sk, &a).expect("ta");
        let tb = sign_session_token(&sk, &b).expect("tb");
        assert_ne!(ta, tb);
    }

    #[test]
    fn token_serializes_transparently() {
        let sk = fixed_signing_key();
        let payload = sample_payload();
        let token = sign_session_token(&sk, &payload).expect("sign");
        let json = serde_json::to_string(&token).expect("ser");
        assert!(json.starts_with('"'));
        let back: SignedSessionToken = serde_json::from_str(&json).expect("de");
        assert_eq!(back, token);
    }
}
