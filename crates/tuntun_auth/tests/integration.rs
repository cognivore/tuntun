//! Integration test for `tuntun_auth`. Exercises the full happy-path flow:
//!
//! 1. A tenant logs in: we hash their password, then verify it.
//! 2. The server issues a session token signed with its long-term key.
//! 3. The token round-trips through wire format and verifies cleanly.
//! 4. A separate tunnel client authenticates via challenge-response.
//! 5. A rate limiter throttles repeated login attempts.
//!
//! Pure: no clocks, no RNG, no I/O.

use ed25519_dalek::{Signer as _, SigningKey};
use tuntun_auth::{
    build_challenge_message, encode_cookie, hash_password, parse_cookie_header,
    sign_session_token, try_consume, verify_password, verify_session_token,
    verify_tunnel_signature, CookieAttrs, PasswordError, RateLimiterState, SameSitePolicy, Salt,
    SessionTokenPayload,
};
use tuntun_core::{Ed25519PublicKey, Ed25519Signature, Nonce, TenantId, Timestamp};

#[test]
fn end_to_end_login_and_session() {
    // (1) Register tenant: hash password with a per-tenant salt.
    let salt = Salt::from_bytes([0x42; 16]);
    let stored = hash_password(b"swordfish", &salt).expect("hash");
    // Later: tenant logs in with the right password.
    verify_password(&stored, b"swordfish").expect("login ok");
    // Wrong password is rejected.
    assert!(matches!(
        verify_password(&stored, b"hunter2").unwrap_err(),
        PasswordError::VerificationFailed
    ));

    // (2) Server signs a session token after successful login.
    let server_signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let payload = SessionTokenPayload {
        tenant: TenantId::new("jm").expect("tenant"),
        label: "session".to_string(),
        issued_at: Timestamp::from_seconds(1_000),
        expires_at: Timestamp::from_seconds(2_000),
        nonce: Nonce::from_bytes([3u8; 32]),
    };
    let token = sign_session_token(&server_signing_key, &payload).expect("sign");

    // (3) Token round-trips cleanly.
    let verified = verify_session_token(
        &server_signing_key.verifying_key(),
        &token,
        Timestamp::from_seconds(1_500),
    )
    .expect("verify");
    assert_eq!(verified, payload);

    // After expiry, it must fail.
    assert!(verify_session_token(
        &server_signing_key.verifying_key(),
        &token,
        Timestamp::from_seconds(2_001),
    )
    .is_err());
}

#[test]
fn end_to_end_tunnel_handshake() {
    // Tunnel client has a long-term Ed25519 keypair.
    let client_sk = SigningKey::from_bytes(&[9u8; 32]);
    let client_pk = Ed25519PublicKey::from_bytes(client_sk.verifying_key().to_bytes());

    // Server has the client's pubkey in its tenant's authorized_keys.
    let authorized = [client_pk];
    let tenant = TenantId::new("jm").expect("tenant");

    // Server issues a fresh nonce and the client signs.
    let nonce = Nonce::from_bytes([0xCD; 32]);
    let challenge = build_challenge_message(&nonce, &tenant);
    let raw_sig = client_sk.sign(&challenge);
    let sig = Ed25519Signature(raw_sig.to_bytes());

    // Server verifies the signature.
    let matched =
        verify_tunnel_signature(&authorized, &nonce, &tenant, &sig).expect("authorized");
    assert_eq!(*matched, client_pk);

    // A different tenant must reject the same signature.
    let other_tenant = TenantId::new("other").expect("other");
    assert!(verify_tunnel_signature(&authorized, &nonce, &other_tenant, &sig).is_err());
}

#[test]
fn cookie_round_trip_through_browser() {
    let attrs = CookieAttrs {
        domain: ".memorici.de".to_string(),
        path: "/".to_string(),
        max_age_seconds: 3_600,
        secure: true,
        http_only: true,
        same_site: SameSitePolicy::Lax,
    };
    let header = encode_cookie("session", "abc123", &attrs);

    // The browser would echo back the first segment in `Cookie:`.
    let browser_echo = header
        .split(';')
        .next()
        .expect("at least one segment")
        .to_string();
    let parsed = parse_cookie_header(&browser_echo);
    assert_eq!(parsed.get("session").map(String::as_str), Some("abc123"));
}

#[test]
fn rate_limiter_locks_out_burst_then_recovers() {
    let mut bucket = RateLimiterState::defaults_at(Timestamp::from_seconds(0));
    for _ in 0..5 {
        try_consume(&mut bucket, Timestamp::from_seconds(0), 1.0).expect("admit");
    }
    // Next attempt is denied with a positive retry-after.
    let err = try_consume(&mut bucket, Timestamp::from_seconds(0), 1.0).unwrap_err();
    assert!(err.retry_after_seconds > 0);

    // 30 seconds later, exactly one more attempt is admitted.
    try_consume(&mut bucket, Timestamp::from_seconds(30), 1.0).expect("after refill");
    assert!(try_consume(&mut bucket, Timestamp::from_seconds(30), 1.0).is_err());
}
