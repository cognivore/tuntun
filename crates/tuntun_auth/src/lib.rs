//! `tuntun_auth` -- cryptographic primitives and authentication state machines.
//!
//! This crate performs **zero I/O**. All clocks, randomness, and persistence
//! enter through arguments — never through `std::time` or `std::fs`.
//!
//! Modules:
//!
//! - [`password`]: Argon2id password hashing and verification.
//! - [`session`]: Ed25519-signed session token envelopes.
//! - [`tunnel_auth`]: Ed25519 challenge-response for tunnel clients.
//! - [`cookie`]: `Set-Cookie` and `Cookie:` header codec.
//! - [`rate_limit`]: Token-bucket rate limiter.
//!
//! See the workspace root `CLAUDE.md` for the full architectural contract,
//! particularly rules 1, 5, and 7.

pub mod cookie;
pub mod password;
pub mod rate_limit;
pub mod session;
pub mod tunnel_auth;

pub use cookie::{encode_cookie, parse_cookie_header, CookieAttrs, SameSitePolicy};
pub use password::{hash_password, verify_password, PasswordError, PasswordHashPhc, Salt};
pub use rate_limit::{try_consume, RateLimitedError, RateLimiterState};
pub use session::{
    sign_session_token, verify_session_token, SessionError, SessionTokenPayload, SignedSessionToken,
};
pub use tunnel_auth::{build_challenge_message, verify_tunnel_signature, TunnelAuthError};
