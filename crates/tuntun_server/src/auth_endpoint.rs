//! Internal HTTP endpoints:
//!
//! - `GET /verify` — Caddy `forward_auth` target. Returns 200 if the
//!   request's session cookie verifies for the relevant tenant, else 401.
//! - `GET /login` — login form for end-users.
//! - `POST /login` — submit credentials; sets the session cookie on success.
//! - `GET /logout` — clears the cookie.
//! - `GET /healthz` — readiness probe.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Form, Router};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore as _;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use tuntun_auth::cookie::{encode_cookie, parse_cookie_header, CookieAttrs};
use tuntun_auth::password::{verify_password, PasswordHashPhc};
use tuntun_auth::rate_limit::{try_consume, RateLimiterState};
use tuntun_auth::session::{
    sign_session_token, verify_session_token, SessionTokenPayload, SignedSessionToken,
};
use tuntun_core::{Nonce, TenantId, Timestamp};

use crate::config::ServerConfig;

const SESSION_COOKIE_NAME: &str = "tuntun_session";
const SESSION_LIFETIME_SECONDS: i64 = 3_600;

#[derive(Debug)]
pub struct AuthState {
    pub config: Arc<ServerConfig>,
    pub signing_key: Arc<SigningKey>,
    /// Per-IP rate-limit buckets for the login endpoint.
    rate_limit: Mutex<BTreeMap<IpAddr, RateLimiterState>>,
}

impl AuthState {
    pub fn new(config: Arc<ServerConfig>, signing_key: Arc<SigningKey>) -> Self {
        Self {
            config,
            signing_key,
            rate_limit: Mutex::new(BTreeMap::new()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub redirect: Option<String>,
}

pub fn router(state: Arc<AuthState>) -> Router {
    Router::new()
        .route("/verify", get(verify))
        .route("/login", get(login_get).post(login_post))
        .route("/logout", get(logout))
        .route("/healthz", get(healthz))
        .with_state(state)
}

pub async fn serve(addr: &str, state: Arc<AuthState>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("auth endpoint listening on {addr}");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn verify(
    axum::extract::State(state): axum::extract::State<Arc<AuthState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let cookie_header = match headers.get("cookie") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return (StatusCode::UNAUTHORIZED, "bad cookie header"),
        },
        None => return (StatusCode::UNAUTHORIZED, "no cookie"),
    };

    let cookies = parse_cookie_header(&cookie_header);
    let token_str = match cookies.get(SESSION_COOKIE_NAME) {
        Some(s) => s.clone(),
        None => return (StatusCode::UNAUTHORIZED, "no session"),
    };

    let token = SignedSessionToken::from_string(token_str);
    let now = current_timestamp();
    let verifying = state.signing_key.verifying_key();
    let payload = match verify_session_token(&verifying, &token, now) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!("session verify failed: {e}");
            return (StatusCode::UNAUTHORIZED, "session invalid");
        }
    };

    // Tenant binding: compare the cookie's tenant to the host header's
    // tenant prefix when present. We treat host as `<sub>.<domain>`; the
    // tenant scoping is whatever the operator put in the cookie. For now we
    // accept any matching cookie and just log the host.
    if let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) {
        tracing::debug!(
            "verify: tenant={} host={} subject={}",
            payload.tenant,
            host,
            payload.label
        );
    }

    (StatusCode::OK, "ok")
}

async fn login_get() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        LOGIN_FORM_HTML,
    )
}

async fn login_post(
    axum::extract::State(state): axum::extract::State<Arc<AuthState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Form(form): Form<LoginForm>,
) -> axum::response::Response {
    // Rate-limit per source IP.
    let now = current_timestamp();
    {
        let mut buckets = state.rate_limit.lock().await;
        let entry = buckets
            .entry(addr.ip())
            .or_insert_with(|| RateLimiterState::defaults_at(now));
        if let Err(rl) = try_consume(entry, now, 1.0) {
            tracing::info!(
                "login rate-limited for {ip}: retry_after={s}s",
                ip = addr.ip(),
                s = rl.retry_after_seconds
            );
            use axum::http::header::{HeaderValue, RETRY_AFTER};
            let retry_str = rl.retry_after_seconds.to_string();
            let retry_hv = HeaderValue::from_str(&retry_str)
                .unwrap_or_else(|_| HeaderValue::from_static("60"));
            let mut headers = HeaderMap::new();
            headers.insert(RETRY_AFTER, retry_hv);
            return (StatusCode::TOO_MANY_REQUESTS, headers, "too many attempts")
                .into_response();
        }
    }

    let tenant = match TenantId::new(form.tenant.clone()) {
        Ok(t) => t,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
        }
    };

    // Look up the tenant's password hash.
    let hash = match load_tenant_password_hash(&state.config, &tenant).await {
        Ok(h) => h,
        Err(e) => {
            tracing::info!("login: load tenant hash failed: {e:#}");
            return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
        }
    };

    if verify_password(&hash, form.password.as_bytes()).is_err() {
        return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    }

    // Mint a session token.
    let payload = SessionTokenPayload {
        tenant: tenant.clone(),
        label: "guest".to_string(),
        issued_at: now,
        expires_at: Timestamp::from_seconds(now.seconds + SESSION_LIFETIME_SECONDS),
        nonce: random_nonce(),
    };
    let token = match sign_session_token(&state.signing_key, &payload) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("sign session token: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let attrs = CookieAttrs::defaults_for_domain(format!(".{}", state.config.domain));
    let cookie_value = encode_cookie(SESSION_COOKIE_NAME, token.as_str(), &attrs);

    use axum::http::header::{HeaderValue, LOCATION, SET_COOKIE};
    let location = form.redirect.as_deref().unwrap_or("/").to_string();
    let location_hv = HeaderValue::from_str(&location)
        .unwrap_or_else(|_| HeaderValue::from_static("/"));
    let cookie_hv = match HeaderValue::from_str(&cookie_value) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "bad cookie").into_response(),
    };
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, location_hv);
    headers.insert(SET_COOKIE, cookie_hv);
    (StatusCode::SEE_OTHER, headers, "").into_response()
}

async fn logout(
    axum::extract::State(state): axum::extract::State<Arc<AuthState>>,
) -> axum::response::Response {
    use axum::http::header::{HeaderValue, LOCATION, SET_COOKIE};
    let mut attrs = CookieAttrs::defaults_for_domain(format!(".{}", state.config.domain));
    attrs.max_age_seconds = 0;
    let cookie_value = encode_cookie(SESSION_COOKIE_NAME, "", &attrs);
    let cookie_hv = match HeaderValue::from_str(&cookie_value) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "bad cookie").into_response(),
    };
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, HeaderValue::from_static("/login"));
    headers.insert(SET_COOKIE, cookie_hv);
    (StatusCode::SEE_OTHER, headers, "").into_response()
}

fn current_timestamp() -> Timestamp {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::from_seconds(i64::try_from(dur.as_secs()).unwrap_or(i64::MAX))
}

fn random_nonce() -> Nonce {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    Nonce::from_bytes(buf)
}

async fn load_tenant_password_hash(
    cfg: &ServerConfig,
    tenant: &TenantId,
) -> Result<PasswordHashPhc> {
    let path = locate_tenant_password_file(cfg, tenant)?;
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let s = std::str::from_utf8(&bytes)
        .map_err(|e| anyhow::anyhow!("password hash {} not utf-8: {e}", path.display()))?;
    let trimmed = s.trim();
    PasswordHashPhc::parse(trimmed.to_string())
        .map_err(|e| anyhow::anyhow!("parse PHC at {}: {e}", path.display()))
}

fn locate_tenant_password_file(cfg: &ServerConfig, tenant: &TenantId) -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        let candidate = PathBuf::from(dir).join(format!("tenant-password-{tenant}"));
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    let candidate = cfg
        .state_dir
        .join("tenants")
        .join(format!("{tenant}.password-hash"));
    Ok(candidate)
}

const LOGIN_FORM_HTML: &str = r#"<!doctype html>
<html><head><title>tuntun login</title>
<style>
body { font-family: -apple-system, system-ui, sans-serif; max-width: 28rem; margin: 4rem auto; padding: 1rem; }
form { display: flex; flex-direction: column; gap: 0.75rem; }
input, button { padding: 0.5rem; font-size: 1rem; }
button { background: #111; color: #fff; border: 0; border-radius: 0.25rem; cursor: pointer; }
</style></head>
<body>
<h1>tuntun</h1>
<form method="POST" action="/login">
  <label>Tenant <input name="tenant" autocomplete="username" required></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  <button type="submit">Sign in</button>
</form>
</body></html>"#;
