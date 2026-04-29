//! Internal HTTP endpoints serving every tenant's login site.
//!
//! Caddy proxies `auth.<tenant>.<domain>` to this single binary; we read the
//! `Host` header to figure out which tenant the request belongs to. Each
//! tenant gets its own browser-scoped session cookie at
//! `Domain=.<tenant>.<domain>`, so a session for tenant A is never sent to
//! tenant B's services.
//!
//! Endpoints:
//!
//! - `GET /verify` — Caddy `forward_auth` target. Reads the cookie + the
//!   forwarded host headers; redirects to the tenant's login site (302) when
//!   the cookie is missing/invalid/revoked, returns `200 ok` when valid.
//! - `GET /login` — login form. Sets a CSRF token in a cookie (`tuntun_csrf`)
//!   and embeds it in a hidden `_csrf` form field (double-submit pattern).
//! - `POST /login` — validates CSRF, rate-limit, password; mints a fresh
//!   Ed25519-signed session token; sets `tuntun_session` with `Domain=
//!   .<tenant>.<domain>`. Redirects to `?redirect=` or `/`.
//! - `POST /logout` — validates CSRF, parses the cookie's nonce, adds it to
//!   the persisted revocation set, clears the cookie.
//! - `GET /healthz` — liveness probe.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Router};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore as _;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use tuntun_auth::cookie::{encode_cookie, parse_cookie_header, CookieAttrs, SameSitePolicy};
use tuntun_auth::password::{verify_password, PasswordHashPhc};
use tuntun_auth::rate_limit::{try_consume, RateLimiterState};
use tuntun_auth::session::{
    sign_session_token, verify_session_token, SessionTokenPayload, SignedSessionToken,
};
use tuntun_core::{Nonce, TenantId, Timestamp};

use crate::config::ServerConfig;

const SESSION_COOKIE_NAME: &str = "tuntun_session";
const CSRF_COOKIE_NAME: &str = "tuntun_csrf";
const SESSION_LIFETIME_SECONDS: i64 = 3_600;
const CSRF_LIFETIME_SECONDS: i64 = 900; // 15 minutes — long enough to fill out a form
const REVOCATION_FILE: &str = "revoked-nonces.json";

#[derive(Debug)]
pub struct AuthState {
    pub config: Arc<ServerConfig>,
    pub signing_key: Arc<SigningKey>,
    /// Per-IP rate-limit buckets for the login endpoint.
    rate_limit: Mutex<BTreeMap<IpAddr, RateLimiterState>>,
    /// Persisted revocation set: `nonce_hex -> expires_at_secs`. Sessions
    /// whose nonce is in this map are rejected by `/verify` even if their
    /// signature and expiry would otherwise pass.
    revocation: Mutex<RevocationSet>,
}

impl AuthState {
    pub fn new(config: Arc<ServerConfig>, signing_key: Arc<SigningKey>) -> Self {
        let path = config.state_dir.join(REVOCATION_FILE);
        let revocation = RevocationSet::load(path);
        Self {
            config,
            signing_key,
            rate_limit: Mutex::new(BTreeMap::new()),
            revocation: Mutex::new(revocation),
        }
    }
}

#[derive(Debug, Default)]
struct RevocationSet {
    inner: HashMap<String, i64>,
    path: PathBuf,
}

impl RevocationSet {
    fn load(path: PathBuf) -> Self {
        let inner = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => HashMap::new(),
        };
        Self { inner, path }
    }

    /// Add `nonce` to the revocation set with its original `expires_at`.
    /// Also lazily purges entries that have aged out so the set stays bounded
    /// at roughly `(active_sessions + recently-revoked-but-not-yet-expired)`.
    fn revoke(&mut self, nonce: &Nonce, expires_at: Timestamp, now: Timestamp) {
        self.inner.retain(|_, exp| *exp > now.seconds);
        self.inner.insert(hex_nonce(nonce), expires_at.seconds);
        self.persist();
    }

    fn is_revoked(&self, nonce: &Nonce) -> bool {
        self.inner.contains_key(&hex_nonce(nonce))
    }

    fn persist(&self) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        let bytes = match serde_json::to_vec(&self.inner) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("revocation: serialize: {e}");
                return;
            }
        };
        let tmp = self.path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, &bytes) {
            tracing::error!("revocation: write {}: {e}", tmp.display());
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &self.path) {
            tracing::error!("revocation: rename {}: {e}", self.path.display());
        }
    }
}

fn hex_nonce(n: &Nonce) -> String {
    let mut s = String::with_capacity(64);
    for b in n.0 {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub redirect: Option<String>,
    #[serde(default, rename = "_csrf")]
    pub csrf: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutForm {
    #[serde(default, rename = "_csrf")]
    pub csrf: String,
}

pub fn router(state: Arc<AuthState>) -> Router {
    Router::new()
        .route("/", get(root_redirect))
        .route("/verify", get(verify))
        .route("/login", get(login_get).post(login_post))
        .route("/logout", post(logout_post))
        .route("/healthz", get(healthz))
        .with_state(state)
}

/// `GET /` on the per-tenant login host: a stray bare visit (typed URL,
/// stale bookmark, follow-on after a logout) lands here. Bounce to
/// `/login` so the user sees a useful page instead of a 404.
async fn root_redirect() -> impl IntoResponse {
    use axum::http::header::{HeaderValue, LOCATION};
    let mut hdrs = HeaderMap::new();
    hdrs.insert(LOCATION, HeaderValue::from_static("/login"));
    (StatusCode::FOUND, hdrs, "")
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

// ---------- /verify ----------------------------------------------------------

async fn verify(
    axum::extract::State(state): axum::extract::State<Arc<AuthState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let original_host = match header_str(&headers, "x-tuntun-forwarded-host")
        .or_else(|| header_str(&headers, "x-forwarded-host"))
        .or_else(|| header_str(&headers, "host"))
    {
        Some(h) => h.to_string(),
        None => {
            return (StatusCode::BAD_REQUEST, HeaderMap::new(), "missing host header")
                .into_response();
        }
    };
    let original_uri = header_str(&headers, "x-tuntun-forwarded-uri")
        .unwrap_or("/")
        .to_string();
    let original_proto = header_str(&headers, "x-tuntun-forwarded-proto")
        .unwrap_or("https")
        .to_string();

    let tenant = match extract_tenant_from_host(&original_host, &state.config.domain) {
        Some(t) => t,
        None => {
            return (StatusCode::BAD_REQUEST, HeaderMap::new(), "host outside tuntun domain")
                .into_response();
        }
    };

    let cookies = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(parse_cookie_header)
        .unwrap_or_default();

    let payload = cookies
        .get(SESSION_COOKIE_NAME)
        .map(|s| SignedSessionToken::from_string(s.clone()))
        .and_then(|tok| {
            verify_session_token(&state.signing_key.verifying_key(), &tok, current_timestamp())
                .ok()
        });

    if let Some(payload) = payload {
        // Cookie validates structurally — now check tenant binding and
        // revocation. Browser scoping should already prevent tenant-A's cookie
        // landing on tenant-B's site, but we cross-check for defense in depth.
        if payload.tenant == tenant {
            let revoked = state.revocation.lock().await.is_revoked(&payload.nonce);
            if !revoked {
                return (StatusCode::OK, HeaderMap::new(), "ok").into_response();
            }
            tracing::debug!("verify: cookie nonce revoked");
        } else {
            tracing::debug!(
                "verify: cookie tenant {} mismatches host tenant {}",
                payload.tenant,
                tenant
            );
        }
    }

    // Anything else: redirect the browser to the tenant's login page with a
    // ?redirect= back to the original URL. Caddy's forward_auth passes 3xx
    // responses straight through to the client.
    let redirect_target = format!("{original_proto}://{original_host}{original_uri}");
    let login_url = format!(
        "https://auth.{tenant}.{domain}/login?redirect={enc}",
        domain = state.config.domain,
        enc = url_encode(&redirect_target),
    );
    use axum::http::header::{HeaderValue, LOCATION};
    let mut hdrs = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&login_url) {
        hdrs.insert(LOCATION, v);
    }
    (StatusCode::SEE_OTHER, hdrs, "session required").into_response()
}

// ---------- /login -----------------------------------------------------------

async fn login_get(
    axum::extract::State(state): axum::extract::State<Arc<AuthState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let host = header_str(&headers, "host").unwrap_or("");
    let tenant = match extract_tenant_from_host(host, &state.config.domain) {
        Some(t) => t,
        None => {
            return (StatusCode::BAD_REQUEST, "host outside tuntun domain").into_response();
        }
    };
    let redirect = parse_query_param(host_query(&headers), "redirect").unwrap_or_else(|| "/".to_string());

    let csrf = mint_csrf();
    let html = render_login_html(&tenant, &redirect, &csrf);

    let csrf_attrs = CookieAttrs {
        domain: format!(".{tenant}.{domain}", domain = state.config.domain),
        path: "/".into(),
        max_age_seconds: CSRF_LIFETIME_SECONDS,
        secure: true,
        http_only: true,
        same_site: SameSitePolicy::Strict,
    };
    let csrf_cookie = encode_cookie(CSRF_COOKIE_NAME, &csrf, &csrf_attrs);

    use axum::http::header::{HeaderValue, CONTENT_TYPE, SET_COOKIE};
    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    if let Ok(v) = HeaderValue::from_str(&csrf_cookie) {
        hdrs.insert(SET_COOKIE, v);
    }
    (StatusCode::OK, hdrs, html).into_response()
}

async fn login_post(
    axum::extract::State(state): axum::extract::State<Arc<AuthState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> axum::response::Response {
    // 1. Tenant binding from Host.
    let host = header_str(&headers, "host").unwrap_or("");
    let tenant = match extract_tenant_from_host(host, &state.config.domain) {
        Some(t) => t,
        None => {
            return (StatusCode::BAD_REQUEST, "host outside tuntun domain").into_response();
        }
    };

    // 2. CSRF (double-submit).
    let cookies = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(parse_cookie_header)
        .unwrap_or_default();
    let csrf_cookie = cookies.get(CSRF_COOKIE_NAME).cloned().unwrap_or_default();
    if csrf_cookie.is_empty()
        || form.csrf.is_empty()
        || !constant_time_str_eq(&csrf_cookie, &form.csrf)
    {
        return (StatusCode::FORBIDDEN, "csrf").into_response();
    }

    // 3. Rate limit per source IP.
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
            let mut hdrs = HeaderMap::new();
            if let Ok(v) = HeaderValue::from_str(&rl.retry_after_seconds.to_string()) {
                hdrs.insert(RETRY_AFTER, v);
            }
            return (StatusCode::TOO_MANY_REQUESTS, hdrs, "too many attempts").into_response();
        }
    }

    // 4. Password verify.
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

    // 5. Mint and set session.
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
    let session_attrs = CookieAttrs::defaults_for_domain(format!(
        ".{tenant}.{domain}",
        domain = state.config.domain
    ));
    let session_cookie = encode_cookie(SESSION_COOKIE_NAME, token.as_str(), &session_attrs);

    // Clear the CSRF cookie too — it's single-use.
    let mut clear_csrf = session_attrs.clone();
    clear_csrf.max_age_seconds = 0;
    clear_csrf.same_site = SameSitePolicy::Strict;
    let clear_csrf_cookie = encode_cookie(CSRF_COOKIE_NAME, "", &clear_csrf);

    use axum::http::header::{HeaderValue, LOCATION, SET_COOKIE};
    let mut hdrs = HeaderMap::new();
    let location = sanitize_redirect(
        form.redirect.as_deref().unwrap_or("/"),
        &tenant,
        &state.config.domain,
    );
    if let Ok(v) = HeaderValue::from_str(&location) {
        hdrs.insert(LOCATION, v);
    }
    if let Ok(v) = HeaderValue::from_str(&session_cookie) {
        hdrs.insert(SET_COOKIE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&clear_csrf_cookie) {
        hdrs.append(SET_COOKIE, v);
    }
    (StatusCode::SEE_OTHER, hdrs, "").into_response()
}

// ---------- /logout ----------------------------------------------------------

async fn logout_post(
    axum::extract::State(state): axum::extract::State<Arc<AuthState>>,
    headers: HeaderMap,
    Form(form): Form<LogoutForm>,
) -> axum::response::Response {
    let host = header_str(&headers, "host").unwrap_or("");
    let tenant = match extract_tenant_from_host(host, &state.config.domain) {
        Some(t) => t,
        None => {
            return (StatusCode::BAD_REQUEST, "host outside tuntun domain").into_response();
        }
    };

    let cookies = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(parse_cookie_header)
        .unwrap_or_default();
    let csrf_cookie = cookies.get(CSRF_COOKIE_NAME).cloned().unwrap_or_default();
    if csrf_cookie.is_empty()
        || form.csrf.is_empty()
        || !constant_time_str_eq(&csrf_cookie, &form.csrf)
    {
        return (StatusCode::FORBIDDEN, "csrf").into_response();
    }

    // Best-effort: if there's a parseable session cookie, revoke its nonce.
    if let Some(raw) = cookies.get(SESSION_COOKIE_NAME) {
        let token = SignedSessionToken::from_string(raw.clone());
        if let Ok(payload) =
            verify_session_token(&state.signing_key.verifying_key(), &token, current_timestamp())
        {
            state
                .revocation
                .lock()
                .await
                .revoke(&payload.nonce, payload.expires_at, current_timestamp());
        }
    }

    // Clear both cookies.
    let mut session_attrs = CookieAttrs::defaults_for_domain(format!(
        ".{tenant}.{domain}",
        domain = state.config.domain
    ));
    session_attrs.max_age_seconds = 0;
    let session_cookie = encode_cookie(SESSION_COOKIE_NAME, "", &session_attrs);
    let mut csrf_attrs = session_attrs.clone();
    csrf_attrs.same_site = SameSitePolicy::Strict;
    let csrf_cookie = encode_cookie(CSRF_COOKIE_NAME, "", &csrf_attrs);

    use axum::http::header::{HeaderValue, LOCATION, SET_COOKIE};
    let login_url = format!(
        "https://auth.{tenant}.{domain}/login",
        domain = state.config.domain
    );
    let mut hdrs = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&login_url) {
        hdrs.insert(LOCATION, v);
    }
    if let Ok(v) = HeaderValue::from_str(&session_cookie) {
        hdrs.insert(SET_COOKIE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&csrf_cookie) {
        hdrs.append(SET_COOKIE, v);
    }
    (StatusCode::SEE_OTHER, hdrs, "").into_response()
}

// ---------- helpers ----------------------------------------------------------

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

fn mint_csrf() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn host_query(headers: &HeaderMap) -> &str {
    header_str(headers, "x-tuntun-forwarded-uri")
        .or_else(|| header_str(headers, "uri"))
        .unwrap_or("")
}

fn parse_query_param(uri_with_query: &str, key: &str) -> Option<String> {
    let q = uri_with_query.split_once('?')?.1;
    for part in q.split('&') {
        let (k, v) = part.split_once('=')?;
        if k == key {
            return Some(url_decode(v));
        }
    }
    None
}

/// Strip `[port]` and any trailing dot, then peel off the configured `domain`
/// suffix. The leftmost surviving label is the tenant.
fn extract_tenant_from_host(host: &str, server_domain: &str) -> Option<TenantId> {
    let host = host.split(':').next()?.trim_end_matches('.');
    let suffix = format!(".{server_domain}");
    let rest = host.strip_suffix(&suffix).or_else(|| {
        if host == server_domain {
            Some("")
        } else {
            None
        }
    })?;
    if rest.is_empty() {
        return None;
    }
    let last = rest.rsplit('.').next()?;
    TenantId::new(last.to_string()).ok()
}

/// Decide what `Location:` to send the browser to after a successful
/// login. Two shapes are accepted; everything else falls back to `/login`
/// on the current login host.
///
/// 1. **Server-relative path** (`^/[^/]`): used verbatim. This is the
///    legitimate "logged in, now go to the dashboard at this same host"
///    case. We forbid `//host/...` because browsers parse those as
///    scheme-relative URLs that change the host.
/// 2. **Absolute URL inside the same tenant subtree**: the URL the user
///    was originally trying to reach, carried through the login flow as
///    `?redirect=https://blog.<tenant>.<domain>/...`. We accept it iff
///    its scheme is `https://` and its host is `<anything>.<tenant>.
///    <domain>` (or the tenant's own apex `<tenant>.<domain>`). Anything
///    else — bare IP, a different tenant, a different domain entirely —
///    is treated as an open-redirect attempt and discarded.
fn sanitize_redirect(s: &str, tenant: &TenantId, server_domain: &str) -> String {
    let fallback = "/login".to_string();
    if s.is_empty() {
        return fallback;
    }
    if s.starts_with('/') && !s.starts_with("//") {
        return s.to_string();
    }
    let Some(rest) = s.strip_prefix("https://") else {
        return fallback;
    };
    let (host, _path) = rest.split_once('/').unwrap_or((rest, ""));
    // Strip optional `:port`. The tenant subtree never carries non-default
    // ports for tuntun-served URLs, but tolerate them rather than
    // user-confusingly drop a redirect.
    let host = host.split(':').next().unwrap_or(host);
    let tenant_root = format!("{tenant}.{server_domain}");
    let tenant_suffix = format!(".{tenant}.{server_domain}");
    if host == tenant_root || host.ends_with(&tenant_suffix) {
        s.to_string()
    } else {
        fallback
    }
}

fn constant_time_str_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.' | b'~' | b'/' | b':') {
            out.push(*b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push(((h * 16 + l) & 0xff) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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
    PasswordHashPhc::parse(s.trim().to_string())
        .map_err(|e| anyhow::anyhow!("parse PHC at {}: {e}", path.display()))
}

fn locate_tenant_password_file(cfg: &ServerConfig, tenant: &TenantId) -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        let candidate = Path::new(&dir).join(format!("tenant-password-{tenant}"));
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Ok(cfg
        .state_dir
        .join("tenants")
        .join(format!("{tenant}.password-hash")))
}

fn render_login_html(tenant: &TenantId, redirect: &str, csrf: &str) -> String {
    let tenant_e = html_escape(tenant.as_str());
    let redirect_e = html_escape(redirect);
    let csrf_e = html_escape(csrf);
    format!(
        r#"<!doctype html>
<html><head><title>tuntun login — {tenant_e}</title>
<style>
body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 28rem; margin: 4rem auto; padding: 1rem; }}
form {{ display: flex; flex-direction: column; gap: 0.75rem; }}
input, button {{ padding: 0.5rem; font-size: 1rem; }}
button {{ background: #111; color: #fff; border: 0; border-radius: 0.25rem; cursor: pointer; }}
.tenant {{ color: #666; font-family: ui-monospace, monospace; }}
</style></head>
<body>
<h1>tuntun</h1>
<p>Tenant: <span class="tenant">{tenant_e}</span></p>
<form method="POST" action="/login">
  <input type="hidden" name="_csrf" value="{csrf_e}">
  <input type="hidden" name="redirect" value="{redirect_e}">
  <label>Password <input name="password" type="password" autocomplete="current-password" required autofocus></label>
  <button type="submit">Sign in</button>
</form>
</body></html>"#
    )
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_tenant_strips_apex_and_returns_last_label() {
        let d = "fere.me";
        assert_eq!(
            extract_tenant_from_host("blog.sweater.fere.me", d).unwrap().as_str(),
            "sweater"
        );
        assert_eq!(
            extract_tenant_from_host("auth.sweater.fere.me", d).unwrap().as_str(),
            "sweater"
        );
        assert_eq!(
            extract_tenant_from_host("sweater.fere.me", d).unwrap().as_str(),
            "sweater"
        );
        assert_eq!(
            extract_tenant_from_host("blog.sweater.fere.me:8443", d).unwrap().as_str(),
            "sweater"
        );
    }

    #[test]
    fn extract_tenant_rejects_apex_or_outsider() {
        let d = "fere.me";
        assert!(extract_tenant_from_host("fere.me", d).is_none());
        assert!(extract_tenant_from_host("evil.com", d).is_none());
        assert!(extract_tenant_from_host("", d).is_none());
    }

    #[test]
    fn sanitize_redirect_blocks_external() {
        let t = TenantId::new("sweater").expect("tenant");
        let d = "fere.me";
        // Server-relative paths: passed through.
        assert_eq!(sanitize_redirect("/dashboard", &t, d), "/dashboard");
        assert_eq!(sanitize_redirect("/", &t, d), "/");
        // Same-tenant absolute URLs: passed through (the legitimate case
        // for "log in then bounce back to the protected service URL").
        assert_eq!(
            sanitize_redirect("https://zensurance.sweater.fere.me/", &t, d),
            "https://zensurance.sweater.fere.me/"
        );
        assert_eq!(
            sanitize_redirect("https://blog.sweater.fere.me/posts/1", &t, d),
            "https://blog.sweater.fere.me/posts/1"
        );
        // Tenant's own apex.
        assert_eq!(
            sanitize_redirect("https://sweater.fere.me/", &t, d),
            "https://sweater.fere.me/"
        );
        // Cross-tenant absolute: rejected.
        assert_eq!(
            sanitize_redirect("https://blog.othertenant.fere.me/", &t, d),
            "/login"
        );
        // Different domain entirely: rejected.
        assert_eq!(sanitize_redirect("https://evil.com/", &t, d), "/login");
        // Scheme-relative trickery: rejected.
        assert_eq!(sanitize_redirect("//evil.com/", &t, d), "/login");
        // Non-https scheme: rejected.
        assert_eq!(sanitize_redirect("javascript:alert(1)", &t, d), "/login");
        assert_eq!(
            sanitize_redirect("http://zensurance.sweater.fere.me/", &t, d),
            "/login"
        );
        // Empty: fallback.
        assert_eq!(sanitize_redirect("", &t, d), "/login");
        // Sneaky suffix-confusion: NOT same tenant.
        assert_eq!(
            sanitize_redirect("https://evilsweater.fere.me/", &t, d),
            "/login"
        );
    }

    #[test]
    fn revocation_round_trip() {
        let dir = std::env::temp_dir().join(format!("tuntun-revoke-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("revoked.json");
        let _ = std::fs::remove_file(&path);

        let mut set = RevocationSet::load(path.clone());
        let n = Nonce::from_bytes([7u8; 32]);
        assert!(!set.is_revoked(&n));
        set.revoke(&n, Timestamp::from_seconds(2_000), Timestamp::from_seconds(1_000));
        assert!(set.is_revoked(&n));

        // Reload from disk.
        let set2 = RevocationSet::load(path.clone());
        assert!(set2.is_revoked(&n));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn revocation_purges_expired_on_insert() {
        let dir = std::env::temp_dir().join(format!("tuntun-revoke-purge-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("revoked.json");
        let _ = std::fs::remove_file(&path);

        let mut set = RevocationSet::load(path.clone());
        let stale = Nonce::from_bytes([1u8; 32]);
        let fresh = Nonce::from_bytes([2u8; 32]);
        // First insert: a session that expired at t=100.
        set.revoke(&stale, Timestamp::from_seconds(100), Timestamp::from_seconds(50));
        assert!(set.is_revoked(&stale));
        // Now we're at t=200 inserting a fresh entry — the stale one should
        // be purged because its expires_at (100) <= now (200).
        set.revoke(&fresh, Timestamp::from_seconds(1_000), Timestamp::from_seconds(200));
        assert!(set.is_revoked(&fresh));
        assert!(!set.is_revoked(&stale));

        let _ = std::fs::remove_file(&path);
    }
}
