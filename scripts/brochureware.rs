#!/usr/bin/env rust-script
//! Tiny HTTP server that serves a static "this is tuntun" brochureware
//! page. Used as the `auth = "public"` smoke-test target in
//! `./tuntun.nix`, so the e2e proxy chain can be exercised without
//! flipping any customer project's auth knob.
//!
//! Usage:
//!     rust-script -f scripts/brochureware.rs [PORT]
//!
//! Default port: 31326. The repo-root `tuntun.nix` declares
//! `services.public.localPort = 31326`, so leaving the default lets you
//! just run this and `tuntun .` and have `public.<tenant>.<domain>` work.
//!
//! IMPORTANT: re-run with `-f` after editing — without it the cached
//! binary executes and edits are silently ignored.
//!
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! tiny_http = "0.12"
//! ```

use anyhow::{Context, Result};

const HTML: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>tuntun</title>
<style>
body{font:14px/1.55 system-ui,-apple-system,sans-serif;max-width:38rem;margin:4rem auto;padding:0 1rem;color:#222}
h1{margin:0 0 .25rem;font-size:2.4rem;letter-spacing:-.01em}
.tag{color:#666;margin:0 0 1.4rem}
code{background:#f3f3f3;padding:.05rem .3rem;border-radius:.25rem;font-size:.95em}
a{color:#1f66c2}
.card{margin-top:1.4rem;padding:1rem 1.1rem;border:1px solid #e3e3e3;border-radius:.4rem;background:#fbfbfb}
ul{margin:.4rem 0 0;padding-left:1.2rem}
li{margin:.15rem 0}
</style></head><body>
<h1>tuntun</h1>
<p class="tag">"VPN for poor": declarative reverse-tunneling with a cryptographically rigorous auth layer.</p>

<p>If you're reading this on the public internet, the full chain is healthy: DNS → Caddy → ACME TLS → forward_auth pass-through (because this service was declared <code>auth = "public"</code>) → server-side per-service listener → yamux outbound stream over the tenant's existing tunnel → laptop daemon → <code>127.0.0.1:31326</code> → this little HTTP server.</p>

<div class="card">
<strong>How services land here</strong>
<ul>
  <li>A laptop runs the <code>tuntun</code> daemon, authenticated via Ed25519 challenge-response.</li>
  <li>It registers services declared in <code>tuntun.nix</code> on the server.</li>
  <li>Each service gets a public hostname <code>&lt;service&gt;.&lt;tenant&gt;.&lt;domain&gt;</code> via a per-tenant <code>*.&lt;tenant&gt;.&lt;domain&gt;</code> wildcard A record.</li>
  <li><code>auth = "tenant"</code> services are gated by a per-tenant login at <code>auth.&lt;tenant&gt;.&lt;domain&gt;</code> — Argon2id passwords + Ed25519-signed session cookies, server-side revocable, CSRF on the login form.</li>
  <li><code>auth = "public"</code> services skip that gate. This page is one.</li>
  <li><code>ssh.&lt;tenant&gt;.&lt;domain&gt;</code> is also reachable: a bastion <code>sshd</code> on the server forwards SSH end-to-end through the existing tunnel to the laptop's local sshd.</li>
</ul>
</div>

<p style="margin-top:1.4rem;font-size:.9rem;color:#888">
Source: <a href="https://github.com/cognivore/tuntun">github.com/cognivore/tuntun</a>.
This page is served by <code>scripts/brochureware.rs</code> on a laptop, exposed through the tunnel via the repo-root <code>tuntun.nix</code>.
</p>
</body></html>
"#;

fn main() -> Result<()> {
    let port: u16 = std::env::args()
        .nth(1)
        .map_or(Ok(31326), |s| s.parse())
        .context("parse PORT arg")?;
    let addr = format!("127.0.0.1:{port}");
    let server = tiny_http::Server::http(&addr)
        .map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?;
    eprintln!("brochureware listening on http://{addr}/");

    for req in server.incoming_requests() {
        let resp = tiny_http::Response::from_string(HTML)
            .with_header(
                tiny_http::Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"text/html; charset=utf-8"[..],
                )
                .expect("static header"),
            )
            .with_status_code(200);
        if let Err(e) = req.respond(resp) {
            eprintln!("respond: {e}");
        }
    }
    Ok(())
}
