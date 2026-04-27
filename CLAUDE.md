# CLAUDE.md -- tuntun

## What this is

`tuntun` is a "VPN for poor": a declarative reverse-tunneling system that exposes
services running on a developer's laptop through a public domain served by a
NixOS server the user controls. Think `ngrok` or `cloudflared`, but self-hosted,
declarative, and gated by a cryptographic authentication layer.

The server side is **NixOS only** — `services.tuntun-server` is a NixOS module.
Do not add Ubuntu / system-manager / generic-Linux deployment paths.

### The flow

```
                                                          ┌────────────────────┐
                                                          │  Developer laptop  │
                                                          │  (run: tuntun .)   │
                                                          │                    │
                                                          │  ┌──────────────┐  │
                                                          │  │ local app on │  │
                                                          │  │ 127.0.0.1:N  │  │
                                                          │  └──────▲───────┘  │
                                                          │         │          │
                                                          │  ┌──────┴───────┐  │
                                                          │  │ tuntun_cli   │  │
                                                          │  │  (launchd or │  │
                                                          │  │  systemd     │  │
                                                          │  │  user agent) │  │
                                                          │  └──────▲───────┘  │
                                                          └─────────┼──────────┘
                                                                    │
                                                                    │  yamux streams
                                                                    │  over rustls
                                                                    │  (mTLS-ish:
                                                                    │   server cert
                                                                    │   pinned;
                                                                    │   client auth
                                                                    │   via ed25519
                                                                    │   token)
                                                                    │
┌──────────────┐    HTTPS         ┌─────────────────────────────────▼────────────┐
│ Browser /    │ ───────────────▶ │            Remote server                     │
│ end-user     │  *.tenant.tld    │                                              │
└──────────────┘                  │  ┌────────┐    ┌──────────────────────────┐  │
                                  │  │ Caddy  │◀──▶│ tuntun_server (daemon)   │  │
                                  │  │  TLS   │    │  - tunnel acceptor       │  │
                                  │  │ ACME   │    │  - project registry      │  │
                                  │  │forward_│    │  - Caddyfile generator   │  │
                                  │  │  auth  │    │  - forward_auth endpoint │  │
                                  │  └────────┘    │  - Porkbun reconciler    │  │
                                  │                └──────────────────────────┘  │
                                  └──────────────────────────────────────────────┘
                                                ▲
                                                │
                                                │  Porkbun JSON API
                                                │  (DNS A/CNAME upserts)
                                                ▼
                                  ┌──────────────────────────────────────────────┐
                                  │            api.porkbun.com                   │
                                  └──────────────────────────────────────────────┘
```

The user types `tuntun .` in a project directory that contains a `tuntun.nix`
file. The CLI evaluates that file with `nix eval --json`, registers each
declared service with the server over the control protocol, and the server
generates a Caddyfile, reloads Caddy, and starts proxying public traffic
through the tunnel back to the laptop. DNS records on Porkbun are reconciled
by the server (or by the CLI in laptop-only mode) so that `*.tenant.tld`
resolves to the server's IP.

### Architecture, in three sentences

1. **Library crates** (`tuntun_core`, `tuntun_dns`, `tuntun_auth`, `tuntun_proto`,
   `tuntun_caddy`, `tuntun_config`) describe *what* to do via port traits.
2. **Binary crates** (`tuntun_cli`, `tuntun_server`) implement port adapters and
   decide *how* to do it. They are the only places I/O lives.
3. **Nix modules** wire the binaries into systemd (NixOS server) and launchd
   or systemd-user (laptop, via home-manager), and provide a `lib.mkProject`
   helper that downstream flakes use to declare their services.

## Build & test

```
nix develop                       # enter dev shell with Rust toolchain + Caddy
cargo check                       # type-check workspace
cargo test                        # run all tests (no network, no fs writes outside tmp)
cargo clippy --workspace          # lint
cargo build --release             # build both binaries

nix build .#tuntun-cli            # build CLI via nix
nix build .#tuntun-server         # build server via nix
nix flake check                   # evaluate all flake outputs

# Run the laptop CLI against a local fake server (integration smoke test):
cargo run -p tuntun_cli -- --dry-run register .
```

## Operational scripts

Operational glue (deploy, smoke test, key rotation) is written as
[`rust-script`](https://rust-script.org/) files in `scripts/`, **never** as
shell scripts. Each begins with the standard shebang:

```rust
#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! ```
```

> **CRITICAL**: After editing a `rust-script` file, you must re-run it via
> `rust-script -f scripts/whatever.rs` to force recompilation. Without `-f`,
> `rust-script` will execute the previously-cached binary and silently ignore
> your edits. Document this in script comments and CI.

## Compliance rules for patches

Every patch submitted to this repository MUST satisfy all of the following.
Violations are grounds for rejection.

### 1. Library crates perform ZERO I/O

The crates `tuntun_core`, `tuntun_dns`, `tuntun_auth`, `tuntun_proto`,
`tuntun_caddy`, and `tuntun_config` must never import or call anything that
performs I/O. This means:

- No `std::fs`, `std::net`, `std::process`, `std::time::SystemTime::now`
- No `tokio::fs`, `tokio::net`, `tokio::process`, `tokio::time::sleep`
- No `reqwest`, `rustls` (the I/O layer), `quinn`, `hyper` server/client
- No file handles, no sockets, no subprocesses, no clocks

These crates may use `serde`, `serde_json`, `bytes`, `argon2`, `ed25519-dalek`
(crypto math is not I/O), `rand_core::CryptoRng` traits, `subtle` for
constant-time comparison, etc.

**Compliant** (`tuntun_dns/src/porkbun.rs`):
```rust
pub fn build_create_a_record_request(
    creds: &PorkbunCreds,
    domain: &Domain,
    name: &Subdomain,
    ip: &Ipv4Addr,
    ttl: Ttl,
) -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Post,
        url: format!("{}/dns/create/{}", PORKBUN_API_BASE, domain.as_str()),
        body: serde_json::to_vec(&CreatePayload { ... }).unwrap(),
        ..
    }
}
```

**Non-compliant**:
```rust
// WRONG: direct I/O in a library crate
let resp = reqwest::Client::new().post(url).send().await?;
```

### 2. Programs are generic over port traits (tagless final)

All composite operations (registering a project, reconciling DNS, running the
tunnel) must be parameterized over port trait bounds. They must never reference
a concrete adapter type.

**Compliant**:
```rust
pub async fn register_project<H, D, S, C, R>(
    http: &H, dns: &D, secrets: &S, clock: &C, rng: &R,
    spec: &ProjectSpec,
) -> Result<RegistrationReport>
where
    H: HttpPort,
    D: DnsPort,
    S: SecretPort,
    C: ClockPort,
    R: RandomPort,
```

**Non-compliant**:
```rust
// WRONG: concrete type instead of trait bound
pub async fn register_project(
    http: &ReqwestHttp, dns: &PorkbunDns, ...
) -> Result<RegistrationReport>
```

### 3. Port methods accept/return domain types

Port traits operate on strongly-typed Rust structs (`PorkbunDnsRecord`,
`TunnelFrame`, `AuthChallenge`). Never pass raw SQL strings,
`serde_json::Value`, or untyped maps across a port boundary. Untyped data only
exists at the very edges (raw HTTP body bytes, raw stdin, raw cookies),
immediately parsed into typed values.

**Compliant**:
```rust
async fn upsert_a_record(&self, rec: &DnsARecord) -> Result<DnsRecordId>;
```

**Non-compliant**:
```rust
// WRONG: untyped data at the port boundary
async fn execute_dns_call(&self, endpoint: &str, body: Value) -> Result<Value>;
```

### 4. Validated newtypes for domain identifiers

All domain identifiers (`TenantId`, `ProjectId`, `Subdomain`, `Domain`,
`ServicePort`, `DnsRecordId`, `SessionTokenId`, `TunnelStreamId`, etc.) must
use the `define_id!` macro defined in `tuntun_core::id`. The macro provides:

- A fallible constructor that validates the input
- An `as_str()` accessor
- `Display`, `FromStr`, `Eq`, `Ord`, `Hash`
- Transparent `serde::{Serialize, Deserialize}`

For numeric ports/ttls, use `u16`/`u32` newtypes via `define_numeric_id!`.

### 5. Authentication is cryptographically rigorous

This is the most security-sensitive part of the system. Apply these rules
literally:

- **Password hashing**: Argon2id only. Parameters: `m_cost = 19_456`,
  `t_cost = 2`, `p_cost = 1` (matches OWASP 2024 guidance). Stored as
  PHC-format strings.
- **Session tokens**: Ed25519-signed envelopes carrying
  `(tenant_id, label, issued_at, expires_at, nonce)`. Signed by the server's
  long-term ed25519 private key. Public key pinned in the auth verifier.
- **Tunnel client auth**: Ed25519 challenge-response. Server sends a 32-byte
  random nonce; client signs `b"tuntun-tunnel-auth-v1" || nonce || tenant_id`.
  Server verifies the signature against the per-tenant `authorized_keys` set.
  Domain separator required to defeat cross-protocol attacks.
- **Constant-time comparison**: All MAC/signature/hash comparisons go through
  `subtle::ConstantTimeEq`. Never `==` on bytes.
- **No homegrown crypto**: Use `argon2`, `ed25519-dalek`, `rustls`,
  `rand::rngs::OsRng`. Do not write a custom AEAD, KDF, or RNG.
- **Cookies**: `HttpOnly`, `Secure`, `SameSite=Lax`, `Domain=.tenant.tld`,
  `Path=/`, `Max-Age=3600`. Login form has CSRF token (random per-session).
- **Rate limit**: Login endpoint rate-limited per IP via token bucket
  (5 attempts / 60s, refill 1/30s). Exhaustion returns HTTP 429 without
  revealing whether the password was correct.

### 6. Workspace lints

```toml
[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

`unwrap()` and `expect()` are banned in non-test code. Use `?` and explicit
error types. Test code may use `expect()` with descriptive messages.

A patch that introduces new clippy warnings must fix them before merge.

### 7. Only `tuntun_cli` and `tuntun_server` have I/O dependencies

The only crates that may depend on `reqwest`, `rustls`, `tokio` (full),
`hyper`, `quinn`, `clap`, `tracing-subscriber`, `notify` (filesystem watcher),
or any other I/O library are `tuntun_cli` and `tuntun_server`. If you need a
new external interaction, add a method to a port trait in `tuntun_core`, then
implement it in an adapter inside the binary crate.

### 8. Tests use mock ports

All composite logic must be testable via mock port implementations in
`tuntun_core::testing` (e.g., `MockHttp` with canned responses, `MockDns`
backed by `RefCell<HashMap<...>>`, `FixedClock`, `DeterministicRng`). Tests in
library crates must not require a network connection, filesystem, or wall
clock.

Each library crate ships a `tests/` directory with at least one integration
test that exercises the public API end-to-end with mocks.

### 9. Secrets via passveil

All secrets are loaded at runtime through `SecretPort`. The real adapter
shells out to `passveil show <key>`. Keys are namespaced under `tuntun/`:

| Key                              | Where      | Contents                                  |
| -------------------------------- | ---------- | ----------------------------------------- |
| `tuntun/tunnel-private-key`      | laptop     | Ed25519 private key (PKCS#8)              |
| `tuntun/server-host`             | laptop     | `host:port` of server's tunnel acceptor   |
| `tuntun/server-pubkey-fingerprint` | laptop   | SHA-256 of server's pinned cert (hex)     |
| `tuntun/porkbun-api`             | server     | `api_key\nsecret_key`                     |
| `tuntun/server-signing-key`      | server     | Ed25519 private key for session tokens    |
| `tuntun/tenant/<id>/password-hash` | server   | Argon2id PHC hash for tenant guest access |

Secrets must never be committed, logged, or included in error messages. The
`SecretPort::load` adapter must redact in `Debug` impls. Keys to be persisted
(e.g., a freshly generated tunnel keypair on first run) are stored via
`passveil insert`.

### 10. Resilience defaults

Long-running tasks must auto-restart with bounded backoff:

- `tuntun_cli` daemon: launchd `KeepAlive = { SuccessfulExit = false; Crashed = true; }`
  with `ThrottleInterval = 5`. Inside the daemon, the tunnel reconnect loop
  uses exponential backoff with full jitter: 200ms base, 30s cap. Reset on
  successful handshake.
- `tuntun_server` daemon: systemd `Restart=on-failure RestartSec=2s
  StartLimitBurst=10 StartLimitIntervalSec=60`. Caddy is supervised as a
  subprocess via `ProcessPort` with the same restart semantics.
- Health checks: server pings each connected client every 15s with a 5s
  timeout. Three consecutive failures = drop tunnel, deregister project, log.
- Caddy reload (not restart) is preferred for config changes. If reload fails,
  fall back to restart with a 1-second drain.

These behaviors are tested by injecting failures via mock ports.

### 11. Operational scripts in `scripts/` are `rust-script`, not bash

If you find yourself writing a `.sh` file, stop. Use `rust-script` instead.
Document any non-obvious operational invariants in the script's doc comment.

> **Reminder**: To re-run a `rust-script` after editing it, you must invoke it
> as `rust-script -f scripts/foo.rs`. Without `-f`, the cached binary runs and
> your edits are silently ignored. The shebang form (`./scripts/foo.rs`) does
> NOT pass `-f` and will use the cached binary.

The only exception is the absolute minimum bootstrap: a single `flake.nix`
shell hook line that prints a startup message. Even `nix develop` activation
should not run shell logic of any consequence.

### 12. Caddy is a subprocess, not an embedded library

`tuntun_server` runs Caddy via `ProcessPort` (not embedded). The Caddyfile is
generated from typed inputs by `tuntun_caddy::render`. Hot-reload is preferred
(`caddy reload --config /var/lib/tuntun/Caddyfile`). This keeps Caddy upgrades
decoupled from tuntun upgrades and avoids C/Go FFI in our Rust binary.

The pattern is borrowed from
[`music-box`](https://git.sr.ht/~do/music-box/tree/main/item/nix/home-manager.nix#L96-L129):
declarative Caddyfile generation, supervisor process restarts on crash.

## Architectural reference points

| Aspect                       | Borrowed from                          |
| ---------------------------- | -------------------------------------- |
| Caddy supervisor + Caddyfile | `~/Srht/music-box/nix/home-manager.nix` |
| Porkbun upsert pattern       | `~/Github/orim/scripts/lib.sh:121-160`  |
| passveil for secrets         | `~/Github/orim/scripts/lib.sh:110-117`  |
| Tagless-final crate split    | `~/Github/mighty-rearranger/CLAUDE.md`  |
| Per-project Nix ergonomics   | `~/Srht/zensurance/flake.nix`           |
| Home-manager service module  | `~/Github/nixvana/home-manager/include/services/backup-darwin.nix` |
| systemd service module       | `~/Github/nixvana/system-manager/urborg/sites.nix` |

## Public API: `tuntun.nix` schema

A project declares its tuntun configuration like this:

```nix
# /path/to/project/tuntun.nix
{ tuntun, ... }:

tuntun.mkProject {
  tenant = "memorici-de";              # tenant id (server-side)
  domain = "memorici.de";              # owned in Porkbun
  services = {
    blog = {
      subdomain = "blog";              # → blog.memorici.de
      localPort = 4000;                # local app port on laptop
      auth = "tenant";                 # "tenant" | "public" | "none"
      healthCheck.path = "/_health";   # optional
    };
    api = {
      subdomain = "api";
      localPort = 3000;
      auth = "public";                 # bypass auth (still TLS)
    };
  };
}
```

Evaluated to JSON by `nix eval --json -f tuntun.nix --apply '...'`. Schema
lives in `tuntun_config::ProjectSpec`.

## Daemon ↔ CLI handoff

The first-cut implementation does **not** use a Unix-domain socket between
`tuntun register` and the long-running daemon. Instead:

- `tuntun register .` evaluates `tuntun.nix`, validates it, and writes the
  resulting `ProjectSpec` JSON to `<state_dir>/projects/<project>.json`.
- The daemon polls `<state_dir>/projects/*.json` every two seconds; when the
  set of files (or their mtimes) changes, the daemon snapshots the new
  spec list and feeds it into the next session's `Register` frame.

A future revision should switch to a `tokio::net::UnixListener` at
`<state_dir>/control.sock` so registrations propagate immediately and a
single daemon process can multiplex multiple project registrations without
races. The `notify` crate is already in the dependency graph for that.

## Public API: NixOS server module

```nix
services.tuntun-server = {
  enable = true;
  domain = "memorici.de";
  publicIp = "203.0.113.42";
  porkbun = {
    apiKeyFile = "/run/secrets/porkbun-api-key";
    secretKeyFile = "/run/secrets/porkbun-secret-key";
  };
  tunnelListen = "0.0.0.0:7000";
  tenants.jm = {
    passwordHashFile = "/run/secrets/tuntun-jm-password-hash";
    authorizedKeys = [
      "ed25519:AAAA..."   # laptop public keys
    ];
  };
};
```

## Public API: home-manager laptop module

```nix
services.tuntun-cli = {
  enable = true;
  serverHost = "edge.memorici.de:7000";
  serverPubkeyFingerprint = "sha256:...";
  privateKeySource = "passveil:tuntun/tunnel-private-key";
  defaultTenant = "jm";
};
```

## Crate dependency graph

```
                          ┌────────────────┐
                          │  tuntun_core   │   types, ports, errors
                          └────────┬───────┘
              ┌────────────────────┼─────────────────────┐
              │                    │                     │
      ┌───────▼──────┐    ┌────────▼────────┐   ┌────────▼────────┐
      │ tuntun_dns   │    │  tuntun_auth    │   │  tuntun_proto   │
      └───────┬──────┘    └────────┬────────┘   └────────┬────────┘
              │                    │                     │
      ┌───────▼──────┐    ┌────────▼────────┐            │
      │ tuntun_caddy │    │ tuntun_config   │            │
      └───────┬──────┘    └────────┬────────┘            │
              └────────────────────┼─────────────────────┘
                                   │
                       ┌───────────┴───────────┐
                       │                       │
                ┌──────▼──────┐         ┌──────▼──────┐
                │ tuntun_cli  │         │tuntun_server│
                └─────────────┘         └─────────────┘
                  (binary)                 (binary)
```

Library crates form a DAG with `tuntun_core` at the bottom. No library crate
depends on any binary crate. No library crate depends on `tokio` (only
`futures-core` traits where async is needed at the type level — see
`tuntun_proto`).

## Repo layout

```
tuntun/
├── CLAUDE.md                ← you are here
├── README.md
├── flake.nix
├── flake.lock
├── Cargo.toml               ← workspace root
├── rust-toolchain.toml
├── .envrc
├── crates/
│   ├── tuntun_core/
│   ├── tuntun_dns/
│   ├── tuntun_auth/
│   ├── tuntun_proto/
│   ├── tuntun_caddy/
│   ├── tuntun_config/
│   ├── tuntun_cli/
│   └── tuntun_server/
├── nix/
│   ├── nixos-module.nix     ← services.tuntun-server
│   ├── home-manager-module.nix  ← services.tuntun-cli
│   └── lib.nix              ← mkProject helper
├── scripts/
│   └── *.rs                 ← rust-script ops scripts
└── examples/
    └── tuntun.nix           ← example project config
```
