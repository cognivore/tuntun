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
│ end-user     │ *.<t>.<domain>   │                                              │
└──────────────┘                  │  ┌────────┐    ┌──────────────────────────┐  │
                                  │  │ Caddy  │◀──▶│ tuntun_server (daemon)   │  │
                                  │  │  TLS   │    │  - tunnel acceptor       │  │
                                  │  │ ACME   │    │  - project registry      │  │
                                  │  │forward_│    │  - Caddyfile generator   │  │
                                  │  │  auth  │    │  - per-tenant /login,    │  │
                                  │  │        │    │    /verify, /logout      │  │
                                  │  └────────┘    │  - Porkbun reconciler    │  │
                                  │                │  - SSH bastion side-car  │  │
                                  │                │    (sshd :2222)          │  │
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
through the tunnel back to the laptop.

**URL pattern**: every public hostname is `<service>.<tenant>.<domain>`. The
tenant is part of the URL so two tenants on the same server can each declare
a service called `blog` without colliding. DNS records on Porkbun are
reconciled by the server as one wildcard A record per tenant
(`*.<tenant>.<domain>`), which covers all current and future services for
that tenant — including the auto-provisioned reverse-SSH endpoint at
`ssh.<tenant>.<domain>`.

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

## Provisioning the production server

The AWS EC2 / NixOS provisioning runbook lives at
[`AWS_PROVISION.md`](./AWS_PROVISION.md). It is the authoritative source for
turning an empty AWS account into a running tuntun-server box. If you are an
agent and the user asks for provisioning, deployment, or "spinning up the
server", read that file first and follow its `Operating notes for an AI
agent` section.

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
literally. They cover the **end-user web auth** surface; tunnel-client and
SSH-bastion auth are key-based (Ed25519, see §9 and the bastion section).

- **Password hashing**: Argon2id only. Parameters: `m_cost = 19_456`,
  `t_cost = 2`, `p_cost = 1` (matches OWASP 2024 guidance). Stored as
  PHC-format strings.
- **Session tokens**: Ed25519-signed envelopes carrying
  `(tenant_id, label, issued_at, expires_at, nonce)`, postcard-encoded payload
  + 64-byte signature, base64url with a `.` between them (JWS-shaped, no
  JOSE header — there is no `alg` field for an attacker to lie about). Signed
  by the server's long-term ed25519 private key.
- **Tunnel client auth**: Ed25519 challenge-response. Server sends a 32-byte
  random nonce; client signs
  `b"tuntun-tunnel-auth-v1\0" || nonce || tenant_id`. Server verifies the
  signature against the per-tenant `authorized_keys` set. The domain
  separator (with trailing NUL) is mandatory — it defeats cross-protocol
  signature replay.
- **Constant-time comparison**: All MAC/signature/hash comparisons go through
  `subtle::ConstantTimeEq`. Never `==` on bytes. `argon2::verify` and
  `ed25519_dalek::verify_strict` already do this internally; the auth
  endpoint also uses `ct_eq` for the CSRF double-submit check.
- **Strict signature verification**: Always `verify_strict` on the verifier
  side, never `verify`. This rejects the malleable encoding from RFC 8032
  §5.1.7.
- **No homegrown crypto**: Use `argon2`, `ed25519-dalek`, `rustls`,
  `rand::rngs::OsRng`. Do not write a custom AEAD, KDF, or RNG.
- **Per-tenant cookie scoping**: cookies carry `Domain=.<tenant>.<domain>`,
  `Path=/`, `Max-Age=3600`, `Secure`, `HttpOnly`, `SameSite=Lax`. Each tenant
  has its own login site at `auth.<tenant>.<domain>` so the browser will
  never send tenant A's cookie to tenant B's services. The verifier
  cross-checks the cookie's `tenant` claim against the request host as
  defense in depth.
- **Server-side revocation**: every issued session is identified by its
  `nonce`. `POST /logout` adds the nonce to a persistent JSON revocation set
  at `<state_dir>/revoked-nonces.json`; `/verify` consults the set after
  signature/expiry checks. Entries are purged lazily once their original
  `expires_at` has passed, so the set stays bounded.
- **CSRF on login & logout**: double-submit pattern. `GET /login` mints a
  256-bit OsRng token, sets it as `tuntun_csrf` (`HttpOnly`,
  `SameSite=Strict`, scoped to the same tenant subtree) and embeds it as a
  hidden `_csrf` form field. `POST /login` and `POST /logout` reject any
  request whose form `_csrf` does not equal the cookie value (compared via
  `ct_eq`).
- **Open-redirect defense**: `?redirect=` parameters on `/login` are
  whitelisted to server-relative paths (`^/[^/]`); anything else falls back
  to `/`.
- **Rate limit**: Login endpoint rate-limited per IP via token bucket
  (capacity 5, refill 1 token / 30 s, cost 1 / attempt). 429 is returned
  *before* Argon2id verification so the response is constant-cost regardless
  of whether the tenant or password exists.

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

### 9. Secrets via rageveil

All laptop-side secrets are loaded at runtime through `SecretPort`. The real
adapter shells out to `rageveil show <key>` (`rageveil` is a git+age password
manager whose CLI shape is near-identical to `passveil` —
`show <path>`, `insert <path> --batch`, `list`, `sync`). Server-side secrets
are loaded by systemd `LoadCredential` and surfaced through
`${CREDENTIALS_DIRECTORY}/<name>`; the daemon never reads from arbitrary
paths.

| Key                                | Where    | Contents                                  |
| ---------------------------------- | -------- | ----------------------------------------- |
| `tuntun/tunnel-private-key`        | laptop   | Ed25519 private key (PKCS#8 PEM)          |
| `tuntun/server-pubkey-fingerprint` | laptop   | SHA-256 of server's pinned cert (hex)     |
| `tuntun/tenant/<id>/password`      | laptop   | Tenant guest password (32-char base64url) |
| `${CREDENTIALS_DIRECTORY}/porkbun-api-key`        | server | Porkbun API key       |
| `${CREDENTIALS_DIRECTORY}/porkbun-secret-key`     | server | Porkbun secret key    |
| `${CREDENTIALS_DIRECTORY}/server-signing-key`     | server | Ed25519 PKCS#8 PEM    |
| `${CREDENTIALS_DIRECTORY}/tenant-password-<id>`   | server | Argon2id PHC hash     |

Secrets must never be committed, logged, or included in error messages. The
`SecretPort::load` adapter must redact in `Debug` impls. Keys to be persisted
on the laptop (e.g., a freshly generated tunnel keypair) are stored via
`rageveil insert <path> --batch`. The `--batch` flag is mandatory in scripts
so a daemon-side regeneration never blocks on an interactive prompt.

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
| rageveil for secrets         | git+age password manager, drop-in shape with the orim shell-out pattern |
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
  tenant = "sweater";                  # tenant id (server-side)
  domain = "trolltech.art";            # owned in Porkbun
  services = {
    blog = {
      subdomain = "blog";              # → blog.sweater.trolltech.art
      localPort = 4000;                # local app port on laptop
      auth = "tenant";                 # "tenant" | "public"
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

The public hostname for each service is **`<subdomain>.<tenant>.<domain>`**.
The tenant is part of the URL so two tenants on the same `tuntun-server` can
each declare a service called `blog` without colliding. DNS is reconciled by
the server as a per-tenant wildcard A record `*.<tenant>.<domain>`, which
covers all of that tenant's services (and the SSH bastion entry, see below)
with a single record.

Evaluated to JSON by `nix eval --json -f tuntun.nix --apply '...'`. Schema
lives in `tuntun_config::ProjectSpec`.

## Reverse-SSH bastion side-car

In addition to the user-declared services, each connected tenant
automatically gets a reverse-SSH endpoint at
**`ssh ssh.<tenant>.<domain>`**. The flow:

```
laptop sshd (127.0.0.1:22)
        ▲
        │  yamux stream (StreamOpenBuiltin{Ssh})
        │  inside the tenant's existing outbound tunnel
        │
   tuntun_server
        ▲
        │  /var/lib/tuntun/bastion.sock  (unix socket, header `tenant=<id>\n`)
        │
   tuntun-server tcp-forward <tenant>     ← OpenSSH `ForceCommand`
        ▲
   sshd (port 2222, Match LocalPort)      ← bastion side of the tuntun-server box
        ▲
   ssh ssh.sweater.trolltech.art          ← user's laptop / colleague's machine
```

Key properties:

- **End-to-end SSH crypto**. The bastion `sshd` only authenticates the *jump*
  via `command="tuntun-server tcp-forward <tenant>",no-pty,…` lines in its
  `AuthorizedKeysCommand` output. The forced command is a dumb byte pipe; it
  never reads the inner SSH session.
- **Tenant identity is bound to the public key**, not to the SSH username.
  The `command=` prefix on each authorized line uniquely binds a key to a
  tenant. The home-manager module writes a matching `Host` block to
  `~/.ssh/config` so users still type plain `ssh ssh.<tenant>.<domain>`.
- **Reverse**, not forward: the laptop never accepts public inbound TCP. The
  server reaches into the laptop's already-open tunnel by emitting a new
  `StreamOpenBuiltin{Ssh}` control frame; the laptop's daemon dials its own
  `127.0.0.1:<sshLocalPort>` (default 22) and pumps bytes.
- **No second sshd**. The bastion is wired into the existing
  `services.openssh` instance via a `Match LocalPort <bastionPort>` block,
  which scopes the forced-command behavior to the bastion port and leaves
  admin SSH on port 22 untouched.

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
  domain = "trolltech.art";
  publicIp = "203.0.113.42";
  porkbun = {
    apiKeyFile = "/run/secrets/porkbun-api-key";
    secretKeyFile = "/run/secrets/porkbun-secret-key";
  };
  tunnelListen = "0.0.0.0:7000";

  # Reverse-SSH bastion side-car. Defaults: enable = true; bastionPort = 2222.
  # The bastion attaches to the existing `services.openssh` via Match LocalPort.
  ssh = {
    enable = true;
    bastionPort = 2222;
  };

  tenants.sweater = {
    passwordHashFile = "/run/secrets/tuntun-sweater-password-hash";
    authorizedKeys = [
      "ed25519:AAAA..."   # laptop public keys; same keys gate the SSH bastion
    ];
  };
};
```

## Public API: home-manager laptop module

```nix
services.tuntun-cli = {
  enable = true;
  serverHost = "edge.trolltech.art:7000";
  serverPubkeyFingerprint = "sha256:...";
  privateKeySource = "passveil:tuntun/tunnel-private-key";
  defaultTenant = "sweater";

  # Generates a `Host ssh.<defaultTenant>.<serverDomain>` block in
  # ~/.ssh/config so `ssh ssh.sweater.trolltech.art` works out of the box.
  bastion = {
    enable = true;
    serverDomain = "trolltech.art";
    bastionPort = 2222;
    sshLocalPort = 22;          # the laptop's local sshd
    identityFile = "~/.ssh/id_ed25519";
  };
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
