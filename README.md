# tuntun

From an enrolled laptop, reach the primary Mac with:

```console
ssh ssh.sweater.fere.me
```

Its SSH URL is **`ssh://sweater@ssh.sweater.fere.me`**. The SSH configuration
installed during enrollment connects through the public bastion on port 2222,
then authenticates end to end to the Mac. A bare connection to that hostname's
port 22 reaches the server's administration endpoint.

The Mac only makes an outbound connection. It can use home Wi-Fi, a phone's
hotspot, or another network without inbound port forwarding. Both tunnel ends
send heartbeats every 15 seconds, allow 5 seconds for a reply, and abandon a
session after three consecutive misses. Reconnection uses jitter with a
30-second cap and bounded connection/handshake attempts. An interrupted SSH
session must be opened again; use `tmux` for work that should survive a
disconnected terminal. The Mac must be awake and online, and its network must
allow the outbound tunnel port (currently 7000). **tuntun does not change power
settings.**

On the trusted Mac, enroll the other laptop using its existing key:

```console
rust-script -f ~/Github/octoprophet/installer/enroll-tuntun.rs --host 192.168.0.103
```

The script authorizes the laptop's existing Ed25519 public key on both SSH
hops, installs pinned host keys and SSH configuration, and verifies the
returned hostname through the public route. For full Octoprophet enrollment,
use `rust-script -f ~/Github/octoprophet/installer/enroll.rs enroll --host HOST`
and supply the public enrollment request as before. Always use `-f` after editing
a rust-script file so the compiled cache cannot hide your changes.

For manual enrollment, `tuntun authorize-key other-laptop.pub --label NAME`
authorizes an existing public key; `tuntun unbless NAME` revokes that label.
Never transfer the tunnel private key just to grant SSH access. Verify access
with `ssh ssh.sweater.fere.me hostname`; `tuntun status` reports configuration,
not proof that an end-to-end connection currently works.

The primary tunnel uses client ID `laptop-<tenant>`. Every additional device
publishing services for that tenant needs its own `services.tuntun-cli.clientId`
(for example `"octoprophet"`), or `client_id` in its daemon config. Additional
devices do not replace the primary reverse-SSH target. Upgrade the server before
the clients: management sessions now use the append-only `ControlOnly` frame
and no longer register a competing tunnel.

To repeat the live failure test from the Mac after enrollment:

```console
rust-script -f scripts/check-roaming.rs sweater@192.168.0.103
```

This briefly pauses the tunnel daemon to exercise heartbeat expiry, checks
recovery, and reconnects three times while checking for leaked listeners.
It interrupts existing tunneled connections, but never changes networking or
power settings.

> **VPN for poor**: declarative reverse-tunneling with a cryptographically
> rigorous authentication layer in front of every exposed service.

Run `tuntun .` in a project directory containing a `tuntun.nix`. Your local
services become reachable at the public hostnames you declared, served through
your own NixOS box, gated by a per-tenant password.

```nix
# tuntun.nix
{ tuntun, ... }:
tuntun.mkProject {
  tenant = "sweater";
  domain = "trolltech.art";
  services = {
    blog.subdomain = "blog";  blog.localPort = 4000;       # → blog.sweater.trolltech.art
    api.subdomain  = "api";   api.localPort  = 3000;  api.auth = "public";
  };
}
```

The public hostname is `<service>.<tenant>.<domain>`, so two tenants on the
same server can both have a `blog`. DNS is reconciled in Porkbun automatically
(per-tenant `*.<tenant>.<domain>` wildcard A records). TLS is provisioned by
Caddy via ACME. The reverse proxy delegates auth to a per-tenant login site at
`auth.<tenant>.<domain>`, which checks an Ed25519-signed, server-revocable
session cookie scoped to that tenant's subtree.

You also automatically get reverse-SSH at `ssh.<tenant>.<domain>` — your
laptop's local sshd, reachable from the wild internet via a bastion `sshd` on
the server, with end-to-end SSH crypto preserved.

## Design

See [CLAUDE.md](./CLAUDE.md) for the full architectural contract — crate
layout, port traits, compliance rules, and the cryptographic assumptions.

In one paragraph: the system is split into six **library crates** that
perform zero I/O (`tuntun_core`, `tuntun_dns`, `tuntun_auth`, `tuntun_proto`,
`tuntun_caddy`, `tuntun_config`) and two **binary crates** that hold all the
adapters (`tuntun_cli` on the laptop, `tuntun_server` on NixOS). Library code
is generic over port traits — tagless final, the same pattern used in
[mighty-rearranger](https://github.com/cognivore/mighty-rearranger).

## Components borrowed

| From                          | What                                         |
| ----------------------------- | -------------------------------------------- |
| [`music-box`](https://git.sr.ht/~do/music-box) | Caddy supervisor + declarative Caddyfile generation |
| [`orim`](https://github.com/cognivore/orim)    | Porkbun JSON API client + secrets-via-shell-out pattern (now over `rageveil`) |
| [`zensurance`](https://git.sr.ht/~do/zensurance) | Per-project Nix ergonomics                |
| [`mighty-rearranger`](https://github.com/cognivore/mighty-rearranger) | Tagless-final crate split |
| [`nixvana`](https://github.com/cognivore/nixvana) | home-manager integration surface          |

## Quick start

### Server (NixOS)

```nix
# /etc/nixos/configuration.nix
{ inputs, ... }:
{
  imports = [ inputs.tuntun.nixosModules.tuntun-server ];

  services.tuntun-server = {
    enable = true;
    domain = "trolltech.art";
    publicIp = "203.0.113.42";
    porkbun = {
      apiKeyFile    = "/run/secrets/porkbun-api-key";
      secretKeyFile = "/run/secrets/porkbun-secret-key";
    };
    serverSigningKeyFile = "/run/secrets/tuntun-server-signing-key.pem";
    tenants.sweater = {
      passwordHashFile = "/run/secrets/tuntun-sweater-password.phc";
      authorizedKeys = [
        "ed25519:AAAA..."   # one of your laptops, see scripts/regen-client-keys.rs
      ];
    };
    # The reverse-SSH bastion is on by default at port 2222.
  };
}
```

### Laptop (home-manager)

```nix
# home.nix
{ inputs, ... }:
{
  imports = [ inputs.tuntun.homeManagerModules.tuntun-cli ];

  services.tuntun-cli = {
    enable = true;
    serverHost = "edge.trolltech.art:7000";
    serverPubkeyFingerprint = "sha256:...";
    defaultTenant = "sweater";
    bastion = {
      serverDomain = "trolltech.art";
      bastionPort = 2222;
      identityFile = "~/.ssh/id_ed25519";
    };
  };
}
```

### Project

```sh
cd ~/my-app
$EDITOR tuntun.nix     # see examples/tuntun.nix
tuntun .               # registers, opens the tunnel, prints public URLs
```

## Ops

Operational scripts live in [`scripts/`](./scripts) and are written as
[`rust-script`](https://rust-script.org/) files, **never** shell.

> After editing a `rust-script`, re-run with `rust-script -f
> scripts/<name>.rs`. Without `-f`, the cached binary executes and your
> edits are silently ignored.

## License

AGPL-3.0-or-later.
