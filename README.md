# tuntun

> **VPN for poor**: declarative reverse-tunneling with a cryptographically
> rigorous authentication layer in front of every exposed service.

Run `tuntun .` in a project directory containing a `tuntun.nix`. Your local
services become reachable at the public hostnames you declared, served through
your own NixOS box, gated by a per-tenant password.

```nix
# tuntun.nix
{ tuntun, ... }:
tuntun.mkProject {
  tenant = "memorici-de";
  domain = "memorici.de";
  services = {
    blog.subdomain = "blog";  blog.localPort = 4000;
    api.subdomain  = "api";   api.localPort  = 3000;  api.auth = "public";
  };
}
```

DNS is reconciled in Porkbun automatically. TLS is provisioned by Caddy via
ACME. The reverse proxy delegates auth to a dedicated tuntun service
(`forward_auth`), which checks an Ed25519-signed session cookie scoped to the
tenant's domain.

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
| [`orim`](https://github.com/cognivore/orim)    | Porkbun JSON API client + passveil secrets pattern |
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
    domain = "memorici.de";
    publicIp = "203.0.113.42";
    porkbun = {
      apiKeyFile    = "/run/secrets/porkbun-api-key";
      secretKeyFile = "/run/secrets/porkbun-secret-key";
    };
    tenants.jm = {
      passwordHashFile = "/run/secrets/tuntun-jm-password-hash";
      authorizedKeys = [
        "ed25519:AAAA..."   # one of your laptops, see scripts/regen-client-keys.rs
      ];
    };
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
    serverHost = "edge.memorici.de:7000";
    serverPubkeyFingerprint = "sha256:...";
    defaultTenant = "jm";
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
