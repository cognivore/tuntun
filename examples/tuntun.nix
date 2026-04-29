# Example tuntun.nix
#
# Place this at the root of any project you want to expose through tuntun.
# Then run `tuntun .` from that directory.
#
# `tuntun` is a function imported from this repo's flake — see the example
# flake.nix below for how to wire it up:
#
# {
#   inputs.tuntun.url = "github:cognivore/tuntun";
#   outputs = { self, nixpkgs, tuntun, ... }: {
#     # Evaluating tuntun.nix at the project root is what `tuntun .` does.
#     # The CLI calls `nix eval --json -f tuntun.nix --apply 'f: f { tuntun = tuntun.lib; }'`.
#   };
# }
#

{ tuntun, ... }:

tuntun.mkProject {
  # Tenant id (must match a tenants.<id> entry on your tuntun-server NixOS host).
  tenant = "memorici-de";

  # Apex domain you own in Porkbun.
  domain = "memorici.de";

  # Optional explicit project name (default: directory name of the flake).
  # project = "my-app";

  services = {
    blog = {
      subdomain = "blog";          # public hostname → blog.<tenant>.<domain>
      localPort = 4000;            # the app on your laptop
      auth = "tenant";             # require tenant password (default)
      healthCheck = {
        path = "/_health";
        timeoutSeconds = 5;
      };
    };

    api = {
      subdomain = "api";
      localPort = 3000;
      auth = "public";             # bypass auth (still TLS, still tunneled)
    };

    grafana = {
      subdomain = "grafana";
      localPort = 3030;
      auth = "tenant";
    };
  };

  # `ssh ssh.<tenant>.<domain>` is provisioned automatically as a reverse-SSH
  # side-car alongside the services declared above. There is no per-project
  # config for it — it follows directly from the tenant's authorizedKeys on
  # the server.
}
