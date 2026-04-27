# tuntun.lib helpers for downstream flakes.
#
# Usage in a project's flake:
#
#   {
#     inputs.tuntun.url = "github:cognivore/tuntun";
#     outputs = { self, tuntun, ... }: {
#       # tuntun.nix in the project root then evaluates with `tuntun.lib`
#       # passed in as an argument.
#     };
#   }
#
# `tuntun .` invokes `nix eval --json -f tuntun.nix --apply 'f: f { tuntun = <lib>; }'`
# (passing the lib it gets from this flake), so the result of `mkProject` ends
# up as a JSON document the CLI parses via tuntun_config::ProjectSpec.

{ }:

rec {
  # Schema-stable wrapper. Returns its argument unchanged today; the function
  # exists so we can rewrite/normalize fields in future without breaking
  # downstream tuntun.nix files.
  mkProject =
    spec:
    let
      # Defaults applied per-service if the user didn't specify them.
      withServiceDefaults =
        svc:
        {
          auth = "tenant";
          healthCheck = null;
        }
        // svc;

      services =
        if spec ? services
        then builtins.mapAttrs (_: withServiceDefaults) spec.services
        else { };
    in
    {
      tenant = spec.tenant;
      domain = spec.domain;
      project = spec.project or null;
      inherit services;
    };

  # Convenience: assert a spec is valid at evaluation time. The Rust side
  # also validates, but doing it here gives a Nix-level error early.
  assertValid =
    spec:
    let
      svcs = builtins.attrValues spec.services or { };
      subs = map (s: s.subdomain) svcs;
      ports = map (s: s.localPort) svcs;
      hasDup = xs: builtins.length xs != builtins.length (builtins.unique xs);
    in
    if (spec ? services) && (builtins.length (builtins.attrNames spec.services) == 0)
    then throw "tuntun: services must not be empty"
    else if hasDup subs
    then throw "tuntun: duplicate subdomain in services"
    else if hasDup ports
    then throw "tuntun: duplicate localPort in services"
    else spec;
}
