# Example: a downstream project's flake.nix that wires up tuntun.
#
# Drop this near your project's flake.nix and adapt. The minimal contract is:
#
#   1. add `tuntun` to inputs;
#   2. `tuntun.nix` at the project root takes `{ tuntun }` and calls `tuntun.mkProject`;
#   3. `tuntun .` evaluates that file with `tuntun.lib` injected and registers the project.

{
  description = "example-app served via tuntun";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    tuntun.url = "github:cognivore/tuntun";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, tuntun, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        # Make `tuntun` itself available in `nix develop` so you can run
        # `tuntun .` straight from this shell.
        devShells.default = pkgs.mkShell {
          packages = [
            tuntun.packages.${system}.tuntun-cli
          ];
        };

        # Optional: re-export the project spec so other tools can read it.
        packages.tuntunSpec = pkgs.writeText "tuntun-spec.json" (
          builtins.toJSON (
            (import ./tuntun.nix) { tuntun = tuntun.lib; }
          )
        );
      }
    );
}
