{
  description = "tuntun -- declarative reverse-tunneling with cryptographic auth (\"VPN for poor\")";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, flake-utils, rust-overlay, ... }:
    let
      perSystem = flake-utils.lib.eachDefaultSystem (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };

          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };

          commonNativeBuildInputs = with pkgs; [ pkg-config ];
          commonBuildInputs = with pkgs; [ openssl ]
            ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [ libiconv ];

          buildPkg = { name, bin }: rustPlatform.buildRustPackage {
            pname = name;
            version = "0.1.0";
            src = ./.;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            cargoBuildFlags = [ "-p" name ];
            doCheck = false;
            nativeBuildInputs = commonNativeBuildInputs;
            buildInputs = commonBuildInputs;
            meta = with pkgs.lib; {
              description = "tuntun ${name} binary (${bin})";
              license = licenses.agpl3Plus;
            };
          };

          # Packages are conditionally built only when Cargo.lock exists; on a
          # fresh checkout the dev shell is enough to bootstrap one.
          mkPackages =
            if builtins.pathExists ./Cargo.lock then {
              tuntun-cli = buildPkg { name = "tuntun_cli"; bin = "tuntun"; };
              tuntun-server = buildPkg { name = "tuntun_server"; bin = "tuntun-server"; };
            } else { };

          rustScriptNote = pkgs.writeShellScriptBin "tuntun-rust-script-note" ''
            cat <<EOF
            tuntun: rust-script reminder
            ============================

              After editing scripts/<name>.rs, re-run with:

                  rust-script -f scripts/<name>.rs

              Without -f, the cached compiled binary runs and your edits
              are silently ignored.
            EOF
          '';
        in
        {
          packages = mkPackages // {
            default =
              if mkPackages ? tuntun-cli
              then mkPackages.tuntun-cli
              else pkgs.runCommand "tuntun-bootstrap-required" { } ''
                cat >&2 <<EOF
                tuntun: Cargo.lock not present. Run \`nix develop\`, then
                \`cargo generate-lockfile\` in the dev shell to bootstrap.
                EOF
                exit 1
              '';
          };

          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              rustToolchain
              rust-script
              caddy
              jq
              curl
              cargo-watch
              cargo-nextest
              pkg-config
              openssl
              rustScriptNote
            ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              libiconv
            ];
            shellHook = ''
              echo "[tuntun] dev shell ready."
              echo "[tuntun] Run 'cargo check' to type-check the workspace."
              echo "[tuntun] After editing scripts/*.rs run: rust-script -f scripts/<name>.rs"
            '';
            # OpenSSL for reqwest, etc.
            OPENSSL_NO_VENDOR = "1";
            PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
          };

          formatter = pkgs.nixpkgs-fmt;
        }
      );

      nixosModule = import ./nix/nixos-module.nix { inherit self; };
      homeManagerModule = import ./nix/home-manager-module.nix { inherit self; };
      tuntunLib = import ./nix/lib.nix { };
    in
    perSystem
    // {
      nixosModules = {
        default = nixosModule;
        tuntun-server = nixosModule;
      };
      homeManagerModules = {
        default = homeManagerModule;
        tuntun-cli = homeManagerModule;
      };
      lib = tuntunLib;
    };
}
