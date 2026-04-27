# home-manager module: services.tuntun-cli
#
# On Darwin: launchd user agent with KeepAlive (matching music-box's pattern).
# On Linux: systemd user service.
#
# The module installs a managed `tuntun` binary in the user's PATH, plus a
# launchd/systemd unit that runs `tuntun daemon` (the always-on tunnel
# maintainer). The CLI itself can also be invoked directly: `tuntun .`,
# `tuntun status`, `tuntun login`.

{ self }:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.tuntun-cli;

  cliPkg =
    if cfg.package != null
    then cfg.package
    else
      let
        sysPkgs = self.packages.${pkgs.stdenv.hostPlatform.system} or { };
      in
      sysPkgs.tuntun-cli or (throw ''
        services.tuntun-cli: no `tuntun-cli` package available for
        ${pkgs.stdenv.hostPlatform.system}. Either build the workspace
        first (`cargo build -p tuntun_cli`) or set
        `services.tuntun-cli.package` explicitly.
      '');

  daemonConfigToml = pkgs.writeText "tuntun-cli.toml" ''
    server_host = "${cfg.serverHost}"
    server_pubkey_fingerprint = "${cfg.serverPubkeyFingerprint}"
    default_tenant = "${cfg.defaultTenant}"
    state_dir = "${cfg.stateDir}"
    private_key_secret_name = "${cfg.privateKeySecretName}"
  '';

  isDarwin = pkgs.stdenv.isDarwin;

  daemonExec = "${cliPkg}/bin/tuntun daemon --config ${daemonConfigToml}";
in
{
  options.services.tuntun-cli = {
    enable = lib.mkEnableOption "tuntun reverse-tunnel client";

    package = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "The tuntun-cli package to use. Defaults to the flake output.";
    };

    serverHost = lib.mkOption {
      type = lib.types.str;
      example = "edge.memorici.de:7000";
      description = "host:port of the tuntun-server's tunnel listener.";
    };

    serverPubkeyFingerprint = lib.mkOption {
      type = lib.types.str;
      example = "sha256:abc123...";
      description = "SHA-256 fingerprint of the server's pinned TLS cert / signing key.";
    };

    defaultTenant = lib.mkOption {
      type = lib.types.str;
      example = "jm";
      description = "Tenant id used for `tuntun .` when not overridden by tuntun.nix.";
    };

    privateKeySecretName = lib.mkOption {
      type = lib.types.str;
      default = "tuntun/tunnel-private-key";
      description = "passveil key path holding the laptop's ed25519 tunnel private key.";
    };

    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "${config.home.homeDirectory}/.local/share/tuntun";
      description = "Directory for cached state, recent logs, etc.";
    };

    autostart = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to launch the tunnel daemon on user login.";
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      home.packages = [ cliPkg ];

      home.activation.tuntunStateDir = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        mkdir -p "${cfg.stateDir}"
      '';
    }

    (lib.mkIf (cfg.autostart && isDarwin) {
      launchd.agents.tuntun-cli = {
        enable = true;
        config = {
          Label = "com.memorici.tuntun-cli";
          ProgramArguments = lib.splitString " " daemonExec;
          RunAtLoad = true;
          KeepAlive = {
            SuccessfulExit = false;
            Crashed = true;
          };
          ThrottleInterval = 5;
          StandardOutPath = "${cfg.stateDir}/daemon.stdout.log";
          StandardErrorPath = "${cfg.stateDir}/daemon.stderr.log";
          EnvironmentVariables = {
            RUST_LOG = "info,tuntun_cli=debug";
          };
        };
      };
    })

    (lib.mkIf (cfg.autostart && !isDarwin) {
      systemd.user.services.tuntun-cli = {
        Unit = {
          Description = "tuntun reverse-tunnel client daemon";
          After = [ "network-online.target" ];
        };
        Service = {
          ExecStart = daemonExec;
          Restart = "on-failure";
          RestartSec = "2s";
          Environment = [ "RUST_LOG=info,tuntun_cli=debug" ];
        };
        Install = {
          WantedBy = [ "default.target" ];
        };
      };
    })
  ]);
}
