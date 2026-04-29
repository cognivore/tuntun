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
    ssh_local_port = "${toString cfg.bastion.sshLocalPort}"
    server_domain = "${cfg.bastion.serverDomain}"
  '';

  bastionHostName = "ssh.${cfg.defaultTenant}.${cfg.bastion.serverDomain}";

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
      description = "rageveil key path holding the laptop's ed25519 tunnel private key.";
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

    bastion = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Whether to install an `~/.ssh/config` block that lets you reach the
          laptop itself via the reverse-SSH bastion (`ssh ssh.<tenant>.<domain>`).
          Set to false if you handle the SSH config yourself.
        '';
      };

      serverDomain = lib.mkOption {
        type = lib.types.str;
        example = "memorici.de";
        description = ''
          Apex domain of the tuntun server (matches
          `services.tuntun-server.domain` on the NixOS box). Used to build
          the `Host ssh.<tenant>.<domain>` block.
        '';
      };

      bastionPort = lib.mkOption {
        type = lib.types.port;
        default = 2222;
        description = ''
          Port the server's bastion `sshd` listens on (matches
          `services.tuntun-server.ssh.bastionPort`).
        '';
      };

      identityFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "~/.ssh/id_ed25519";
        description = ''
          OpenSSH-format private key file used to authenticate to the bastion.
          The matching public key must appear in
          `services.tuntun-server.tenants.<defaultTenant>.authorizedKeys` on
          the server. If null, OpenSSH's default identity selection applies.
        '';
      };

      sshLocalPort = lib.mkOption {
        type = lib.types.port;
        default = 22;
        description = ''
          TCP port the laptop's local `sshd` listens on. The reverse-SSH
          bastion pipes inbound connections here. On macOS this is 22 once
          "Remote Login" is enabled in System Settings.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      home.packages = [ cliPkg ];

      home.activation.tuntunStateDir = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        mkdir -p "${cfg.stateDir}"
      '';
    }

    (lib.mkIf cfg.bastion.enable {
      programs.ssh.enable = lib.mkDefault true;
      programs.ssh.matchBlocks."tuntun-bastion" = {
        host = bastionHostName;
        hostname = cfg.bastion.serverDomain;
        port = cfg.bastion.bastionPort;
        user = "tuntun";
        identityFile = lib.mkIf (cfg.bastion.identityFile != null) cfg.bastion.identityFile;
        # The bastion's authorized_keys lines all carry a forced command,
        # so OpenSSH won't open an interactive shell — these tweaks just
        # avoid client-side warnings when that "command" runs to completion.
        extraOptions = {
          RequestTTY = "no";
          ServerAliveInterval = "30";
          ServerAliveCountMax = "3";
        };
      };
    })

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
