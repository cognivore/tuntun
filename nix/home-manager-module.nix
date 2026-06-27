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

  # Private alias for the bastion-jump leg. Distinct from `bastionHostName`
  # so the inner ssh invocation (the ProxyCommand) doesn't recursively match
  # the outer destination block. Both names resolve via the same
  # `*.<tenant>.<domain>` wildcard A record.
  bastionJumpAlias = "_tuntun_bastion_${cfg.defaultTenant}";

  isDarwin = pkgs.stdenv.isDarwin;

  daemonExec = "${cliPkg}/bin/tuntun daemon --config ${daemonConfigToml}";

  # Build a tuntun_config::ProjectSpec as an attrset for one declarative
  # project. Field names match the Rust serde shape exactly: camelCase
  # (`localPort`, `healthCheck`, `expectedStatus`, `timeoutSeconds`) and
  # lowercase auth (`tenant` | `public`). `project` is the attr name so each
  # spec lands in its own `<name>.json` and never collides with another
  # project's file.
  mkProjectSpec = name: proj: {
    inherit (proj) tenant domain;
    project = name;
    services = lib.mapAttrs (_: svc:
      {
        inherit (svc) subdomain localPort auth;
      }
      // lib.optionalAttrs (svc.healthCheck != null) {
        healthCheck = {
          inherit (svc.healthCheck) path expectedStatus timeoutSeconds;
        };
      }) proj.services;
  };

  projectSpecFiles = lib.mapAttrs
    (name: proj:
      pkgs.writeText "tuntun-project-${name}.json"
        (builtins.toJSON (mkProjectSpec name proj)))
    cfg.projects;
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

    projects = lib.mkOption {
      default = { };
      description = ''
        Declaratively registered tunnel projects. Each entry is rendered to
        `<stateDir>/projects/<name>.json` at activation; the always-on daemon
        polls that directory and registers the services with the server on
        its own. This is the declarative equivalent of dropping a `tuntun.nix`
        into a repo and running `tuntun register .` — there is no manual step.
      '';
      example = lib.literalExpression ''
        {
          zensurance.services.zensurance = {
            subdomain = "zensurance";
            localPort = config.services.zensurance.port;
            auth = "tenant";
          };
        }
      '';
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          tenant = lib.mkOption {
            type = lib.types.str;
            default = cfg.defaultTenant;
            defaultText = lib.literalExpression "config.services.tuntun-cli.defaultTenant";
            description = "Tenant this project registers under.";
          };

          domain = lib.mkOption {
            type = lib.types.str;
            default = cfg.bastion.serverDomain;
            defaultText = lib.literalExpression "config.services.tuntun-cli.bastion.serverDomain";
            description = ''
              Apex domain the services are published under; the public FQDN is
              `<subdomain>.<tenant>.<domain>`.
            '';
          };

          services = lib.mkOption {
            description = "Map of service name → public-exposure spec.";
            type = lib.types.attrsOf (lib.types.submodule ({ name, ... }: {
              options = {
                subdomain = lib.mkOption {
                  type = lib.types.str;
                  default = name;
                  defaultText = lib.literalExpression "<the service's attribute name>";
                  description = "DNS label → `<subdomain>.<tenant>.<domain>`.";
                };

                localPort = lib.mkOption {
                  type = lib.types.port;
                  description = ''
                    Local TCP port the service listens on. Reference the
                    backing service's own port option here (e.g.
                    `config.services.zensurance.port`) to keep a single source
                    of truth.
                  '';
                };

                auth = lib.mkOption {
                  type = lib.types.enum [ "tenant" "public" ];
                  default = "tenant";
                  description = ''
                    `tenant` gates the service behind the per-tenant login;
                    `public` serves it directly (still over TLS).
                  '';
                };

                healthCheck = lib.mkOption {
                  default = null;
                  description = "Optional health-check probe configuration.";
                  type = lib.types.nullOr (lib.types.submodule {
                    options = {
                      path = lib.mkOption {
                        type = lib.types.str;
                        description = "Probe path; must start with `/`.";
                      };
                      expectedStatus = lib.mkOption {
                        type = lib.types.nullOr (lib.types.ints.between 100 599);
                        default = null;
                        description = "Expected HTTP status; any 2xx when null.";
                      };
                      timeoutSeconds = lib.mkOption {
                        type = lib.types.ints.unsigned;
                        default = 5;
                        description = "Probe timeout in seconds.";
                      };
                    };
                  });
                };
              };
            }));
          };
        };
      });
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      home.packages = [ cliPkg ];

      home.activation.tuntunStateDir = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        mkdir -p "${cfg.stateDir}"
      '';

      # Declarative project registration. Render each `projects.<name>` to
      # `<stateDir>/projects/<name>.json` (a symlink into the store) so the
      # running daemon picks it up on its next poll — no manual `tuntun
      # register`. Stale managed specs from a previous generation are pruned;
      # real files placed by an interactive `tuntun register` are left alone
      # (we only remove symlinks whose target is a `tuntun-project-*` store
      # path).
      home.activation.tuntunProjects = lib.hm.dag.entryAfter [ "tuntunStateDir" ] ''
        projectsDir="${cfg.stateDir}/projects"
        $DRY_RUN_CMD mkdir -p "$projectsDir"
        for f in "$projectsDir"/*.json; do
          [ -e "$f" ] || continue
          case "$(readlink "$f" 2>/dev/null || true)" in
            *tuntun-project-*) $DRY_RUN_CMD rm -f "$f" ;;
          esac
        done
        ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: file:
          ''$DRY_RUN_CMD ln -sfn ${file} "$projectsDir/${name}.json"'')
          projectSpecFiles)}
      '';
    }

    (lib.mkIf cfg.bastion.enable {
      programs.ssh.enable = lib.mkDefault true;

      # Destination block: this is what the user types as
      # `ssh ssh.<tenant>.<domain>`. The outer ssh client speaks SSH protocol
      # end-to-end with the laptop's local sshd; the bastion only proxies
      # bytes via the jump alias below. `User` is the laptop's own login
      # name because the inner sshd authenticates a normal interactive
      # session.
      programs.ssh.matchBlocks."tuntun-bastion" = {
        host = bastionHostName;
        hostname = bastionHostName;
        user = config.home.username;
        proxyCommand = "ssh -T ${bastionJumpAlias}";
        identityFile = lib.mkIf (cfg.bastion.identityFile != null) cfg.bastion.identityFile;
        extraOptions = {
          IdentitiesOnly = "yes";
          ServerAliveInterval = "30";
          ServerAliveCountMax = "3";
        };
      };

      # Bastion-jump alias: invoked exclusively by the ProxyCommand above.
      # The bastion sshd's `command="tuntun-server tcp-forward <tenant>"`
      # forced command pumps stdin/stdout to the unix socket bridged into
      # the tunnel — so this ssh's session-channel byte stream is what the
      # outer ssh sees as a "TCP connection" to the laptop's sshd.
      # `RequestTTY no` avoids the harmless "PTY allocation request failed"
      # message; the forced command doesn't allocate one anyway.
      programs.ssh.matchBlocks."tuntun-bastion-jump" = {
        host = bastionJumpAlias;
        hostname = bastionHostName;
        port = cfg.bastion.bastionPort;
        user = "tuntun";
        identityFile = lib.mkIf (cfg.bastion.identityFile != null) cfg.bastion.identityFile;
        extraOptions = {
          IdentitiesOnly = "yes";
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
          # The daemon shells out to `rageveil` to load the tunnel private
          # key. launchd starts agents with a minimal PATH that doesn't
          # include the user's nix profile, so we inject one explicitly.
          EnvironmentVariables = {
            RUST_LOG = "info,tuntun_cli=debug";
            PATH = "${config.home.profileDirectory}/bin:/usr/local/bin:/usr/bin:/bin";
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
          # Same rationale as the launchd agent above: ensure `rageveil`
          # (and friends installed via home-manager) are reachable.
          Environment = [
            "RUST_LOG=info,tuntun_cli=debug"
            "PATH=${config.home.profileDirectory}/bin:/usr/local/bin:/usr/bin:/bin"
          ];
        };
        Install = {
          WantedBy = [ "default.target" ];
        };
      };
    })
  ]);
}
