# NixOS host configuration for the AWS EC2 box that runs services.tuntun-server.
#
# Provisioned by AWS_PROVISION.md (eu-west-2, t4g.medium aarch64, NixOS AMI).
# Deployed via:
#
#     nixos-rebuild switch \
#       --target-host root@18.171.39.154 \
#       --build-host root@18.171.39.154 \
#       --flake .#tuntun-aws
#
# Secrets live at /var/lib/tuntun-secrets/* (mode 0600, owner root). They are
# scp'd before the first deploy and persist across rebuilds. The systemd unit
# loads them via LoadCredential — they never enter the Nix store.

{ modulesPath, lib, pkgs, ... }:

{
  imports = [
    "${modulesPath}/virtualisation/amazon-image.nix"
  ];

  ec2.efi = true;

  networking.hostName = "tuntun-aws";

  # cloud-init injects the instance's authorized SSH key for root automatically;
  # we just need sshd up.
  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "prohibit-password";
      PasswordAuthentication = false;
    };
  };

  # Nix flakes for the deploy itself.
  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  # tuntun-server.
  services.tuntun-server = {
    enable = true;
    domain = "fere.me";
    publicIp = "18.171.39.154";
    tunnelListen = "0.0.0.0:7000";
    acmeEmail = "jm@memorici.de";

    porkbun.apiKeyFile = "/var/lib/tuntun-secrets/porkbun-api-key";
    porkbun.secretKeyFile = "/var/lib/tuntun-secrets/porkbun-secret-key";
    serverSigningKeyFile = "/var/lib/tuntun-secrets/server-signing-key.pem";

    tenants.sweater = {
      passwordHashFile = "/var/lib/tuntun-secrets/tenant-sweater-password.phc";
      authorizedKeys = [
        # septnesis laptop, minted by scripts/regen-client-keys.rs on 2026-04-28.
        # Private half lives in rageveil at tuntun/tunnel-private-key.
        "ed25519:NQPqMhZzw8AXysGuu1XJYzuHT4S16n7zjxUIFFiQoUo"
      ];
    };
  };

  # Make sure the secrets dir exists with safe perms; deploy populates files.
  systemd.tmpfiles.rules = [
    "d /var/lib/tuntun-secrets 0700 root root -"
  ];

  system.stateVersion = "25.11";
}
