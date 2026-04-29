{ tuntun, ... }:

# Repo-root `tuntun.nix` for the tuntun project itself.
#
# Run `tuntun .` from the repo root after starting `scripts/brochureware.rs`
# to publish the project's brochureware at `public.<tenant>.<domain>`.
# This is the canonical smoke-test target: a real `auth = "public"`
# service, tenant-scoped, no special-casing, no `auth` flip on any
# customer project's `tuntun.nix`.

tuntun.mkProject {
  tenant = "sweater";
  domain = "fere.me";
  project = "tuntun";

  services = {
    public = {
      subdomain = "public";       # → public.sweater.fere.me
      localPort = 31326;          # `rust-script -f scripts/brochureware.rs`
      auth = "public";            # explicit opt-in: this surface is intentionally open
    };
  };
}
