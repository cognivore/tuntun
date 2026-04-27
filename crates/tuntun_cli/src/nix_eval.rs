//! Shell-out to `nix eval` to load a project's `tuntun.nix` as JSON.
//!
//! The CLI evaluates the user's `tuntun.nix` with `tuntun.lib` injected from
//! the tuntun flake. The result is a JSON document that
//! `tuntun_config::ProjectSpec` can deserialize.

use std::path::Path;

use anyhow::{anyhow, Context, Result};

/// Evaluate `tuntun.nix` in `project_dir`, returning the parsed JSON.
///
/// The path must contain a `tuntun.nix` file. Behavior:
/// 1. Build a one-shot Nix expression that imports `tuntun.nix` and applies
///    it with `{ tuntun = (builtins.getFlake "<tuntun-flake>").lib; }`.
/// 2. Run `nix eval --json --impure` to print the JSON.
/// 3. Parse and return.
///
/// `tuntun_flake_ref` is the flake URL pointing at this repo (e.g. the user's
/// tuntun input). On a local checkout we use the pinned absolute path.
pub async fn eval_project_spec(project_dir: &Path, tuntun_flake_ref: &str) -> Result<serde_json::Value> {
    let nix_file = project_dir.join("tuntun.nix");
    if !nix_file.exists() {
        return Err(anyhow!(
            "no tuntun.nix found in {} — create one (see examples/tuntun.nix)",
            project_dir.display()
        ));
    }

    let nix_path = nix_file.display();
    let expr = format!(
        "let \
            f = import \"{nix_path}\"; \
            tuntunFlake = builtins.getFlake \"{tuntun_flake_ref}\"; \
         in f {{ tuntun = tuntunFlake.lib; }}"
    );

    let output = tokio::process::Command::new("nix")
        .args([
            "eval",
            "--json",
            "--impure",
            "--expr",
            &expr,
        ])
        .output()
        .await
        .context("running `nix eval` -- is nix installed?")?;

    if !output.status.success() {
        return Err(anyhow!(
            "nix eval failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("parse nix eval JSON output")?;
    Ok(value)
}
