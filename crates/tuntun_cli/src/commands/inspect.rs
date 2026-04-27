use std::path::Path;

use anyhow::{Context, Result};

use tuntun_config::parse_project_spec_from_json;

use crate::nix_eval::eval_project_spec;

pub async fn run(project_dir: &Path) -> Result<()> {
    // For inspect, default to a relative path-style flake reference so the
    // user can run this without configuring the daemon. We try the local
    // checkout first, fall back to the default GitHub flake.
    let flake_ref = std::env::var("TUNTUN_FLAKE")
        .unwrap_or_else(|_| "github:cognivore/tuntun".to_string());

    let json = eval_project_spec(project_dir, &flake_ref).await?;
    let spec = parse_project_spec_from_json(&json)
        .context("parse tuntun.nix output as ProjectSpec")?;

    let pretty = serde_json::to_string_pretty(&spec)?;
    println!("{pretty}");
    Ok(())
}
