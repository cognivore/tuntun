//! `tuntun register .` — load tuntun.nix, validate, drop the spec into the
//! daemon's project directory.
//!
//! The daemon polls `<state_dir>/projects/*.json` every couple of seconds and
//! pushes a fresh `Register` frame to the server when the snapshot changes.

use std::path::Path;

use anyhow::{Context, Result};

use tuntun_config::parse_project_spec_from_json;

use crate::config::DaemonConfig;
use crate::nix_eval::eval_project_spec;

pub async fn run(project_dir: &Path, config: Option<&Path>, dry_run: bool) -> Result<()> {
    let cfg = DaemonConfig::load(config).await?;

    tracing::info!(
        "loading tuntun.nix from {} (flake ref: {})",
        project_dir.display(),
        cfg.tuntun_flake_ref
    );

    let json = eval_project_spec(project_dir, &cfg.tuntun_flake_ref).await?;
    let spec = parse_project_spec_from_json(&json)
        .context("parse tuntun.nix output as ProjectSpec")?;

    println!(
        "tuntun: project {tenant}/{domain} -- {n_services} service(s)",
        tenant = spec.tenant,
        domain = spec.domain,
        n_services = spec.services.len()
    );
    for (name, svc) in &spec.services {
        println!(
            "  - {name}: {sub}.{domain} -> 127.0.0.1:{port} (auth={auth:?})",
            sub = svc.subdomain,
            domain = spec.domain,
            port = svc.local_port,
            auth = svc.auth,
        );
    }

    if dry_run {
        println!("(dry run — daemon not contacted)");
        return Ok(());
    }

    // Drop the spec at <state_dir>/projects/<project>.json. The daemon
    // watches that directory and reloads on change.
    let projects_dir = cfg.state_dir.join("projects");
    tokio::fs::create_dir_all(&projects_dir)
        .await
        .with_context(|| format!("mkdir {}", projects_dir.display()))?;

    let project_id = spec
        .project
        .as_ref()
        .map_or_else(|| spec.tenant.as_str().to_string(), |p| p.as_str().to_string());
    let path = projects_dir.join(format!("{project_id}.json"));
    let json_bytes = serde_json::to_vec_pretty(&spec).context("serialize ProjectSpec")?;
    tokio::fs::write(&path, &json_bytes)
        .await
        .with_context(|| format!("write {}", path.display()))?;

    println!("(spec written to {} — daemon picks up automatically)", path.display());
    Ok(())
}
