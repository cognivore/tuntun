//! `tuntun register .` — load tuntun.nix, validate, drop the spec into the
//! daemon's project directory.
//!
//! The daemon polls `<state_dir>/projects/*.json` every couple of seconds and
//! pushes a fresh `Register` frame to the server when the snapshot changes.

use std::path::Path;

use anyhow::{anyhow, Context, Result};

use tuntun_config::{parse_project_spec_from_json, ProjectSpec};
use tuntun_core::ProjectId;

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
    let mut spec = parse_project_spec_from_json(&json)
        .context("parse tuntun.nix output as ProjectSpec")?;

    // Resolve the project identity once and pin it onto the spec, so the
    // filename, the stored JSON, and the server all agree on one explicit
    // name (see `resolve_project_id`).
    let project_id = resolve_project_id(&spec, project_dir).await?;
    spec.project = Some(project_id.clone());

    println!(
        "tuntun: project {project_id} ({tenant}/{domain}) -- {n_services} service(s)",
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

    let path = projects_dir.join(format!("{project_id}.json"));
    let json_bytes = serde_json::to_vec_pretty(&spec).context("serialize ProjectSpec")?;
    tokio::fs::write(&path, &json_bytes)
        .await
        .with_context(|| format!("write {}", path.display()))?;

    println!("(spec written to {} — daemon picks up automatically)", path.display());
    Ok(())
}

/// Resolve the registry identity for a project.
///
/// Precedence — and there is deliberately **no** tenant-id fallback, since
/// every project a tenant owns would then collapse onto the same
/// `<tenant>.json` file and silently overwrite the previous registration:
///
/// 1. An explicit `project` in `tuntun.nix` — the canonical way to name a
///    project; used verbatim.
/// 2. Otherwise the project *directory's* own name, exactly as the
///    `ProjectSpec::project` documentation promises.
async fn resolve_project_id(spec: &ProjectSpec, project_dir: &Path) -> Result<ProjectId> {
    if let Some(project) = &spec.project {
        return Ok(project.clone());
    }

    let canonical = tokio::fs::canonicalize(project_dir)
        .await
        .with_context(|| format!("canonicalize project directory {}", project_dir.display()))?;
    project_id_from_dir(&canonical)
}

/// Derive a [`ProjectId`] from a project directory path: its final component,
/// validated as a slug. Pure (no I/O) so the rule is unit-testable. Returns an
/// error — never a guess — when the directory name is not a usable id, telling
/// the caller to set `project` explicitly.
fn project_id_from_dir(dir: &Path) -> Result<ProjectId> {
    let dir_name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow!(
                "cannot derive a project name from directory {}; \
                 set an explicit `project = \"<name>\";` in tuntun.nix",
                dir.display()
            )
        })?;

    ProjectId::new(dir_name).map_err(|err| {
        anyhow!(
            "project directory name {dir_name:?} is not a usable project id ({err}); \
             set an explicit `project = \"<name>\";` in tuntun.nix \
             (lowercase letters, digits and hyphens, up to 64 characters)"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::project_id_from_dir;
    use std::path::Path;

    #[test]
    fn dir_name_becomes_the_project_id() {
        let id = project_id_from_dir(Path::new("/Users/sweater/Srht/zensurance"));
        assert_eq!(id.map(tuntun_core::ProjectId::into_inner).ok().as_deref(), Some("zensurance"));
    }

    #[test]
    fn trailing_slash_is_handled() {
        let id = project_id_from_dir(Path::new("/home/me/annexwyrm/"));
        assert_eq!(id.map(tuntun_core::ProjectId::into_inner).ok().as_deref(), Some("annexwyrm"));
    }

    #[test]
    fn invalid_slug_errors_instead_of_guessing() {
        // No silent tenant fallback: an unusable directory name surfaces an
        // error that points the user at the explicit `project` field.
        assert!(project_id_from_dir(Path::new("/tmp/My_App")).is_err());
    }

    #[test]
    fn filesystem_root_has_no_name() {
        assert!(project_id_from_dir(Path::new("/")).is_err());
    }
}
