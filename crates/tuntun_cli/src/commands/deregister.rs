//! Remove an interactive registration; the daemon observes the deletion.

use std::path::Path;

use anyhow::{Context, Result};
use tuntun_config::parse_project_spec_from_json;

use crate::config::DaemonConfig;
use crate::nix_eval::eval_project_spec;

use super::register::resolve_project_id;

pub async fn run(project_dir: &Path, config: Option<&Path>, dry_run: bool) -> Result<()> {
    let cfg = DaemonConfig::load(config).await?;
    let json = eval_project_spec(project_dir, &cfg.tuntun_flake_ref).await?;
    let spec =
        parse_project_spec_from_json(&json).context("parse tuntun.nix output as ProjectSpec")?;
    let project = resolve_project_id(&spec, project_dir).await?;
    let path = cfg
        .state_dir
        .join("projects")
        .join(format!("{project}.json"));
    remove_registration(&path, dry_run).await
}

async fn remove_registration(path: &Path, dry_run: bool) -> Result<()> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("tuntun: {} is already deregistered", path.display());
            return Ok(());
        }
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    };
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "{} is a managed or linked registration; remove the project from \
         services.tuntun-cli.projects and reactivate Home Manager instead",
        path.display()
    );
    anyhow::ensure!(
        metadata.is_file(),
        "{} is not a registration file",
        path.display()
    );
    if dry_run {
        println!("(dry run — would remove {})", path.display());
        return Ok(());
    }
    tokio::fs::remove_file(path)
        .await
        .with_context(|| format!("remove {}", path.display()))?;
    println!(
        "tuntun: removed {} — daemon picks up automatically",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::remove_registration;

    #[tokio::test]
    async fn deregistration_respects_dry_run_and_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("tuntun-deregister-{}", rand::random::<u64>()));
        tokio::fs::create_dir(&dir)
            .await
            .expect("temporary directory");
        let path = dir.join("project.json");
        tokio::fs::write(&path, b"{}").await.expect("registration");
        remove_registration(&path, true).await.expect("dry run");
        assert!(path.is_file(), "dry run retains registration");
        remove_registration(&path, false).await.expect("deregister");
        assert!(!path.exists(), "registration removed");
        remove_registration(&path, false)
            .await
            .expect("already absent");
        tokio::fs::remove_dir(&dir).await.expect("cleanup");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn declarative_symlinks_and_their_targets_are_preserved() {
        let dir = std::env::temp_dir().join(format!("tuntun-managed-{}", rand::random::<u64>()));
        tokio::fs::create_dir(&dir)
            .await
            .expect("temporary directory");
        let target = dir.join("tuntun-project-example.json");
        let path = dir.join("example.json");
        tokio::fs::write(&target, b"{}")
            .await
            .expect("managed spec");
        std::os::unix::fs::symlink(&target, &path).expect("managed registration");
        for dry_run in [true, false] {
            let error = remove_registration(&path, dry_run)
                .await
                .expect_err("managed registration");
            assert!(error.to_string().contains("services.tuntun-cli.projects"));
            assert!(path.is_symlink(), "managed link retained");
            assert!(target.is_file(), "managed target retained");
        }
        tokio::fs::remove_dir_all(&dir).await.expect("cleanup");
    }
}
