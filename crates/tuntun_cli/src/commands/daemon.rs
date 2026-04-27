use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use tuntun_config::parse_project_spec_from_str;

use crate::config::DaemonConfig;
use crate::tunnel::client::{ProjectsSnapshot, TunnelClient};

pub async fn run(config: Option<&Path>) -> Result<()> {
    let cfg = Arc::new(DaemonConfig::load(config).await?);
    tracing::info!(
        "tuntun daemon starting (server={}, tenant={})",
        cfg.server_host,
        cfg.default_tenant
    );

    let client = Arc::new(TunnelClient::new(cfg.clone()));
    let projects_dir = cfg.state_dir.join("projects");

    // Initial scan + watcher: any *.json file in `<state_dir>/projects/` is
    // a `tuntun_config::ProjectSpec`. The CLI's `register` subcommand drops
    // its specs there. We poll on a short interval — the `notify` crate's
    // backend would be preferable but in this initial cut we keep it simple.
    let projects_handle = client.projects_handle();
    let projects_dir_for_watcher = projects_dir.clone();
    tokio::spawn(async move {
        if let Err(e) = watch_projects(projects_dir_for_watcher, projects_handle).await {
            tracing::warn!("project watcher exited: {e:#}");
        }
    });

    client.run_forever().await
}

async fn watch_projects(
    dir: std::path::PathBuf,
    snapshot_handle: Arc<tokio::sync::RwLock<ProjectsSnapshot>>,
) -> Result<()> {
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        tracing::warn!("mkdir {} failed: {e}", dir.display());
    }

    let mut last_mtimes: std::collections::BTreeMap<std::path::PathBuf, std::time::SystemTime> =
        std::collections::BTreeMap::new();

    loop {
        match scan_projects_dir(&dir).await {
            Ok((snapshot, mtimes)) => {
                if mtimes != last_mtimes {
                    let mut guard = snapshot_handle.write().await;
                    *guard = snapshot;
                    drop(guard);
                    last_mtimes = mtimes;
                    tracing::info!("project snapshot updated from {}", dir.display());
                }
            }
            Err(e) => {
                tracing::debug!("scan {} failed: {e}", dir.display());
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn scan_projects_dir(
    dir: &std::path::Path,
) -> Result<(
    ProjectsSnapshot,
    std::collections::BTreeMap<std::path::PathBuf, std::time::SystemTime>,
)> {
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .with_context(|| format!("read {}", dir.display()))?;
    let mut snapshot = ProjectsSnapshot::default();
    let mut mtimes = std::collections::BTreeMap::new();

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let meta = match tokio::fs::metadata(&path).await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("read {}: {e}", path.display());
                continue;
            }
        };
        let s = match std::str::from_utf8(&bytes) {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!("project file {} not utf-8", path.display());
                continue;
            }
        };
        match parse_project_spec_from_str(s) {
            Ok(spec) => {
                snapshot.projects.push(spec);
                if let Ok(modified) = meta.modified() {
                    mtimes.insert(path, modified);
                }
            }
            Err(e) => tracing::warn!("parse project file {}: {e}", path.display()),
        }
    }

    Ok((snapshot, mtimes))
}
