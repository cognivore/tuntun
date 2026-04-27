//! Caddy supervisor.
//!
//! Spawns Caddy in the background, writes/refreshes the Caddyfile generated
//! by `tuntun_caddy::render_caddyfile`, and triggers `caddy reload` via the
//! admin API when service registrations change.
//!
//! The pattern is borrowed from `~/Srht/music-box/nix/home-manager.nix:96-129`
//! (the launchd wrapper). Here we do the equivalent in a long-running server
//! process: the daemon owns Caddy's lifecycle.

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::sync::Mutex;

use tuntun_caddy::{render_caddyfile, CaddyInput};

use crate::config::ServerConfig;

#[derive(Debug)]
pub struct CaddySupervisor {
    config: Arc<ServerConfig>,
    state: Mutex<SupervisorState>,
}

#[derive(Debug, Default)]
struct SupervisorState {
    last_rendered: Option<String>,
}

impl CaddySupervisor {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            state: Mutex::new(SupervisorState::default()),
        }
    }

    /// Spawn Caddy. Idempotent: if already running, just reload.
    pub async fn launch(&self) -> Result<()> {
        // Write an initial empty(ish) Caddyfile so Caddy has something to
        // start with — we'll reload as soon as the first client registers.
        let initial = "{\n}\n".to_string();
        tokio::fs::write(&self.config.caddyfile_path, initial.as_bytes())
            .await
            .with_context(|| {
                format!(
                    "write initial Caddyfile to {}",
                    self.config.caddyfile_path.display()
                )
            })?;

        let mut cmd = tokio::process::Command::new(&self.config.caddy_bin);
        cmd.arg("run")
            .arg("--config")
            .arg(&self.config.caddyfile_path)
            .arg("--adapter")
            .arg("caddyfile")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        cmd.spawn()
            .with_context(|| format!("spawn caddy at {}", self.config.caddy_bin.display()))?;
        tracing::info!("caddy launched");
        Ok(())
    }

    /// Render a fresh Caddyfile from `input` and trigger Caddy to reload.
    pub async fn render_and_reload(&self, input: &CaddyInput) -> Result<()> {
        let rendered = render_caddyfile(input)
            .map_err(|e| anyhow!("render Caddyfile: {e}"))?;

        let mut state = self.state.lock().await;
        if state.last_rendered.as_deref() == Some(rendered.as_str()) {
            tracing::debug!("Caddyfile unchanged; skipping reload");
            return Ok(());
        }

        atomic_write(&self.config.caddyfile_path, rendered.as_bytes()).await?;
        state.last_rendered = Some(rendered);
        drop(state);

        self.reload().await
    }

    async fn reload(&self) -> Result<()> {
        let output = tokio::process::Command::new(&self.config.caddy_bin)
            .arg("reload")
            .arg("--config")
            .arg(&self.config.caddyfile_path)
            .arg("--address")
            .arg(&self.config.caddy_admin)
            .output()
            .await
            .context("spawn caddy reload")?;

        if !output.status.success() {
            return Err(anyhow!(
                "caddy reload failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        tracing::info!("caddy reloaded");
        Ok(())
    }
}

async fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}
