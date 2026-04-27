use std::path::Path;

use anyhow::Result;

use crate::config::DaemonConfig;

pub async fn run(config: Option<&Path>, lines: usize) -> Result<()> {
    let cfg = DaemonConfig::load(config).await?;
    let log = cfg.state_dir.join("daemon.stderr.log");
    if !log.exists() {
        println!("(no log yet at {})", log.display());
        return Ok(());
    }

    let bytes = tokio::fs::read(&log).await?;
    let text = String::from_utf8_lossy(&bytes);
    let collected: Vec<&str> = text.lines().collect();
    let start = collected.len().saturating_sub(lines);
    for line in &collected[start..] {
        println!("{line}");
    }
    Ok(())
}
