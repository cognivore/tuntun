use std::path::Path;

use anyhow::Result;

use crate::config::DaemonConfig;

pub async fn run(config: Option<&Path>) -> Result<()> {
    let cfg = DaemonConfig::load(config).await?;
    println!("server: {}", cfg.server_host);
    println!("tenant: {}", cfg.default_tenant);
    println!("state:  {}", cfg.state_dir.display());
    println!("(daemon liveness check pending)");
    Ok(())
}
