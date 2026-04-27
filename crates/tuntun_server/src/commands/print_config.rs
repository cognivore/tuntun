use std::path::Path;

use anyhow::Result;

use crate::config::ServerConfig;

pub async fn run(config: Option<&Path>) -> Result<()> {
    let cfg = ServerConfig::load(config).await?;
    let pretty = serde_json::to_string_pretty(&cfg)?;
    println!("{pretty}");
    Ok(())
}
