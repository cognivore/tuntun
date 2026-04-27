use std::path::Path;

use anyhow::Result;

pub async fn run(project_dir: &Path, _config: Option<&Path>, _dry_run: bool) -> Result<()> {
    println!("tuntun deregister: {} (placeholder)", project_dir.display());
    Ok(())
}
