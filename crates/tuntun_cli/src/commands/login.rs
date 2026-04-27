use std::path::Path;

use anyhow::Result;

use crate::config::DaemonConfig;

pub async fn run(config: Option<&Path>, tenant: Option<&str>) -> Result<()> {
    let cfg = DaemonConfig::load(config).await?;
    let tenant_id = tenant.unwrap_or(&cfg.default_tenant);
    println!("(open https://auth.<your-domain>/login?tenant={tenant_id} in a browser)");
    Ok(())
}
