use std::path::Path;

use anyhow::Result;

use crate::config::DaemonConfig;

pub async fn run(config: Option<&Path>) -> Result<()> {
    let cfg = DaemonConfig::load(config).await?;
    println!("server: {}", cfg.server_host);
    println!("tenant: {}", cfg.default_tenant);
    println!("state:  {}", cfg.state_dir.display());
    let domain = super::bless::resolve_domain(&cfg)?;
    println!(
        "SSH:    ssh://{}@ssh.{}.{domain}",
        std::env::var("USER")?,
        cfg.default_tenant
    );
    println!(
        "Connect from an enrolled device: ssh ssh.{}.{domain}",
        cfg.default_tenant
    );
    println!(
        "This is configured state. Verify the live route with: ssh ssh.{}.{domain} hostname",
        cfg.default_tenant
    );
    Ok(())
}
