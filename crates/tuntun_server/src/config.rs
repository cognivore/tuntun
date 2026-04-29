//! Server config loader. Format matches the TOML the NixOS module emits.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub domain: String,
    pub public_ip: String,
    pub tunnel_listen: String,
    pub auth_listen: String,
    pub login_listen: String,
    pub state_dir: PathBuf,
    pub caddy_bin: PathBuf,
    pub caddyfile_path: PathBuf,
    pub caddy_admin: String,
    pub caddy_log: PathBuf,
    pub acme_email: String,
    pub tenants_file: PathBuf,
    /// Path of the unix-domain socket the SSH bastion side-car listens on.
    /// The OpenSSH `ForceCommand` helper (`tuntun-server tcp-forward`)
    /// connects to this path.
    pub bastion_socket: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TenantsFile(pub BTreeMap<String, TenantsFileEntry>);

#[derive(Debug, Clone, Deserialize)]
pub struct TenantsFileEntry {
    #[serde(rename = "authorizedKeys", default)]
    pub authorized_keys: Vec<String>,
}

impl ServerConfig {
    pub async fn load(explicit: Option<&Path>) -> Result<Self> {
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => default_config_path()?,
        };

        let bytes = tokio::fs::read(&path)
            .await
            .with_context(|| format!("read server config at {}", path.display()))?;
        parse_minimal_toml(&bytes)
            .with_context(|| format!("parse server config at {}", path.display()))
    }

    pub async fn load_tenants(&self) -> Result<TenantsFile> {
        let bytes = tokio::fs::read(&self.tenants_file)
            .await
            .with_context(|| format!("read tenants file {}", self.tenants_file.display()))?;
        let parsed: BTreeMap<String, TenantsFileEntry> =
            serde_json::from_slice(&bytes).with_context(|| {
                format!("parse tenants file {} as JSON", self.tenants_file.display())
            })?;
        Ok(TenantsFile(parsed))
    }
}

fn default_config_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("TUNTUN_CONFIG") {
        return Ok(PathBuf::from(p));
    }
    Err(anyhow!(
        "no --config and TUNTUN_CONFIG unset; pass an explicit path"
    ))
}

fn parse_minimal_toml(bytes: &[u8]) -> Result<ServerConfig> {
    let s = std::str::from_utf8(bytes).context("config not utf-8")?;
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for (lineno, raw) in s.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("line {}: expected `key = \"value\"`", lineno + 1))?;
        let v = v.trim().trim_matches('"').to_string();
        map.insert(k.trim().to_string(), v);
    }

    let take = |k: &str| -> Result<String> {
        map.get(k)
            .cloned()
            .ok_or_else(|| anyhow!("missing required field `{k}`"))
    };

    Ok(ServerConfig {
        domain: take("domain")?,
        public_ip: take("public_ip")?,
        tunnel_listen: take("tunnel_listen")?,
        auth_listen: take("auth_listen")?,
        login_listen: take("login_listen")?,
        state_dir: PathBuf::from(take("state_dir")?),
        caddy_bin: PathBuf::from(take("caddy_bin")?),
        caddyfile_path: PathBuf::from(take("caddyfile_path")?),
        caddy_admin: take("caddy_admin")?,
        caddy_log: PathBuf::from(take("caddy_log")?),
        acme_email: take("acme_email")?,
        tenants_file: PathBuf::from(take("tenants_file")?),
        bastion_socket: PathBuf::from(take("bastion_socket")?),
    })
}
