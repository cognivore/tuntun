//! Daemon-config (`cli.toml`) loader.
//!
//! Format (small TOML, written by the home-manager module):
//!
//! ```toml
//! server_host = "edge.memorici.de:7000"
//! server_pubkey_fingerprint = "sha256:abc123..."
//! default_tenant = "jm"
//! state_dir = "/Users/jm/.local/share/tuntun"
//! private_key_secret_name = "tuntun/tunnel-private-key"
//! ```

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    pub server_host: String,
    pub server_pubkey_fingerprint: String,
    pub default_tenant: String,
    pub state_dir: PathBuf,
    #[serde(default = "default_private_key_secret_name")]
    pub private_key_secret_name: String,
    /// Override the tuntun flake reference passed to `nix eval`. Defaults to
    /// the GitHub repo URL.
    #[serde(default = "default_tuntun_flake_ref")]
    pub tuntun_flake_ref: String,
}

fn default_private_key_secret_name() -> String {
    "tuntun/tunnel-private-key".to_string()
}

fn default_tuntun_flake_ref() -> String {
    "github:cognivore/tuntun".to_string()
}

impl DaemonConfig {
    pub async fn load(explicit: Option<&Path>) -> Result<Self> {
        let path = if let Some(p) = explicit {
            p.to_path_buf()
        } else {
            default_config_path()
                .ok_or_else(|| anyhow!("could not determine default config path"))?
        };

        let bytes = tokio::fs::read(&path)
            .await
            .with_context(|| format!("read config at {}", path.display()))?;
        // Naive TOML parser via the toml crate would normally go here, but
        // we want to avoid pulling another dep. Use a minimal hand parser
        // sufficient for the small flat schema. For richer needs, switch to
        // the `toml` crate later.
        parse_minimal_toml(&bytes)
            .with_context(|| format!("parse config at {}", path.display()))
    }
}

fn default_config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("TUNTUN_CONFIG") {
        return Some(PathBuf::from(p));
    }
    let base = dirs::config_dir()?;
    Some(base.join("tuntun").join("cli.toml"))
}

fn parse_minimal_toml(bytes: &[u8]) -> Result<DaemonConfig> {
    let s = std::str::from_utf8(bytes).context("config is not utf-8")?;
    let mut map = std::collections::BTreeMap::new();
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

    Ok(DaemonConfig {
        server_host: take("server_host")?,
        server_pubkey_fingerprint: take("server_pubkey_fingerprint")?,
        default_tenant: take("default_tenant")?,
        state_dir: PathBuf::from(take("state_dir")?),
        private_key_secret_name: map
            .get("private_key_secret_name")
            .cloned()
            .unwrap_or_else(default_private_key_secret_name),
        tuntun_flake_ref: map
            .get("tuntun_flake_ref")
            .cloned()
            .unwrap_or_else(default_tuntun_flake_ref),
    })
}
