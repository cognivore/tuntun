//! Server config loader. Format matches the TOML the NixOS module emits.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use tuntun_core::{MoshPort, TenantId};

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
    /// Public UDP ports relayed to this tenant's `mosh-server`, if any.
    #[serde(rename = "moshPorts", default)]
    pub mosh_ports: Option<MoshPortRange>,
}

/// Inclusive, non-empty range of mosh ports owned by one tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoshPortRange {
    from: MoshPort,
    to: MoshPort,
}

impl MoshPortRange {
    pub fn new(from: MoshPort, to: MoshPort) -> Result<Self> {
        if from > to {
            return Err(anyhow!("mosh port range {from}-{to} is empty"));
        }
        Ok(Self { from, to })
    }

    pub fn ports(self) -> impl Iterator<Item = MoshPort> {
        (self.from.value()..=self.to.value()).filter_map(|p| MoshPort::new(p).ok())
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.from <= other.to && other.from <= self.to
    }
}

impl std::fmt::Display for MoshPortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.from, self.to)
    }
}

impl<'de> Deserialize<'de> for MoshPortRange {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            from: MoshPort,
            to: MoshPort,
        }
        let raw = Raw::deserialize(d)?;
        Self::new(raw.from, raw.to).map_err(serde::de::Error::custom)
    }
}

impl TenantsFile {
    /// Every tenant's mosh range. Overlaps are refused here because two
    /// tenants cannot both own a UDP port.
    pub fn mosh_ranges(&self) -> Result<Vec<(TenantId, MoshPortRange)>> {
        let mut out: Vec<(TenantId, MoshPortRange)> = Vec::new();
        for (name, entry) in &self.0 {
            let Some(range) = entry.mosh_ports else {
                continue;
            };
            let tenant = TenantId::new(name.clone())
                .map_err(|e| anyhow!("tenant id {name:?} in tenants file: {e}"))?;
            if let Some((other, _)) = out.iter().find(|(_, r)| r.overlaps(range)) {
                return Err(anyhow!(
                    "mosh ports {range} of tenant {tenant} overlap tenant {other}"
                ));
            }
            out.push((tenant, range));
        }
        Ok(out)
    }
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
        let parsed: BTreeMap<String, TenantsFileEntry> = serde_json::from_slice(&bytes)
            .with_context(|| {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tenants(json: &str) -> Result<TenantsFile> {
        Ok(TenantsFile(serde_json::from_str(json)?))
    }

    #[test]
    fn mosh_ranges_are_parsed_per_tenant_and_must_not_overlap() {
        let file = tenants(
            r#"{"alice":{"authorizedKeys":[],"moshPorts":{"from":60000,"to":60002}},
                "bob":{"authorizedKeys":[],"moshPorts":null},
                "carol":{"authorizedKeys":[]}}"#,
        )
        .expect("parse");
        let ranges = file.mosh_ranges().expect("ranges");
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].0.as_str(), "alice");
        let ports: Vec<u16> = ranges[0].1.ports().map(MoshPort::value).collect();
        assert_eq!(ports, [60_000, 60_001, 60_002]);

        let clash = tenants(
            r#"{"alice":{"moshPorts":{"from":60000,"to":60009}},
                "bob":{"moshPorts":{"from":60009,"to":60010}}}"#,
        )
        .expect("parse");
        assert!(clash.mosh_ranges().is_err());
    }

    #[test]
    fn mosh_ranges_outside_the_mosh_range_or_reversed_are_rejected() {
        assert!(tenants(r#"{"a":{"moshPorts":{"from":22,"to":60000}}}"#).is_err());
        assert!(tenants(r#"{"a":{"moshPorts":{"from":60001,"to":60000}}}"#).is_err());
    }
}
