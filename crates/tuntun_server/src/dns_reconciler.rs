//! Periodic DNS reconciler.
//!
//! Computes the desired DNS state from the active service registry plus the
//! configured apex domain and `publicIp`, then drives the `PorkbunDns`
//! adapter to converge.
//!
//! Porkbun has no domain-wide listing endpoint, so this reconciler queries
//! per `(name, kind)` via [`PorkbunDns::list_records_for`], then runs the
//! pure planner [`tuntun_dns::plan_dns_reconciliation`] over the aggregated
//! observation. Deletes are not emitted: we don't track which records are
//! tuntun-owned vs user-managed, so removing them is unsafe.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};

use tuntun_core::{
    DnsPort, DnsRecord, DnsRecordContent, DnsRecordSpec, Domain, HttpPort, Subdomain, Ttl,
};
use tuntun_dns::PorkbunDns;

use crate::config::ServerConfig;
use crate::registry::Registry;

const DEFAULT_TTL: u32 = 300;
const DEFAULT_PERIOD: Duration = Duration::from_secs(5 * 60);

#[derive(Debug)]
pub struct Reconciler<H: HttpPort + 'static> {
    config: Arc<ServerConfig>,
    registry: Arc<Registry>,
    dns: Arc<PorkbunDns<H>>,
}

impl<H: HttpPort + 'static> Reconciler<H> {
    pub fn new(
        config: Arc<ServerConfig>,
        registry: Arc<Registry>,
        dns: Arc<PorkbunDns<H>>,
    ) -> Self {
        Self {
            config,
            registry,
            dns,
        }
    }

    pub async fn desired(&self) -> Result<Vec<DnsRecordSpec>> {
        let domain = Domain::new(self.config.domain.clone())
            .map_err(|e| anyhow!("invalid domain {}: {e}", self.config.domain))?;
        let ttl = Ttl::new(DEFAULT_TTL).map_err(|e| anyhow!("ttl: {e}"))?;
        let ip = Ipv4Addr::from_str(&self.config.public_ip)
            .map_err(|e| anyhow!("public_ip {}: {e}", self.config.public_ip))?;

        let services = self.registry.snapshot_services().await;
        let mut out = Vec::with_capacity(services.len() + 1);

        if let Ok(wildcard) = Subdomain::new("*") {
            out.push(DnsRecordSpec {
                apex: domain.clone(),
                name: wildcard,
                ttl,
                content: DnsRecordContent::A { ip },
            });
        }

        for svc in services {
            let fqdn_str = svc.fqdn.as_str();
            let Some(idx) = fqdn_str.find('.') else { continue };
            let label = &fqdn_str[..idx];
            if let Ok(name) = Subdomain::new(label.to_string()) {
                out.push(DnsRecordSpec {
                    apex: domain.clone(),
                    name,
                    ttl,
                    content: DnsRecordContent::A { ip },
                });
            }
        }

        Ok(out)
    }

    pub async fn reconcile_once(&self) -> Result<()> {
        let desired = self.desired().await?;

        let mut observed: Vec<DnsRecord> = Vec::with_capacity(desired.len());
        for spec in &desired {
            match self
                .dns
                .list_records_for(&spec.apex, &spec.name, spec.content.kind())
                .await
            {
                Ok(records) => observed.extend(records),
                Err(e) => tracing::debug!(
                    "list_records_for {}/{} {}: {e}",
                    spec.apex,
                    spec.name,
                    spec.content.kind()
                ),
            }
        }

        let actions = tuntun_dns::plan_dns_reconciliation(&desired, &observed);
        tracing::info!(
            "dns reconcile: {} desired, {} observed, {} actions",
            desired.len(),
            observed.len(),
            actions.len()
        );

        for action in actions {
            match action {
                tuntun_dns::DnsAction::Create(spec) => {
                    if let Err(e) = self.dns.create_record(&spec).await {
                        tracing::warn!(
                            "create_record {}/{}: {e}",
                            spec.apex,
                            spec.name
                        );
                    }
                }
                tuntun_dns::DnsAction::Update(spec) => {
                    if let Err(e) = self.dns.update_record(&spec).await {
                        tracing::warn!(
                            "update_record {}/{}: {e}",
                            spec.apex,
                            spec.name
                        );
                    }
                }
                // Skip Delete: see module docstring.
                tuntun_dns::DnsAction::Delete { .. } | tuntun_dns::DnsAction::NoOp(_) => {}
            }
        }

        Ok(())
    }

    pub async fn run_forever(self: Arc<Self>) -> Result<()> {
        let mut ticker = tokio::time::interval(DEFAULT_PERIOD);
        loop {
            ticker.tick().await;
            if let Err(e) = self.reconcile_once().await {
                tracing::error!("dns reconcile error: {e:#}");
            }
        }
    }
}
