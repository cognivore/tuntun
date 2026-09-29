//! Published tunnels keyed by tenant and device. Cleanup checks session identity.
use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tuntun_core::{Fqdn, ProjectId, ServiceName, ServicePort, TenantId, TunnelClientId};
use tuntun_proto::{AuthPolicy, HealthCheckSpec};

use crate::tunnel::per_service_listener::OpenStreamRequest;

#[derive(Clone)]
pub struct ClientRecord {
    pub client_id: TunnelClientId,
    pub tenant: TenantId,
    pub stream_tx: mpsc::Sender<OpenStreamRequest>,
    pub cancelled: CancellationToken,
    pub projects: BTreeMap<ProjectId, ProjectRecord>,
}

impl std::fmt::Debug for ClientRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRecord")
            .field("client_id", &self.client_id)
            .field("tenant", &self.tenant)
            .field("projects", &self.projects)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct ProjectRecord {
    pub project: ProjectId,
    pub services: BTreeMap<ServiceName, ServiceRecord>,
}

#[derive(Debug, Clone)]
pub struct ServiceRecord {
    pub service: ServiceName,
    pub fqdn: Fqdn,
    pub server_port: ServicePort,
    pub auth_policy: AuthPolicy,
    pub health_check: Option<HealthCheckSpec>,
}

#[derive(Debug, Default)]
pub struct Registry {
    clients: RwLock<BTreeMap<(TenantId, TunnelClientId), ClientRecord>>,
    /// Serialize Caddy snapshots and reloads to prevent stale publication.
    pub publication: tokio::sync::Mutex<()>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn upsert_client(&self, record: ClientRecord) {
        let mut clients = self.clients.write().await;
        if let Some(previous) =
            clients.insert((record.tenant.clone(), record.client_id.clone()), record)
        {
            previous.cancelled.cancel();
        }
    }

    pub async fn drop_client(&self, record: &ClientRecord) {
        let mut clients = self.clients.write().await;
        let key = (record.tenant.clone(), record.client_id.clone());
        if clients
            .get(&key)
            .is_some_and(|current| current.stream_tx.same_channel(&record.stream_tx))
        {
            clients.remove(&key);
        }
    }

    pub async fn snapshot_services(&self) -> Vec<ServiceRecord> {
        self.clients
            .read()
            .await
            .values()
            .flat_map(|client| client.projects.values())
            .flat_map(|project| project.services.values().cloned())
            .collect()
    }

    pub async fn lookup_by_tenant(self: &Arc<Self>, tenant: &TenantId) -> Option<ClientRecord> {
        // The stable reverse-SSH address always targets the primary laptop.
        // Other devices use distinct client IDs and may publish web services.
        let clients = self.clients.read().await;
        clients
            .values()
            .find(|client| {
                &client.tenant == tenant && client.client_id.as_str() == format!("laptop-{tenant}")
            })
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(tenant: &str) -> ClientRecord {
        ClientRecord {
            client_id: TunnelClientId::new(format!("laptop-{tenant}")).expect("valid client id"),
            tenant: TenantId::new(tenant).expect("valid tenant"),
            stream_tx: mpsc::channel(1).0,
            cancelled: CancellationToken::new(),
            projects: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn stale_cleanup_cannot_remove_replacement_or_another_tenant() {
        let registry = Arc::new(Registry::new());
        let old = client("alice");
        let new = client("alice");
        let other = client("bob");
        let mut secondary = client("alice");
        secondary.client_id = TunnelClientId::new("octoprophet").expect("device id");
        registry.upsert_client(old.clone()).await;
        registry.upsert_client(other.clone()).await;
        registry.upsert_client(secondary.clone()).await;
        registry.upsert_client(new.clone()).await;
        assert!(old.cancelled.is_cancelled());
        assert!(!other.cancelled.is_cancelled());
        assert!(!secondary.cancelled.is_cancelled());
        registry.drop_client(&old).await;
        let current = registry
            .lookup_by_tenant(&new.tenant)
            .await
            .expect("replacement survives");
        assert!(current.stream_tx.same_channel(&new.stream_tx));
        assert!(registry.lookup_by_tenant(&other.tenant).await.is_some());
        registry.drop_client(&new).await;
        assert!(registry.lookup_by_tenant(&new.tenant).await.is_none());
    }
}
