//! In-memory registry of currently-connected tunnel clients and their
//! registered services. Backed by `tokio::sync::RwLock`.
//!
//! Keys are typed via `tuntun_core` newtypes; the registry never accepts
//! raw strings.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};

use tuntun_core::{Fqdn, ProjectId, ServiceName, ServicePort, TenantId, TunnelClientId};
use tuntun_proto::{AuthPolicy, ControlFrame, HealthCheckSpec};

const PORT_FLOOR: u16 = 20_000;

#[derive(Debug, Clone)]
pub struct ClientRecord {
    pub client_id: TunnelClientId,
    pub tenant: TenantId,
    pub control_tx: mpsc::Sender<ControlFrame>,
    pub projects: BTreeMap<ProjectId, ProjectRecord>,
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
    inner: RwLock<RegistryInner>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    clients: BTreeMap<TunnelClientId, ClientRecord>,
    /// Reverse index: which client owns which fqdn.
    fqdn_to_client: BTreeMap<Fqdn, TunnelClientId>,
    next_port: u16,
}

impl Registry {
    pub fn new(port_range_start: u16) -> Self {
        Self {
            inner: RwLock::new(RegistryInner {
                clients: BTreeMap::new(),
                fqdn_to_client: BTreeMap::new(),
                next_port: port_range_start,
            }),
        }
    }

    pub async fn upsert_client(self: &Arc<Self>, record: ClientRecord) {
        let mut inner = self.inner.write().await;
        inner.clients.insert(record.client_id.clone(), record);
    }

    pub async fn drop_client(self: &Arc<Self>, client_id: &TunnelClientId) {
        let mut inner = self.inner.write().await;
        if let Some(client) = inner.clients.remove(client_id) {
            for (_, project) in client.projects {
                for (_, svc) in project.services {
                    inner.fqdn_to_client.remove(&svc.fqdn);
                }
            }
        }
    }

    pub async fn allocate_port(self: &Arc<Self>) -> ServicePort {
        // Clamp into [PORT_FLOOR, u16::MAX] so ServicePort::new never fails
        // (its only invariant is `>= 1`). We bias high to stay clear of
        // user-managed services on the same host.
        let mut inner = self.inner.write().await;
        if inner.next_port < PORT_FLOOR {
            inner.next_port = PORT_FLOOR;
        }
        let p = inner.next_port;
        inner.next_port = inner.next_port.saturating_add(1);
        ServicePort::new(p).unwrap_or_else(|_| {
            ServicePort::new(PORT_FLOOR).unwrap_or_else(|_| {
                // Truly unreachable: PORT_FLOOR is a non-zero const.
                ServicePort::new(1).unwrap_or_else(|_| unreachable!())
            })
        })
    }

    pub async fn snapshot_services(self: &Arc<Self>) -> Vec<ServiceRecord> {
        let inner = self.inner.read().await;
        let mut out = Vec::new();
        for client in inner.clients.values() {
            for project in client.projects.values() {
                for svc in project.services.values() {
                    out.push(svc.clone());
                }
            }
        }
        out
    }

    pub async fn lookup_by_fqdn(self: &Arc<Self>, fqdn: &Fqdn) -> Option<TunnelClientId> {
        self.inner
            .read()
            .await
            .fqdn_to_client
            .get(fqdn)
            .cloned()
    }
}
