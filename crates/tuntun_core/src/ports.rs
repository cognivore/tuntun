//! Port traits.
//!
//! All composite operations in library crates accept generic parameters
//! bounded by these traits. Adapters live exclusively in `tuntun_cli` and
//! `tuntun_server`.
//!
//! Note: `async-trait` is used here for ergonomics. The performance overhead
//! (a heap-allocated future per call) is irrelevant for the control-plane
//! traffic these ports carry. Data-plane byte pumping is done in the binaries
//! directly without a port boundary.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::dns::{DnsRecord, DnsRecordKind, DnsRecordSpec};
use crate::error::Result;
use crate::http::{HttpRequest, HttpResponse};
use crate::ids::{DnsName, Domain, DnsRecordId, SecretKey};
use crate::process::{ProcessExit, ProcessSpec};
use crate::secret::SecretValue;
use crate::time::{Instant, Timestamp};

// ---------- HttpPort ----------------------------------------------------------

#[async_trait]
pub trait HttpPort: Send + Sync {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse>;
}

#[async_trait]
impl<T: HttpPort + ?Sized> HttpPort for Arc<T> {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        (**self).request(req).await
    }
}

#[async_trait]
impl<T: HttpPort + ?Sized> HttpPort for &T {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        (**self).request(req).await
    }
}

// ---------- DnsPort -----------------------------------------------------------

#[async_trait]
pub trait DnsPort: Send + Sync {
    /// List all records for a domain.
    async fn list_records(&self, domain: &Domain) -> Result<Vec<DnsRecord>>;

    /// Create a new record. Returns the provider's record id.
    async fn create_record(&self, spec: &DnsRecordSpec) -> Result<DnsRecordId>;

    /// Update an existing record (identified by name + kind on the apex).
    async fn update_record(&self, spec: &DnsRecordSpec) -> Result<()>;

    /// Delete a record by name + kind.
    async fn delete_record(
        &self,
        domain: &Domain,
        name: &DnsName,
        kind: DnsRecordKind,
    ) -> Result<()>;
}

#[async_trait]
impl<T: DnsPort + ?Sized> DnsPort for Arc<T> {
    async fn list_records(&self, domain: &Domain) -> Result<Vec<DnsRecord>> {
        (**self).list_records(domain).await
    }
    async fn create_record(&self, spec: &DnsRecordSpec) -> Result<DnsRecordId> {
        (**self).create_record(spec).await
    }
    async fn update_record(&self, spec: &DnsRecordSpec) -> Result<()> {
        (**self).update_record(spec).await
    }
    async fn delete_record(
        &self,
        domain: &Domain,
        name: &DnsName,
        kind: DnsRecordKind,
    ) -> Result<()> {
        (**self).delete_record(domain, name, kind).await
    }
}

// ---------- ClockPort ---------------------------------------------------------

pub trait ClockPort: Send + Sync {
    fn now(&self) -> Timestamp;
    fn instant(&self) -> Instant;
}

// ---------- SecretPort --------------------------------------------------------

#[async_trait]
pub trait SecretPort: Send + Sync {
    async fn load(&self, key: &SecretKey) -> Result<SecretValue>;
    async fn store(&self, key: &SecretKey, value: &SecretValue) -> Result<()>;
    async fn exists(&self, key: &SecretKey) -> Result<bool>;
}

#[async_trait]
impl<T: SecretPort + ?Sized> SecretPort for Arc<T> {
    async fn load(&self, key: &SecretKey) -> Result<SecretValue> {
        (**self).load(key).await
    }
    async fn store(&self, key: &SecretKey, value: &SecretValue) -> Result<()> {
        (**self).store(key, value).await
    }
    async fn exists(&self, key: &SecretKey) -> Result<bool> {
        (**self).exists(key).await
    }
}

// ---------- ProcessPort -------------------------------------------------------

#[async_trait]
pub trait ProcessPort: Send + Sync {
    /// Run a one-shot subprocess to completion. Used for `caddy reload`,
    /// `rageveil show`, and similar short-lived calls.
    async fn run_to_completion(&self, spec: &ProcessSpec) -> Result<ProcessExit>;
}

#[async_trait]
impl<T: ProcessPort + ?Sized> ProcessPort for Arc<T> {
    async fn run_to_completion(&self, spec: &ProcessSpec) -> Result<ProcessExit> {
        (**self).run_to_completion(spec).await
    }
}

// ---------- FsPort ------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FsPath(pub String);

impl FsPath {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[async_trait]
pub trait FsPort: Send + Sync {
    async fn write_file(&self, path: &FsPath, contents: &[u8]) -> Result<()>;
    async fn read_file(&self, path: &FsPath) -> Result<Vec<u8>>;
    async fn ensure_dir(&self, path: &FsPath) -> Result<()>;
    async fn remove_file(&self, path: &FsPath) -> Result<()>;
    async fn rename(&self, from: &FsPath, to: &FsPath) -> Result<()>;
}

#[async_trait]
impl<T: FsPort + ?Sized> FsPort for Arc<T> {
    async fn write_file(&self, path: &FsPath, contents: &[u8]) -> Result<()> {
        (**self).write_file(path, contents).await
    }
    async fn read_file(&self, path: &FsPath) -> Result<Vec<u8>> {
        (**self).read_file(path).await
    }
    async fn ensure_dir(&self, path: &FsPath) -> Result<()> {
        (**self).ensure_dir(path).await
    }
    async fn remove_file(&self, path: &FsPath) -> Result<()> {
        (**self).remove_file(path).await
    }
    async fn rename(&self, from: &FsPath, to: &FsPath) -> Result<()> {
        (**self).rename(from, to).await
    }
}

impl<T: ClockPort + ?Sized> ClockPort for Arc<T> {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
    fn instant(&self) -> Instant {
        (**self).instant()
    }
}
