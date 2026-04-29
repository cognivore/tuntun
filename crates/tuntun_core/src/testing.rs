//! Mock port implementations for tests in any library crate.
//!
//! These types use `std::sync::Mutex` (a synchronization primitive, not I/O)
//! so they can be used from `async-trait` impls without depending on a
//! specific runtime. Locks are held only for short, sync sections.
//!
//! This module is intended for use from `#[cfg(test)]` blocks in other
//! crates; the `expect`/`unwrap` calls used here on `Mutex::lock` are safe
//! given Rust's lock-poisoning semantics in single-threaded tests, and are
//! permitted here by the module-level allows below.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_errors_doc
)]

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Mutex;

use async_trait::async_trait;

use crate::dns::{DnsRecord, DnsRecordKind, DnsRecordSpec};
use crate::error::{Error, Result};
use crate::http::{HttpRequest, HttpResponse, HttpStatus};
use crate::ids::{DnsName, DnsRecordId, Domain, SecretKey};
use crate::ports::{ClockPort, DnsPort, FsPath, FsPort, HttpPort, ProcessPort, SecretPort};
use crate::process::{ProcessExit, ProcessExitCode, ProcessSpec};
use crate::secret::SecretValue;
use crate::time::{Instant, Timestamp};

// ---------- MockHttp ---------------------------------------------------------

#[derive(Debug)]
pub struct MockHttp {
    /// Queue of canned responses, in order.
    responses: Mutex<VecDeque<Result<HttpResponse>>>,
    /// All requests received, in order.
    requests: Mutex<Vec<HttpRequest>>,
}

impl Default for MockHttp {
    fn default() -> Self {
        Self::new()
    }
}

impl MockHttp {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(VecDeque::new()),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn push_response(&self, resp: HttpResponse) {
        self.responses
            .lock()
            .expect("mock-http lock")
            .push_back(Ok(resp));
    }

    pub fn push_json_response(&self, status: u16, body: &impl serde::Serialize) {
        let bytes = serde_json::to_vec(body).expect("serialize mock body");
        self.push_response(HttpResponse::new(HttpStatus(status), bytes));
    }

    pub fn push_error(&self, err: Error) {
        self.responses
            .lock()
            .expect("mock-http lock")
            .push_back(Err(err));
    }

    pub fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().expect("mock-http lock").clone()
    }

    pub fn last_request(&self) -> Option<HttpRequest> {
        self.requests.lock().expect("mock-http lock").last().cloned()
    }
}

#[async_trait]
impl HttpPort for MockHttp {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        self.requests
            .lock()
            .expect("mock-http lock")
            .push(req.clone());
        let next = self
            .responses
            .lock()
            .expect("mock-http lock")
            .pop_front()
            .ok_or_else(|| Error::other("MockHttp: no canned response left"))?;
        next
    }
}

// ---------- MockDns ----------------------------------------------------------

#[derive(Debug, Default)]
pub struct MockDns {
    inner: Mutex<MockDnsInner>,
}

#[derive(Debug, Default)]
struct MockDnsInner {
    /// (domain, name, kind) -> record
    records: HashMap<(Domain, DnsName, DnsRecordKind), DnsRecord>,
    next_id: u64,
}

impl MockDns {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DnsPort for MockDns {
    async fn list_records(&self, domain: &Domain) -> Result<Vec<DnsRecord>> {
        let inner = self.inner.lock().expect("mock-dns lock");
        Ok(inner
            .records
            .values()
            .filter(|r| &r.apex == domain)
            .cloned()
            .collect())
    }

    async fn create_record(&self, spec: &DnsRecordSpec) -> Result<DnsRecordId> {
        let mut inner = self.inner.lock().expect("mock-dns lock");
        let key = (spec.apex.clone(), spec.name.clone(), spec.content.kind());
        if inner.records.contains_key(&key) {
            return Err(Error::conflict(format!(
                "{}/{} {} already exists",
                spec.apex,
                spec.name,
                spec.content.kind()
            )));
        }
        inner.next_id += 1;
        let id = DnsRecordId::new(format!("rec-{}", inner.next_id))
            .map_err(|e| Error::other(format!("mock id: {e}")))?;
        let rec = DnsRecord {
            id: id.clone(),
            apex: spec.apex.clone(),
            name: spec.name.clone(),
            ttl: spec.ttl,
            content: spec.content.clone(),
        };
        inner.records.insert(key, rec);
        Ok(id)
    }

    async fn update_record(&self, spec: &DnsRecordSpec) -> Result<()> {
        let mut inner = self.inner.lock().expect("mock-dns lock");
        let key = (spec.apex.clone(), spec.name.clone(), spec.content.kind());
        let entry = inner.records.get_mut(&key).ok_or_else(|| {
            Error::not_found(
                "dns_record",
                format!("{}/{} {}", spec.apex, spec.name, spec.content.kind()),
            )
        })?;
        entry.ttl = spec.ttl;
        entry.content = spec.content.clone();
        Ok(())
    }

    async fn delete_record(
        &self,
        domain: &Domain,
        name: &DnsName,
        kind: DnsRecordKind,
    ) -> Result<()> {
        let mut inner = self.inner.lock().expect("mock-dns lock");
        let key = (domain.clone(), name.clone(), kind);
        inner.records.remove(&key).ok_or_else(|| {
            Error::not_found("dns_record", format!("{domain}/{name} {kind}"))
        })?;
        Ok(())
    }
}

// ---------- FixedClock -------------------------------------------------------

#[derive(Debug)]
pub struct FixedClock {
    timestamp: Mutex<Timestamp>,
    instant: Mutex<Instant>,
}

impl FixedClock {
    pub fn new(timestamp: Timestamp) -> Self {
        Self {
            timestamp: Mutex::new(timestamp),
            instant: Mutex::new(Instant::from_nanos(0)),
        }
    }

    pub fn advance_seconds(&self, seconds: i64) {
        let mut t = self.timestamp.lock().expect("clock lock");
        t.seconds += seconds;
        let mut i = self.instant.lock().expect("clock lock");
        i.ticks_ns += (seconds as u128).saturating_mul(1_000_000_000);
    }

    pub fn set(&self, timestamp: Timestamp) {
        *self.timestamp.lock().expect("clock lock") = timestamp;
    }
}

impl ClockPort for FixedClock {
    fn now(&self) -> Timestamp {
        *self.timestamp.lock().expect("clock lock")
    }

    fn instant(&self) -> Instant {
        *self.instant.lock().expect("clock lock")
    }
}

// ---------- MockSecrets ------------------------------------------------------

#[derive(Debug, Default)]
pub struct MockSecrets {
    store: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MockSecrets {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn preload(&self, key: &str, value: &[u8]) {
        self.store
            .lock()
            .expect("secrets lock")
            .insert(key.to_string(), value.to_vec());
    }
}

#[async_trait]
impl SecretPort for MockSecrets {
    async fn load(&self, key: &SecretKey) -> Result<SecretValue> {
        let store = self.store.lock().expect("secrets lock");
        let bytes = store
            .get(key.as_str())
            .cloned()
            .ok_or_else(|| Error::not_found("secret", key.as_str()))?;
        Ok(SecretValue::from_bytes(bytes))
    }

    async fn store(&self, key: &SecretKey, value: &SecretValue) -> Result<()> {
        self.store
            .lock()
            .expect("secrets lock")
            .insert(key.as_str().to_string(), value.expose_bytes().to_vec());
        Ok(())
    }

    async fn exists(&self, key: &SecretKey) -> Result<bool> {
        Ok(self
            .store
            .lock()
            .expect("secrets lock")
            .contains_key(key.as_str()))
    }
}

// ---------- MockProcess ------------------------------------------------------

#[derive(Debug, Default)]
pub struct MockProcess {
    canned: Mutex<VecDeque<Result<ProcessExit>>>,
    invocations: Mutex<Vec<ProcessSpec>>,
}

impl MockProcess {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_success(&self, stdout: &[u8], stderr: &[u8]) {
        self.canned
            .lock()
            .expect("process lock")
            .push_back(Ok(ProcessExit {
                code: Some(ProcessExitCode(0)),
                stdout: stdout.to_vec(),
                stderr: stderr.to_vec(),
            }));
    }

    pub fn push_failure(&self, code: i32, stderr: &[u8]) {
        self.canned
            .lock()
            .expect("process lock")
            .push_back(Ok(ProcessExit {
                code: Some(ProcessExitCode(code)),
                stdout: Vec::new(),
                stderr: stderr.to_vec(),
            }));
    }

    pub fn invocations(&self) -> Vec<ProcessSpec> {
        self.invocations.lock().expect("process lock").clone()
    }
}

#[async_trait]
impl ProcessPort for MockProcess {
    async fn run_to_completion(&self, spec: &ProcessSpec) -> Result<ProcessExit> {
        self.invocations
            .lock()
            .expect("process lock")
            .push(spec.clone());
        self.canned
            .lock()
            .expect("process lock")
            .pop_front()
            .ok_or_else(|| Error::other("MockProcess: no canned exit"))?
    }
}

// ---------- MockFs -----------------------------------------------------------

#[derive(Debug, Default)]
pub struct MockFs {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    dirs: Mutex<BTreeSet<String>>,
}

impl MockFs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn preload_file(&self, path: &str, contents: &[u8]) {
        self.files
            .lock()
            .expect("fs lock")
            .insert(path.to_string(), contents.to_vec());
    }

    pub fn read_back(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().expect("fs lock").get(path).cloned()
    }
}

#[async_trait]
impl FsPort for MockFs {
    async fn write_file(&self, path: &FsPath, contents: &[u8]) -> Result<()> {
        self.files
            .lock()
            .expect("fs lock")
            .insert(path.as_str().to_string(), contents.to_vec());
        Ok(())
    }

    async fn read_file(&self, path: &FsPath) -> Result<Vec<u8>> {
        let files = self.files.lock().expect("fs lock");
        files
            .get(path.as_str())
            .cloned()
            .ok_or_else(|| Error::not_found("file", path.as_str()))
    }

    async fn ensure_dir(&self, path: &FsPath) -> Result<()> {
        self.dirs
            .lock()
            .expect("fs lock")
            .insert(path.as_str().to_string());
        Ok(())
    }

    async fn remove_file(&self, path: &FsPath) -> Result<()> {
        self.files
            .lock()
            .expect("fs lock")
            .remove(path.as_str())
            .ok_or_else(|| Error::not_found("file", path.as_str()))?;
        Ok(())
    }

    async fn rename(&self, from: &FsPath, to: &FsPath) -> Result<()> {
        let mut files = self.files.lock().expect("fs lock");
        let bytes = files
            .remove(from.as_str())
            .ok_or_else(|| Error::not_found("file", from.as_str()))?;
        files.insert(to.as_str().to_string(), bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsRecordContent;
    use crate::ids::Ttl;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn mock_dns_basic_round_trip() {
        let dns = MockDns::new();
        let spec = DnsRecordSpec {
            apex: Domain::new("example.com").unwrap(),
            name: DnsName::new("blog").unwrap(),
            ttl: Ttl::new(60).unwrap(),
            content: DnsRecordContent::A {
                ip: Ipv4Addr::new(1, 2, 3, 4),
            },
        };
        let id = dns.create_record(&spec).await.unwrap();
        assert_eq!(id.as_str(), "rec-1");
        let recs = dns
            .list_records(&Domain::new("example.com").unwrap())
            .await
            .unwrap();
        assert_eq!(recs.len(), 1);

        // duplicate is a conflict
        let err = dns.create_record(&spec).await.unwrap_err();
        assert!(matches!(err, Error::Conflict(_)));
    }

    #[test]
    fn fixed_clock_advances() {
        let clock = FixedClock::new(Timestamp::from_seconds(1_000));
        assert_eq!(clock.now().seconds, 1_000);
        clock.advance_seconds(60);
        assert_eq!(clock.now().seconds, 1_060);
    }
}
