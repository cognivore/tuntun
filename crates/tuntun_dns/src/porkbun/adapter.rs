//! [`PorkbunDns`] -- a [`DnsPort`] adapter generic over an [`HttpPort`].
//!
//! All I/O happens via the injected `HttpPort` (which lives in a binary crate);
//! this struct is pure orchestration of pure builders + pure parsers.

use async_trait::async_trait;
use tuntun_core::{
    DnsName, DnsPort, DnsRecord, DnsRecordId, DnsRecordKind, DnsRecordSpec, Domain, HttpPort,
    Result,
};

use super::creds::PorkbunCreds;
use super::request::{
    build_create_request, build_delete_request, build_list_request, build_update_request,
};
use super::response::{parse_create_response, parse_list_response, parse_status_response};

/// `DnsPort` implementation backed by Porkbun's JSON API. Generic over the
/// HTTP transport so that production binaries can plug in `reqwest` while
/// library tests use `tuntun_core::testing::MockHttp`.
pub struct PorkbunDns<H: HttpPort> {
    http: H,
    creds: PorkbunCreds,
}

impl<H: HttpPort> std::fmt::Debug for PorkbunDns<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PorkbunDns")
            .field("creds", &self.creds)
            .finish_non_exhaustive()
    }
}

impl<H: HttpPort> PorkbunDns<H> {
    pub fn new(http: H, creds: PorkbunCreds) -> Self {
        Self { http, creds }
    }

    /// Borrow the underlying transport. Useful for tests that want to inspect
    /// the requests that the adapter emitted via the mock port.
    pub fn http(&self) -> &H {
        &self.http
    }

    pub fn creds(&self) -> &PorkbunCreds {
        &self.creds
    }
}

#[async_trait]
impl<H: HttpPort> DnsPort for PorkbunDns<H> {
    async fn list_records(&self, _domain: &Domain) -> Result<Vec<DnsRecord>> {
        // Porkbun has no wildcard-by-domain list endpoint; the closest
        // primitive is `retrieveByNameType`, which is keyed by
        // `(domain, type, subdomain)`. The reconciler uses
        // [`Self::list_records_for`] directly. We keep the trait method
        // honest by returning a typed error rather than silently lying about
        // an empty domain.
        Err(tuntun_core::Error::dns(
            "PorkbunDns::list_records: Porkbun has no domain-wide list endpoint; \
             call list_records_for(domain, name, kind) instead",
        ))
    }

    async fn create_record(&self, spec: &DnsRecordSpec) -> Result<DnsRecordId> {
        let req = build_create_request(&self.creds, spec)?;
        let resp = self.http.request(req).await?;
        let id = parse_create_response(&resp)?;
        Ok(id)
    }

    async fn update_record(&self, spec: &DnsRecordSpec) -> Result<()> {
        let req = build_update_request(&self.creds, spec)?;
        let resp = self.http.request(req).await?;
        parse_status_response(&resp)?;
        Ok(())
    }

    async fn delete_record(
        &self,
        domain: &Domain,
        name: &DnsName,
        kind: DnsRecordKind,
    ) -> Result<()> {
        let req = build_delete_request(&self.creds, domain, name, kind)?;
        let resp = self.http.request(req).await?;
        parse_status_response(&resp)?;
        Ok(())
    }
}

impl<H: HttpPort> PorkbunDns<H> {
    /// List records for a specific (domain, name, kind) triple. This maps
    /// directly onto Porkbun's `retrieveByNameType` endpoint and is what the
    /// reconciler uses — a domain-wide listing is not supported by Porkbun
    /// without iterating over known names.
    pub async fn list_records_for(
        &self,
        domain: &Domain,
        name: &DnsName,
        kind: DnsRecordKind,
    ) -> Result<Vec<DnsRecord>> {
        let req = build_list_request(&self.creds, domain, name, kind)?;
        let resp = self.http.request(req).await?;
        let records = parse_list_response(&resp, domain)?;
        Ok(records)
    }
}
