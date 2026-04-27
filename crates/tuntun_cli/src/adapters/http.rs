//! Reqwest-backed `HttpPort` adapter.

use async_trait::async_trait;

use tuntun_core::{Error, HttpHeader, HttpPort, HttpRequest, HttpResponse, HttpStatus, Result};

#[derive(Debug)]
pub struct ReqwestHttp {
    client: reqwest::Client,
}

impl ReqwestHttp {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("tuntun-cli/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Error::port("http", format!("build reqwest client: {e}")))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HttpPort for ReqwestHttp {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        let method = match req.method {
            tuntun_core::HttpMethod::Get => reqwest::Method::GET,
            tuntun_core::HttpMethod::Post => reqwest::Method::POST,
            tuntun_core::HttpMethod::Put => reqwest::Method::PUT,
            tuntun_core::HttpMethod::Patch => reqwest::Method::PATCH,
            tuntun_core::HttpMethod::Delete => reqwest::Method::DELETE,
            tuntun_core::HttpMethod::Head => reqwest::Method::HEAD,
            tuntun_core::HttpMethod::Options => reqwest::Method::OPTIONS,
        };

        let mut builder = self.client.request(method, req.url.as_str());
        for h in &req.headers {
            builder = builder.header(&h.name, &h.value);
        }
        let resp = builder
            .body(req.body)
            .send()
            .await
            .map_err(|e| Error::port("http", format!("send: {e}")))?;

        let status = resp.status().as_u16();
        let mut headers = Vec::with_capacity(resp.headers().len());
        for (k, v) in resp.headers() {
            if let Ok(value_str) = v.to_str() {
                headers.push(HttpHeader::new(k.as_str(), value_str));
            }
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::port("http", format!("read body: {e}")))?
            .to_vec();

        Ok(HttpResponse {
            status: HttpStatus(status),
            headers,
            body,
        })
    }
}
