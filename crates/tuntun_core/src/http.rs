//! HTTP request/response value types used at the `HttpPort` boundary.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::id::IdError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HttpUrl(String);

impl HttpUrl {
    pub fn new(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        if s.is_empty() {
            return Err(IdError::Empty("HttpUrl"));
        }
        if !(s.starts_with("http://") || s.starts_with("https://")) {
            return Err(IdError::Invalid {
                kind: "HttpUrl",
                value: s,
                reason: "must start with http:// or https://",
            });
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

impl HttpHeader {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: HttpUrl,
    #[serde(default)]
    pub headers: Vec<HttpHeader>,
    #[serde(default)]
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, url: HttpUrl) -> Self {
        Self {
            method,
            url,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(HttpHeader::new(name, value));
        self
    }

    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn with_json_body(mut self, body: &impl Serialize) -> Result<Self, serde_json::Error> {
        let bytes = serde_json::to_vec(body)?;
        self.headers
            .push(HttpHeader::new("Content-Type", "application/json"));
        self.body = bytes;
        Ok(self)
    }

    /// Group headers by name (last value wins for non-multi-valued keys).
    pub fn header_map(&self) -> BTreeMap<&str, &str> {
        let mut m = BTreeMap::new();
        for h in &self.headers {
            m.insert(h.name.as_str(), h.value.as_str());
        }
        m
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HttpStatus(pub u16);

impl HttpStatus {
    pub fn is_success(self) -> bool {
        (200..300).contains(&self.0)
    }

    pub fn is_client_error(self) -> bool {
        (400..500).contains(&self.0)
    }

    pub fn is_server_error(self) -> bool {
        (500..600).contains(&self.0)
    }
}

impl fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: HttpStatus,
    #[serde(default)]
    pub headers: Vec<HttpHeader>,
    #[serde(default)]
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: HttpStatus, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }

    pub fn body_as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    pub fn parse_json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validates_scheme() {
        assert!(HttpUrl::new("https://api.porkbun.com").is_ok());
        assert!(HttpUrl::new("http://localhost:7000").is_ok());
        assert!(HttpUrl::new("api.porkbun.com").is_err());
        assert!(HttpUrl::new("").is_err());
    }

    #[test]
    fn request_builders() {
        let req = HttpRequest::new(
            HttpMethod::Post,
            HttpUrl::new("https://api.porkbun.com/x").unwrap(),
        )
        .with_header("X-Trace", "abc")
        .with_body(b"hello".to_vec());
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn status_categories() {
        assert!(HttpStatus(200).is_success());
        assert!(HttpStatus(404).is_client_error());
        assert!(HttpStatus(503).is_server_error());
    }
}
