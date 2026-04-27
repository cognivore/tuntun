//! DNS-specific error type, convertible to [`tuntun_core::Error`].
//!
//! The adapter and parsers map to this type internally; public API returns
//! `tuntun_core::Result<T>` so library consumers see a single unified error.

use thiserror::Error;
use tuntun_core::Error as CoreError;

/// Errors that originate from the DNS provider integration layer.
///
/// These are mapped onto [`CoreError::Upstream`] (with `kind = "porkbun"`) or
/// [`CoreError::Dns`] when crossing the public API boundary.
#[derive(Debug, Error)]
pub enum DnsError {
    /// The HTTP transport returned a status outside `200..300`.
    #[error("porkbun HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },

    /// The response body was not valid UTF-8 / JSON / the expected shape.
    #[error("porkbun response decode: {0}")]
    Decode(String),

    /// The Porkbun API returned `status: \"ERROR\"` with a message.
    #[error("porkbun API error: {0}")]
    Api(String),

    /// A field returned by Porkbun could not be coerced into a tuntun newtype.
    #[error("porkbun returned invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: String,
    },

    /// Caller asked us to delete a record that is not present.
    #[error("dns record not found")]
    NotFound,
}

impl DnsError {
    /// Convenience for parsers that need to wrap a free-form reason string.
    pub fn decode(message: impl Into<String>) -> Self {
        DnsError::Decode(message.into())
    }

    pub fn invalid_field(field: &'static str, reason: impl Into<String>) -> Self {
        DnsError::InvalidField {
            field,
            reason: reason.into(),
        }
    }
}

impl From<DnsError> for CoreError {
    fn from(e: DnsError) -> Self {
        match e {
            DnsError::HttpStatus { status, body } => {
                CoreError::upstream("porkbun", format!("HTTP {status}: {body}"))
            }
            DnsError::Decode(m) => CoreError::upstream("porkbun", format!("decode: {m}")),
            DnsError::Api(m) => CoreError::upstream("porkbun", m),
            DnsError::InvalidField { field, reason } => {
                CoreError::dns(format!("invalid {field}: {reason}"))
            }
            DnsError::NotFound => CoreError::not_found("dns_record", "porkbun"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_http_status() {
        let e = DnsError::HttpStatus {
            status: 503,
            body: "boom".into(),
        };
        let core: CoreError = e.into();
        let s = format!("{core}");
        assert!(s.contains("porkbun"));
        assert!(s.contains("503"));
    }

    #[test]
    fn maps_api_error() {
        let e = DnsError::Api("nope".into());
        let core: CoreError = e.into();
        assert!(matches!(core, CoreError::Upstream { kind: "porkbun", .. }));
    }

    #[test]
    fn maps_invalid_field() {
        let e = DnsError::invalid_field("ttl", "negative");
        let core: CoreError = e.into();
        assert!(matches!(core, CoreError::Dns(_)));
    }

    #[test]
    fn maps_not_found() {
        let core: CoreError = DnsError::NotFound.into();
        assert!(matches!(core, CoreError::NotFound { .. }));
    }
}
