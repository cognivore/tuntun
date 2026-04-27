//! Workspace error type. Library crates use `tuntun_core::Error`; binary
//! crates may wrap with `anyhow` at the outermost layer.

use thiserror::Error;

use crate::id::IdError;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{port}: {message}")]
    Port {
        port: &'static str,
        message: String,
    },

    #[error("identifier: {0}")]
    Id(#[from] IdError),

    #[error("validation: {0}")]
    Validation(String),

    #[error("not found: {kind}={value}")]
    NotFound {
        kind: &'static str,
        value: String,
    },

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("serialization: {0}")]
    Serialization(String),

    #[error("upstream: {kind}: {message}")]
    Upstream {
        kind: &'static str,
        message: String,
    },

    #[error("auth: {0}")]
    Auth(String),

    #[error("dns: {0}")]
    Dns(String),

    #[error("config: {0}")]
    Config(String),

    #[error("other: {0}")]
    Other(String),
}

impl Error {
    pub fn port(port: &'static str, message: impl Into<String>) -> Self {
        Error::Port {
            port,
            message: message.into(),
        }
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Error::Validation(message.into())
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Error::Protocol(message.into())
    }

    pub fn serialization(message: impl Into<String>) -> Self {
        Error::Serialization(message.into())
    }

    pub fn crypto(message: impl Into<String>) -> Self {
        Error::Crypto(message.into())
    }

    pub fn auth(message: impl Into<String>) -> Self {
        Error::Auth(message.into())
    }

    pub fn dns(message: impl Into<String>) -> Self {
        Error::Dns(message.into())
    }

    pub fn config(message: impl Into<String>) -> Self {
        Error::Config(message.into())
    }

    pub fn upstream(kind: &'static str, message: impl Into<String>) -> Self {
        Error::Upstream {
            kind,
            message: message.into(),
        }
    }

    pub fn not_found(kind: &'static str, value: impl Into<String>) -> Self {
        Error::NotFound {
            kind,
            value: value.into(),
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Error::Conflict(message.into())
    }

    pub fn other(message: impl Into<String>) -> Self {
        Error::Other(message.into())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}
