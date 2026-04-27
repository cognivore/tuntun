//! `tuntun_caddy` -- pure Caddyfile generation.
//!
//! This crate performs **zero I/O**. Given a typed [`CaddyInput`] describing
//! the global block, login site, forward-auth endpoint, and a list of
//! published services, [`render_caddyfile`] returns the exact Caddyfile
//! text the supervising `tuntun_server` binary writes to disk.
//!
//! Modeled on the music-box pattern but for production HTTPS:
//! tenant-protected services emit a `forward_auth` block routed to
//! `tuntun_server`'s `/verify` endpoint, and public sites bypass auth.
//!
//! Determinism: same input always produces byte-identical output.

pub mod error;
pub mod model;
pub mod render;

pub use crate::error::CaddyError;
pub use crate::model::{
    AuthEndpointConfig, AuthPolicy, CaddyInput, GlobalConfig, LoginSiteConfig, ServiceSite,
};
pub use crate::render::render_caddyfile;
