//! Errors that can arise while rendering a Caddyfile.
//!
//! Rendering is a pure function over a typed [`crate::CaddyInput`]. The only
//! way to fail is to violate one of the input invariants the renderer
//! enforces (currently: unique service FQDNs).

use thiserror::Error;

/// Reasons [`crate::render_caddyfile`] may refuse to produce output.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CaddyError {
    /// Two or more `ServiceSite` entries share the same FQDN. Caddy would
    /// silently merge or warn on duplicates; we reject up-front so callers
    /// get a deterministic, descriptive error instead.
    #[error("duplicate service FQDN: {fqdn}")]
    DuplicateFqdn { fqdn: String },
}
