//! Error types for the tuntun control-plane wire protocol.

use thiserror::Error;

/// Errors produced by the protocol codec.
#[derive(Debug, Error)]
pub enum ProtoError {
    /// Encoding or decoding failed at the postcard layer.
    #[error("postcard codec error: {0}")]
    Postcard(#[from] postcard::Error),

    /// Input did not contain a complete frame.
    #[error("truncated frame")]
    Truncated,

    /// The length prefix announced a frame larger than [`MAX_FRAME_LEN`].
    ///
    /// [`MAX_FRAME_LEN`]: crate::codec::MAX_FRAME_LEN
    #[error("frame too large: {len} bytes")]
    FrameTooLarge { len: usize },

    /// Catch-all for protocol invariants violated by the caller.
    #[error("protocol error: {0}")]
    Other(String),
}
