//! Length-prefixed postcard codec for [`ControlFrame`].
//!
//! Wire layout: `len: u32 (LE) || postcard(ControlFrame)`.
//!
//! The codec is **synchronous and zero-I/O**: callers feed bytes in and pull
//! decoded frames out. Use [`encode_frame`]/[`decode_frame`] for one-shot
//! buffers, and [`FrameBuffer`] for streaming reads.

use bytes::BytesMut;

use crate::error::ProtoError;
use crate::frames::ControlFrame;

/// Maximum permitted frame body size (1 MiB). Length prefixes larger than
/// this are rejected with [`ProtoError::FrameTooLarge`].
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Number of bytes occupied by the length prefix.
const LEN_PREFIX: usize = core::mem::size_of::<u32>();

/// Encode a frame as `len: u32 LE || postcard(frame)`.
pub fn encode_frame(frame: &ControlFrame) -> Result<Vec<u8>, ProtoError> {
    let body = postcard::to_allocvec(frame)?;
    if body.len() > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge { len: body.len() });
    }
    let mut out = Vec::with_capacity(LEN_PREFIX + body.len());
    let len = u32::try_from(body.len())
        .map_err(|_| ProtoError::FrameTooLarge { len: body.len() })?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a single frame from the front of `buf`.
///
/// Returns the decoded frame and the number of bytes consumed (length prefix
/// plus body) so callers can advance their own buffer pointer.
///
/// Errors:
/// - [`ProtoError::Truncated`] if `buf` does not yet contain a complete frame.
/// - [`ProtoError::FrameTooLarge`] if the length prefix exceeds
///   [`MAX_FRAME_LEN`].
/// - [`ProtoError::Postcard`] if the body fails to deserialize.
pub fn decode_frame(buf: &[u8]) -> Result<(ControlFrame, usize), ProtoError> {
    if buf.len() < LEN_PREFIX {
        return Err(ProtoError::Truncated);
    }
    let mut len_bytes = [0u8; LEN_PREFIX];
    len_bytes.copy_from_slice(&buf[..LEN_PREFIX]);
    let body_len = u32::from_le_bytes(len_bytes) as usize;
    if body_len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge { len: body_len });
    }
    let total = LEN_PREFIX
        .checked_add(body_len)
        .ok_or(ProtoError::FrameTooLarge { len: body_len })?;
    if buf.len() < total {
        return Err(ProtoError::Truncated);
    }
    let body = &buf[LEN_PREFIX..total];
    let frame: ControlFrame = postcard::from_bytes(body)?;
    Ok((frame, total))
}

/// Streaming decoder that accumulates bytes and emits whole frames.
///
/// Wrap a transport's reads with `push`, then drain frames with
/// `try_pop_frame` until it returns `Ok(None)`.
#[derive(Debug, Default)]
pub struct FrameBuffer {
    buf: BytesMut,
}

impl FrameBuffer {
    /// Construct an empty buffer.
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
        }
    }

    /// Append freshly-read bytes to the buffer.
    #[inline]
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Currently buffered byte count. Useful for back-pressure assertions.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether any bytes are buffered.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Try to extract the next complete frame.
    ///
    /// Returns:
    /// - `Ok(Some(frame))` if a full frame was available and consumed.
    /// - `Ok(None)` if more bytes are needed.
    /// - `Err(ProtoError::FrameTooLarge { .. })` if the next length prefix
    ///   exceeds [`MAX_FRAME_LEN`]. The buffer is left intact so the caller
    ///   can choose to drop the connection.
    /// - `Err(ProtoError::Postcard(_))` if the body fails to deserialize.
    ///   The bytes that announced the bad frame are consumed before the error
    ///   is returned, so the buffer is positioned at the next frame.
    pub fn try_pop_frame(&mut self) -> Result<Option<ControlFrame>, ProtoError> {
        if self.buf.len() < LEN_PREFIX {
            return Ok(None);
        }
        let mut len_bytes = [0u8; LEN_PREFIX];
        len_bytes.copy_from_slice(&self.buf[..LEN_PREFIX]);
        let body_len = u32::from_le_bytes(len_bytes) as usize;
        if body_len > MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge { len: body_len });
        }
        let total = LEN_PREFIX
            .checked_add(body_len)
            .ok_or(ProtoError::FrameTooLarge { len: body_len })?;
        if self.buf.len() < total {
            return Ok(None);
        }
        let body_start = LEN_PREFIX;
        let frame_result: Result<ControlFrame, postcard::Error> =
            postcard::from_bytes(&self.buf[body_start..total]);
        // Drop the consumed bytes regardless of decode success: the length
        // prefix told us where this frame ends, so leaving its bytes around
        // would only desynchronize the stream.
        let _ = self.buf.split_to(total);
        match frame_result {
            Ok(frame) => Ok(Some(frame)),
            Err(e) => Err(ProtoError::Postcard(e)),
        }
    }
}
