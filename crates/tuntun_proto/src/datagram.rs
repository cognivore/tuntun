//! Datagram framing for UDP relayed over a yamux stream.
//!
//! Wire layout: `len: u16 (BE) || payload`, repeated. A stream carries one
//! UDP flow; the framing only restores the datagram boundaries that a byte
//! stream erases. Like [`crate::codec`], it is synchronous and zero-I/O.

use bytes::{Buf as _, Bytes, BytesMut};

use crate::error::ProtoError;

/// Largest datagram the framing can carry. Every IPv4 UDP payload fits.
pub const MAX_DATAGRAM_LEN: usize = u16::MAX as usize;

/// Number of bytes occupied by the length prefix.
const LEN_PREFIX: usize = core::mem::size_of::<u16>();

/// Encode one datagram as `len: u16 BE || payload`.
pub fn encode_datagram(payload: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let len = u16::try_from(payload.len())
        .map_err(|_| ProtoError::FrameTooLarge { len: payload.len() })?;
    let mut out = Vec::with_capacity(LEN_PREFIX + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Streaming decoder that accumulates bytes and emits whole datagrams.
#[derive(Debug, Default)]
pub struct DatagramBuffer {
    buf: BytesMut,
}

impl DatagramBuffer {
    /// Construct an empty buffer.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append freshly-read bytes to the buffer.
    #[inline]
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Whether any bytes are buffered.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Extract the next complete datagram, or `None` if more bytes are
    /// needed. Every length prefix is valid, so decoding cannot fail.
    pub fn try_pop(&mut self) -> Option<Bytes> {
        if self.buf.len() < LEN_PREFIX {
            return None;
        }
        let len = usize::from(u16::from_be_bytes([self.buf[0], self.buf[1]]));
        if self.buf.len() < LEN_PREFIX + len {
            return None;
        }
        self.buf.advance(LEN_PREFIX);
        Some(self.buf.split_to(len).freeze())
    }
}
