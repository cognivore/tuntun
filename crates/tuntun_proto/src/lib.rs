//! `tuntun_proto` -- control-plane wire protocol between `tuntun_cli` (laptop)
//! and `tuntun_server` (NixOS box).
//!
//! This crate is **zero I/O**: it defines the frame types and a synchronous
//! length-prefixed postcard codec. Transport (TLS, sockets, yamux) lives in
//! the binary crates that depend on this one.
//!
//! # Wire layout
//!
//! Every frame on the control channel is `len: u32 (LE) || postcard(ControlFrame)`.
//!
//! - [`encode_frame`] produces a complete length-prefixed buffer.
//! - [`decode_frame`] reads one complete frame from the front of a slice.
//! - [`FrameBuffer`] accumulates partial reads from a streaming transport and
//!   emits whole frames as they arrive.
//! - [`MAX_FRAME_LEN`] caps a single frame at 1 MiB.
//!
//! # Wire stability
//!
//! All public enums use postcard's default representation, whose variant tags
//! are derived from declaration order. **Do not reorder or remove** variants
//! of any public enum in this crate; append new variants at the end only.

#![doc(html_root_url = "https://docs.rs/tuntun_proto/0.1.0")]

pub mod codec;
pub mod error;
pub mod frames;

pub use codec::{decode_frame, encode_frame, FrameBuffer, MAX_FRAME_LEN};
pub use error::ProtoError;
pub use frames::{
    AuthChallengeFrame, AuthPolicy, AuthRequestFrame, AuthResponseFrame, AuthResultFrame,
    BuiltinService, ControlFrame, DeregisterFrame, ErrorCode, ErrorFrame, HealthCheckSpec,
    HelloFrame, PingFrame, PongFrame, ProjectRegistration, RegisterFrame, RegisteredFrame,
    ServiceAllocation, ServiceRegistration, StreamCloseFrame, StreamCloseReason,
    StreamDataFrame, StreamOpenBuiltinFrame, StreamOpenFrame, WelcomeFrame, PROTOCOL_VERSION,
};
