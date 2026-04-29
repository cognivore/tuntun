//! Integration tests for the tuntun control-plane codec.
//!
//! Helpers in this file use `.expect()` because they construct values that
//! must always parse; integration tests are themselves test code, so the
//! workspace `clippy.toml` allows it inside `#[test]` functions, and this
//! module-level allow extends the same exception to the supporting helpers.
#![allow(clippy::expect_used, clippy::too_many_lines)]

use std::fmt::Write as _;

use serde_bytes::ByteBuf;

use tuntun_core::{
    Ed25519PublicKey, Ed25519Signature, Fqdn, Nonce, ProjectId, ServiceName, ServicePort,
    Subdomain, TenantId, TunnelClientId,
};
use tuntun_proto::{
    decode_frame, encode_frame, AuthChallengeFrame, AuthPolicy, AuthRequestFrame,
    AuthResponseFrame, AuthResultFrame, BlessKeyAckFrame, BlessKeyFrame, BuiltinService,
    ControlFrame, DeregisterFrame, ErrorCode, ErrorFrame, FrameBuffer, HealthCheckSpec,
    HelloFrame, PingFrame, PongFrame, ProjectRegistration, ProtoError, RegisterFrame,
    RegisteredFrame, ServiceAllocation, ServiceRegistration, StreamCloseFrame, StreamCloseReason,
    StreamDataFrame, StreamOpenBuiltinFrame, StreamOpenFrame, WelcomeFrame, MAX_FRAME_LEN,
    PROTOCOL_VERSION,
};

fn tenant() -> TenantId {
    TenantId::new("memorici-de").expect("valid tenant id")
}

fn client() -> TunnelClientId {
    TunnelClientId::new("client-001").expect("valid client id")
}

fn project() -> ProjectId {
    ProjectId::new("blog").expect("valid project id")
}

fn service() -> ServiceName {
    ServiceName::new("api").expect("valid service name")
}

fn subdomain() -> Subdomain {
    Subdomain::new("api").expect("valid subdomain")
}

fn fqdn() -> Fqdn {
    Fqdn::new("api.blog.memorici.de").expect("valid fqdn")
}

fn port() -> ServicePort {
    ServicePort::new(34567).expect("valid port")
}

fn signature() -> Ed25519Signature {
    Ed25519Signature([3u8; 64])
}

fn pubkey() -> Ed25519PublicKey {
    Ed25519PublicKey([7u8; 32])
}

fn nonce() -> Nonce {
    Nonce([42u8; 32])
}

fn all_frames() -> Vec<ControlFrame> {
    vec![
        ControlFrame::Hello(HelloFrame {
            protocol_version: PROTOCOL_VERSION,
            client_id: client(),
            tenant: tenant(),
            software_version: "tuntun-cli/0.1.0".to_string(),
        }),
        ControlFrame::Welcome(WelcomeFrame {
            protocol_version: PROTOCOL_VERSION,
            server_id: "tuntun-srv-01".to_string(),
            software_version: "tuntun-server/0.1.0".to_string(),
        }),
        ControlFrame::AuthRequest(AuthRequestFrame {}),
        ControlFrame::AuthChallenge(AuthChallengeFrame { nonce: nonce() }),
        ControlFrame::AuthResponse(AuthResponseFrame {
            signature: signature(),
            public_key: pubkey(),
        }),
        ControlFrame::AuthResult(AuthResultFrame {
            ok: true,
            message: None,
        }),
        ControlFrame::AuthResult(AuthResultFrame {
            ok: false,
            message: Some("bad signature".to_string()),
        }),
        ControlFrame::Register(RegisterFrame {
            projects: vec![ProjectRegistration {
                project: project(),
                services: vec![ServiceRegistration {
                    service: service(),
                    subdomain: subdomain(),
                    auth_policy: AuthPolicy::Tenant,
                    health_check: Some(HealthCheckSpec {
                        path: "/healthz".to_string(),
                        expected_status: Some(200),
                        timeout_seconds: 5,
                    }),
                }],
            }],
        }),
        ControlFrame::Registered(RegisteredFrame {
            allocations: vec![ServiceAllocation {
                project: project(),
                service: service(),
                public_fqdn: fqdn(),
                server_internal_port: port(),
            }],
        }),
        ControlFrame::Deregister(DeregisterFrame {}),
        ControlFrame::Ping(PingFrame { nonce: 0xdead_beef }),
        ControlFrame::Pong(PongFrame { nonce: 0xdead_beef }),
        ControlFrame::StreamOpen(StreamOpenFrame {
            stream_id: 17,
            project: project(),
            service: service(),
        }),
        ControlFrame::StreamData(StreamDataFrame {
            stream_id: 17,
            payload: ByteBuf::from(b"hello world".to_vec()),
        }),
        ControlFrame::StreamClose(StreamCloseFrame {
            stream_id: 17,
            reason: StreamCloseReason::Eof,
        }),
        ControlFrame::StreamClose(StreamCloseFrame {
            stream_id: 18,
            reason: StreamCloseReason::Cancelled,
        }),
        ControlFrame::StreamClose(StreamCloseFrame {
            stream_id: 19,
            reason: StreamCloseReason::Reset,
        }),
        ControlFrame::StreamClose(StreamCloseFrame {
            stream_id: 20,
            reason: StreamCloseReason::Error("upstream timeout".to_string()),
        }),
        ControlFrame::Error(ErrorFrame {
            code: ErrorCode::ProtocolViolation,
            message: "unexpected frame".to_string(),
        }),
        ControlFrame::Error(ErrorFrame {
            code: ErrorCode::AuthRequired,
            message: "auth first".to_string(),
        }),
        ControlFrame::Error(ErrorFrame {
            code: ErrorCode::AuthDenied,
            message: "no".to_string(),
        }),
        ControlFrame::Error(ErrorFrame {
            code: ErrorCode::NotRegistered,
            message: "register first".to_string(),
        }),
        ControlFrame::Error(ErrorFrame {
            code: ErrorCode::RateLimited,
            message: "slow down".to_string(),
        }),
        ControlFrame::Error(ErrorFrame {
            code: ErrorCode::InternalError,
            message: "boom".to_string(),
        }),
        ControlFrame::Error(ErrorFrame {
            code: ErrorCode::UnknownProject,
            message: "no such project".to_string(),
        }),
        ControlFrame::StreamOpenBuiltin(StreamOpenBuiltinFrame {
            stream_id: 99,
            kind: BuiltinService::Ssh,
        }),
        ControlFrame::BlessKey(BlessKeyFrame {
            public_key: pubkey(),
            label: "operator@laptop.example.com".to_string(),
        }),
        ControlFrame::BlessKeyAck(BlessKeyAckFrame {
            ok: true,
            message: None,
        }),
        ControlFrame::BlessKeyAck(BlessKeyAckFrame {
            ok: false,
            message: Some("appendable failure".to_string()),
        }),
    ]
}

#[test]
fn round_trip_every_variant() {
    for frame in all_frames() {
        let bytes = encode_frame(&frame).expect("encode");
        let (decoded, consumed) = decode_frame(&bytes).expect("decode");
        assert_eq!(consumed, bytes.len(), "consumed all bytes");
        assert_eq!(decoded, frame);
    }
}

#[test]
fn frame_buffer_handles_fragmented_input() {
    let frames = all_frames();
    let mut wire = Vec::new();
    for f in &frames {
        wire.extend_from_slice(&encode_frame(f).expect("encode"));
    }

    let mut buf = FrameBuffer::new();
    let mut got = Vec::new();
    // Push one byte at a time to exercise the worst-case fragmentation.
    for byte in &wire {
        buf.push(std::slice::from_ref(byte));
        while let Some(frame) = buf.try_pop_frame().expect("pop") {
            got.push(frame);
        }
    }
    assert!(buf.is_empty(), "buffer drained");
    assert_eq!(got, frames);
}

#[test]
fn frame_buffer_pulls_multiple_frames_in_one_push() {
    let frames = all_frames();
    let mut wire = Vec::new();
    for f in &frames {
        wire.extend_from_slice(&encode_frame(f).expect("encode"));
    }

    let mut buf = FrameBuffer::new();
    buf.push(&wire);

    let mut got = Vec::new();
    while let Some(frame) = buf.try_pop_frame().expect("pop") {
        got.push(frame);
    }
    assert!(buf.is_empty(), "buffer drained");
    assert_eq!(got, frames);
}

#[test]
fn frame_buffer_rejects_oversize_length_prefix() {
    let mut buf = FrameBuffer::new();
    // Length prefix of MAX_FRAME_LEN + 1, body absent.
    let bad_len = u32::try_from(MAX_FRAME_LEN + 1).expect("fits in u32");
    buf.push(&bad_len.to_le_bytes());
    match buf.try_pop_frame() {
        Err(ProtoError::FrameTooLarge { len }) => {
            assert_eq!(len, MAX_FRAME_LEN + 1);
        }
        other => panic!("expected FrameTooLarge, got {other:?}"),
    }
}

#[test]
fn decode_rejects_truncated_input() {
    let frame = ControlFrame::Ping(PingFrame { nonce: 1 });
    let wire = encode_frame(&frame).expect("encode");
    // Drop just the last byte of the body.
    let truncated = &wire[..wire.len() - 1];
    match decode_frame(truncated) {
        Err(ProtoError::Truncated) => {}
        other => panic!("expected Truncated, got {other:?}"),
    }

    // Empty input should also be Truncated.
    match decode_frame(&[]) {
        Err(ProtoError::Truncated) => {}
        other => panic!("expected Truncated for empty input, got {other:?}"),
    }

    // Length prefix only: still Truncated.
    let prefix_only = &wire[..4];
    match decode_frame(prefix_only) {
        Err(ProtoError::Truncated) => {}
        other => panic!("expected Truncated for prefix-only, got {other:?}"),
    }
}

#[test]
fn decode_rejects_oversize_length_prefix() {
    let bad_len = u32::try_from(MAX_FRAME_LEN + 1).expect("fits in u32");
    let mut wire = Vec::new();
    wire.extend_from_slice(&bad_len.to_le_bytes());
    // Body intentionally absent — error must fire on the prefix alone.
    match decode_frame(&wire) {
        Err(ProtoError::FrameTooLarge { len }) => assert_eq!(len, MAX_FRAME_LEN + 1),
        other => panic!("expected FrameTooLarge, got {other:?}"),
    }
}

#[test]
fn encode_rejects_oversize_body() {
    // Build a StreamData payload large enough to exceed MAX_FRAME_LEN once
    // encoded. The postcard byte-string length prefix is at most 5 bytes plus
    // the stream_id varint, so 2 MiB of payload is comfortably oversized.
    let payload = vec![0u8; MAX_FRAME_LEN + 1024];
    let frame = ControlFrame::StreamData(StreamDataFrame {
        stream_id: 0,
        payload: ByteBuf::from(payload),
    });
    match encode_frame(&frame) {
        Err(ProtoError::FrameTooLarge { len }) => {
            assert!(
                len > MAX_FRAME_LEN,
                "reported len {len} exceeds MAX_FRAME_LEN"
            );
        }
        other => panic!("expected FrameTooLarge, got {other:?}"),
    }
}

/// Golden hex for a deliberately tiny, fully-deterministic frame. If this
/// test fails, the wire format changed — bump `PROTOCOL_VERSION` and update
/// the golden bytes intentionally.
#[test]
fn golden_ping_frame_hex() {
    let frame = ControlFrame::Ping(PingFrame { nonce: 1 });
    let wire = encode_frame(&frame).expect("encode");
    // Postcard uses varint encoding for both the enum tag and `u64`. The
    // `Ping` variant is the 10th in declaration order (index 9), so the body
    // is `09 01` — two bytes. Length prefix is `02 00 00 00` little-endian.
    let expected_hex = "020000000901";
    assert_eq!(hex_encode(&wire), expected_hex);

    // And it must round-trip through decode_frame.
    let (decoded, consumed) = decode_frame(&wire).expect("decode");
    assert_eq!(consumed, wire.len());
    assert_eq!(decoded, frame);
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Helpers above already documented the test-only allow; writing into
        // a String can't fail in this context.
        let _ = write!(s, "{b:02x}");
    }
    s
}
