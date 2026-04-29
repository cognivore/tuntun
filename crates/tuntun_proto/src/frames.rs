//! Control-plane frame definitions.
//!
//! Every variant of [`ControlFrame`] is serialized as a postcard-encoded enum.
//! Postcard's variant tags are derived from **declaration order** and are
//! therefore stable as long as we never reorder, remove, or insert variants
//! mid-list. New variants must be appended to the end of [`ControlFrame`] (and
//! every other public enum here) to preserve wire compatibility.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use tuntun_core::{
    Ed25519PublicKey, Ed25519Signature, Fqdn, Nonce, ProjectId, ServiceName, ServicePort,
    Subdomain, TenantId, TunnelClientId,
};

/// Wire-protocol version. Bumped whenever the framing or any frame's shape
/// changes in a way that is not append-only.
pub const PROTOCOL_VERSION: u32 = 1;

/// Top-level control-plane frame exchanged between client and server.
///
/// **Wire stability**: variant order below is part of the wire contract.
/// Postcard derives variant tags from declaration order, so:
///
/// - Never reorder variants.
/// - Never remove variants (mark deprecated with a doc comment instead).
/// - Append new variants only at the end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlFrame {
    /// Client -> Server. First message after TLS handshake.
    Hello(HelloFrame),
    /// Server -> Client. Reply to Hello.
    Welcome(WelcomeFrame),

    /// Client -> Server. Server replies with [`ControlFrame::AuthChallenge`].
    AuthRequest(AuthRequestFrame),
    /// Server -> Client. 32-byte nonce.
    AuthChallenge(AuthChallengeFrame),
    /// Client -> Server. Signature over
    /// `domain_separator || nonce || tenant_id`.
    AuthResponse(AuthResponseFrame),
    /// Server -> Client. Authentication outcome.
    AuthResult(AuthResultFrame),

    /// Client -> Server. Register a project's services.
    Register(RegisterFrame),
    /// Server -> Client. Acceptance with the allocated server-side ports.
    Registered(RegisteredFrame),
    /// Client -> Server. Tear down all the client's registrations.
    Deregister(DeregisterFrame),

    /// Either direction, periodic.
    Ping(PingFrame),
    /// Reply to [`ControlFrame::Ping`] carrying the same nonce.
    Pong(PongFrame),

    /// Server -> Client. A new TCP connection arrived from the public for
    /// `service_name`; please open a yamux stream with id `stream_id`.
    StreamOpen(StreamOpenFrame),
    /// Either direction, raw bytes for an open stream.
    StreamData(StreamDataFrame),
    /// Either direction, EOF or error.
    StreamClose(StreamCloseFrame),

    /// Either direction. A protocol-level error report.
    Error(ErrorFrame),

    /// Server -> Client. A new connection arrived for a built-in side-car
    /// service that is not declared in `tuntun.nix` (currently: the SSH
    /// bastion). The client should open a yamux stream with the provided id
    /// and pipe it to the appropriate local socket (e.g., `127.0.0.1:22` for
    /// [`BuiltinService::Ssh`]).
    StreamOpenBuiltin(StreamOpenBuiltinFrame),

    /// Client -> Server. Authorize a new public key against the connecting
    /// tenant's bastion at runtime, without a NixOS rebuild. The server
    /// appends the key to `<state_dir>/tenants/<tenant>/bless.keys`, which
    /// the bastion's `AuthorizedKeysCommand` reads on every SSH attempt.
    BlessKey(BlessKeyFrame),
    /// Server -> Client. Outcome of a [`BlessKeyFrame`].
    BlessKeyAck(BlessKeyAckFrame),

    /// Client -> Server. Remove every line in the tenant's `bless.keys`
    /// whose trailing-comment label matches `label` exactly.
    UnblessKey(UnblessKeyFrame),
    /// Server -> Client. Outcome of an [`UnblessKeyFrame`].
    UnblessKeyAck(UnblessKeyAckFrame),

    /// Client -> Server. Ask for the current contents of the tenant's
    /// `bless.keys`.
    ListBlessings(ListBlessingsFrame),
    /// Server -> Client. Reply to a [`ListBlessingsFrame`].
    BlessingsList(BlessingsListFrame),
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Initial frame sent by the client after the TLS handshake completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloFrame {
    /// Wire-protocol version the client speaks. Should equal
    /// [`PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// Self-assigned client identifier; the server may issue a fresh one in
    /// the matching [`WelcomeFrame`].
    pub client_id: TunnelClientId,
    /// Tenant (account/organization) the client claims to belong to.
    pub tenant: TenantId,
    /// Free-form software version string for diagnostics.
    pub software_version: String,
}

/// Server's reply to [`HelloFrame`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeFrame {
    /// Wire-protocol version the server speaks.
    pub protocol_version: u32,
    /// Server identifier (e.g., short hostname or build id) for diagnostics.
    pub server_id: String,
    /// Server software version for diagnostics.
    pub software_version: String,
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Empty marker requesting an authentication challenge from the server.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuthRequestFrame {}

/// Server-issued 32-byte nonce the client must sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallengeFrame {
    /// Random 32-byte nonce.
    pub nonce: Nonce,
}

/// Client's signature response to [`AuthChallengeFrame`].
///
/// The signature is computed over
/// `domain_separator || nonce || tenant_id_bytes`. The server-side
/// `domain_separator` constant lives in `tuntun_auth` to keep this crate I/O-
/// and crypto-free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResponseFrame {
    /// 64-byte Ed25519 signature.
    pub signature: Ed25519Signature,
    /// Public key the server should verify the signature against.
    pub public_key: Ed25519PublicKey,
}

/// Outcome of the authentication exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResultFrame {
    /// Whether authentication succeeded.
    pub ok: bool,
    /// Optional human-readable explanation (typically populated only on
    /// failure).
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Auth policy for an individual service exposed through the tunnel.
///
/// **Wire stability**: variant order is part of the wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthPolicy {
    /// Only members of the owning tenant may reach the service.
    Tenant,
    /// Anyone on the public internet may reach the service. The tunnel
    /// performs no auth check; the service is responsible for any auth it
    /// cares about (e.g. its own OAuth login screen).
    Public,
}

/// Optional health-check description for a registered service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckSpec {
    /// HTTP path probed periodically.
    pub path: String,
    /// Expected status code; if `None`, any 2xx counts as healthy.
    pub expected_status: Option<u16>,
    /// Per-probe timeout in seconds.
    pub timeout_seconds: u32,
}

/// One service entry inside a [`ProjectRegistration`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRegistration {
    /// Logical service name within the project.
    pub service: ServiceName,
    /// Subdomain label the service should be reachable under.
    pub subdomain: Subdomain,
    /// Auth policy applied to inbound public traffic.
    pub auth_policy: AuthPolicy,
    /// Optional health check.
    pub health_check: Option<HealthCheckSpec>,
}

/// All services registered under a single project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRegistration {
    /// Project identifier.
    pub project: ProjectId,
    /// Services to expose.
    pub services: Vec<ServiceRegistration>,
}

/// Client -> Server: register one or more projects.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RegisterFrame {
    /// Projects (with their services) to register.
    pub projects: Vec<ProjectRegistration>,
}

/// Allocation reported by the server for a single registered service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAllocation {
    /// Project identifier.
    pub project: ProjectId,
    /// Service name within the project.
    pub service: ServiceName,
    /// Public FQDN the server published for this service.
    pub public_fqdn: Fqdn,
    /// Server-internal port the multiplexer routes traffic to.
    pub server_internal_port: ServicePort,
}

/// Server -> Client: registration acceptance with allocated ports.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RegisteredFrame {
    /// Allocations matching the [`RegisterFrame::projects`] entries.
    pub allocations: Vec<ServiceAllocation>,
}

/// Client -> Server: tear down every registration owned by this client.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DeregisterFrame {}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

/// Heartbeat request carrying an opaque nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingFrame {
    /// Opaque nonce; the responder echoes it in [`PongFrame::nonce`].
    pub nonce: u64,
}

/// Heartbeat reply echoing the request nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PongFrame {
    /// Same value as the matching [`PingFrame::nonce`].
    pub nonce: u64,
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

/// Server -> Client: a new public connection arrived for a registered
/// service; the client should open a yamux stream with the provided id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamOpenFrame {
    /// Yamux-layer stream identifier the client should use.
    pub stream_id: u32,
    /// Project the connection is destined for.
    pub project: ProjectId,
    /// Service the connection is destined for.
    pub service: ServiceName,
}

/// Either direction: opaque bytes for an established stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamDataFrame {
    /// Stream this payload belongs to.
    pub stream_id: u32,
    /// Raw bytes — encoded as a postcard byte-string via `serde_bytes`.
    pub payload: ByteBuf,
}

/// Reason a stream was closed.
///
/// **Wire stability**: variant order is part of the wire contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamCloseReason {
    /// Clean EOF from the originating side.
    Eof,
    /// Local cancellation (e.g. user aborted).
    Cancelled,
    /// Underlying TCP connection reset.
    Reset,
    /// Free-form error description from the closing side.
    Error(String),
}

/// Either direction: stream-level EOF or error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCloseFrame {
    /// Stream being closed.
    pub stream_id: u32,
    /// Why the stream is being closed.
    pub reason: StreamCloseReason,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Categorical error reported by either side.
///
/// **Wire stability**: variant order is part of the wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// The peer sent a frame that violates the protocol.
    ProtocolViolation,
    /// An operation was attempted before successful authentication.
    AuthRequired,
    /// Authentication was attempted and rejected.
    AuthDenied,
    /// The peer referenced a registration that does not exist.
    NotRegistered,
    /// The peer is being throttled.
    RateLimited,
    /// Internal error on the reporting side.
    InternalError,
    /// The peer referenced a project the server does not know about.
    UnknownProject,
}

/// Either direction: protocol-level error report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorFrame {
    /// Categorical error code.
    pub code: ErrorCode,
    /// Free-form human-readable explanation.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Built-in side-car services
// ---------------------------------------------------------------------------

/// Server-managed services that are *not* declared in the user's
/// `tuntun.nix`, and therefore cannot be addressed via the regular
/// `(project, service)` pair carried by [`StreamOpenFrame`].
///
/// **Wire stability**: variant order is part of the wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuiltinService {
    /// Reverse-SSH bastion. The client should pipe the stream to its local
    /// `sshd` (typically `127.0.0.1:22`).
    Ssh,
}

/// Server -> Client: a new public connection arrived for a built-in side-car
/// service. The client opens an inbound yamux stream with `stream_id` and
/// forwards it to the local socket implied by `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamOpenBuiltinFrame {
    /// Yamux-layer stream identifier the client should use.
    pub stream_id: u32,
    /// Which built-in service the stream is for.
    pub kind: BuiltinService,
}

// ---------------------------------------------------------------------------
// Runtime bastion-key blessings (`tuntun bless`)
// ---------------------------------------------------------------------------

/// Client -> Server: authorize `public_key` against the bastion for the
/// session's tenant. The label is a free-form human-readable identifier
/// (typically `user@host`) that the server writes alongside the key in
/// `bless.keys` so an operator can later spot what each entry is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlessKeyFrame {
    pub public_key: Ed25519PublicKey,
    pub label: String,
}

/// Server -> Client: result of a [`BlessKeyFrame`]. `ok = true` means the
/// key has been appended to `bless.keys` and is live for new SSH attempts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlessKeyAckFrame {
    pub ok: bool,
    pub message: Option<String>,
}

/// Client -> Server: remove all bless.keys lines whose label exactly
/// matches `label`. Typically used to revoke a `tuntun bless` for a
/// specific `user@host`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnblessKeyFrame {
    pub label: String,
}

/// Server -> Client: outcome of an unbless. `removed` is the number of
/// lines actually deleted; zero is not an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnblessKeyAckFrame {
    pub ok: bool,
    pub removed: u32,
    pub message: Option<String>,
}

/// Client -> Server: empty marker requesting the current list of blessed
/// keys for the connecting tenant.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ListBlessingsFrame {}

/// One row in the bless.keys file, decoded for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlessingEntry {
    /// The SSH key algorithm name, e.g. `"ssh-ed25519"`.
    pub algorithm: String,
    /// The wire-format public key body, base64-encoded (RFC 4253 §6.6).
    /// This is the second whitespace-separated field of an OpenSSH
    /// `authorized_keys` line.
    pub public_key_b64: String,
    /// Free-form trailing label (everything after the second field on
    /// the line). For keys minted by `tuntun bless` this is the
    /// `tuntun-bless-<tenant>-<user@host>` we wrote at bless time.
    pub label: String,
}

/// Server -> Client: response to a [`ListBlessingsFrame`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BlessingsListFrame {
    pub entries: Vec<BlessingEntry>,
}
