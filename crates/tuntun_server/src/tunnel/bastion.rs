//! SSH bastion side-car: a Unix-domain socket listener that accepts
//! connections from the OpenSSH `ForceCommand` helper (the
//! `tuntun-server tcp-forward <tenant>` subcommand) and dispatches them as
//! [`OpenStreamRequest`]s on the right tenant's tunnel session.
//!
//! The wire protocol on the unix socket is intentionally trivial: the helper
//! sends a single line `tenant=<id>\n` followed by raw bytes. Once the header
//! is parsed, the listener:
//!
//! 1. Looks up the connected client for `<id>` in the [`Registry`].
//! 2. Forwards an [`OpenStreamRequest`] with [`OpenStreamSubject::Builtin`]
//!    `(BuiltinService::Ssh)` and the unix-socket as the inbound transport.
//! 3. The session's stream-opener allocates a yamux outbound stream, sends a
//!    [`StreamOpenBuiltinFrame`] over the control channel, and pumps bytes
//!    between the unix socket and the new yamux stream — which the laptop's
//!    daemon, on receipt, pumps to its local `127.0.0.1:22`.
//!
//! End-to-end SSH crypto is preserved because the bastion `sshd` only
//! authenticates the *jump* (the `ForceCommand` is bound to a key in
//! `authorized_keys` whose only allowed action is to invoke the helper).
//! The bastion never sees the inner SSH session keystrokes.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

use tuntun_core::TenantId;
use tuntun_proto::BuiltinService;

use crate::registry::Registry;
use crate::tunnel::per_service_listener::{OpenStreamRequest, OpenStreamSubject};

/// Length cap on the header line. Tenant ids are <= 64 chars; we leave
/// generous slack for `tenant=` and the trailing newline.
const HEADER_MAX_BYTES: usize = 256;

/// Run the bastion unix-socket listener forever.
///
/// Removes any stale socket file at `path` first, then binds and accepts
/// connections in a loop. Each accepted connection is handled in its own task.
pub async fn run_listener(path: PathBuf, registry: Arc<Registry>) -> Result<()> {
    if path.exists() {
        // Stale socket from a previous run. Best-effort remove.
        if let Err(e) = tokio::fs::remove_file(&path).await {
            tracing::warn!("remove stale bastion socket {}: {e}", path.display());
        }
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("mkdir {}", parent.display()))?;
    }

    let listener = UnixListener::bind(&path)
        .with_context(|| format!("bind bastion socket {}", path.display()))?;
    set_socket_perms(&path).await?;
    tracing::info!("ssh bastion listener on {}", path.display());

    loop {
        match listener.accept().await {
            Ok((sock, _addr)) => {
                let registry = registry.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(sock, registry).await {
                        tracing::info!("bastion connection ended: {e:#}");
                    }
                });
            }
            Err(e) => {
                tracing::warn!("bastion accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// On unix, ensure the socket is mode 0660 so only the owner group (the
/// `tuntun` system user, which the bastion sshd's
/// `AuthorizedKeysCommandUser` runs as) can read/write it. We already own
/// the socket since we just created it.
async fn set_socket_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o660);
    tokio::fs::set_permissions(path, perms)
        .await
        .with_context(|| format!("chmod 0660 {}", path.display()))
}

async fn handle_connection(mut sock: UnixStream, registry: Arc<Registry>) -> Result<()> {
    // 1. Read the header line one byte at a time so the underlying socket has
    // no buffered prefix once the header is consumed — the next reader (the
    // session's `pump_stream`) sees only payload bytes.
    let header = read_header_line(&mut sock).await.context("read header")?;
    let tenant_str = header
        .strip_prefix("tenant=")
        .ok_or_else(|| anyhow!("bastion header missing tenant= prefix: {header:?}"))?;
    let tenant = TenantId::new(tenant_str.to_string())
        .map_err(|e| anyhow!("bastion header tenant id invalid: {e}"))?;

    // 2. Look up the connected client for that tenant.
    let Some(client) = registry.lookup_by_tenant(&tenant).await else {
        // Politely tell the helper we have nothing to forward to. The
        // helper's stdin is the bastion's ssh client, which will see EOF.
        let _ = sock
            .write_all(b"no tunnel connected for this tenant\n")
            .await;
        let _ = sock.shutdown().await;
        return Err(anyhow!("no tunnel connected for tenant {tenant}"));
    };

    // 3. Forward as a builtin SSH stream.
    let (ack_tx, ack_rx) = oneshot::channel();
    let request = OpenStreamRequest {
        subject: OpenStreamSubject::Builtin(BuiltinService::Ssh),
        inbound: Box::new(sock),
        ack: ack_tx,
    };
    if client.stream_tx.send(request).await.is_err() {
        return Err(anyhow!(
            "tenant {tenant} session closed while dispatching bastion stream"
        ));
    }

    match ack_rx.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!("bastion ack dropped")),
    }
}

async fn read_header_line(sock: &mut UnixStream) -> Result<String> {
    let mut buf = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        if buf.len() >= HEADER_MAX_BYTES {
            return Err(anyhow!(
                "bastion header exceeds {HEADER_MAX_BYTES} bytes"
            ));
        }
        let n = sock.read(&mut byte).await?;
        if n == 0 {
            return Err(anyhow!("bastion peer closed before newline"));
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    let s = String::from_utf8(buf)
        .map_err(|e| anyhow!("bastion header is not utf-8: {e}"))?;
    Ok(s.trim_end_matches('\r').to_string())
}
