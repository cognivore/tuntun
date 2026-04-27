#!/usr/bin/env rust-script
//! Generate a fresh ed25519 keypair for a laptop client. Stores the private
//! key in passveil at `tuntun/tunnel-private-key` and prints the corresponding
//! `authorized_keys`-style line for inclusion in the server's
//! `services.tuntun-server.tenants.<id>.authorizedKeys` list.
//!
//! IMPORTANT: After editing, re-run as
//!     rust-script -f scripts/regen-client-keys.rs
//! `rust-script` (without `-f`) caches compiled binaries and will skip your
//! edits.
//!
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! ed25519-dalek = { version = "2", features = ["pkcs8", "pem", "rand_core"] }
//! rand = "0.8"
//! base64 = "0.22"
//! ```

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::io::Write;
use std::process::Command;

fn main() -> Result<()> {
    let signing = SigningKey::generate(&mut OsRng);
    let pem = signing
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .context("encode pkcs8 pem")?;
    let pub_b64 = STANDARD_NO_PAD.encode(signing.verifying_key().to_bytes());

    let mut child = Command::new("passveil")
        .args(["insert", "tuntun/tunnel-private-key"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("spawn passveil insert")?;
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(pem.as_bytes())
        .context("write key to passveil stdin")?;
    let status = child.wait().context("wait passveil")?;
    if !status.success() {
        anyhow::bail!("passveil insert failed: {status}");
    }

    println!("Wrote tuntun/tunnel-private-key.");
    println!();
    println!("Add the following line to the server's");
    println!("services.tuntun-server.tenants.<id>.authorizedKeys:");
    println!();
    println!("    \"ed25519:{pub_b64}\"");

    Ok(())
}
