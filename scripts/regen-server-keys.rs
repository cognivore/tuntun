#!/usr/bin/env rust-script
//! Regenerate the tuntun server's long-term ed25519 signing key and write it
//! into passveil at `tuntun/server-signing-key`. Also prints the corresponding
//! public key so you can pin it on laptops via
//! `tuntun/server-pubkey-fingerprint`.
//!
//! IMPORTANT: After editing this script, run it as
//!     rust-script -f scripts/regen-server-keys.rs
//! Without `-f`, rust-script silently runs the *previously cached* compiled
//! binary and your edits are ignored. Yes, really.
//!
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! ed25519-dalek = { version = "2", features = ["pkcs8", "pem", "rand_core"] }
//! rand = "0.8"
//! sha2 = "0.10"
//! hex = "0.4"
//! ```

use anyhow::{Context, Result};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::process::Command;

fn main() -> Result<()> {
    let signing = SigningKey::generate(&mut OsRng);
    let pem = signing
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .context("encode pkcs8 pem")?;

    let pub_bytes = signing.verifying_key().to_bytes();
    let mut hasher = Sha256::new();
    hasher.update(pub_bytes);
    let fp = hasher.finalize();
    let fp_hex = hex::encode(fp);

    println!("== generated tuntun server signing key ==");
    println!("public key fingerprint: sha256:{fp_hex}");

    let status = Command::new("passveil")
        .args(["insert", "tuntun/server-signing-key"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .expect("piped stdin")
                .write_all(pem.as_bytes())?;
            child.wait()
        })
        .context("spawn passveil insert")?;

    if !status.success() {
        anyhow::bail!("passveil insert failed: {status}");
    }

    println!();
    println!("Wrote tuntun/server-signing-key.");
    println!("Next: pin the fingerprint on each laptop with");
    println!("    passveil insert tuntun/server-pubkey-fingerprint");
    println!("    (then paste:  sha256:{fp_hex})");

    Ok(())
}
