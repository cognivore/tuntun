#!/usr/bin/env rust-script
//! Verify reverse SSH and recovery from a silent tunnel on macOS.
//! Run: rust-script -f scripts/check-roaming.rs sweater@OTHER-LAPTOP
//! The other laptop must already be enrolled. This briefly interrupts SSH
//! through tuntun by pausing only the daemon, then restores it and reconnects
//! three times. It never changes Wi-Fi or power settings. Requires trusted
//! admin SSH alias tuntun-aws and the standard launchd agent label.
//! After editing, always run with -f: otherwise rust-script may use its cache.
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! ```
use anyhow::{ensure, Context, Result};
use std::{
    env,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn run(program: &str, args: &[&str]) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("start {program}"))?;
    let deadline = Instant::now() + Duration::from_secs(25);
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            anyhow::bail!("{program} exceeded 25-second deadline");
        }
        thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output()?;
    ensure!(
        out.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).context("command output UTF-8")
}

fn ssh(host: &str, command: &str) -> Result<String> {
    run(
        "ssh",
        &[
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=10",
            host,
            command,
        ],
    )
}

fn check(other: &str, expected: &str) -> Result<()> {
    let actual = ssh(
        other,
        "ssh -o BatchMode=yes -o ConnectTimeout=10 ssh.sweater.fere.me hostname",
    )?;
    ensure!(
        actual.trim() == expected,
        "SSH reached {:?}, expected {expected}",
        actual.trim()
    );
    Ok(())
}

fn recover(other: &str, expected: &str) -> Result<()> {
    let start = Instant::now();
    loop {
        match check(other, expected) {
            Ok(()) => {
                println!(
                    "PASS: reverse SSH recovered in {:.1}s",
                    start.elapsed().as_secs_f64()
                );
                return Ok(());
            }
            Err(error) if start.elapsed() >= Duration::from_secs(90) => {
                return Err(error).context("recovery deadline exceeded")
            }
            Err(_) => thread::sleep(Duration::from_secs(1)),
        }
    }
}

struct ResumeOnDrop(String);
impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        let _ = Command::new("kill").args(["-CONT", &self.0]).status();
    }
}

fn main() -> Result<()> {
    let other = env::args()
        .nth(1)
        .context("usage: rust-script -f scripts/check-roaming.rs sweater@OTHER-LAPTOP")?;
    if other == "--help" {
        println!("rust-script -f scripts/check-roaming.rs sweater@OTHER-LAPTOP\nBriefly pauses the Mac tunnel, verifies disconnection/recovery, and checks three reconnects for listener leaks.");
        return Ok(());
    }
    ensure!(env::consts::OS == "macos", "run on the primary Mac");
    ensure!(
        !other.starts_with('-')
            && other
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@.-_:".contains(&b)),
        "invalid SSH target"
    );
    let expected = run("hostname", &[])?;
    check(&other, expected.trim())?;
    let before = ssh("tuntun-aws", "ss -H -ltn")?.lines().count();
    let uid = run("id", &["-u"])?;
    let service = format!("gui/{}/com.memorici.tuntun-cli", uid.trim());
    let info = run("launchctl", &["print", &service])?;
    let pid = info
        .lines()
        .find_map(|line| line.trim().strip_prefix("pid = "))
        .context("daemon PID")?
        .to_string();
    ensure!(pid.parse::<u32>().is_ok(), "invalid daemon PID");
    let resume = ResumeOnDrop(pid.clone());
    run("kill", &["-STOP", &pid])?;
    println!("Tunnel paused for 55 seconds to exercise heartbeat expiry; power and networking settings are untouched.");
    thread::sleep(Duration::from_secs(55));
    let disconnected = check(&other, expected.trim()).is_err();
    drop(resume);
    ensure!(
        disconnected,
        "paused primary tunnel unexpectedly remained accessible"
    );
    println!("PASS: dead primary tunnel is unavailable, rather than routing to the other laptop");
    recover(&other, expected.trim())?;
    for _ in 0..3 {
        run("launchctl", &["kickstart", "-k", &service])?;
        recover(&other, expected.trim())?;
    }
    thread::sleep(Duration::from_secs(2));
    let after = ssh("tuntun-aws", "ss -H -ltn")?.lines().count();
    ensure!(
        after == before,
        "listener count changed after recovery: {before} -> {after}"
    );
    println!("PASS: listener count stayed at {before}; SSH URL ssh://sweater@ssh.sweater.fere.me");
    Ok(())
}
