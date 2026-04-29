//! `tuntun` -- laptop CLI and tunnel daemon.
//!
//! All subcommands route through this entrypoint; the long-running daemon is
//! spawned via launchd / systemd-user (see the home-manager module) but can
//! also be run manually with `tuntun daemon`.

// Several adapter and tunnel-state types are wired into the binary but only
// activated once the rustls + yamux byte-pump in `tunnel::client` is filled
// in. Until then they are dead from cargo's POV — the design intent is for
// them to land together with the session impl, not to be deleted.
#![allow(
    dead_code,
    clippy::unused_async,
    clippy::needless_pass_by_value,
    clippy::doc_markdown,
    clippy::cast_precision_loss,
    clippy::manual_let_else,
    clippy::too_many_lines,
    clippy::single_match_else,
    clippy::type_complexity,
    clippy::needless_continue,
    clippy::unnecessary_wraps
)]

mod adapters;
mod commands;
mod config;
mod nix_eval;
mod tls;
mod tunnel;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "tuntun",
    version,
    about = "Declarative reverse-tunneling with cryptographic auth (\"VPN for poor\")."
)]
struct Cli {
    /// Override the daemon config file. Defaults to
    /// $XDG_CONFIG_HOME/tuntun/cli.toml or the path the home-manager module
    /// installs.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Increase verbosity (-v info, -vv debug, -vvv trace).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Pretend mode: print actions without performing them.
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Register the project at <PATH> with the tuntun server. Default path
    /// is the current directory; `tuntun .` is the canonical invocation.
    Register {
        /// Project directory containing tuntun.nix.
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Tear down a previously registered project.
    Deregister {
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Show the daemon status and currently registered projects.
    Status,

    /// Run the long-running tunnel daemon (foreground). Normally launched by
    /// launchd / systemd-user, but useful for debugging.
    Daemon,

    /// Tail the daemon logs.
    Logs {
        /// Number of lines to print before tailing.
        #[arg(short, long, default_value_t = 50)]
        lines: usize,
    },

    /// Authenticate as a tenant guest in the browser by printing a one-time
    /// magic-link URL to the terminal (also opens the browser if possible).
    Login {
        /// Tenant id to log into. Defaults to the daemon config's
        /// `default_tenant`.
        #[arg(long)]
        tenant: Option<String>,
    },

    /// Print the laptop's public ed25519 fingerprint (for adding to the
    /// server's `services.tuntun-server.tenants.<id>.authorizedKeys`).
    Whoami,

    /// Print machine-readable JSON describing the project's configuration as
    /// loaded from tuntun.nix. Useful for piping into other tools.
    Inspect {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    // rustls 0.23 demands a process-level CryptoProvider before any TLS code
    // runs. We pin `ring` to match the workspace feature flag.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    if let Err(e) = init_tracing(cli.verbose) {
        eprintln!("tuntun: failed to initialize tracing: {e}");
        return ExitCode::from(2);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("tuntun: failed to start tokio runtime: {e}");
            return ExitCode::from(2);
        }
    };

    let result: Result<()> = runtime.block_on(async move {
        match cli.command {
            Command::Register { path } => {
                commands::register::run(&path, cli.config.as_deref(), cli.dry_run).await
            }
            Command::Deregister { path } => {
                commands::deregister::run(&path, cli.config.as_deref(), cli.dry_run).await
            }
            Command::Status => commands::status::run(cli.config.as_deref()).await,
            Command::Daemon => commands::daemon::run(cli.config.as_deref()).await,
            Command::Logs { lines } => commands::logs::run(cli.config.as_deref(), lines).await,
            Command::Login { tenant } => {
                commands::login::run(cli.config.as_deref(), tenant.as_deref()).await
            }
            Command::Whoami => commands::whoami::run(cli.config.as_deref()).await,
            Command::Inspect { path } => commands::inspect::run(&path).await,
        }
    });

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("tuntun: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn init_tracing(verbosity: u8) -> Result<()> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let default_level = match verbosity {
        0 => "warn,tuntun_cli=info",
        1 => "info,tuntun_cli=debug",
        2 => "debug,tuntun_cli=trace",
        _ => "trace",
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).with_writer(std::io::stderr))
        .try_init()
        .map_err(|e| anyhow::anyhow!("init tracing: {e}"))
}
