//! `tuntun-server` -- daemon that terminates tunnels, supervises Caddy, runs
//! the auth endpoint, and reconciles DNS.

// As with `tuntun_cli`, the registry/session/auth-endpoint scaffolding is
// wired but several methods stay dead-from-cargo's-POV until the rustls +
// yamux session pump and full forward_auth state machine land — see
// CLAUDE.md §10. We allow these here rather than scattering attributes.
#![allow(
    dead_code,
    clippy::unused_async,
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::needless_pass_by_value,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::manual_let_else,
    clippy::missing_fields_in_debug,
    clippy::needless_continue,
    clippy::ptr_arg,
    clippy::unnecessary_wraps
)]

mod adapters;
mod auth_endpoint;
mod caddy_supervisor;
mod commands;
mod config;
mod dns_reconciler;
mod registry;
mod tls;
mod tunnel;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "tuntun-server",
    version,
    about = "tuntun reverse-tunnel server daemon."
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the server daemon (foreground, sd_notify-aware).
    Run,

    /// Print the resolved server config (for debugging the NixOS module).
    PrintConfig,

    /// Reconcile DNS records once and exit (admin tool).
    ReconcileDns,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(e) = init_tracing(cli.verbose) {
        eprintln!("tuntun-server: failed to initialize tracing: {e}");
        return ExitCode::from(2);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("tuntun-server: failed to start tokio runtime: {e}");
            return ExitCode::from(2);
        }
    };

    let result: Result<()> = runtime.block_on(async move {
        match cli.command {
            Command::Run => commands::run::run(cli.config.as_deref()).await,
            Command::PrintConfig => commands::print_config::run(cli.config.as_deref()).await,
            Command::ReconcileDns => commands::reconcile_dns::run(cli.config.as_deref()).await,
        }
    });

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("tuntun-server: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn init_tracing(verbosity: u8) -> Result<()> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let default = match verbosity {
        0 => "warn,tuntun_server=info",
        1 => "info,tuntun_server=debug",
        2 => "debug,tuntun_server=trace",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).with_writer(std::io::stderr).json())
        .try_init()
        .map_err(|e| anyhow::anyhow!("init tracing: {e}"))
}
