//! `dz6-mcp` — a Model Context Protocol server that exposes the dz6 hex
//! editor to any MCP-capable harness over stdio.
//!
//! stdout is reserved for the JSON-RPC protocol. All diagnostics go to stderr.

mod binary;
mod logging;
mod ops;
mod pattern;
mod server;
mod state;
mod tools;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use rmcp::{ServiceExt, transport::stdio};

use crate::server::Dz6Server;

#[derive(Parser, Debug)]
#[command(
    name = "dz6-mcp",
    version,
    about = "Model Context Protocol server for the dz6 hex editor"
)]
struct Args {
    /// Open every file read-only. Write tools return an error.
    #[arg(long)]
    readonly: bool,

    /// Increase log verbosity (repeatable). Logs are written to stderr.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Log filter directive: trace, debug, info, warn, error, off, or a list
    /// such as "dz6_mcp=debug,rmcp=info". Overrides -v and RUST_LOG.
    #[arg(long, value_name = "FILTER")]
    log_level: Option<String>,

    /// Also append logs to this file (in addition to stderr).
    #[arg(long, value_name = "PATH")]
    log_file: Option<PathBuf>,
}

impl Args {
    /// Resolve the filter: `--log-level` > `RUST_LOG` > `-v`.
    fn log_filter(&self) -> String {
        if let Some(level) = &self.log_level {
            return level.clone();
        }
        if let Ok(env) = std::env::var("RUST_LOG")
            && !env.trim().is_empty()
        {
            return env;
        }
        match self.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
        .to_string()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let level = args.log_filter();

    // Logs MUST go to stderr: stdout carries the MCP protocol.
    let diagnostics = logging::init(&level, args.log_file.clone())?;

    let mode = if args.readonly {
        "read-only"
    } else {
        "read-write"
    };
    diagnostics.notify(&format!(
        "dz6-mcp {} (pid {}) — stdio transport, {mode} mode",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
    ));
    let log_file = diagnostics
        .log_file()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "none".to_string());
    diagnostics.notify(&format!(
        "log level: {} (change with --log-level, RUST_LOG or the log_level tool); log file: {log_file}",
        diagnostics.level(),
    ));

    let server = Dz6Server::new(args.readonly, diagnostics.clone());
    let service = server.serve(stdio()).await?;
    diagnostics.notify("client initialized; serving tools on stdio");
    service.waiting().await?;
    diagnostics.notify(&format!(
        "client disconnected; exiting after {:.2}s",
        diagnostics.uptime_seconds(),
    ));

    Ok(())
}
