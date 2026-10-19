//! Diagnostics tools: server metadata, runtime log level and recent logs.
//!
//! These exist because an MCP client cannot see the server's stderr. They let
//! the model inspect version/uptime, raise verbosity while debugging a tool
//! call, and read back the in-memory log ring buffer.

use rmcp::{handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::logging::LOG_CAPACITY;
use crate::server::Dz6Server;

use super::{err, ok_value};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LogLevelParams {
    /// New filter directive: "trace", "debug", "info", "warn", "error",
    /// "off", or a list such as "dz6_mcp=debug,rmcp=info". Omit to read the
    /// current level.
    #[serde(default)]
    pub level: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LogsTailParams {
    /// Number of lines to return, newest last. Defaults to 100.
    #[serde(default)]
    pub limit: Option<usize>,
}

#[tool_router(router = debug_router, vis = "pub(crate)")]
impl Dz6Server {
    #[tool(
        description = "Report server metadata: version, pid, uptime, transport, log level, log file, number of open files and available tools.",
        annotations(read_only_hint = true)
    )]
    async fn server_info(&self) -> CallToolResult {
        let diagnostics = self.diagnostics();
        let (open_files, default_readonly) = {
            let state = self.lock();
            (state.docs().count(), state.default_readonly())
        };
        let log_file = diagnostics
            .log_file()
            .map(|path| path.display().to_string());

        ok_value(json!({
            "name": "dz6-mcp",
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "uptime_seconds": diagnostics.uptime_seconds(),
            "transport": "stdio",
            "default_readonly": default_readonly,
            "log_level": diagnostics.level(),
            "log_file": log_file,
            "log_lines": diagnostics.buffer().len(),
            "open_files": open_files,
            "tools": self.tool_count(),
        }))
    }

    #[tool(
        description = "Read the current log level, or set it at runtime. Accepts a level ('trace', 'debug', 'info', 'warn', 'error', 'off') or an EnvFilter directive list such as 'dz6_mcp=debug,rmcp=info'.",
        annotations(read_only_hint = false)
    )]
    async fn log_level(&self, Parameters(p): Parameters<LogLevelParams>) -> CallToolResult {
        let diagnostics = self.diagnostics();
        match p.level {
            Some(level) => match diagnostics.set_level(&level) {
                Ok(level) => ok_value(json!({
                    "level": level,
                    "changed": true,
                })),
                Err(e) => err(e),
            },
            None => ok_value(json!({
                "level": diagnostics.level(),
                "changed": false,
            })),
        }
    }

    #[tool(
        description = "Return up to `limit` recent log lines (newest last) from the in-memory ring buffer.",
        annotations(read_only_hint = true)
    )]
    async fn logs_tail(&self, Parameters(p): Parameters<LogsTailParams>) -> CallToolResult {
        let diagnostics = self.diagnostics();
        let limit = p.limit.unwrap_or(100).min(LOG_CAPACITY);
        let lines = diagnostics.buffer().tail(limit);
        ok_value(json!({
            "count": lines.len(),
            "capacity": LOG_CAPACITY,
            "lines": lines,
        }))
    }

    #[tool(
        description = "Clear the in-memory log ring buffer. Logging to stderr and the log file continues.",
        annotations(read_only_hint = false)
    )]
    async fn logs_clear(&self) -> CallToolResult {
        let diagnostics = self.diagnostics();
        let cleared = diagnostics.buffer().len();
        diagnostics.buffer().clear();
        ok_value(json!({
            "cleared": cleared,
        }))
    }
}
