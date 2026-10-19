//! Search and string-extraction tools.

use dz6::commands::Commands;
use rmcp::{handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::ops;
use crate::server::Dz6Server;

use super::{err, ok_value};

const MAX_MATCHES: usize = 10_000;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchParams {
    /// Path to the file.
    pub path: String,
    /// Text to find. In hex mode this is a hex string such as "4d5a" and may
    /// use dz6 pattern syntax: "??" (any byte) and "[00-ff]" (byte class).
    pub needle: String,
    /// "text" (default) or "hex".
    #[serde(default)]
    pub mode: Option<String>,
    /// "forward" (default) or "backward".
    #[serde(default)]
    pub direction: Option<String>,
    /// Absolute offset to start from. Defaults to the current cursor for
    /// forward searches, or end-of-file for backward searches.
    #[serde(default)]
    pub offset: Option<usize>,
    /// Skip the current cursor position and search for the next occurrence.
    #[serde(default)]
    pub next: Option<bool>,
    /// Case-insensitive ASCII search. Defaults to false.
    #[serde(default)]
    pub ignore_case: Option<bool>,
    /// Disable ignore_case when the needle contains an uppercase letter.
    #[serde(default)]
    pub smart_case: Option<bool>,
    /// Wrap around the end/start of the file. Defaults to false for MCP calls.
    #[serde(default)]
    pub wrapscan: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchAllParams {
    /// Path to the file.
    pub path: String,
    /// Text or hex pattern to find (same syntax as `search`).
    pub needle: String,
    /// "text" (default) or "hex".
    #[serde(default)]
    pub mode: Option<String>,
    /// "forward" (default) or "backward". Backward results are returned in
    /// decreasing offset order but each offset is still absolute.
    #[serde(default)]
    pub direction: Option<String>,
    /// Absolute offset to start from. Defaults to 0 (forward) or EOF (backward).
    #[serde(default)]
    pub offset: Option<usize>,
    /// Maximum number of matches. Defaults to 100, capped at 10000.
    #[serde(default)]
    pub max: Option<usize>,
    /// Case-insensitive ASCII search. Defaults to false.
    #[serde(default)]
    pub ignore_case: Option<bool>,
    /// Disable ignore_case when the needle contains an uppercase letter.
    #[serde(default)]
    pub smart_case: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StringsParams {
    /// Path to the file.
    pub path: String,
    /// Minimum string length. Defaults to 4.
    #[serde(default)]
    pub min_length: Option<usize>,
    /// Maximum number of strings to collect. Defaults to 3000.
    #[serde(default)]
    pub max: Option<usize>,
    /// Case-insensitive regular expression used to filter strings.
    #[serde(default)]
    pub regex: Option<String>,
    /// Only return strings at or after this offset.
    #[serde(default)]
    pub offset: Option<usize>,
    /// Only return strings before `offset + length`.
    #[serde(default)]
    pub length: Option<usize>,
}

#[tool_router(router = search_router, vis = "pub(crate)")]
impl Dz6Server {
    #[tool(
        description = "Search for text or a hex pattern. Returns the first matching absolute offset.",
        annotations(read_only_hint = true)
    )]
    async fn search(&self, Parameters(p): Parameters<SearchParams>) -> CallToolResult {
        if p.needle.is_empty() {
            return err("needle must not be empty");
        }
        let mode = p.mode.as_deref().unwrap_or("text");
        let direction = p.direction.as_deref().unwrap_or("forward");

        match self.with_doc(&p.path, |doc| {
            let size = doc.size();
            if size == 0 {
                return Ok(json!({"found": false, "reason": "empty file"}));
            }
            let backward = direction.eq_ignore_ascii_case("backward");
            let start = p.offset.unwrap_or(if backward {
                size - 1
            } else {
                doc.app.hex_view.offset.min(size - 1)
            });
            let query = ops::SearchQuery {
                needle: &p.needle,
                mode,
                direction,
                ignore_case: p.ignore_case.unwrap_or(false),
                smart_case: p.smart_case.unwrap_or(false),
            };
            let found = ops::search_once(
                &mut doc.app,
                &query,
                start,
                p.next.unwrap_or(false),
                p.wrapscan.unwrap_or(false),
            );
            Ok(json!({
                "path": doc.canonical(),
                "needle": p.needle,
                "mode": if mode.eq_ignore_ascii_case("hex") { "hex" } else { "text" },
                "direction": if backward { "backward" } else { "forward" },
                "start_offset": start,
                "found": found.is_some(),
                "offset": found,
                "offset_hex": found.map(|o| format!("{o:#x}")),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Find every occurrence of a text or hex pattern (up to `max`).",
        annotations(read_only_hint = true)
    )]
    async fn search_all(&self, Parameters(p): Parameters<SearchAllParams>) -> CallToolResult {
        if p.needle.is_empty() {
            return err("needle must not be empty");
        }
        let mode = p.mode.as_deref().unwrap_or("text");
        let direction = p.direction.as_deref().unwrap_or("forward");
        let max = p.max.unwrap_or(100).min(MAX_MATCHES);

        match self.with_doc(&p.path, |doc| {
            let size = doc.size();
            if size == 0 {
                return Ok(json!({"count": 0, "matches": [], "truncated": false}));
            }
            let backward = direction.eq_ignore_ascii_case("backward");
            let start = p.offset.unwrap_or(if backward { size - 1 } else { 0 });
            let query = ops::SearchQuery {
                needle: &p.needle,
                mode,
                direction,
                ignore_case: p.ignore_case.unwrap_or(false),
                smart_case: p.smart_case.unwrap_or(false),
            };
            let matches = ops::search_all(&mut doc.app, &query, start, max);
            let truncated = matches.len() >= max;
            Ok(json!({
                "path": doc.canonical(),
                "needle": p.needle,
                "mode": if mode.eq_ignore_ascii_case("hex") { "hex" } else { "text" },
                "direction": if backward { "backward" } else { "forward" },
                "count": matches.len(),
                "matches": matches,
                "matches_hex": matches.iter().map(|o| format!("{o:#x}")).collect::<Vec<_>>(),
                "truncated": truncated,
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Extract printable strings (dz6's string list) with optional regex filtering and offset range.",
        annotations(read_only_hint = true)
    )]
    async fn strings(&self, Parameters(p): Parameters<StringsParams>) -> CallToolResult {
        if let Some(pattern) = &p.regex
            && let Err(e) = regex::Regex::new(pattern)
        {
            return err(format!("invalid regex: {e}"));
        }

        match self.with_doc(&p.path, |doc| {
            let app = &mut doc.app;
            app.config.minimum_string_length = p.min_length.unwrap_or(4).max(1);
            app.config.maximum_strings_to_show = p.max.unwrap_or(3000).max(1);
            app.string_regex = p.regex.clone().unwrap_or_default();
            Commands::load_strings(app, true);

            let filter = match (p.offset, p.length) {
                (Some(offset), Some(length)) => Some((offset, offset.saturating_add(length))),
                (None, Some(length)) => Some((0, length)),
                (Some(offset), None) => Some((offset, app.file_info.size)),
                (None, None) => None,
            };
            Ok(ops::strings_json(app, filter))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }
}
