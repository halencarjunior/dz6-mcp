//! Signature / pattern scanning tools.

use rmcp::{handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ops;
use crate::pattern::{self, Compiled, ScanOptions};
use crate::server::Dz6Server;

use super::{err, ok_value};

const MAX_MATCHES: usize = 10_000;
const MAX_CONTEXT: usize = 64;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct PatternSpec {
    /// Optional label echoed with every match from this pattern.
    #[serde(default)]
    pub name: Option<String>,
    /// The pattern body. Hex by default; see `pattern_scan` for the syntax.
    pub pattern: String,
    /// "hex" (default) or "text" for this specific pattern.
    #[serde(default)]
    pub mode: Option<String>,
    /// Case-insensitive matching (text mode only). Defaults to false.
    #[serde(default)]
    pub ignore_case: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatternScanParams {
    /// Path to the file.
    pub path: String,
    /// Shorthand for a single pattern. Ignored when `patterns` is provided.
    #[serde(default)]
    pub pattern: Option<String>,
    /// One or more patterns to scan for.
    #[serde(default)]
    pub patterns: Option<Vec<PatternSpec>>,
    /// Default mode for patterns without their own: "hex" (default) or "text".
    #[serde(default)]
    pub mode: Option<String>,
    /// Start the scan at this absolute offset. Defaults to 0.
    #[serde(default)]
    pub offset: Option<usize>,
    /// Number of bytes to scan. Defaults to the rest of the file.
    #[serde(default)]
    pub length: Option<usize>,
    /// Maximum number of matches. Defaults to 100, capped at 10000.
    #[serde(default)]
    pub max: Option<usize>,
    /// Bytes of context before and after each match. Defaults to 0, capped at 64.
    #[serde(default)]
    pub context: Option<usize>,
    /// Return only the earliest match. Defaults to false.
    #[serde(default)]
    pub first_only: Option<bool>,
    /// Include the matched bytes as hex. Defaults to true.
    #[serde(default)]
    pub include_bytes: Option<bool>,
}

#[tool_router(router = pattern_router, vis = "pub(crate)")]
impl Dz6Server {
    #[tool(
        description = "Scan for one or more byte/text signatures and return every match with optional \
surrounding context. Hex syntax: literal bytes, `??` any byte, `A?`/`?A` nibble wildcards, \
`[00-ff]` byte ranges, `{n}`/`{n-m}` gaps, `(AA|BB)` alternation and `VALUE:MASK` masked matches.",
        annotations(read_only_hint = true)
    )]
    async fn pattern_scan(&self, Parameters(p): Parameters<PatternScanParams>) -> CallToolResult {
        let mut specs: Vec<PatternSpec> = p.patterns.clone().unwrap_or_default();
        if specs.is_empty()
            && let Some(single) = &p.pattern
        {
            specs.push(PatternSpec {
                name: None,
                pattern: single.clone(),
                mode: None,
                ignore_case: None,
            });
        }
        if specs.is_empty() {
            return err("provide `pattern` or at least one entry in `patterns`");
        }

        let default_mode = p.mode.clone().unwrap_or_else(|| "hex".to_string());
        let mut compiled: Vec<Compiled> = Vec::with_capacity(specs.len());
        for spec in &specs {
            let mode = spec.mode.clone().unwrap_or_else(|| default_mode.clone());
            match pattern::compile(
                spec.name.clone(),
                &spec.pattern,
                &mode,
                spec.ignore_case.unwrap_or(false),
            ) {
                Ok(compiled_pattern) => compiled.push(compiled_pattern),
                Err(e) => return err(format!("pattern {:?}: {e}", spec.pattern)),
            }
        }

        let context = p.context.unwrap_or(0).min(MAX_CONTEXT);
        let max = p.max.unwrap_or(100).min(MAX_MATCHES);
        let first_only = p.first_only.unwrap_or(false);
        let include_bytes = p.include_bytes.unwrap_or(true);

        match self.with_doc(&p.path, |doc| {
            let canonical = doc.canonical();
            let size = doc.size();
            let offset = p.offset.unwrap_or(0);
            if offset > size {
                return Err(format!(
                    "offset {offset:#x} is past end of file ({size:#x})"
                ));
            }
            let end = match p.length {
                Some(len) => offset.saturating_add(len).min(size),
                None => size,
            };

            let buf = ops::search_buffer(&mut doc.app);
            let (hits, truncated) = pattern::scan(
                &buf,
                &compiled,
                &ScanOptions {
                    start: offset,
                    end,
                    max,
                    first_only,
                },
            );

            let matches: Vec<Value> = hits
                .iter()
                .map(|hit| {
                    let pat = &compiled[hit.pattern];
                    let mut value = json!({
                        "pattern": pat.source,
                        "name": pat.name,
                        "mode": pat.mode,
                        "offset": hit.offset,
                        "offset_hex": format!("{:#x}", hit.offset),
                        "length": hit.length,
                    });
                    let match_end = (hit.offset + hit.length).min(buf.len());
                    if include_bytes {
                        value["bytes"] = json!(ops::hex_dump(&buf[hit.offset..match_end]));
                    }
                    if context > 0 {
                        let before_start = hit.offset.saturating_sub(context);
                        let after_end = (match_end + context).min(buf.len());
                        value["context_offset"] = json!(before_start);
                        value["context_before"] =
                            json!(ops::hex_dump(&buf[before_start..hit.offset]));
                        value["context_after"] = json!(ops::hex_dump(&buf[match_end..after_end]));
                    }
                    value
                })
                .collect();

            Ok(json!({
                "path": canonical,
                "file_size": size,
                "range": { "offset": offset, "length": end - offset },
                "patterns": compiled
                    .iter()
                    .map(|c| json!({ "pattern": c.source, "name": c.name, "mode": c.mode }))
                    .collect::<Vec<_>>(),
                "count": matches.len(),
                "truncated": truncated,
                "matches": matches,
            }))
        }) {
            Ok(value) => ok_value(value),
            Err(e) => err(e),
        }
    }
}
