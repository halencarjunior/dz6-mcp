//! Editing tools.
//!
//! Edits are staged in dz6's in-memory buffer (`changed_bytes`). They become
//! visible to every read tool immediately but are only written to disk by
//! `save`. `truncate` is the exception: it modifies the file immediately, just
//! like dz6's `t`/`T` keys.

use rmcp::{handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::ops;
use crate::server::Dz6Server;
use crate::tools::file::PathParams;

use super::{err, ok_value};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteBytesParams {
    /// Path to the file.
    pub path: String,
    /// Absolute offset where the patch starts.
    pub offset: usize,
    /// Bytes to write as a hex string. Spaces and common separators are ignored
    /// ("4d 5a 90", "4d5a90" and "0x4d5a90" are equivalent).
    pub data: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FillParams {
    /// Path to the file.
    pub path: String,
    /// Absolute offset where the fill starts.
    pub offset: usize,
    /// Number of bytes to fill.
    pub length: usize,
    /// Byte value to fill with (0-255). Defaults to 0.
    #[serde(default)]
    pub value: Option<u8>,
    /// Shorthand for common fills: "zero" (0x00) or "nop" (0x90).
    #[serde(default)]
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UndoParams {
    /// Path to the file.
    pub path: String,
    /// Number of staged edits to undo. Defaults to 1.
    #[serde(default)]
    pub steps: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TruncateParams {
    /// Path to the file.
    pub path: String,
    /// Offset that becomes the boundary.
    pub offset: usize,
    /// "after" keeps bytes up to and including `offset` (dz6's `t`).
    /// "before" drops everything before `offset`, shifting the tail to 0
    /// (dz6's `T`). This is immediate and cannot be undone.
    pub mode: String,
}

fn clean_hex(input: &str) -> String {
    let mut s = input.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        s = rest;
    }
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-' && *c != '_')
        .collect()
}

#[tool_router(router = edit_router, vis = "pub(crate)")]
impl Dz6Server {
    #[tool(
        description = "Stage a byte patch in memory. Nothing is written to disk until `save`. Reads reflect staged edits immediately.",
        annotations(read_only_hint = false)
    )]
    async fn write_bytes(&self, Parameters(p): Parameters<WriteBytesParams>) -> CallToolResult {
        let cleaned = clean_hex(&p.data);
        if cleaned.is_empty() {
            return err("data must contain at least one byte");
        }
        let bytes = match hex::decode(&cleaned) {
            Ok(b) => b,
            Err(e) => return err(format!("invalid hex data: {e}")),
        };

        match self.with_doc(&p.path, |doc| {
            let written = ops::write_bytes(&mut doc.app, p.offset, &bytes)?;
            Ok(json!({
                "path": doc.canonical(),
                "offset": p.offset,
                "bytes_written": written,
                "pending_changes": ops::pending_changes(&doc.app),
                "saved": false,
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Fill a range with zeroes, NOPs (0x90) or an arbitrary byte, staged in memory.",
        annotations(read_only_hint = false)
    )]
    async fn fill(&self, Parameters(p): Parameters<FillParams>) -> CallToolResult {
        if p.length == 0 {
            return err("length must be greater than zero");
        }
        let value = match p.kind.as_deref() {
            Some(k) if k.eq_ignore_ascii_case("zero") || k.eq_ignore_ascii_case("zeros") => 0x00,
            Some(k) if k.eq_ignore_ascii_case("nop") || k.eq_ignore_ascii_case("nops") => 0x90,
            Some(other) => return err(format!("invalid kind '{other}'; use 'zero' or 'nop'")),
            None => p.value.unwrap_or(0),
        };

        match self.with_doc(&p.path, |doc| {
            let written = ops::fill_range(&mut doc.app, p.offset, p.length, value)?;
            Ok(json!({
                "path": doc.canonical(),
                "offset": p.offset,
                "length": written,
                "value": format!("{value:#04x}"),
                "pending_changes": ops::pending_changes(&doc.app),
                "saved": false,
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Undo staged edits (newest first). Returns how many were undone.",
        annotations(read_only_hint = false)
    )]
    async fn undo(&self, Parameters(p): Parameters<UndoParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let undone = ops::undo(&mut doc.app, p.steps.unwrap_or(1));
            Ok(json!({
                "path": doc.canonical(),
                "undone": undone,
                "pending_changes": ops::pending_changes(&doc.app),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Write all staged edits to disk and persist the .dz6 annotation database.",
        annotations(read_only_hint = false)
    )]
    async fn save(&self, Parameters(p): Parameters<PathParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            if doc.readonly() {
                return Err("file is read-only; reopen it with readonly=false to save".into());
            }
            let (written, db_saved) = ops::save(&mut doc.app)?;
            Ok(json!({
                "path": doc.canonical(),
                "bytes_written": written,
                "database_saved": db_saved,
                "pending_changes": ops::pending_changes(&doc.app),
                "file_size": doc.size(),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Immediately truncate the file. mode='after' keeps bytes through `offset`; mode='before' removes bytes before `offset`. Cannot be undone; requires no pending edits.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn truncate(&self, Parameters(p): Parameters<TruncateParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let new_size = ops::truncate(&mut doc.app, p.offset, &p.mode)?;
            Ok(json!({
                "path": doc.canonical(),
                "mode": p.mode,
                "offset": p.offset,
                "new_size": new_size,
                "new_size_hex": format!("{new_size:#x}"),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }
}
