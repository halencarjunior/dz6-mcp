//! Read-only inspection tools.

use rmcp::{handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::ops;
use crate::server::Dz6Server;

use super::{err, ok_value};

const MAX_READ: usize = 1 << 20; // 1 MiB per response
const MAX_ANALYZE: usize = 64 << 20; // 64 MiB of entropy analysis

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadBytesParams {
    /// Path to the file.
    pub path: String,
    /// Absolute byte offset to start at.
    pub offset: usize,
    /// Number of bytes to read. Defaults to 256; capped at 1 MiB.
    #[serde(default)]
    pub length: Option<usize>,
    /// Output format: "both" (default), "hex" or "ascii".
    #[serde(default)]
    pub format: Option<String>,
    /// Include the raw byte values as a JSON array. Defaults to false.
    #[serde(default)]
    pub include_bytes: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadIntParams {
    /// Path to the file.
    pub path: String,
    /// Absolute byte offset of the integer.
    pub offset: usize,
    /// Width in bytes: 1, 2, 4 or 8.
    pub size: usize,
    /// Interpret the value as signed. Defaults to false.
    #[serde(default)]
    pub signed: Option<bool>,
    /// "little" (default) or "big".
    #[serde(default)]
    pub endian: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadStringParams {
    /// Path to the file.
    pub path: String,
    /// Absolute byte offset where the string starts.
    pub offset: usize,
    /// "utf8" (default), "latin1", "utf16le" or "utf16be".
    #[serde(default)]
    pub encoding: Option<String>,
    /// Maximum number of characters (bytes for 8-bit encodings). Defaults to 256.
    #[serde(default)]
    pub max_length: Option<usize>,
    /// Stop at the first NUL. Defaults to true.
    #[serde(default)]
    pub stop_at_nul: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DumpParams {
    /// Path to the source file.
    pub path: String,
    /// Destination path for the extracted bytes.
    pub out_path: String,
    /// Absolute byte offset to start at.
    pub offset: usize,
    /// Number of bytes to extract.
    pub length: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeParams {
    /// Path to the file.
    pub path: String,
    /// Absolute byte offset to start at. Defaults to 0.
    #[serde(default)]
    pub offset: Option<usize>,
    /// Number of bytes to analyze. Defaults to the rest of the file (capped at 64 MiB).
    #[serde(default)]
    pub length: Option<usize>,
}

#[tool_router(router = read_router, vis = "pub(crate)")]
impl Dz6Server {
    #[tool(
        description = "Read bytes and return a hex dump and ASCII rendering. Pending unsaved edits are reflected.",
        annotations(read_only_hint = true)
    )]
    async fn read_bytes(&self, Parameters(p): Parameters<ReadBytesParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let size = doc.size();
            if p.offset > size {
                return Err(format!(
                    "offset {} is past end of file ({size:#x})",
                    p.offset
                ));
            }
            let requested = p.length.unwrap_or(256);
            let length = requested.min(MAX_READ).min(size - p.offset);
            let bytes = ops::effective_range(&mut doc.app, p.offset, length);
            let format = p.format.as_deref().unwrap_or("both").to_ascii_lowercase();
            let mut out = json!({
                "path": doc.canonical(),
                "offset": p.offset,
                "length": bytes.len(),
                "requested_length": requested,
                "truncated": bytes.len() < requested,
                "file_size": size,
            });
            if format == "both" || format == "hex" {
                out["hex"] = json!(ops::hex_dump(&bytes));
            }
            if format == "both" || format == "ascii" {
                out["ascii"] = json!(ops::ascii_dump(&bytes, '.'));
            }
            if p.include_bytes.unwrap_or(false) {
                out["bytes"] = json!(bytes);
            }
            Ok(out)
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Read a 1/2/4/8-byte integer, little- or big-endian, signed or unsigned. Pending edits are reflected.",
        annotations(read_only_hint = true)
    )]
    async fn read_int(&self, Parameters(p): Parameters<ReadIntParams>) -> CallToolResult {
        if !matches!(p.size, 1 | 2 | 4 | 8) {
            return err("size must be 1, 2, 4 or 8");
        }
        let big_endian = p
            .endian
            .as_deref()
            .map(|e| e.eq_ignore_ascii_case("big") || e.eq_ignore_ascii_case("be"))
            .unwrap_or(false);
        let signed = p.signed.unwrap_or(false);

        match self.with_doc(&p.path, |doc| {
            let size = doc.size();
            if p.offset.checked_add(p.size).is_none_or(|end| end > size) {
                return Err(format!(
                    "read out of range: offset {:#x} + {} bytes exceeds file size {size:#x}",
                    p.offset, p.size
                ));
            }
            let bytes = ops::effective_range(&mut doc.app, p.offset, p.size);
            let value = ops::read_int(&mut doc.app, p.offset, p.size, signed, big_endian)
                .ok_or_else(|| "could not read integer".to_string())?;
            Ok(json!({
                "path": doc.canonical(),
                "offset": p.offset,
                "size": p.size,
                "signed": signed,
                "endian": if big_endian { "big" } else { "little" },
                "decimal": value.to_string(),
                "raw_hex": ops::hex_dump(&bytes),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Decode a string at an offset as utf8, latin1, utf16le or utf16be.",
        annotations(read_only_hint = true)
    )]
    async fn read_string(&self, Parameters(p): Parameters<ReadStringParams>) -> CallToolResult {
        let encoding = p.encoding.as_deref().unwrap_or("utf8");
        let max_length = p.max_length.unwrap_or(256).min(MAX_READ);

        match self.with_doc(&p.path, |doc| {
            let size = doc.size();
            if p.offset >= size {
                return Err(format!(
                    "offset {} is past end of file ({size:#x})",
                    p.offset
                ));
            }
            let (text, byte_length) = ops::read_string(
                &mut doc.app,
                p.offset,
                encoding,
                max_length,
                p.stop_at_nul.unwrap_or(true),
            )?;
            Ok(json!({
                "path": doc.canonical(),
                "offset": p.offset,
                "encoding": encoding,
                "text": text,
                "byte_length": byte_length,
                "char_length": text.chars().count(),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Extract a byte range to a file on disk (equivalent to dz6's `:dump`).",
        annotations(read_only_hint = false)
    )]
    async fn dump(&self, Parameters(p): Parameters<DumpParams>) -> CallToolResult {
        if p.out_path.trim().is_empty() {
            return err("out_path must not be empty");
        }
        match self.with_doc(&p.path, |doc| {
            let written = ops::dump_to(&mut doc.app, &p.out_path, p.offset, p.length)?;
            Ok(json!({
                "path": doc.canonical(),
                "out_path": p.out_path,
                "offset": p.offset,
                "bytes_written": written,
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Compute Shannon entropy, printable ratio and unique-byte count for a range. Useful for spotting compressed or encrypted regions.",
        annotations(read_only_hint = true)
    )]
    async fn analyze(&self, Parameters(p): Parameters<AnalyzeParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let size = doc.size();
            let offset = p.offset.unwrap_or(0);
            if offset > size {
                return Err(format!(
                    "offset {offset:#x} is past end of file ({size:#x})"
                ));
            }
            let length = p
                .length
                .unwrap_or(size - offset)
                .min(size - offset)
                .min(MAX_ANALYZE);
            let stats = ops::analyze(&mut doc.app, offset, length);
            Ok(json!({
                "path": doc.canonical(),
                "file_size": size,
                "offset": stats.offset,
                "length": stats.length,
                "entropy": stats.entropy,
                "printable_ratio": stats.printable_ratio,
                "unique_bytes": stats.unique_bytes,
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }
}
