//! File lifecycle and metadata tools.

use rmcp::{handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ops;
use crate::server::Dz6Server;
use crate::state::Document;

use super::{err, ok_value};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenFileParams {
    /// Path to the file to open.
    pub path: String,
    /// Open the file read-only. Defaults to the server-wide setting.
    #[serde(default)]
    pub readonly: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PathParams {
    /// Path to an open (or lazily opened) file.
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloseFileParams {
    /// Path to close.
    pub path: String,
    /// Flush pending edits before closing. Defaults to false (discard).
    #[serde(default)]
    pub save: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GotoParams {
    /// Path to the file.
    pub path: String,
    /// Absolute byte offset to move the editor cursor to.
    pub offset: usize,
}

fn doc_info_json(doc: &Document) -> Value {
    json!({
        "path": doc.canonical(),
        "size": doc.size(),
        "size_hex": format!("{:#x}", doc.size()),
        "type": doc.file_type(),
        "readonly": doc.readonly(),
        "dirty": doc.dirty(),
        "pending_changes": doc.app.hex_view.changed_bytes.len(),
        "offset": doc.app.hex_view.offset,
        "bookmarks": doc.app.hex_view.bookmarks.len(),
        "comments": doc.app.hex_view.comments.len(),
        "blocks": doc.app.hex_view.blocks.len(),
    })
}

#[tool_router(router = file_router, vis = "pub(crate)")]
impl Dz6Server {
    #[tool(
        description = "Open a file and return its metadata. Files are also opened lazily by other tools, but this lets you choose the read-only mode explicitly.",
        annotations(read_only_hint = true)
    )]
    async fn open_file(&self, Parameters(p): Parameters<OpenFileParams>) -> CallToolResult {
        let mut state = self.lock();
        match state.open_doc(&p.path, p.readonly) {
            Ok(doc) => ok_value(json!({
                "opened": true,
                "file": doc_info_json(doc),
            })),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Close an open file. Set save=true to flush pending edits first; otherwise edits are discarded.",
        annotations(read_only_hint = false)
    )]
    async fn close_file(&self, Parameters(p): Parameters<CloseFileParams>) -> CallToolResult {
        let mut state = self.lock();

        if p.save.unwrap_or(false) {
            let doc = match state.open_doc(&p.path, None) {
                Ok(doc) => doc,
                Err(e) => return err(e),
            };
            if let Err(e) = ops::save(&mut doc.app) {
                return err(e);
            }
        }

        match state.close(&p.path) {
            Ok(closed) => ok_value(json!({ "closed": closed, "path": p.path })),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "List every file currently open in this MCP session.",
        annotations(read_only_hint = true)
    )]
    async fn list_open_files(&self) -> CallToolResult {
        let state = self.lock();
        let files: Vec<Value> = state.docs().map(doc_info_json).collect();
        ok_value(json!({
            "count": files.len(),
            "files": files,
        }))
    }

    #[tool(
        description = "Return metadata for one file: size, detected type (PE/ELF/...), read-only state, pending edits and annotation counts.",
        annotations(read_only_hint = true)
    )]
    async fn file_info(&self, Parameters(p): Parameters<PathParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| Ok(doc_info_json(doc))) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Move the editor cursor to an absolute offset. This affects the default start point of subsequent searches.",
        annotations(read_only_hint = true)
    )]
    async fn goto(&self, Parameters(p): Parameters<GotoParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let size = doc.size();
            if p.offset >= size {
                return Err(format!(
                    "offset {} is out of range (file size {:#x})",
                    p.offset, size
                ));
            }
            doc.app.hex_view.last_visited_offset = doc.app.hex_view.offset;
            doc.app.hex_view.offset = p.offset;
            Ok(json!({ "offset": p.offset, "file_size": size }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }
}
