//! Comments, bookmarks and colored blocks.
//!
//! These match dz6's annotations and are persisted to the `<file>.dz6` TOML
//! sidecar when `save` runs (unless the database was disabled).

use rmcp::{handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::ops;
use crate::server::Dz6Server;
use crate::tools::file::PathParams;

use super::{err, ok_value};

const MAX_BOOKMARKS: usize = 8;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommentSetParams {
    /// Path to the file.
    pub path: String,
    /// Absolute offset to annotate.
    pub offset: usize,
    /// Comment text. An empty string removes the comment.
    pub comment: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BookmarkAddParams {
    /// Path to the file.
    pub path: String,
    /// Absolute offset to bookmark.
    pub offset: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BookmarkRemoveParams {
    /// Path to the file.
    pub path: String,
    /// Offset to remove. When omitted, the most recently added bookmark is removed.
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BlockAddParams {
    /// Path to the file.
    pub path: String,
    /// First byte of the block.
    pub start: usize,
    /// Last byte of the block (inclusive).
    pub end: usize,
    /// Background color as 0x00RRGGBB (ratatui's `Color::from_u32`). Random if omitted.
    #[serde(default)]
    pub bg_color: Option<u32>,
    /// Foreground color as 0x00RRGGBB. Random if omitted.
    #[serde(default)]
    pub fg_color: Option<u32>,
}

fn bookmarks_json(bookmarks: &[usize]) -> serde_json::Value {
    json!({
        "count": bookmarks.len(),
        "bookmarks": bookmarks,
        "bookmarks_hex": bookmarks.iter().map(|o| format!("{o:#x}")).collect::<Vec<_>>(),
    })
}

#[tool_router(router = annotations_router, vis = "pub(crate)")]
impl Dz6Server {
    #[tool(
        description = "Add, replace or remove a comment at an offset. Persisted on `save`.",
        annotations(read_only_hint = false)
    )]
    async fn comment_set(&self, Parameters(p): Parameters<CommentSetParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            if p.offset >= doc.size() {
                return Err(format!(
                    "offset {:#x} is past end of file ({:#x})",
                    p.offset,
                    doc.size()
                ));
            }
            ops::set_comment(&mut doc.app, p.offset, &p.comment);
            Ok(json!({
                "path": doc.canonical(),
                "offset": p.offset,
                "comment": p.comment,
                "comments": doc.app.hex_view.comments.len(),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "List comments (offset -> text), sorted by offset.",
        annotations(read_only_hint = true)
    )]
    async fn comments_list(&self, Parameters(p): Parameters<PathParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let mut items: Vec<_> = doc.app.hex_view.comments.iter().collect();
            items.sort_by_key(|(offset, _)| **offset);
            let comments: Vec<_> = items
                .iter()
                .map(|(offset, text)| {
                    json!({
                        "offset": **offset,
                        "offset_hex": format!("{:#x}", **offset),
                        "comment": *text,
                    })
                })
                .collect();
            Ok(json!({
                "path": doc.canonical(),
                "count": comments.len(),
                "comments": comments,
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Add a bookmark at an offset (dz6 supports up to 8).",
        annotations(read_only_hint = false)
    )]
    async fn bookmark_add(&self, Parameters(p): Parameters<BookmarkAddParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            if p.offset >= doc.size() {
                return Err(format!(
                    "offset {:#x} is past end of file ({:#x})",
                    p.offset,
                    doc.size()
                ));
            }
            if let Some(pos) = doc
                .app
                .hex_view
                .bookmarks
                .iter()
                .position(|&o| o == p.offset)
            {
                return Ok(json!({
                    "added": false,
                    "already_bookmarked": true,
                    "index": pos,
                    "bookmarks": bookmarks_json(&doc.app.hex_view.bookmarks),
                }));
            }
            if doc.app.hex_view.bookmarks.len() >= MAX_BOOKMARKS {
                return Err(format!(
                    "bookmark limit reached ({MAX_BOOKMARKS}); remove one first"
                ));
            }
            doc.app.hex_view.bookmarks.push(p.offset);
            Ok(json!({
                "added": true,
                "offset": p.offset,
                "bookmarks": bookmarks_json(&doc.app.hex_view.bookmarks),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Remove one bookmark by offset, or the most recent bookmark when offset is omitted.",
        annotations(read_only_hint = false)
    )]
    async fn bookmark_remove(
        &self,
        Parameters(p): Parameters<BookmarkRemoveParams>,
    ) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let removed = match p.offset {
                Some(offset) => {
                    match doc.app.hex_view.bookmarks.iter().position(|&o| o == offset) {
                        Some(pos) => Some(doc.app.hex_view.bookmarks.remove(pos)),
                        None => None,
                    }
                }
                None => doc.app.hex_view.bookmarks.pop(),
            };
            Ok(json!({
                "removed": removed,
                "removed_hex": removed.map(|o| format!("{o:#x}")),
                "bookmarks": bookmarks_json(&doc.app.hex_view.bookmarks),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "List all bookmarks.",
        annotations(read_only_hint = true)
    )]
    async fn bookmarks_list(&self, Parameters(p): Parameters<PathParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            Ok(json!({
                "path": doc.canonical(),
                "bookmarks": bookmarks_json(&doc.app.hex_view.bookmarks),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Remove every bookmark.",
        annotations(read_only_hint = false)
    )]
    async fn bookmark_clear(&self, Parameters(p): Parameters<PathParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            doc.app.hex_view.bookmarks.clear();
            Ok(json!({
                "path": doc.canonical(),
                "bookmarks": bookmarks_json(&doc.app.hex_view.bookmarks),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Mark a byte range with a color (like dz6's Alt+m). Colors are 0x00RRGGBB.",
        annotations(read_only_hint = false)
    )]
    async fn block_add(&self, Parameters(p): Parameters<BlockAddParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            ops::block_add(&mut doc.app, p.start, p.end, p.bg_color, p.fg_color)?;
            Ok(json!({
                "path": doc.canonical(),
                "start": p.start,
                "end": p.end,
                "blocks": doc.app.hex_view.blocks.len(),
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "List colored blocks.",
        annotations(read_only_hint = true)
    )]
    async fn blocks_list(&self, Parameters(p): Parameters<PathParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let blocks: Vec<_> = doc
                .app
                .hex_view
                .blocks
                .iter()
                .map(|b| {
                    json!({
                        "start": b.start,
                        "end": b.end,
                        "start_hex": format!("{:#x}", b.start),
                        "end_hex": format!("{:#x}", b.end),
                        "bg_color": format!("{:#08x}", b.bg_color),
                        "fg_color": format!("{:#08x}", b.fg_color),
                    })
                })
                .collect();
            Ok(json!({
                "path": doc.canonical(),
                "count": blocks.len(),
                "blocks": blocks,
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Remove every colored block.",
        annotations(read_only_hint = false)
    )]
    async fn block_clear(&self, params: Parameters<PathParams>) -> CallToolResult {
        let Parameters(p) = params;
        match self.with_doc(&p.path, |doc| {
            doc.app.hex_view.blocks.clear();
            Ok(json!({
                "path": doc.canonical(),
                "blocks": 0,
            }))
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }
}
