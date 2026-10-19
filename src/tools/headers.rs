//! Executable-header parsing (PE and ELF), backed by dz6's goblin integration.

use rmcp::{handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router};
use serde_json::json;

use crate::ops;
use crate::server::Dz6Server;

use super::{err, ok_value};
use crate::tools::file::PathParams;

#[tool_router(router = headers_router, vis = "pub(crate)")]
impl Dz6Server {
    #[tool(
        description = "Parse PE or ELF headers and return sections, imports/exports (PE), program headers, symbols and relocations (ELF). Returns parsed=false for other formats.",
        annotations(read_only_hint = true)
    )]
    async fn headers(&self, Parameters(p): Parameters<PathParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let mut value = ops::headers_json(&mut doc.app);
            if let Some(obj) = value.as_object_mut() {
                obj.insert("path".into(), json!(doc.canonical()));
                obj.insert("file_size".into(), json!(doc.size()));
            }
            Ok(value)
        }) {
            Ok(v) => ok_value(v),
            Err(e) => err(e),
        }
    }
}
