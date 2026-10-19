//! The MCP server type and shared state plumbing.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext},
    model::{
        CallToolRequestParams, CallToolResponse, Implementation, ServerCapabilities, ServerConfig,
    },
    service::RequestContext,
    tool_handler,
};

use crate::logging::Diagnostics;
use crate::state::{Document, ServerState};

#[derive(Clone)]
pub struct Dz6Server {
    pub(crate) state: Arc<Mutex<ServerState>>,
    tool_router: ToolRouter<Self>,
    diagnostics: Arc<Diagnostics>,
}

impl Dz6Server {
    pub fn new(default_readonly: bool, diagnostics: Arc<Diagnostics>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ServerState::new(default_readonly))),
            tool_router: Self::file_router()
                + Self::read_router()
                + Self::search_router()
                + Self::pattern_router()
                + Self::headers_router()
                + Self::binary_router()
                + Self::edit_router()
                + Self::annotations_router()
                + Self::debug_router(),
            diagnostics,
        }
    }

    pub(crate) fn diagnostics(&self) -> &Diagnostics {
        self.diagnostics.as_ref()
    }

    pub(crate) fn tool_count(&self) -> usize {
        self.tool_router.list_all().len()
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, ServerState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Run `f` against an open document. This is a synchronous helper so that
    /// no mutex guard ever crosses an `.await` point in the tool methods.
    pub(crate) fn with_doc<T>(
        &self,
        path: &str,
        f: impl FnOnce(&mut Document) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut state = self.lock();
        let doc = state.open_doc(path, None)?;
        f(doc)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Dz6Server {
    /// Log every tool invocation before dispatching it. The macro detects this
    /// method and does not generate its own.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let tool = request.name.to_string();
        let started = Instant::now();
        tracing::info!(tool = %tool, "tool call");

        let call = ToolCallContext::new(self, request, context);
        let result = self.tool_router.call(call).await;
        let elapsed_ms = started.elapsed().as_millis();

        match &result {
            Ok(CallToolResponse::Complete(result)) if result.is_error == Some(true) => {
                tracing::warn!(tool = %tool, elapsed_ms, "tool returned an error");
            }
            Ok(_) => tracing::info!(tool = %tool, elapsed_ms, "tool completed"),
            Err(error) => tracing::error!(tool = %tool, elapsed_ms, %error, "tool failed"),
        }
        result
    }

    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("dz6-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "dz6-mcp exposes the dz6 terminal hex editor to MCP clients.\n\
             \n\
             Files are opened lazily; every file tool accepts a `path`. Use `open_file` \
             explicitly when you need to control the read-only mode.\n\
             \n\
             Analysis: `file_info`, `read_bytes`, `read_int`, `read_string`, `headers`, \
             `search`, `search_all`, `pattern_scan` (advanced signatures), `strings`, \
             `analyze`, `dump`. Binary layout: `sections`, `symbols`, `address_translate`, \
             `read_at_address`, `pe_info`, `elf_info`.\n\
             \n\
             Editing (staged in memory, written only by `save`): `write_bytes`, `fill`, \
             `undo`, `save`, `truncate`.\n\
             \n\
             Annotations (persisted in a `<file>.dz6` sidecar on `save`): `comment_set`, \
             `comments_list`, `bookmark_add`, `bookmark_remove`, `bookmarks_list`, \
             `bookmark_clear`, `block_add`, `blocks_list`, `block_clear`.\n\
             \n\
             Diagnostics: `server_info`, `log_level` (read or change verbosity), `logs_tail` \
             (recent stderr log lines) and `logs_clear`.\n\
             \n\
             Offsets are decimal unless a string is documented otherwise. Read-only \
             documents reject all editing tools.",
            )
    }
}
