//! Tool implementations, split by area.
//!
//! Each module contributes a router; [`crate::server::Dz6Server::new`] merges
//! them into a single [`rmcp::handler::server::router::tool::ToolRouter`].

pub mod annotations;
pub mod binary;
pub mod debug;
pub mod edit;
pub mod file;
pub mod headers;
pub mod pattern;
pub mod read;
pub mod search;

use rmcp::model::CallToolResult;
use serde_json::{Value, json};

pub(crate) fn ok_value(value: Value) -> CallToolResult {
    CallToolResult::structured(value)
}

pub(crate) fn err(message: impl Into<String>) -> CallToolResult {
    CallToolResult::structured_error(json!({ "error": message.into() }))
}
