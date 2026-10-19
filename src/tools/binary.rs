//! Deep PE/ELF inspection tools.

use rmcp::{handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::binary::{self, SymbolFilter};
use crate::ops;
use crate::server::Dz6Server;

use super::file::PathParams;
use super::{err, ok_value};

const MAX_READ: usize = 1 << 20; // 1 MiB per response

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SymbolsParams {
    /// Path to the file.
    pub path: String,
    /// Only return symbols whose name matches this regular expression.
    #[serde(default)]
    pub name_regex: Option<String>,
    /// "all" (default), "function", "object", "import" or "export".
    #[serde(default)]
    pub kind: Option<String>,
    /// ELF: read the dynamic symbol table instead of `.symtab`.
    #[serde(default)]
    pub dynamic_only: Option<bool>,
    /// ELF: only keep non-local symbols.
    #[serde(default)]
    pub global_only: Option<bool>,
    /// Maximum number of entries. Defaults to 1000, capped at 10000.
    #[serde(default)]
    pub max: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddressTranslateParams {
    /// Path to the file.
    pub path: String,
    /// Address to translate (hex `0x...` or decimal). Required unless `offset` is set.
    #[serde(default)]
    pub address: Option<String>,
    /// File offset to translate back to an address. Required unless `address` is set.
    #[serde(default)]
    pub offset: Option<usize>,
    /// PE addresses only: treat `address` as an RVA instead of a VA.
    #[serde(default)]
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadAtAddressParams {
    /// Path to the file.
    pub path: String,
    /// Virtual address (or RVA when `kind` is "rva") to read from.
    pub address: String,
    /// PE only: "va" (default) or "rva".
    #[serde(default)]
    pub kind: Option<String>,
    /// Number of bytes to read. Defaults to 256, capped at 1 MiB.
    #[serde(default)]
    pub length: Option<usize>,
    /// "both" (default), "hex" or "ascii".
    #[serde(default)]
    pub format: Option<String>,
    /// Include the raw byte values as a JSON array. Defaults to false.
    #[serde(default)]
    pub include_bytes: Option<bool>,
}

fn parse_number(input: &str) -> Result<u64, String> {
    let trimmed = input.trim().replace('_', "");
    let parsed = if let Some(rest) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(rest, 16)
    } else {
        trimmed.parse::<u64>()
    };
    parsed.map_err(|_| format!("invalid number: {input:?} (use decimal or 0x-prefixed hex)"))
}

#[tool_router(router = binary_router, vis = "pub(crate)")]
impl Dz6Server {
    #[tool(
        description = "Return the section/segment layout of a PE or ELF file: addresses, file offsets, decoded flags, per-section entropy and (ELF) the owning segment.",
        annotations(read_only_hint = true)
    )]
    async fn sections(&self, Parameters(p): Parameters<PathParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let mut value = binary::layout_json(&mut doc.app)?;
            if let Some(obj) = value.as_object_mut() {
                obj.insert("path".into(), json!(doc.canonical()));
                obj.insert("file_size".into(), json!(doc.size()));
            }
            Ok(value)
        }) {
            Ok(value) => ok_value(value),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "List symbols with filters. ELF: .symtab or .dynsym with type/bind/section and file offset. PE: exports and imports with RVA/VA/file offset.",
        annotations(read_only_hint = true)
    )]
    async fn symbols(&self, Parameters(p): Parameters<SymbolsParams>) -> CallToolResult {
        let kind = p.kind.as_deref().unwrap_or("all");
        let filter = SymbolFilter {
            name_regex: p.name_regex.as_deref(),
            kind,
            dynamic_only: p.dynamic_only.unwrap_or(false),
            global_only: p.global_only.unwrap_or(false),
            max: p.max.unwrap_or(1000),
        };
        match self.with_doc(&p.path, |doc| {
            let mut value = binary::symbols_json(&mut doc.app, &filter)?;
            if let Some(obj) = value.as_object_mut() {
                obj.insert("path".into(), json!(doc.canonical()));
            }
            Ok(value)
        }) {
            Ok(value) => ok_value(value),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "Translate between virtual addresses and file offsets. PE understands VA and RVA; ELF uses PT_LOAD segments with a section fallback. Returns the owning section/segment.",
        annotations(read_only_hint = true)
    )]
    async fn address_translate(
        &self,
        Parameters(p): Parameters<AddressTranslateParams>,
    ) -> CallToolResult {
        let kind = p.kind.as_deref().unwrap_or("va");
        if !kind.eq_ignore_ascii_case("va") && !kind.eq_ignore_ascii_case("rva") {
            return err("kind must be \"va\" or \"rva\"");
        }

        match (p.address.as_deref(), p.offset) {
            (Some(_), Some(_)) => err("provide either `address` or `offset`, not both"),
            (None, None) => err("provide `address` or `offset`"),
            (Some(address), None) => match parse_number(address) {
                Ok(address) => match self.with_doc(&p.path, |doc| {
                    let translation = binary::va_to_offset(&mut doc.app, address, kind)?;
                    let mut value = translation.to_json();
                    value["path"] = json!(doc.canonical());
                    Ok(value)
                }) {
                    Ok(value) => ok_value(value),
                    Err(e) => err(e),
                },
                Err(e) => err(e),
            },
            (None, Some(offset)) => match self.with_doc(&p.path, |doc| {
                let translation = binary::offset_to_va(&mut doc.app, offset)?;
                let mut value = translation.to_json();
                value["path"] = json!(doc.canonical());
                Ok(value)
            }) {
                Ok(value) => ok_value(value),
                Err(e) => err(e),
            },
        }
    }

    #[tool(
        description = "Read bytes by virtual address (or PE RVA). Pending unsaved edits are reflected.",
        annotations(read_only_hint = true)
    )]
    async fn read_at_address(
        &self,
        Parameters(p): Parameters<ReadAtAddressParams>,
    ) -> CallToolResult {
        let kind = p.kind.as_deref().unwrap_or("va");
        if !kind.eq_ignore_ascii_case("va") && !kind.eq_ignore_ascii_case("rva") {
            return err("kind must be \"va\" or \"rva\"");
        }
        let address = match parse_number(&p.address) {
            Ok(address) => address,
            Err(e) => return err(e),
        };
        let requested = p.length.unwrap_or(256);
        let length = requested.min(MAX_READ);

        match self.with_doc(&p.path, |doc| {
            let (translation, bytes) =
                binary::read_at_address(&mut doc.app, address, kind, length)?;
            let format = p.format.as_deref().unwrap_or("both").to_ascii_lowercase();
            let mut value = translation.to_json();
            value["path"] = json!(doc.canonical());
            value["requested_length"] = json!(requested);
            value["length"] = json!(bytes.len());
            value["truncated"] = json!(bytes.len() < requested);
            if format == "both" || format == "hex" {
                value["hex"] = json!(ops::hex_dump(&bytes));
            }
            if format == "both" || format == "ascii" {
                value["ascii"] = json!(ops::ascii_dump(&bytes, '.'));
            }
            if p.include_bytes.unwrap_or(false) {
                value["bytes"] = json!(bytes);
            }
            Ok(value)
        }) {
            Ok(value) => ok_value(value),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "PE-specific metadata: named data directories, debug/PDB info, TLS callbacks, exceptions, relocations, load config, Authenticode certificates, resources, CLR (.NET), Rich header and overlay.",
        annotations(read_only_hint = true)
    )]
    async fn pe_info(&self, Parameters(p): Parameters<PathParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let mut value = binary::pe_info_json(&mut doc.app)?;
            if let Some(obj) = value.as_object_mut() {
                obj.insert("path".into(), json!(doc.canonical()));
                obj.insert("file_size".into(), json!(doc.size()));
            }
            Ok(value)
        }) {
            Ok(value) => ok_value(value),
            Err(e) => err(e),
        }
    }

    #[tool(
        description = "ELF-specific metadata: interpreter, NEEDED/SONAME/RPATH/RUNPATH, dynamic tags, GNU notes (build-id/ABI) and program headers.",
        annotations(read_only_hint = true)
    )]
    async fn elf_info(&self, Parameters(p): Parameters<PathParams>) -> CallToolResult {
        match self.with_doc(&p.path, |doc| {
            let mut value = binary::elf_info_json(&mut doc.app)?;
            if let Some(obj) = value.as_object_mut() {
                obj.insert("path".into(), json!(doc.canonical()));
                obj.insert("file_size".into(), json!(doc.size()));
            }
            Ok(value)
        }) {
            Ok(value) => ok_value(value),
            Err(e) => err(e),
        }
    }
}
