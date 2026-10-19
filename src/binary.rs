//! Deep PE/ELF inspection on top of dz6's memory map.
//!
//! dz6 already parses the basic headers (see `ops::headers_json`). This module
//! adds what reverse-engineering workflows need on top of that:
//!
//! - section/segment layout with decoded flags and per-section entropy
//! - virtual address <-> file offset translation (PE VA/RVA and ELF VA)
//! - filterable symbols/imports/exports
//! - PE-only directories: debug/PDB, TLS, exceptions, relocations, load config,
//!   certificates, resources, CLR and overlay
//! - ELF-only metadata: dynamic entries, NEEDED/SONAME/RPATH/RUNPATH, notes
//!   (including the GNU build-id)
//!
//! Structure is parsed from the memory-mapped file. Byte reads use
//! `ops::effective_range`, so they still see staged edits.

use dz6::app::App;
use goblin::elf::Elf;
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use goblin::pe::PE;
use regex::Regex;
use serde_json::{Value, json};

use crate::ops::{OpResult, effective_range, hex_dump};

const MAX_LIST: usize = 10_000;
const MAX_DYNAMIC_ENTRIES: usize = 256;

fn hex(value: impl Into<u64>) -> String {
    format!("{:#x}", value.into())
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn section_slice(buf: &[u8], offset: u64, size: u64) -> &[u8] {
    let start = (offset as usize).min(buf.len());
    let end = start.saturating_add(size as usize).min(buf.len());
    &buf[start..end]
}

/// Detected executable format, if any.
pub fn format_of(app: &App) -> Option<&'static str> {
    if app.header_view.pe.is_some() {
        Some("PE")
    } else if app.header_view.elf.is_some() {
        Some("ELF")
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

const DD_NAMES: [&str; 16] = [
    "export",
    "import",
    "resource",
    "exception",
    "certificate",
    "base_relocation",
    "debug",
    "architecture",
    "global_ptr",
    "tls",
    "load_config",
    "bound_import",
    "iat",
    "delay_import",
    "clr_runtime",
    "reserved",
];

fn pe_section_flags(characteristics: u32) -> Value {
    json!({
        "readable": characteristics & 0x4000_0000 != 0,
        "writable": characteristics & 0x8000_0000 != 0,
        "executable": characteristics & 0x2000_0000 != 0,
        "code": characteristics & 0x0000_0020 != 0,
        "initialized_data": characteristics & 0x0000_0040 != 0,
        "uninitialized_data": characteristics & 0x0000_0080 != 0,
    })
}

fn pe_layout(buf: &[u8], pe: &PE) -> Value {
    let sections: Vec<Value> = pe
        .sections
        .iter()
        .map(|s| {
            let va = pe.image_base + s.virtual_address as u64;
            let raw = section_slice(buf, s.pointer_to_raw_data as u64, s.size_of_raw_data as u64);
            json!({
                "name": s.name().unwrap_or(""),
                "virtual_address": hex(s.virtual_address),
                "virtual_size": hex(s.virtual_size),
                "va_start": hex(va),
                "va_end": hex(va + s.virtual_size as u64),
                "file_offset": hex(s.pointer_to_raw_data),
                "file_size": hex(s.size_of_raw_data),
                "entropy": entropy(raw),
                "characteristics": hex(s.characteristics),
                "flags": pe_section_flags(s.characteristics),
            })
        })
        .collect();

    json!({
        "format": "PE",
        "image_base": hex(pe.image_base),
        "entry_point_rva": hex(pe.entry),
        "entry_point_va": hex(pe.image_base + pe.entry as u64),
        "sections": sections,
        "segments": [],
    })
}

fn elf_section_type_name(t: u32) -> &'static str {
    match t {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        10 => "SHLIB",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        16 => "PREINIT_ARRAY",
        17 => "GROUP",
        18 => "SYMTAB_SHNDX",
        0x6fff_fff6 => "GNU_VERDEF",
        0x6fff_fff7 => "GNU_VERNEED",
        0x6fff_fff8 => "GNU_VERSYM",
        0x6fff_fffd => "GNU_HASH",
        _ => "UNKNOWN",
    }
}

fn elf_segment_type_name(t: u32) -> &'static str {
    match t {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        0x6474_e550 => "GNU_EH_FRAME",
        0x6474_e551 => "GNU_STACK",
        0x6474_e552 => "GNU_RELRO",
        0x6474_e553 => "GNU_PROPERTY",
        _ => "UNKNOWN",
    }
}

fn elf_segment(ph: &goblin::elf::ProgramHeader, index: usize) -> Value {
    json!({
        "index": index,
        "type": hex(ph.p_type),
        "type_name": elf_segment_type_name(ph.p_type),
        "flags": hex(ph.p_flags),
        "readable": ph.p_flags & PF_R != 0,
        "writable": ph.p_flags & PF_W != 0,
        "executable": ph.p_flags & PF_X != 0,
        "offset": hex(ph.p_offset),
        "vaddr": hex(ph.p_vaddr),
        "paddr": hex(ph.p_paddr),
        "filesz": hex(ph.p_filesz),
        "memsz": hex(ph.p_memsz),
        "align": hex(ph.p_align),
    })
}

fn elf_section_name<'a>(elf: &'a Elf, shndx: usize) -> Option<&'a str> {
    elf.section_headers
        .get(shndx)
        .and_then(|s| elf.shdr_strtab.get_at(s.sh_name))
}

fn elf_segment_for_va(elf: &Elf, va: u64) -> Option<usize> {
    elf.program_headers.iter().position(|ph| {
        ph.p_type == PT_LOAD && va >= ph.p_vaddr && va < ph.p_vaddr.saturating_add(ph.p_memsz)
    })
}

fn elf_layout(buf: &[u8], elf: &Elf) -> Value {
    let sections: Vec<Value> = elf
        .section_headers
        .iter()
        .map(|s| {
            let name = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("");
            let raw = section_slice(buf, s.sh_offset, s.sh_size);
            let segment = if s.sh_addr != 0 && s.sh_flags & (SHF_ALLOC as u64) != 0 {
                elf_segment_for_va(elf, s.sh_addr)
            } else {
                None
            };
            json!({
                "name": name,
                "type": hex(s.sh_type),
                "type_name": elf_section_type_name(s.sh_type),
                "flags": hex(s.sh_flags),
                "alloc": s.sh_flags & (SHF_ALLOC as u64) != 0,
                "writable": s.sh_flags & (SHF_WRITE as u64) != 0,
                "executable": s.sh_flags & (SHF_EXECINSTR as u64) != 0,
                "addr": hex(s.sh_addr),
                "offset": hex(s.sh_offset),
                "size": hex(s.sh_size),
                "addralign": hex(s.sh_addralign),
                "entsize": hex(s.sh_entsize),
                "entropy": entropy(raw),
                "segment": segment,
            })
        })
        .collect();

    let segments: Vec<Value> = elf
        .program_headers
        .iter()
        .enumerate()
        .map(|(index, ph)| elf_segment(ph, index))
        .collect();

    json!({
        "format": "ELF",
        "class": if elf.is_64 { "ELF64" } else { "ELF32" },
        "endianness": if elf.little_endian { "little" } else { "big" },
        "object_type": elf_object_type_name(elf.header.e_type),
        "machine": elf_machine_name(elf.header.e_machine),
        "entry_point": hex(elf.entry),
        "image_base": Value::Null,
        "sections": sections,
        "segments": segments,
    })
}

fn elf_object_type_name(t: u16) -> &'static str {
    match t {
        0 => "NONE",
        1 => "REL",
        2 => "EXEC",
        3 => "DYN",
        4 => "CORE",
        _ => "UNKNOWN",
    }
}

fn elf_machine_name(m: u16) -> &'static str {
    match m {
        3 => "x86",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC64",
        40 => "ARM",
        62 => "x86_64",
        183 => "AArch64",
        243 => "RISC-V",
        247 => "BPF",
        _ => "UNKNOWN",
    }
}

/// Sections and (for ELF) program headers with decoded flags and entropy.
pub fn layout_json(app: &mut App) -> OpResult<Value> {
    let format = format_of(app).ok_or_else(|| "not a PE or ELF file".to_string())?;
    let buf = app.file_info.get_buffer();
    if format == "PE" {
        let pe = PE::parse(buf).map_err(|e| format!("PE parse error: {e}"))?;
        Ok(pe_layout(buf, &pe))
    } else {
        let elf = Elf::parse(buf).map_err(|e| format!("ELF parse error: {e}"))?;
        Ok(elf_layout(buf, &elf))
    }
}

// ---------------------------------------------------------------------------
// Symbols
// ---------------------------------------------------------------------------

pub struct SymbolFilter<'a> {
    pub name_regex: Option<&'a str>,
    pub kind: &'a str,
    pub dynamic_only: bool,
    pub global_only: bool,
    pub max: usize,
}

fn elf_sym_type_name(t: u8) -> &'static str {
    match t {
        0 => "NOTYPE",
        1 => "OBJECT",
        2 => "FUNC",
        3 => "SECTION",
        4 => "FILE",
        5 => "COMMON",
        6 => "TLS",
        10 => "GNU_IFUNC",
        _ => "UNKNOWN",
    }
}

fn elf_sym_bind_name(b: u8) -> &'static str {
    match b {
        0 => "LOCAL",
        1 => "GLOBAL",
        2 => "WEAK",
        10 => "GNU_UNIQUE",
        _ => "UNKNOWN",
    }
}

#[allow(clippy::too_many_arguments)]
fn symbol_matches(
    re: Option<&Regex>,
    kind: &str,
    name: &str,
    is_func: bool,
    is_object: bool,
    defined: bool,
    global: bool,
    global_only: bool,
) -> bool {
    if global_only && !global {
        return false;
    }
    match kind {
        "function" | "func" if !is_func => return false,
        "object" | "data" if !is_object => return false,
        "import" | "undefined" if defined => return false,
        "export" | "defined" if !defined || !global => return false,
        _ => {}
    }
    match re {
        Some(re) => re.is_match(name),
        None => true,
    }
}

fn validate_kind(kind: &str) -> OpResult<&'static str> {
    let normalized = match kind.to_ascii_lowercase().as_str() {
        "" | "all" => "all",
        "function" | "func" => "function",
        "object" | "data" => "object",
        "import" | "undefined" => "import",
        "export" | "defined" => "export",
        other => return Err(format!("unsupported symbol kind: {other}")),
    };
    Ok(normalized)
}

fn compile_name_filter(pattern: Option<&str>) -> OpResult<Option<Regex>> {
    match pattern {
        Some(p) if !p.is_empty() => Regex::new(p)
            .map(Some)
            .map_err(|e| format!("invalid name_regex: {e}")),
        _ => Ok(None),
    }
}

/// Filterable symbols: ELF symtab/dynsym, or PE exports+imports.
pub fn symbols_json(app: &mut App, filter: &SymbolFilter) -> OpResult<Value> {
    let format = format_of(app).ok_or_else(|| "not a PE or ELF file".to_string())?;
    let kind = validate_kind(filter.kind)?;
    let re = compile_name_filter(filter.name_regex)?;
    let max = filter.max.clamp(1, MAX_LIST);

    let buf = app.file_info.get_buffer();
    let mut out: Vec<Value> = Vec::new();
    let mut truncated = false;

    if format == "PE" {
        if matches!(kind, "function" | "object") {
            return Err(format!(
                "symbol kind {kind:?} is not available for PE files; use all/import/export"
            ));
        }
        let pe = PE::parse(buf).map_err(|e| format!("PE parse error: {e}"))?;
        let want_import = matches!(kind, "all" | "import");
        let want_export = matches!(kind, "all" | "export");
        if want_export {
            for e in &pe.exports {
                let name = e.name.unwrap_or("");
                if !symbol_matches(
                    re.as_ref(),
                    "export",
                    name,
                    false,
                    false,
                    true,
                    true,
                    filter.global_only,
                ) {
                    continue;
                }
                if out.len() >= max {
                    truncated = true;
                    break;
                }
                out.push(json!({
                    "kind": "export",
                    "name": name,
                    "rva": hex(e.rva as u64),
                    "va": hex(pe.image_base + e.rva as u64),
                    "file_offset": e.offset.map(|o| hex(o as u64)),
                    "size": e.size,
                }));
            }
        }
        if want_import && !truncated {
            for i in &pe.imports {
                if !symbol_matches(
                    re.as_ref(),
                    "import",
                    &i.name,
                    false,
                    false,
                    false,
                    false,
                    false,
                ) {
                    continue;
                }
                if out.len() >= max {
                    truncated = true;
                    break;
                }
                out.push(json!({
                    "kind": "import",
                    "name": i.name,
                    "dll": i.dll,
                    "ordinal": i.ordinal,
                    "rva": hex(i.rva as u64),
                    "file_offset": hex(i.offset as u64),
                }));
            }
        }
    } else {
        let elf = Elf::parse(buf).map_err(|e| format!("ELF parse error: {e}"))?;
        let use_symtab = !filter.dynamic_only && !elf.syms.is_empty();
        if use_symtab {
            for sym in &elf.syms {
                let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
                if push_elf_symbol(
                    &mut out,
                    &elf,
                    name,
                    &sym,
                    "symtab",
                    kind,
                    re.as_ref(),
                    filter,
                    max,
                ) {
                    truncated = true;
                    break;
                }
            }
        } else {
            for sym in &elf.dynsyms {
                let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
                if push_elf_symbol(
                    &mut out,
                    &elf,
                    name,
                    &sym,
                    "dynsym",
                    kind,
                    re.as_ref(),
                    filter,
                    max,
                ) {
                    truncated = true;
                    break;
                }
            }
        }
    }

    if out.len() > max {
        truncated = true;
        out.truncate(max);
    }

    Ok(json!({
        "format": format,
        "count": out.len(),
        "truncated": truncated,
        "symbols": out,
    }))
}

#[allow(clippy::too_many_arguments)]
fn push_elf_symbol(
    out: &mut Vec<Value>,
    elf: &Elf,
    name: &str,
    sym: &goblin::elf::Sym,
    source: &str,
    kind: &str,
    re: Option<&Regex>,
    filter: &SymbolFilter,
    max: usize,
) -> bool {
    let defined = sym.st_shndx != 0;
    let global = sym.st_bind() != 0;
    if !symbol_matches(
        re,
        kind,
        name,
        sym.is_function(),
        sym.st_type() == 1,
        defined,
        global,
        filter.global_only,
    ) {
        return false;
    }
    if out.len() >= max {
        return true;
    }
    let section = if defined {
        elf_section_name(elf, sym.st_shndx).map(str::to_string)
    } else {
        None
    };
    let file_offset = elf_va_to_offset(elf, sym.st_value).map(|(offset, _, _)| offset);
    out.push(json!({
        "kind": if !defined { "import" } else if global { "export" } else { "local" },
        "name": name,
        "source": source,
        "value": hex(sym.st_value),
        "size": sym.st_size,
        "type": elf_sym_type_name(sym.st_type()),
        "bind": elf_sym_bind_name(sym.st_bind()),
        "visibility": sym.st_visibility(),
        "shndx": hex(sym.st_shndx as u64),
        "section": section,
        "file_offset": file_offset.map(|o| hex(o as u64)),
    }));
    false
}

// ---------------------------------------------------------------------------
// Address translation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Translation {
    pub format: &'static str,
    pub file_offset: usize,
    pub va: u64,
    pub rva: Option<u64>,
    pub section: Option<String>,
    pub segment: Option<usize>,
    pub input_kind: String,
    pub input_value: u64,
}

impl Translation {
    pub fn to_json(&self) -> Value {
        json!({
            "format": self.format,
            "input": { "kind": self.input_kind, "value": hex(self.input_value) },
            "mapped": true,
            "file_offset": self.file_offset,
            "file_offset_hex": hex(self.file_offset as u64),
            "va": hex(self.va),
            "rva": self.rva.map(hex),
            "section": self.section,
            "segment": self.segment,
        })
    }
}

fn pe_rva_to_offset(pe: &PE, rva: u64) -> Option<(usize, Option<String>)> {
    let headers = pe
        .header
        .optional_header
        .as_ref()
        .map(|o| o.windows_fields.size_of_headers as u64)
        .unwrap_or(0);
    if rva < headers {
        return Some((rva as usize, None));
    }
    for s in &pe.sections {
        let va = s.virtual_address as u64;
        let span = (s.virtual_size as u64).max(s.size_of_raw_data as u64);
        if rva >= va && rva < va + span {
            let delta = rva - va;
            if delta < s.size_of_raw_data as u64 {
                return Some((
                    s.pointer_to_raw_data as usize + delta as usize,
                    Some(s.name().unwrap_or("").to_string()),
                ));
            }
        }
    }
    None
}

fn pe_offset_to_rva(pe: &PE, offset: usize) -> Option<(u64, Option<String>)> {
    let headers = pe
        .header
        .optional_header
        .as_ref()
        .map(|o| o.windows_fields.size_of_headers as u64)
        .unwrap_or(0);
    if (offset as u64) < headers {
        return Some((offset as u64, None));
    }
    for s in &pe.sections {
        let raw = s.pointer_to_raw_data as usize;
        let size = s.size_of_raw_data as usize;
        if offset >= raw && offset < raw + size {
            return Some((
                s.virtual_address as u64 + (offset - raw) as u64,
                Some(s.name().unwrap_or("").to_string()),
            ));
        }
    }
    None
}

fn elf_va_to_offset(elf: &Elf, va: u64) -> Option<(usize, Option<String>, Option<usize>)> {
    for (index, ph) in elf.program_headers.iter().enumerate() {
        if ph.p_type == PT_LOAD && va >= ph.p_vaddr && va < ph.p_vaddr.saturating_add(ph.p_filesz) {
            let section = elf
                .section_headers
                .iter()
                .find(|s| {
                    s.sh_addr != 0
                        && s.sh_flags & (SHF_ALLOC as u64) != 0
                        && va >= s.sh_addr
                        && va < s.sh_addr.saturating_add(s.sh_size)
                })
                .and_then(|s| elf.shdr_strtab.get_at(s.sh_name))
                .map(str::to_string);
            return Some((
                (ph.p_offset + (va - ph.p_vaddr)) as usize,
                section,
                Some(index),
            ));
        }
    }
    for s in &elf.section_headers {
        if s.sh_addr != 0 && va >= s.sh_addr && va < s.sh_addr.saturating_add(s.sh_size) {
            return Some((
                (s.sh_offset + (va - s.sh_addr)) as usize,
                elf.shdr_strtab.get_at(s.sh_name).map(str::to_string),
                None,
            ));
        }
    }
    None
}

fn elf_offset_to_va(elf: &Elf, offset: usize) -> Option<(u64, Option<String>, Option<usize>)> {
    let offset = offset as u64;
    for (index, ph) in elf.program_headers.iter().enumerate() {
        if ph.p_type == PT_LOAD
            && offset >= ph.p_offset
            && offset < ph.p_offset.saturating_add(ph.p_filesz)
        {
            let va = ph.p_vaddr + (offset - ph.p_offset);
            let section = elf
                .section_headers
                .iter()
                .find(|s| {
                    s.sh_addr != 0
                        && s.sh_flags & (SHF_ALLOC as u64) != 0
                        && va >= s.sh_addr
                        && va < s.sh_addr.saturating_add(s.sh_size)
                })
                .and_then(|s| elf.shdr_strtab.get_at(s.sh_name))
                .map(str::to_string);
            return Some((va, section, Some(index)));
        }
    }
    for s in &elf.section_headers {
        if offset >= s.sh_offset && offset < s.sh_offset.saturating_add(s.sh_size) {
            return Some((
                s.sh_addr + (offset - s.sh_offset),
                elf.shdr_strtab.get_at(s.sh_name).map(str::to_string),
                None,
            ));
        }
    }
    None
}

/// Translate a virtual address (PE: VA by default, or RVA when `kind == "rva"`).
pub fn va_to_offset(app: &mut App, address: u64, kind: &str) -> OpResult<Translation> {
    let format = format_of(app).ok_or_else(|| "not a PE or ELF file".to_string())?;
    let buf = app.file_info.get_buffer();

    if format == "PE" {
        let pe = PE::parse(buf).map_err(|e| format!("PE parse error: {e}"))?;
        let rva = if kind.eq_ignore_ascii_case("rva") {
            address
        } else {
            address.checked_sub(pe.image_base).ok_or_else(|| {
                format!(
                    "address {address:#x} is below image base {:#x}",
                    pe.image_base
                )
            })?
        };
        let (offset, section) = pe_rva_to_offset(&pe, rva)
            .ok_or_else(|| format!("RVA {rva:#x} is not mapped by any section"))?;
        return Ok(Translation {
            format,
            file_offset: offset,
            va: pe.image_base + rva,
            rva: Some(rva),
            section,
            segment: None,
            input_kind: if kind.eq_ignore_ascii_case("rva") {
                "rva".to_string()
            } else {
                "va".to_string()
            },
            input_value: address,
        });
    }

    let elf = Elf::parse(buf).map_err(|e| format!("ELF parse error: {e}"))?;
    if kind.eq_ignore_ascii_case("rva") {
        return Err("RVA is only meaningful for PE files".to_string());
    }
    let (offset, section, segment) = elf_va_to_offset(&elf, address)
        .ok_or_else(|| format!("address {address:#x} is not mapped by any segment or section"))?;
    Ok(Translation {
        format,
        file_offset: offset,
        va: address,
        rva: None,
        section,
        segment,
        input_kind: "va".to_string(),
        input_value: address,
    })
}

/// Translate a file offset back to a virtual address.
pub fn offset_to_va(app: &mut App, offset: usize) -> OpResult<Translation> {
    let format = format_of(app).ok_or_else(|| "not a PE or ELF file".to_string())?;
    let buf = app.file_info.get_buffer();

    if format == "PE" {
        let pe = PE::parse(buf).map_err(|e| format!("PE parse error: {e}"))?;
        let (rva, section) = pe_offset_to_rva(&pe, offset)
            .ok_or_else(|| format!("offset {offset:#x} is not mapped by any section"))?;
        return Ok(Translation {
            format,
            file_offset: offset,
            va: pe.image_base + rva,
            rva: Some(rva),
            section,
            segment: None,
            input_kind: "offset".to_string(),
            input_value: offset as u64,
        });
    }

    let elf = Elf::parse(buf).map_err(|e| format!("ELF parse error: {e}"))?;
    let (va, section, segment) = elf_offset_to_va(&elf, offset)
        .ok_or_else(|| format!("offset {offset:#x} is not mapped by any segment or section"))?;
    Ok(Translation {
        format,
        file_offset: offset,
        va,
        rva: None,
        section,
        segment,
        input_kind: "offset".to_string(),
        input_value: offset as u64,
    })
}

/// Read bytes by virtual address, reflecting staged edits.
pub fn read_at_address(
    app: &mut App,
    address: u64,
    kind: &str,
    length: usize,
) -> OpResult<(Translation, Vec<u8>)> {
    let translation = va_to_offset(app, address, kind)?;
    let size = app.file_info.size;
    let available = size.saturating_sub(translation.file_offset);
    let bytes = effective_range(app, translation.file_offset, length.min(available));
    Ok((translation, bytes))
}

// ---------------------------------------------------------------------------
// PE details
// ---------------------------------------------------------------------------

fn parse_rich_header(buf: &[u8], pe_offset: usize) -> Option<Value> {
    let limit = pe_offset.min(buf.len());
    let pos = buf[..limit]
        .windows(4)
        .position(|window| window == b"Rich")?;
    if pos + 8 > limit {
        return None;
    }
    let key = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().ok()?);

    // Walk backwards one dword at a time, undoing the XOR, until "DanS".
    let mut decoded = Vec::new();
    let mut cursor = pos;
    while cursor >= 4 {
        let value = u32::from_le_bytes(buf[cursor - 4..cursor].try_into().ok()?) ^ key;
        cursor -= 4;
        if value == 0x536E_6144 {
            break;
        }
        decoded.push(value);
        if decoded.len() > 4096 {
            return None;
        }
    }
    if decoded.is_empty() {
        return None;
    }
    decoded.reverse();
    // After DanS are three zero dwords, then (compid, count) pairs.
    if decoded.len() >= 3 && decoded[..3] == [0, 0, 0] {
        decoded.drain(..3);
    }
    let mut entries = Vec::new();
    for pair in decoded.as_chunks::<2>().0 {
        let id = pair[0];
        let count = pair[1];
        entries.push(json!({
            "product_id": id >> 16,
            "build": id & 0xffff,
            "count": count,
        }));
    }
    Some(json!({
        "present": true,
        "key": hex(key),
        "entries": entries,
    }))
}

fn format_guid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn pe_debug(pe: &PE) -> Value {
    let Some(debug) = &pe.debug_data else {
        return Value::Null;
    };
    let pdb = debug
        .codeview_pdb70_debug_info
        .as_ref()
        .map(|info| {
            json!({
                "format": "PDB70",
                "guid": format_guid(&info.signature),
                "age": info.age,
                "path": String::from_utf8_lossy(info.filename)
                    .trim_end_matches('\0')
                    .to_string(),
            })
        })
        .or_else(|| {
            debug.codeview_pdb20_debug_info.as_ref().map(|info| {
                json!({
                    "format": "PDB20",
                    "signature": hex(info.signature),
                    "age": info.age,
                    "path": String::from_utf8_lossy(info.filename)
                        .trim_end_matches('\0')
                        .to_string(),
                })
            })
        });
    json!({
        "pdb": pdb,
        "vcfeature": debug.vcfeature_info.is_some(),
        "extended_dll_characteristics": debug.ex_dll_characteristics_info.is_some(),
        "reproducible_build": debug.repro_info.is_some(),
        "pogo": debug.pogo_info.is_some(),
    })
}

/// PE-specific directories and metadata.
pub fn pe_info_json(app: &mut App) -> OpResult<Value> {
    if format_of(app) != Some("PE") {
        return Err("not a PE file".to_string());
    }
    let buf = app.file_info.get_buffer();
    let pe = PE::parse(buf).map_err(|e| format!("PE parse error: {e}"))?;
    let opt = pe.header.optional_header.as_ref();

    let directories: Vec<Value> = opt
        .map(|o| {
            o.data_directories
                .data_directories
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| {
                    entry.as_ref().map(|(_, dd)| {
                        json!({
                            "index": index,
                            "name": DD_NAMES.get(index).copied().unwrap_or("unknown"),
                            "virtual_address": hex(dd.virtual_address),
                            "va": hex(pe.image_base + dd.virtual_address as u64),
                            "size": hex(dd.size),
                        })
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let tls = pe.tls_data.as_ref().map(|tls| {
        json!({
            "raw_data_start": hex(tls.image_tls_directory.start_address_of_raw_data),
            "raw_data_end": hex(tls.image_tls_directory.end_address_of_raw_data),
            "index_address": hex(tls.image_tls_directory.address_of_index),
            "callbacks_address": hex(tls.image_tls_directory.address_of_callbacks),
            "size_of_zero_fill": tls.image_tls_directory.size_of_zero_fill,
            "characteristics": hex(tls.image_tls_directory.characteristics),
            "slot": tls.slot,
            "callbacks": tls.callbacks.iter().map(|c| hex(*c)).collect::<Vec<_>>(),
            "raw_data_size": tls.raw_data.map(|d| d.len()),
        })
    });

    let load_config = pe.load_config_data.as_ref().map(|lc| {
        let d = &lc.directory;
        json!({
            "size": d.size,
            "security_cookie": d.security_cookie.map(hex),
            "se_handler_table": d.se_handler_table.map(hex),
            "se_handler_count": d.se_handler_count,
            "guard_flags": d.guard_flags.map(hex),
            "guard_cf_function_count": d.guard_cf_function_count,
            "guard_cf_check_function_pointer": d.guard_cf_check_function_pointer.map(hex),
        })
    });

    let certificates: Vec<Value> = pe
        .certificates
        .iter()
        .map(|cert| {
            json!({
                "length": cert.length,
                "revision": format!("{:?}", cert.revision),
                "type": format!("{:?}", cert.certificate_type),
                "bytes": cert.certificate.len(),
            })
        })
        .collect();

    let resources = pe.resource_data.as_ref().map(|r| {
        let dir = &r.image_resource_directory;
        json!({
            "named_entries": dir.number_of_named_entries,
            "id_entries": dir.number_of_id_entries,
            "has_version_info": r.version_info.is_some(),
            "has_manifest": r.manifest_data.is_some(),
        })
    });

    let clr = pe.clr_data.as_ref().map(|clr| {
        let h = &clr.cor20_header;
        json!({
            "runtime_version": format!("{}.{}", h.major_runtime_version, h.minor_runtime_version),
            "flags": hex(h.flags),
            "metadata_rva": hex(h.metadata.virtual_address),
            "metadata_size": hex(h.metadata.size),
            "entry_point_token_or_rva": hex(h.entry_point_token_or_rva),
            "strong_name_signature_size": hex(h.strong_name_signature.size),
        })
    });

    let headers_end = opt
        .map(|o| o.windows_fields.size_of_headers as usize)
        .unwrap_or(0);
    let sections_end = pe
        .sections
        .iter()
        .map(|s| s.pointer_to_raw_data as usize + s.size_of_raw_data as usize)
        .max()
        .unwrap_or(headers_end);
    let overlay_start = headers_end.max(sections_end);
    let overlay = if overlay_start < buf.len() {
        Some(json!({
            "offset": overlay_start,
            "size": buf.len() - overlay_start,
            "entropy": entropy(&buf[overlay_start..]),
        }))
    } else {
        None
    };

    let rich = parse_rich_header(buf, pe.header.dos_header.pe_pointer as usize);

    Ok(json!({
        "format": "PE",
        "is_64": pe.is_64,
        "is_dll": pe.is_lib,
        "machine": goblin::pe::header::machine_to_str(pe.header.coff_header.machine),
        "machine_id": hex(pe.header.coff_header.machine),
        "image_base": hex(pe.image_base),
        "entry_point_rva": hex(pe.entry),
        "entry_point_va": hex(pe.image_base + pe.entry as u64),
        "checksum": opt.map(|o| hex(o.windows_fields.check_sum)),
        "size_of_image": opt.map(|o| hex(o.windows_fields.size_of_image)),
        "subsystem": opt.map(|o| o.windows_fields.subsystem),
        "dll_characteristics": opt.map(|o| hex(o.windows_fields.dll_characteristics)),
        "data_directories": directories,
        "debug": pe_debug(&pe),
        "tls": tls,
        "exceptions": pe.exception_data.as_ref().map(|e| json!({
            "function_count": e.len(),
        })),
        "relocations": pe.relocation_data.as_ref().map(|r| json!({
            "block_count": r.blocks().count(),
        })),
        "load_config": load_config,
        "certificates": certificates,
        "resources": resources,
        "clr": clr,
        "rich_header": rich,
        "overlay": overlay,
    }))
}

// ---------------------------------------------------------------------------
// ELF details
// ---------------------------------------------------------------------------

/// ELF-specific metadata: dynamic tags, needed libraries and notes.
pub fn elf_info_json(app: &mut App) -> OpResult<Value> {
    if format_of(app) != Some("ELF") {
        return Err("not an ELF file".to_string());
    }
    let buf = app.file_info.get_buffer();
    let elf = Elf::parse(buf).map_err(|e| format!("ELF parse error: {e}"))?;

    let notes = collect_notes(&elf, buf);

    let dynamic = elf.dynamic.as_ref().map(|d| {
        let info = &d.info;
        let entries: Vec<Value> = d
            .dyns
            .iter()
            .take(MAX_DYNAMIC_ENTRIES)
            .map(|entry| {
                json!({
                    "tag": hex(entry.d_tag),
                    "value": hex(entry.d_val),
                })
            })
            .collect();
        json!({
            "soname": elf.soname,
            "needed": elf.libraries,
            "rpath": elf.rpaths,
            "runpath": elf.runpaths,
            "flags": hex(info.flags),
            "flags_1": hex(info.flags_1),
            "init": hex(info.init),
            "fini": hex(info.fini),
            "init_array": { "address": hex(info.init_array), "size": hex(info.init_arraysz as u64) },
            "fini_array": { "address": hex(info.fini_array), "size": hex(info.fini_arraysz as u64) },
            "rela": { "address": hex(info.rela as u64), "size": hex(info.relasz as u64), "count": info.relacount },
            "rel": { "address": hex(info.rel as u64), "size": hex(info.relsz as u64), "count": info.relcount },
            "pltgot": info.pltgot.map(hex),
            "textrel": info.textrel,
            "version_definitions": info.verdefnum,
            "version_requirements": info.verneednum,
            "entries": entries,
            "entries_truncated": d.dyns.len() > MAX_DYNAMIC_ENTRIES,
        })
    });

    let segments: Vec<Value> = elf
        .program_headers
        .iter()
        .enumerate()
        .map(|(index, ph)| elf_segment(ph, index))
        .collect();

    Ok(json!({
        "format": "ELF",
        "class": if elf.is_64 { "ELF64" } else { "ELF32" },
        "endianness": if elf.little_endian { "little" } else { "big" },
        "object_type": elf_object_type_name(elf.header.e_type),
        "machine": elf_machine_name(elf.header.e_machine),
        "machine_id": hex(elf.header.e_machine),
        "entry_point": hex(elf.entry),
        "interpreter": elf.interpreter,
        "soname": elf.soname,
        "needed": elf.libraries,
        "rpath": elf.rpaths,
        "runpath": elf.runpaths,
        "notes": notes,
        "dynamic": dynamic,
        "segments": segments,
    }))
}

fn note_value(name: &str, n_type: u32, type_name: &str, desc: &[u8]) -> Value {
    json!({
        "name": name,
        "type": n_type,
        "type_name": type_name,
        "description_hex": hex_dump(desc),
        "description_ascii": desc
            .iter()
            .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
            .collect::<String>(),
    })
}

fn collect_notes(elf: &Elf, buf: &[u8]) -> Vec<Value> {
    let mut notes = Vec::new();

    if let Some(iter) = elf.iter_note_headers(buf) {
        for note in iter.flatten() {
            notes.push(note_value(
                note.name,
                note.n_type,
                note.type_to_str(),
                note.desc,
            ));
        }
    }
    if notes.is_empty()
        && let Some(iter) = elf.iter_note_sections(buf, None)
    {
        for note in iter.flatten() {
            notes.push(note_value(
                note.name,
                note.n_type,
                note.type_to_str(),
                note.desc,
            ));
        }
    }
    notes
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn app_for_current_exe() -> App {
        let exe = std::env::current_exe().unwrap();
        let mut app = App::new();
        app.load_file(exe.to_str().unwrap(), 0, true).unwrap();
        app
    }

    #[test]
    fn elf_layout_and_translation() {
        let mut app = app_for_current_exe();
        assert_eq!(format_of(&app), Some("ELF"));
        let layout = layout_json(&mut app).unwrap();
        assert_eq!(layout["format"], "ELF");
        assert!(layout["sections"].as_array().unwrap().len() > 1);

        // Offset 0 is mapped by the first PT_LOAD of a normal ELF executable.
        let translated = offset_to_va(&mut app, 0).unwrap();
        assert_eq!(translated.file_offset, 0);
        let back = va_to_offset(&mut app, translated.va, "va").unwrap();
        assert_eq!(back.file_offset, 0);
    }

    #[test]
    fn elf_symbols_are_filterable() {
        let mut app = app_for_current_exe();
        let filter = SymbolFilter {
            name_regex: Some("main"),
            kind: "function",
            dynamic_only: false,
            global_only: false,
            max: 50,
        };
        let symbols = symbols_json(&mut app, &filter).unwrap();
        assert_eq!(symbols["format"], "ELF");
        assert!(symbols["symbols"].is_array());
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[0u8; 1024]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }
}
