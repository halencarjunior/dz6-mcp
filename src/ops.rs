//! High-level operations on top of a dz6 [`App`].
//!
//! These functions are deliberately free of any TUI state. They only touch the
//! file mapping, the in-memory edit buffer and the annotation structures, so
//! they can be driven by the MCP server without a terminal.

use std::borrow::Cow;
use std::io::{Seek, SeekFrom, Write};

use dz6::app::App;
use dz6::hex::blocks::ColoredBlock;
use dz6::hex::comment::Comment;
use regex::bytes::{Regex, RegexBuilder};
use serde::Serialize;
use serde_json::{Value, json};

/// A single erroneous condition that the caller should see.
pub type OpResult<T> = Result<T, String>;

fn is_read_only(app: &App) -> bool {
    app.file_info.is_read_only || app.file_info.file.is_none()
}

/// Read `len` bytes starting at `offset`, applying any pending (unsaved) edits.
pub fn effective_range(app: &mut App, offset: usize, len: usize) -> Vec<u8> {
    let size = app.file_info.size;
    if len == 0 || offset >= size {
        return Vec::new();
    }
    let end = offset.saturating_add(len).min(size);
    let mut out = app.file_info.get_buffer()[offset..end].to_vec();
    for (i, b) in out.iter_mut().enumerate() {
        if let Some(s) = app.hex_view.changed_bytes.get(&(offset + i))
            && let Ok(v) = u8::from_str_radix(s, 16)
        {
            *b = v;
        }
    }
    out
}

/// Pending, not-yet-written byte edits.
pub fn pending_changes(app: &App) -> usize {
    app.hex_view.changed_bytes.len()
}

pub fn read_int(
    app: &mut App,
    offset: usize,
    size: usize,
    signed: bool,
    big_endian: bool,
) -> Option<i128> {
    let bytes = effective_range(app, offset, size);
    if bytes.len() != size {
        return None;
    }
    let mut buf = [0u8; 8];
    buf[..size].copy_from_slice(&bytes);
    if big_endian {
        buf[..size].reverse();
    }
    let raw = u64::from_le_bytes(buf);
    let value = if signed {
        match size {
            1 => raw as u8 as i8 as i128,
            2 => raw as u16 as i16 as i128,
            4 => raw as u32 as i32 as i128,
            8 => raw as i64 as i128,
            _ => return None,
        }
    } else {
        raw as i128
    };
    Some(value)
}

pub fn read_string(
    app: &mut App,
    offset: usize,
    encoding: &str,
    max_length: usize,
    stop_at_nul: bool,
) -> OpResult<(String, usize)> {
    let encoding = encoding.to_ascii_lowercase();
    match encoding.as_str() {
        "utf8" | "utf-8" | "ascii" => {
            let bytes = effective_range(app, offset, max_length);
            let cut = if stop_at_nul {
                bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())
            } else {
                bytes.len()
            };
            Ok((String::from_utf8_lossy(&bytes[..cut]).into_owned(), cut))
        }
        "latin1" | "latin-1" | "iso-8859-1" => {
            let bytes = effective_range(app, offset, max_length);
            let cut = if stop_at_nul {
                bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())
            } else {
                bytes.len()
            };
            Ok((bytes[..cut].iter().map(|&b| b as char).collect(), cut))
        }
        "utf16le" | "utf-16le" | "utf16" => read_utf16(app, offset, max_length, stop_at_nul, false),
        "utf16be" | "utf-16be" => read_utf16(app, offset, max_length, stop_at_nul, true),
        other => Err(format!("unsupported encoding: {other}")),
    }
}

fn read_utf16(
    app: &mut App,
    offset: usize,
    max_length: usize,
    stop_at_nul: bool,
    big_endian: bool,
) -> OpResult<(String, usize)> {
    let bytes = effective_range(app, offset, max_length.saturating_mul(2));
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut consumed = 0usize;
    for chunk in bytes.as_chunks::<2>().0 {
        let unit = if big_endian {
            u16::from_be_bytes(*chunk)
        } else {
            u16::from_le_bytes(*chunk)
        };
        consumed += 2;
        if stop_at_nul && unit == 0 {
            break;
        }
        units.push(unit);
    }
    Ok((String::from_utf16_lossy(&units), consumed))
}

/// Case/format helper for byte dumps.
pub fn hex_dump(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn ascii_dump(bytes: &[u8], non_graphic: char) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                non_graphic
            }
        })
        .collect()
}

/// The parameters of a search request, independent of position and direction
/// iteration state.
pub struct SearchQuery<'a> {
    pub needle: &'a str,
    pub mode: &'a str,
    pub direction: &'a str,
    pub ignore_case: bool,
    pub smart_case: bool,
}

/// A compiled needle: either a literal byte sequence or a byte regex.
enum Matcher {
    Bytes(Vec<u8>),
    Regex(Regex),
}

impl Matcher {
    /// First match starting at or after `from`.
    fn find(&self, buf: &[u8], from: usize) -> Option<usize> {
        if from > buf.len() {
            return None;
        }
        let hay = &buf[from..];
        match self {
            Matcher::Bytes(needle) => memchr::memmem::find(hay, needle).map(|p| p + from),
            Matcher::Regex(re) => re.find(hay).map(|m| m.start() + from),
        }
    }

    /// Last match whose start is at or before `upto`.
    fn rfind(&self, buf: &[u8], upto: usize) -> Option<usize> {
        if buf.is_empty() {
            return None;
        }
        let upto = upto.min(buf.len() - 1);
        match self {
            Matcher::Bytes(needle) => {
                let end = upto.saturating_add(needle.len()).min(buf.len());
                memchr::memmem::rfind(&buf[..end], needle)
            }
            Matcher::Regex(re) => re
                .find_iter(buf)
                .filter(|m| m.start() <= upto)
                .last()
                .map(|m| m.start()),
        }
    }
}

fn is_hex_mode(mode: &str) -> bool {
    mode.eq_ignore_ascii_case("hex") || mode.eq_ignore_ascii_case("pattern")
}

fn is_backward(direction: &str) -> bool {
    matches!(
        direction.to_ascii_lowercase().as_str(),
        "backward" | "back" | "reverse" | "prev"
    )
}

/// Port of dz6's `translate_pattern`: turns `4D5A??[00-ff]` into a byte regex.
fn translate_pattern(pattern: &str) -> Option<String> {
    let mut t = String::new();
    let ptn = pattern.replace(' ', "");

    if !ptn
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '?')
        .count()
        .is_multiple_of(2)
    {
        return None;
    }

    let mut next_is_first = true;
    for c in ptn.chars() {
        if c.is_ascii_hexdigit() {
            if next_is_first {
                t.push_str("\\x");
                next_is_first = false;
            } else {
                next_is_first = true;
            }
            t.push(c);
        } else if c == '?' {
            if next_is_first {
                t.push('.');
                next_is_first = false;
            } else {
                next_is_first = true;
            }
        } else if ['[', ']', '-'].contains(&c) {
            t.push(c);
            next_is_first = true;
        }
    }

    t.insert_str(0, "(?s-u)");
    Some(t)
}

fn build_matcher(
    needle: &str,
    mode: &str,
    ignore_case: bool,
    smart_case: bool,
) -> OpResult<Matcher> {
    if needle.is_empty() {
        return Err("needle must not be empty".into());
    }

    if is_hex_mode(mode) {
        if needle.contains(|c| ['?', '[', ']'].contains(&c)) {
            let ptn = translate_pattern(needle).ok_or_else(|| {
                "invalid hex pattern: expected an even number of hex digits and ? wildcards"
                    .to_string()
            })?;
            let re = RegexBuilder::new(&ptn)
                .build()
                .map_err(|e| format!("invalid pattern: {e}"))?;
            Ok(Matcher::Regex(re))
        } else {
            let cleaned: String = needle.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = hex::decode(&cleaned).map_err(|e| format!("invalid hex needle: {e}"))?;
            Ok(Matcher::Bytes(bytes))
        }
    } else {
        let has_upper = needle.bytes().any(|b| b.is_ascii_uppercase());
        let case_insensitive = ignore_case && !(smart_case && has_upper);
        if case_insensitive {
            let re = RegexBuilder::new(&regex::escape(needle))
                .case_insensitive(true)
                .unicode(false)
                .build()
                .map_err(|e| format!("invalid text needle: {e}"))?;
            Ok(Matcher::Regex(re))
        } else {
            Ok(Matcher::Bytes(needle.as_bytes().to_vec()))
        }
    }
}

/// The bytes a search runs against: the mmap, or an overlay when edits exist.
pub(crate) fn search_buffer(app: &mut App) -> Cow<'_, [u8]> {
    if app.hex_view.changed_bytes.is_empty() {
        return Cow::Borrowed(app.file_info.get_buffer());
    }
    const MAX_OVERLAY: usize = 1 << 30; // 1 GiB safety valve
    if app.file_info.size > MAX_OVERLAY {
        tracing::warn!(
            size = app.file_info.size,
            "file too large to overlay pending edits for search; searching on-disk bytes"
        );
        return Cow::Borrowed(app.file_info.get_buffer());
    }
    let mut out = app.file_info.get_buffer().to_vec();
    for (&ofs, value) in &app.hex_view.changed_bytes {
        if let Some(slot) = out.get_mut(ofs)
            && let Ok(v) = u8::from_str_radix(value, 16)
        {
            *slot = v;
        }
    }
    Cow::Owned(out)
}

/// Search once.
///
/// `offset` is the starting byte for forward searches, and the inclusive upper
/// bound for backward searches (so the last byte of the file can be found).
/// `next` skips the current position.
pub fn search_once(
    app: &mut App,
    query: &SearchQuery,
    offset: usize,
    next: bool,
    wrapscan: bool,
) -> Option<usize> {
    let size = app.file_info.size;
    if size == 0 || query.needle.is_empty() {
        return None;
    }
    let matcher = build_matcher(
        query.needle,
        query.mode,
        query.ignore_case,
        query.smart_case,
    )
    .ok()?;
    let buf = search_buffer(app);

    if is_backward(query.direction) {
        let upto = if next {
            offset.saturating_sub(1)
        } else {
            offset.min(size - 1)
        };
        if let Some(found) = matcher.rfind(&buf, upto) {
            return Some(found);
        }
        if wrapscan {
            return matcher.rfind(&buf, size - 1);
        }
    } else {
        let from = if next {
            offset.saturating_add(1)
        } else {
            offset
        };
        if let Some(found) = matcher.find(&buf, from) {
            return Some(found);
        }
        if wrapscan {
            return matcher.find(&buf, 0);
        }
    }
    None
}

/// Search repeatedly, globally. Returns up to `max` absolute offsets.
pub fn search_all(app: &mut App, query: &SearchQuery, start: usize, max: usize) -> Vec<usize> {
    let mut results = Vec::new();
    let size = app.file_info.size;
    if max == 0 || size == 0 || query.needle.is_empty() {
        return results;
    }

    let backward = is_backward(query.direction);
    let mut cursor = start.min(size - 1);

    while results.len() < max {
        let Some(ofs) = search_once(app, query, cursor, false, false) else {
            break;
        };
        results.push(ofs);
        if backward {
            if ofs == 0 {
                break;
            }
            cursor = ofs - 1;
        } else {
            cursor = ofs + 1;
            if cursor >= size {
                break;
            }
        }
    }

    results
}

/// Stage a byte patch in the in-memory buffer. Nothing is written to disk.
pub fn write_bytes(app: &mut App, offset: usize, bytes: &[u8]) -> OpResult<usize> {
    if is_read_only(app) {
        return Err("file is read-only; reopen it with readonly=false to edit".into());
    }
    let size = app.file_info.size;
    if bytes.is_empty() {
        return Err("no bytes to write".into());
    }
    if offset.checked_add(bytes.len()).is_none_or(|end| end > size) {
        return Err(format!(
            "write out of range: offset {offset:#x} + {} bytes exceeds file size {size:#x}",
            bytes.len()
        ));
    }
    for (i, b) in bytes.iter().enumerate() {
        let ofs = offset + i;
        app.hex_view.changed_bytes.insert(ofs, format!("{b:02X}"));
        app.hex_view.changed_history.push(ofs);
    }
    Ok(bytes.len())
}

pub fn fill_range(app: &mut App, offset: usize, length: usize, value: u8) -> OpResult<usize> {
    if is_read_only(app) {
        return Err("file is read-only; reopen it with readonly=false to edit".into());
    }
    if length == 0 {
        return Err("length must be greater than zero".into());
    }
    if offset
        .checked_add(length)
        .is_none_or(|end| end > app.file_info.size)
    {
        return Err("fill range exceeds file size".into());
    }
    for ofs in offset..offset + length {
        app.hex_view
            .changed_bytes
            .insert(ofs, format!("{value:02X}"));
        app.hex_view.changed_history.push(ofs);
    }
    Ok(length)
}

/// Undo up to `steps` staged edits. Returns how many were actually undone.
pub fn undo(app: &mut App, steps: usize) -> usize {
    let mut undone = 0;
    for _ in 0..steps {
        match app.hex_view.changed_history.pop() {
            Some(ofs) => {
                app.hex_view.changed_bytes.remove(&ofs);
                undone += 1;
            }
            None => break,
        }
    }
    undone
}

/// Flush staged edits to disk, and persist the annotation database.
pub fn save(app: &mut App) -> OpResult<(usize, bool)> {
    if app.file_info.file.is_none() {
        return Err("file is not open for writing".into());
    }
    let staged = app.hex_view.changed_bytes.len();
    app.write_to_file()
        .map_err(|e| format!("could not write file: {e}"))?;
    let db_saved = if app.config.database {
        app.save_database().is_ok()
    } else {
        false
    };
    Ok((staged, db_saved))
}

/// `mode = "after"` keeps bytes up to and including `offset` (dz6's `t`).
/// `mode = "before"` drops everything before `offset` (dz6's `T`).
pub fn truncate(app: &mut App, offset: usize, mode: &str) -> OpResult<usize> {
    if app.file_info.file.is_none() {
        return Err("file is read-only; truncation requires write access".into());
    }
    if !app.hex_view.changed_bytes.is_empty() {
        return Err("unsaved changes exist; save or undo them before truncating".into());
    }
    let size = app.file_info.size;

    match mode.to_ascii_lowercase().as_str() {
        "after" | "keep_before" | "t" => {
            if offset >= size {
                return Err(format!("offset {offset:#x} is past the end of file"));
            }
            let new_len = (offset + 1) as u64;
            app.file_info
                .file
                .as_ref()
                .unwrap()
                .set_len(new_len)
                .map_err(|e| format!("truncate failed: {e}"))?;
        }
        "before" | "keep_after" | "reverse" | "T" => {
            if offset == 0 {
                return Ok(size);
            }
            if offset > size {
                return Err(format!("offset {offset:#x} is past the end of file"));
            }
            let tail = app.file_info.get_buffer()[offset..size].to_vec();
            let file = app.file_info.file.as_mut().unwrap();
            file.seek(SeekFrom::Start(0))
                .map_err(|e| format!("seek failed: {e}"))?;
            file.write_all(&tail)
                .map_err(|e| format!("write failed: {e}"))?;
            file.set_len(tail.len() as u64)
                .map_err(|e| format!("truncate failed: {e}"))?;
        }
        other => return Err(format!("invalid truncate mode: {other}")),
    }

    app.hex_view.changed_bytes.clear();
    app.hex_view.changed_history.clear();
    app.reload_file();
    Ok(app.file_info.size)
}

/// Add, replace or (with an empty string) remove a comment.
pub fn set_comment(app: &mut App, offset: usize, comment: &str) {
    app.hex_view
        .comment_name_list
        .retain(|c| c.offset != offset);
    if comment.is_empty() {
        app.hex_view.comments.remove(&offset);
    } else {
        app.hex_view.comments.insert(offset, comment.to_string());
        app.hex_view
            .comment_name_list
            .push(Comment::new(offset, comment.to_string()));
        app.hex_view.comment_name_list.sort_by_key(|c| c.offset);
    }
}

pub fn block_add(
    app: &mut App,
    start: usize,
    end: usize,
    bg_color: Option<u32>,
    fg_color: Option<u32>,
) -> OpResult<()> {
    if start > end {
        return Err("block start must be <= end".into());
    }
    if end >= app.file_info.size {
        return Err(format!(
            "block end {end:#x} is past the end of file ({:#x})",
            app.file_info.size
        ));
    }
    let mut block = ColoredBlock::new(start, end);
    if let Some(bg) = bg_color {
        block.bg_color = bg;
    }
    if let Some(fg) = fg_color {
        block.fg_color = fg;
    }
    app.hex_view.blocks.push(block);
    app.hex_view.blocks.sort_by_key(|b| b.start);
    Ok(())
}

/// Extract a range to a file on disk (equivalent to dz6's `:dump`).
pub fn dump_to(app: &mut App, out_path: &str, offset: usize, length: usize) -> OpResult<usize> {
    if length == 0 {
        return Err("length must be greater than zero".into());
    }
    let bytes = effective_range(app, offset, length);
    if bytes.is_empty() {
        return Err(format!("nothing to dump at offset {offset:#x}"));
    }
    std::fs::write(out_path, &bytes).map_err(|e| format!("could not write {out_path}: {e}"))?;
    Ok(bytes.len())
}

#[derive(Serialize)]
pub struct ByteStats {
    pub offset: usize,
    pub length: usize,
    pub entropy: f64,
    pub printable_ratio: f64,
    pub unique_bytes: usize,
}

pub fn analyze(app: &mut App, offset: usize, length: usize) -> ByteStats {
    let bytes = effective_range(app, offset, length);
    let mut counts = [0u64; 256];
    for &b in &bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len().max(1) as f64;
    let entropy = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum();
    let printable = bytes
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b))
        .count();
    ByteStats {
        offset,
        length: bytes.len(),
        entropy,
        printable_ratio: printable as f64 / total,
        unique_bytes: counts.iter().filter(|&&c| c > 0).count(),
    }
}

fn cstr_at(buf: &[u8], start: usize) -> String {
    if start >= buf.len() {
        return String::new();
    }
    let end = buf[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[start..end]).into_owned()
}

pub fn headers_json(app: &mut App) -> Value {
    if app.header_view.pe.is_some() {
        return pe_json(app, "PE");
    }
    if app.header_view.elf.is_some() {
        return elf_json(app, "ELF");
    }
    json!({
        "format": if app.file_info.r#type.is_empty() { "raw" } else { app.file_info.r#type },
        "parsed": false,
        "message": "no PE or ELF headers were recognized in this file",
    })
}

fn pe_json(app: &mut App, format: &str) -> Value {
    // PE header view data lives in `header_view`; clone the small pieces we
    // need so the borrow does not overlap with the file buffer.
    let pe = app.header_view.pe.as_ref().unwrap();
    let dos = &pe.dos_header;
    let coff = &pe.coff_header;

    let optional = pe.optional_header.as_ref().map(|opt| {
        let dd: Vec<Value> = opt
            .data_directories
            .data_directories
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                e.map(|(_, d)| {
                    json!({
                        "index": i,
                        "virtual_address": format!("{:#x}", d.virtual_address),
                        "size": format!("{:#x}", d.size),
                    })
                })
            })
            .collect();
        json!({
            "magic": format!("{:#x}", opt.standard_fields.magic),
            "major_linker_version": opt.standard_fields.major_linker_version,
            "minor_linker_version": opt.standard_fields.minor_linker_version,
            "size_of_code": opt.standard_fields.size_of_code,
            "size_of_initialized_data": opt.standard_fields.size_of_initialized_data,
            "size_of_uninitialized_data": opt.standard_fields.size_of_uninitialized_data,
            "address_of_entry_point": format!("{:#x}", opt.standard_fields.address_of_entry_point),
            "base_of_code": format!("{:#x}", opt.standard_fields.base_of_code),
            "image_base": format!("{:#x}", opt.windows_fields.image_base),
            "section_alignment": opt.windows_fields.section_alignment,
            "file_alignment": opt.windows_fields.file_alignment,
            "size_of_image": format!("{:#x}", opt.windows_fields.size_of_image),
            "size_of_headers": format!("{:#x}", opt.windows_fields.size_of_headers),
            "subsystem": opt.windows_fields.subsystem,
            "dll_characteristics": format!("{:#x}", opt.windows_fields.dll_characteristics),
            "number_of_rva_and_sizes": opt.windows_fields.number_of_rva_and_sizes,
            "data_directories": dd,
        })
    });

    let sections: Vec<Value> = pe
        .sections
        .iter()
        .map(|s| {
            json!({
                "name": s.name().unwrap_or(""),
                "virtual_address": format!("{:#x}", s.virtual_address),
                "virtual_size": format!("{:#x}", s.virtual_size),
                "pointer_to_raw_data": format!("{:#x}", s.pointer_to_raw_data),
                "size_of_raw_data": format!("{:#x}", s.size_of_raw_data),
                "characteristics": format!("{:#x}", s.characteristics),
            })
        })
        .collect();

    let imports: Vec<Value> = pe
        .imports
        .iter()
        .map(|i| {
            json!({
                "dll": i.dll,
                "name": i.name,
                "offset": format!("{:#x}", i.offset),
                "rva": format!("{:#x}", i.rva),
                "ordinal": i.ordinal,
            })
        })
        .collect();

    let exports: Vec<Value> = pe
        .exports
        .iter()
        .map(|e| {
            json!({
                "name": e.name,
                "offset": format!("{:#x}", e.offset),
                "rva": format!("{:#x}", e.rva),
                "size": e.size,
            })
        })
        .collect();

    json!({
        "format": format,
        "parsed": true,
        "dos_header": {
            "signature": format!("{:#x}", dos.signature),
            "pages_in_file": dos.pages_in_file,
            "relocations": dos.relocations,
            "checksum": dos.checksum,
            "initial_ip": dos.initial_ip,
            "initial_sp": dos.initial_sp,
            "oem_id": dos.oem_id,
            "pe_pointer": format!("{:#x}", dos.pe_pointer),
        },
        "coff_header": {
            "machine": format!("{:#x}", coff.machine),
            "number_of_sections": coff.number_of_sections,
            "time_date_stamp": coff.time_date_stamp,
            "pointer_to_symbol_table": format!("{:#x}", coff.pointer_to_symbol_table),
            "number_of_symbol_table": coff.number_of_symbol_table,
            "size_of_optional_header": coff.size_of_optional_header,
            "characteristics": format!("{:#x}", coff.characteristics),
        },
        "optional_header": optional,
        "sections": sections,
        "imports": imports,
        "exports": exports,
    })
}

fn elf_json(app: &mut App, format: &str) -> Value {
    // Copy the section-name string table first so we can borrow `elf` afterwards.
    let (shstr_off, shstr_size) = {
        let elf = app.header_view.elf.as_ref().unwrap();
        match elf.sections.get(elf.header.e_shstrndx as usize) {
            Some(st) => (st.sh_offset as usize, st.sh_size as usize),
            None => (0, 0),
        }
    };
    let shstrtab = if shstr_size > 0 {
        effective_range(app, shstr_off, shstr_size)
    } else {
        Vec::new()
    };

    let elf = app.header_view.elf.as_ref().unwrap();
    let h = &elf.header;

    let program_headers: Vec<Value> = elf
        .phdrs
        .iter()
        .map(|p| {
            json!({
                "type": format!("{:#x}", p.p_type),
                "offset": format!("{:#x}", p.p_offset),
                "vaddr": format!("{:#x}", p.p_vaddr),
                "paddr": format!("{:#x}", p.p_paddr),
                "filesz": format!("{:#x}", p.p_filesz),
                "memsz": format!("{:#x}", p.p_memsz),
                "flags": format!("{:#x}", p.p_flags),
                "align": format!("{:#x}", p.p_align),
            })
        })
        .collect();

    let sections: Vec<Value> = elf
        .sections
        .iter()
        .map(|s| {
            let name = cstr_at(&shstrtab, s.sh_name);
            json!({
                "name": name,
                "type": format!("{:#x}", s.sh_type),
                "flags": format!("{:#x}", s.sh_flags),
                "addr": format!("{:#x}", s.sh_addr),
                "offset": format!("{:#x}", s.sh_offset),
                "size": format!("{:#x}", s.sh_size),
                "link": s.sh_link,
                "info": s.sh_info,
                "addralign": s.sh_addralign,
                "entsize": s.sh_entsize,
            })
        })
        .collect();

    let symbol = |name: &str, st_value: u64, st_size: u64, st_info: u8, st_shndx: usize| {
        json!({
            "name": name,
            "value": format!("{st_value:#x}"),
            "size": st_size,
            "info": format!("{st_info:#x}"),
            "shndx": st_shndx,
        })
    };

    let symbols: Vec<Value> = elf
        .symtab
        .iter()
        .map(|s| {
            let name = elf.strtab.get(&s.st_name).cloned().unwrap_or_default();
            symbol(&name, s.st_value, s.st_size, s.st_info, s.st_shndx)
        })
        .collect();

    let dynamic_symbols: Vec<Value> = elf
        .dynsymtab
        .iter()
        .map(|s| {
            let name = elf.dynstrtab.get(&s.st_name).cloned().unwrap_or_default();
            symbol(&name, s.st_value, s.st_size, s.st_info, s.st_shndx)
        })
        .collect();

    let relocations: Vec<Value> = elf
        .relocs
        .iter()
        .map(|r| {
            json!({
                "offset": format!("{:#x}", r.r_offset),
                "type": format!("{:#x}", r.r_type),
                "sym": r.r_sym,
                "addend": r.r_addend,
            })
        })
        .collect();

    json!({
        "format": format,
        "parsed": true,
        "class": match h.e_ident[4] { 1 => "ELF32", 2 => "ELF64", _ => "unknown" },
        "endianness": match h.e_ident[5] { 1 => "little", 2 => "big", _ => "unknown" },
        "header": {
            "type": format!("{:#x}", h.e_type),
            "machine": format!("{:#x}", h.e_machine),
            "version": h.e_version,
            "entry": format!("{:#x}", h.e_entry),
            "phoff": format!("{:#x}", h.e_phoff),
            "shoff": format!("{:#x}", h.e_shoff),
            "flags": format!("{:#x}", h.e_flags),
            "ehsize": h.e_ehsize,
            "phentsize": h.e_phentsize,
            "phnum": h.e_phnum,
            "shentsize": h.e_shentsize,
            "shnum": h.e_shnum,
            "shstrndx": h.e_shstrndx,
        },
        "program_headers": program_headers,
        "sections": sections,
        "symbols": symbols,
        "dynamic_symbols": dynamic_symbols,
        "relocations": relocations,
    })
}

/// Collect dz6 strings from the in-memory cache after `load_strings` ran.
pub fn strings_json(app: &App, offset_filter: Option<(usize, usize)>) -> Value {
    let mut items = Vec::new();
    for s in &app.strings {
        if let Some((start, end)) = offset_filter
            && (s.offset < start || s.offset >= end)
        {
            continue;
        }
        items.push(json!({
            "offset": s.offset,
            "size": s.size,
            "content": s.content,
        }));
    }
    json!({
        "count": items.len(),
        "strings": items,
        "minimum_length": app.config.minimum_string_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_with(bytes: &[u8]) -> (tempfile::TempDir, App) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.bin");
        std::fs::write(&path, bytes).unwrap();
        let mut app = App::new();
        app.load_file(path.to_str().unwrap(), 0, false).unwrap();
        (dir, app)
    }

    fn query<'a>(needle: &'a str, mode: &'a str, direction: &'a str) -> SearchQuery<'a> {
        SearchQuery {
            needle,
            mode,
            direction,
            ignore_case: false,
            smart_case: false,
        }
    }

    #[test]
    fn pattern_translation_matches_dz6() {
        assert_eq!(
            translate_pattern("FEC01F803F??07"),
            Some(r"(?s-u)\xFE\xC0\x1F\x80\x3F.\x07".to_string())
        );
        assert_eq!(
            translate_pattern("FEC01F803F[00-ff]07"),
            Some(r"(?s-u)\xFE\xC0\x1F\x80\x3F[\x00-\xff]\x07".to_string())
        );
        assert_eq!(translate_pattern("4D5"), None);
    }

    #[test]
    fn ints_respect_endianness_and_signedness() {
        let (_dir, mut app) = app_with(&[0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(read_int(&mut app, 0, 4, false, false), Some(0x0302_0100));
        assert_eq!(read_int(&mut app, 0, 4, false, true), Some(0x0001_0203));
        assert_eq!(read_int(&mut app, 4, 4, true, false), Some(-1));
        assert_eq!(
            read_int(&mut app, 0, 8, false, false),
            Some(0xffff_ffff_0302_0100)
        );
    }

    #[test]
    fn search_forward_backward_and_all() {
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let (_dir, mut app) = app_with(&data);

        assert_eq!(
            search_once(
                &mut app,
                &query("414243", "hex", "forward"),
                0,
                false,
                false
            ),
            Some(0x41)
        );
        assert_eq!(
            search_once(
                &mut app,
                &query("ff", "hex", "backward"),
                1023,
                false,
                false
            ),
            Some(0x3ff)
        );
        assert_eq!(
            search_all(&mut app, &query("414243", "hex", "forward"), 0, 10),
            vec![0x41, 0x141, 0x241, 0x341]
        );
        // backward iteration visits the same offsets in reverse
        assert_eq!(
            search_all(&mut app, &query("ff", "hex", "backward"), 1023, 3),
            vec![0x3ff, 0x2ff, 0x1ff]
        );
        // wrapscan forward from past the last 0x00 finds the one at offset 0
        assert_eq!(
            search_once(&mut app, &query("00", "hex", "forward"), 769, false, true),
            Some(0)
        );
    }

    #[test]
    fn search_text_ignorecase_and_smartcase() {
        let (_dir, mut app) = app_with(b"Hello hello HELLO");
        let insensitive = SearchQuery {
            needle: "hello",
            mode: "text",
            direction: "forward",
            ignore_case: true,
            smart_case: false,
        };
        assert_eq!(
            search_once(&mut app, &insensitive, 0, false, false),
            Some(0)
        );

        // With smartcase on, an uppercase needle becomes case-sensitive.
        let smart = SearchQuery {
            needle: "HELLO",
            mode: "text",
            direction: "forward",
            ignore_case: true,
            smart_case: true,
        };
        assert_eq!(search_once(&mut app, &smart, 0, false, false), Some(12));
    }

    #[test]
    fn wildcard_pattern_matches() {
        let (_dir, mut app) = app_with(&[0x00, 0xFE, 0xC0, 0x1F, 0x80, 0x3F, 0xAA, 0x07, 0x00]);
        assert_eq!(
            search_once(
                &mut app,
                &query("FEC01F803F??07", "hex", "forward"),
                0,
                false,
                false
            ),
            Some(1)
        );
    }

    #[test]
    fn edits_overlay_reads_and_undo() {
        let (_dir, mut app) = app_with(&[0, 1, 2, 3, 4, 5, 6, 7]);
        write_bytes(&mut app, 2, &[0xAA, 0xBB]).unwrap();
        assert_eq!(effective_range(&mut app, 0, 4), vec![0, 1, 0xAA, 0xBB]);
        assert_eq!(read_int(&mut app, 2, 2, false, false), Some(0xBBAA));
        // search must see pending edits too
        assert_eq!(
            search_once(&mut app, &query("aabb", "hex", "forward"), 0, false, false),
            Some(2)
        );
        assert_eq!(undo(&mut app, 2), 2);
        assert_eq!(effective_range(&mut app, 0, 4), vec![0, 1, 2, 3]);
    }

    #[test]
    fn comments_and_blocks() {
        let (_dir, mut app) = app_with(&[0u8; 16]);
        set_comment(&mut app, 4, "hi");
        assert_eq!(
            app.hex_view.comments.get(&4).map(String::as_str),
            Some("hi")
        );
        set_comment(&mut app, 4, "");
        assert!(app.hex_view.comments.is_empty());

        assert!(block_add(&mut app, 0, 15, Some(0x112233), None).is_ok());
        assert!(block_add(&mut app, 0, 99, None, None).is_err());
    }

    #[test]
    fn invalid_edit_ranges_leave_file_unchanged() {
        let (_dir, mut app) = app_with(&[0, 1, 2, 3]);
        assert!(fill_range(&mut app, 0, usize::MAX, 0).is_err());
        assert!(fill_range(&mut app, usize::MAX, 2, 0).is_err());
        assert!(fill_range(&mut app, 0, 0, 0).is_err());
        assert!(truncate(&mut app, usize::MAX, "after").is_err());
        assert!(truncate(&mut app, 4, "after").is_err());
        assert_eq!(app.file_info.size, 4);
        assert_eq!(pending_changes(&app), 0);
        assert_eq!(effective_range(&mut app, 0, 4), vec![0, 1, 2, 3]);
        assert_eq!(fill_range(&mut app, 1, 2, 0xaa).unwrap(), 2);
        assert_eq!(effective_range(&mut app, 0, 4), vec![0, 0xaa, 0xaa, 3]);
    }

    #[test]
    fn truncate_after_and_before() {
        let (_dir, mut app) = app_with(&(0..32u8).collect::<Vec<u8>>());
        assert_eq!(truncate(&mut app, 15, "after").unwrap(), 16);
        assert_eq!(app.file_info.size, 16);
        assert_eq!(truncate(&mut app, 8, "before").unwrap(), 8);
        assert_eq!(
            effective_range(&mut app, 0, 8),
            (8..16).collect::<Vec<u8>>()
        );
    }
}
