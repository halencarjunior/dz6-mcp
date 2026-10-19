//! Advanced byte-pattern (signature) engine.
//!
//! This is a superset of dz6's hex search syntax. A pattern is compiled once and
//! can then be scanned over a byte range. Supported syntax (hex mode):
//!
//! | Syntax          | Meaning                                                        |
//! | --------------- | -------------------------------------------------------------- |
//! | `4865` / `48 65`| literal bytes (spaces are ignored)                             |
//! | `??`            | any single byte                                                |
//! | `A?`            | high nibble fixed (`0xA0..=0xAF`)                              |
//! | `?A`            | low nibble fixed (`0x0A, 0x1A, …, 0xFA`)                       |
//! | `[00-ff]`       | inclusive byte range (a single byte such as `[41]` also works) |
//! | `{n}`           | gap of exactly `n` arbitrary bytes                             |
//! | `{n-m}`         | gap of `n..=m` arbitrary bytes                                 |
//! | `(AA|BB 43)`    | alternation of byte sequences                                  |
//! | `VALUE:MASK`    | masked match over the whole pattern (`4D5A0000:FFFF0000`)      |
//!
//! Text patterns are always matched literally, optionally case-insensitively.
//!
//! Advanced constructs are compiled to a byte regex, so matches produced by them
//! are non-overlapping. Plain hex and text patterns are scanned with `memchr`
//! and do report overlapping matches.

use regex::bytes::{Regex, RegexBuilder};

/// Upper bound for `{n-m}` gaps, to keep the compiled regex bounded.
const MAX_GAP: usize = 65_536;

/// A compiled needle.
enum Kind {
    Literal(Vec<u8>),
    Regex(Regex),
}

/// A compiled pattern ready to be scanned.
pub struct Compiled {
    /// Optional caller-supplied label.
    pub name: Option<String>,
    /// The pattern as written by the caller.
    pub source: String,
    /// Normalized mode: `"hex"` or `"text"`.
    pub mode: &'static str,
    kind: Kind,
}

/// One match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// Index into the compiled pattern list.
    pub pattern: usize,
    /// Absolute offset of the match.
    pub offset: usize,
    /// Match length in bytes.
    pub length: usize,
}

/// True when a hex pattern uses any advanced construct.
fn is_special(pattern: &str) -> bool {
    pattern
        .chars()
        .any(|c| matches!(c, '?' | '[' | ']' | '{' | '}' | '(' | ')' | '|' | ':'))
}

/// Compile a single pattern.
pub fn compile(
    name: Option<String>,
    pattern: &str,
    mode: &str,
    ignore_case: bool,
) -> Result<Compiled, String> {
    let src = pattern.trim();
    if src.is_empty() {
        return Err("pattern must not be empty".to_string());
    }

    let normalized = if mode.eq_ignore_ascii_case("text") {
        "text"
    } else if mode.eq_ignore_ascii_case("hex") || mode.eq_ignore_ascii_case("pattern") {
        "hex"
    } else {
        return Err(format!("unsupported pattern mode: {mode}"));
    };

    let kind = if normalized == "text" {
        if ignore_case {
            let re = RegexBuilder::new(&regex::escape(src))
                .case_insensitive(true)
                .unicode(false)
                .build()
                .map_err(|e| format!("invalid text pattern: {e}"))?;
            Kind::Regex(re)
        } else {
            Kind::Literal(src.as_bytes().to_vec())
        }
    } else if is_special(src) {
        let body = translate(src)?;
        let re = RegexBuilder::new(&format!("(?s-u){body}"))
            .build()
            .map_err(|e| format!("invalid pattern: {e}"))?;
        Kind::Regex(re)
    } else {
        let cleaned: String = src.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes =
            hex::decode(&cleaned).map_err(|e| format!("invalid hex pattern {src:?}: {e}"))?;
        if bytes.is_empty() {
            return Err("pattern must not be empty".to_string());
        }
        Kind::Literal(bytes)
    };

    Ok(Compiled {
        name,
        source: src.to_string(),
        mode: normalized,
        kind,
    })
}

/// Translate an advanced hex pattern into a byte-regex body.
fn translate(input: &str) -> Result<String, String> {
    let chars: Vec<char> = input.chars().filter(|c| !c.is_whitespace()).collect();
    if chars.is_empty() {
        return Err("pattern must not be empty".to_string());
    }
    if chars.contains(&':') {
        return translate_value_mask(&chars);
    }

    let mut i = 0usize;
    let (body, term) = translate_until(&chars, &mut i, &[])?;
    if let Some(c) = term {
        return Err(format!("unexpected '{c}' in pattern"));
    }
    if i != chars.len() {
        return Err(format!("unexpected '{}' in pattern", chars[i]));
    }
    if body.is_empty() {
        return Err("pattern must not be empty".to_string());
    }
    Ok(body)
}

/// Parse a sequence until a terminator (used for the top level and groups).
fn translate_until(
    s: &[char],
    i: &mut usize,
    terminators: &[char],
) -> Result<(String, Option<char>), String> {
    let mut out = String::new();
    while *i < s.len() {
        let c = s[*i];
        if terminators.contains(&c) {
            return Ok((out, Some(c)));
        }
        match c {
            '(' => {
                *i += 1;
                let mut alts = Vec::new();
                loop {
                    let (alt, term) = translate_until(s, i, &['|', ')'])?;
                    if alt.is_empty() {
                        return Err("empty alternative in pattern group".to_string());
                    }
                    alts.push(alt);
                    match term {
                        Some('|') => {
                            *i += 1;
                        }
                        Some(')') => {
                            *i += 1;
                            break;
                        }
                        _ => return Err("unterminated group: missing ')'".to_string()),
                    }
                }
                out.push_str("(?:");
                out.push_str(&alts.join("|"));
                out.push(')');
            }
            '[' => {
                *i += 1;
                let start = *i;
                while *i < s.len() && s[*i] != ']' {
                    *i += 1;
                }
                if *i >= s.len() {
                    return Err("unterminated byte class: missing ']'".to_string());
                }
                let inner: String = s[start..*i].iter().collect();
                *i += 1;
                out.push_str(&translate_class(&inner)?);
            }
            '{' => {
                *i += 1;
                let start = *i;
                while *i < s.len() && s[*i] != '}' {
                    *i += 1;
                }
                if *i >= s.len() {
                    return Err("unterminated gap: missing '}'".to_string());
                }
                let inner: String = s[start..*i].iter().collect();
                *i += 1;
                out.push_str(&translate_gap(&inner)?);
            }
            '?' => match s.get(*i + 1).copied() {
                Some(h) if h.is_ascii_hexdigit() => {
                    out.push_str(&nibble_low(h));
                    *i += 2;
                }
                Some('?') => {
                    out.push('.');
                    *i += 2;
                }
                _ => {
                    return Err("'?' must be followed by a hex digit or another '?'".to_string());
                }
            },
            c if c.is_ascii_hexdigit() => match s.get(*i + 1).copied() {
                Some(h) if h.is_ascii_hexdigit() => {
                    out.push_str(&format!(
                        "\\x{}{}",
                        c.to_ascii_uppercase(),
                        h.to_ascii_uppercase()
                    ));
                    *i += 2;
                }
                Some('?') => {
                    let hi = c.to_ascii_uppercase();
                    out.push_str(&format!("[\\x{hi}0-\\x{hi}F]"));
                    *i += 2;
                }
                _ => {
                    return Err(format!(
                        "odd hex digit {c:?}: hex patterns must be byte-aligned (use ? for nibbles)"
                    ));
                }
            },
            other => return Err(format!("unexpected character {other:?} in pattern")),
        }
    }
    Ok((out, None))
}

/// `?A` matches any byte whose low nibble is `A`.
fn nibble_low(h: char) -> String {
    let h = h.to_ascii_uppercase();
    let mut class = String::from("[");
    for high in 0..16u8 {
        class.push_str(&format!("\\x{high:X}{h}"));
    }
    class.push(']');
    class
}

/// `[00-ff]` or `[41]`.
fn translate_class(inner: &str) -> Result<String, String> {
    if inner.is_empty() {
        return Err("empty byte class '[]'".to_string());
    }
    let parse = |s: &str| -> Result<u8, String> {
        if s.len() != 2 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "byte class entries must be two hex digits, got {s:?}"
            ));
        }
        u8::from_str_radix(s, 16).map_err(|e| e.to_string())
    };

    match inner.split_once('-') {
        Some((lo, hi)) => {
            let lo = parse(lo)?;
            let hi = parse(hi)?;
            if lo > hi {
                return Err(format!("empty byte class range [{inner}]"));
            }
            Ok(format!("[\\x{lo:02X}-\\x{hi:02X}]"))
        }
        None => {
            let b = parse(inner)?;
            Ok(format!("\\x{b:02X}"))
        }
    }
}

/// `{n}` or `{n-m}`.
fn translate_gap(inner: &str) -> Result<String, String> {
    let parse = |s: &str| -> Result<usize, String> {
        s.trim()
            .parse::<usize>()
            .map_err(|_| format!("invalid gap size {s:?}"))
    };

    let (min, max) = match inner.split_once('-') {
        Some((a, b)) => (parse(a)?, parse(b)?),
        None => {
            let n = parse(inner)?;
            (n, n)
        }
    };
    if min > max {
        return Err(format!("invalid gap {{{inner}}}: lower bound is greater"));
    }
    if max > MAX_GAP {
        return Err(format!("gap {{{inner}}} exceeds the {MAX_GAP} byte limit"));
    }
    if min == max {
        Ok(format!(".{{{min}}}"))
    } else {
        Ok(format!(".{{{min},{max}}}"))
    }
}

/// `VALUE:MASK` over the whole pattern.
fn translate_value_mask(chars: &[char]) -> Result<String, String> {
    let text: String = chars.iter().collect();
    let (value, mask) = text
        .split_once(':')
        .ok_or_else(|| "invalid masked pattern".to_string())?;

    let valid = |s: &str| {
        !s.is_empty() && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())
    };
    if !valid(value) || !valid(mask) || value.len() != mask.len() {
        return Err(
            "masked patterns need two equal-length, even hex strings: VALUE:MASK".to_string(),
        );
    }

    let vb = hex::decode(value).map_err(|e| e.to_string())?;
    let mb = hex::decode(mask).map_err(|e| e.to_string())?;

    let mut out = String::new();
    for (&v, &m) in vb.iter().zip(mb.iter()) {
        if m == 0xFF {
            out.push_str(&format!("\\x{v:02X}"));
        } else if m == 0x00 {
            out.push('.');
        } else {
            let allowed: Vec<u8> = (0u16..=255)
                .map(|x| x as u8)
                .filter(|b| (b & m) == (v & m))
                .collect();
            if allowed.len() == 1 {
                out.push_str(&format!("\\x{:02X}", allowed[0]));
            } else {
                out.push('[');
                for b in allowed {
                    out.push_str(&format!("\\x{b:02X}"));
                }
                out.push(']');
            }
        }
    }
    Ok(out)
}

/// Options for [`scan`].
pub struct ScanOptions {
    /// First byte of the window (inclusive).
    pub start: usize,
    /// End of the window (exclusive).
    pub end: usize,
    /// Maximum number of hits to return.
    pub max: usize,
    /// Return only the earliest hit.
    pub first_only: bool,
}

/// Scan `patterns` over `buf[start..end]`, returning matches sorted by offset.
///
/// Also reports whether the result was truncated by `max`.
pub fn scan(buf: &[u8], patterns: &[Compiled], opts: &ScanOptions) -> (Vec<Hit>, bool) {
    let mut hits: Vec<Hit> = Vec::new();
    if opts.max == 0 {
        return (hits, false);
    }

    let start = opts.start.min(buf.len());
    let end = opts.end.min(buf.len());
    if start >= end {
        return (hits, false);
    }
    let window = &buf[start..end];

    let mut capped = false;
    for (index, pattern) in patterns.iter().enumerate() {
        let per_pattern = if opts.first_only { 1 } else { opts.max };
        let mut count = 0usize;
        match &pattern.kind {
            Kind::Literal(needle) => {
                let mut cursor = 0usize;
                while count < per_pattern {
                    let Some(pos) = memchr::memmem::find(&window[cursor..], needle) else {
                        break;
                    };
                    hits.push(Hit {
                        pattern: index,
                        offset: start + cursor + pos,
                        length: needle.len(),
                    });
                    count += 1;
                    cursor += pos + 1;
                }
                if count == per_pattern {
                    // There may be more matches than requested; re-check cheaply.
                    let more = memchr::memmem::find(&window[cursor.min(window.len())..], needle);
                    if more.is_some() {
                        capped = true;
                    }
                }
            }
            Kind::Regex(re) => {
                for m in re.find_iter(window) {
                    if count >= per_pattern {
                        capped = true;
                        break;
                    }
                    hits.push(Hit {
                        pattern: index,
                        offset: start + m.start(),
                        length: m.end() - m.start(),
                    });
                    count += 1;
                }
            }
        }
    }

    hits.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.pattern.cmp(&b.pattern)));

    let limit = if opts.first_only { 1 } else { opts.max };
    let truncated = capped || hits.len() > limit;

    hits.truncate(limit);
    (hits, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(pattern: &str) -> String {
        translate(pattern).unwrap()
    }

    #[test]
    fn literal_and_wildcards() {
        assert_eq!(body("4865"), "\\x48\\x65");
        assert_eq!(body("48 65"), "\\x48\\x65");
        assert_eq!(body("48??"), "\\x48.");
        assert_eq!(body("A?"), "[\\xA0-\\xAF]");
        assert!(body("?A").starts_with('['));
        assert!(body("?A").contains("\\x0A"));
        assert!(body("?A").contains("\\xFA"));
    }

    #[test]
    fn classes_gaps_and_groups() {
        assert_eq!(body("[41]"), "\\x41");
        assert_eq!(body("[00-ff]"), "[\\x00-\\xFF]");
        assert_eq!(body("AA{2}BB"), "\\xAA.{2}\\xBB");
        assert_eq!(body("AA{2-4}BB"), "\\xAA.{2,4}\\xBB");
        assert_eq!(body("(AA|BB)"), "(?:\\xAA|\\xBB)");
        assert_eq!(body("(AA|BB 43)"), "(?:\\xAA|\\xBB\\x43)");
    }

    #[test]
    fn masked_pattern() {
        assert_eq!(body("4D5A:FFFF"), "\\x4D\\x5A");
        assert_eq!(body("4D00:FF00"), "\\x4D.");
        // Only the low nibble is constrained: 0x?5.
        let masked = body("05:0F");
        assert!(masked.starts_with('['));
        assert!(masked.contains("\\x05"));
        assert!(masked.contains("\\xF5"));
        assert!(!masked.contains("\\x04"));
    }

    #[test]
    fn errors_are_reported() {
        assert!(translate("4D5").is_err());
        assert!(translate("[").is_err());
        assert!(translate("AA{5-2}").is_err());
        assert!(translate("4D5A:FF").is_err());
        assert!(translate(")").is_err());
    }

    #[test]
    fn literals_report_overlaps_and_gaps_match() {
        let buf = b"\xAA\xAA\xAA\xBB\x00\x01\x02\xBB";
        let p = compile(None, "AA", "hex", false).unwrap();
        let (hits, _) = scan(
            buf,
            &[p],
            &ScanOptions {
                start: 0,
                end: buf.len(),
                max: 10,
                first_only: false,
            },
        );
        assert_eq!(
            hits.iter().map(|h| h.offset).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let gap = compile(None, "AA{2-4}BB", "hex", false).unwrap();
        let (hits, _) = scan(
            buf,
            &[gap],
            &ScanOptions {
                start: 0,
                end: buf.len(),
                max: 10,
                first_only: false,
            },
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[0].length, 4);
    }

    #[test]
    fn range_limits_and_first_only() {
        let buf = (0..16u8).collect::<Vec<u8>>();
        let p = compile(None, "0708", "hex", false).unwrap();
        let (hits, _) = scan(
            buf.as_slice(),
            &[p],
            &ScanOptions {
                start: 0,
                end: 8,
                max: 10,
                first_only: false,
            },
        );
        assert!(
            hits.is_empty(),
            "a window ending at 8 must not report the match at 7"
        );
        // The match [07 08] starts at offset 7; a window ending at 9 includes it.
        let p = compile(None, "0708", "hex", false).unwrap();
        let (hits, _) = scan(
            buf.as_slice(),
            &[p],
            &ScanOptions {
                start: 0,
                end: 9,
                max: 10,
                first_only: false,
            },
        );
        assert_eq!(hits.len(), 1);

        let p = compile(None, "0", "hex", false);
        assert!(p.is_err(), "an odd hex digit is not a valid pattern");
    }
}
