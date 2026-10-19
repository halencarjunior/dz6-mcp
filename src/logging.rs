//! Logging and in-memory diagnostics.
//!
//! stdout is reserved for the JSON-RPC protocol, so every diagnostic line goes
//! to stderr. We additionally keep a bounded ring buffer of the same lines so
//! MCP clients can read them back with the `logs_tail` tool, and we expose a
//! reloadable `EnvFilter` so the `log_level` tool can change verbosity at
//! runtime.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Context;
use tracing_subscriber::{
    EnvFilter, Registry, fmt, layer::SubscriberExt, reload, util::SubscriberInitExt,
};

/// How many formatted log lines the ring buffer keeps.
pub const LOG_CAPACITY: usize = 2000;

/// A bounded, newest-last buffer of formatted log lines.
pub struct LogBuffer {
    lines: Mutex<VecDeque<String>>,
    capacity: usize,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            lines: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut VecDeque<String>) -> T) -> T {
        let mut lines = self
            .lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut lines)
    }

    pub fn push(&self, line: String) {
        self.with(|lines| {
            if lines.len() == self.capacity {
                lines.pop_front();
            }
            lines.push_back(line);
        });
    }

    pub fn len(&self) -> usize {
        self.with(|lines| lines.len())
    }

    /// The most recent `n` lines, oldest first.
    pub fn tail(&self, n: usize) -> Vec<String> {
        self.with(|lines| {
            let skip = lines.len().saturating_sub(n);
            lines.iter().skip(skip).cloned().collect()
        })
    }

    pub fn clear(&self) {
        self.with(|lines| lines.clear());
    }
}

/// A writer that tees formatted log lines to stderr, an optional file and the
/// in-memory ring buffer.
#[derive(Clone)]
pub struct TeeWriter {
    buffer: Arc<LogBuffer>,
    file: Option<Arc<Mutex<File>>>,
}

pub struct TeeHandle {
    stderr: io::Stderr,
    file: Option<Arc<Mutex<File>>>,
    buffer: Arc<LogBuffer>,
    /// Bytes of the line currently being written, flushed on `\n`.
    pending: Vec<u8>,
}

impl<'a> fmt::MakeWriter<'a> for TeeWriter {
    type Writer = TeeHandle;

    fn make_writer(&'a self) -> Self::Writer {
        TeeHandle {
            stderr: io::stderr(),
            file: self.file.clone(),
            buffer: self.buffer.clone(),
            pending: Vec::new(),
        }
    }
}

impl Write for TeeHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stderr.write_all(buf)?;
        if let Some(file) = &self.file
            && let Ok(mut file) = file.lock()
        {
            let _ = file.write_all(buf);
        }
        for &byte in buf {
            if byte == b'\n' {
                self.buffer
                    .push(String::from_utf8_lossy(&self.pending).into_owned());
                self.pending.clear();
            } else {
                self.pending.push(byte);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stderr.flush()?;
        if let Some(file) = &self.file
            && let Ok(mut file) = file.lock()
        {
            file.flush()?;
        }
        Ok(())
    }
}

/// Process-wide diagnostics: uptime, log buffer and the runtime log filter.
pub struct Diagnostics {
    started: Instant,
    buffer: Arc<LogBuffer>,
    filter: reload::Handle<EnvFilter, Registry>,
    level: Mutex<String>,
    log_file: Option<PathBuf>,
    file: Option<Arc<Mutex<File>>>,
}

const LEVELS: [&str; 6] = ["trace", "debug", "info", "warn", "error", "off"];

/// Validate and normalise a log filter. Bare levels are restricted to the
/// standard set; anything with `=` or `,` is treated as an EnvFilter directive
/// list and validated by `EnvFilter` itself.
fn validate_filter(level: &str) -> Result<String, String> {
    let level = level.trim();
    if level.is_empty() {
        return Err("log level must not be empty".into());
    }
    if !level.contains('=') && !level.contains(',') {
        let lower = level.to_ascii_lowercase();
        if !LEVELS.contains(&lower.as_str()) {
            return Err(format!(
                "invalid log level '{level}'; use trace, debug, info, warn, error, off, or a directive list such as 'dz6_mcp=debug,rmcp=info'"
            ));
        }
        return Ok(lower);
    }
    EnvFilter::try_new(level)
        .map(|_| level.to_string())
        .map_err(|e| format!("invalid log filter: {e}"))
}

impl Diagnostics {
    pub fn uptime_seconds(&self) -> f64 {
        let secs = self.started.elapsed().as_secs_f64();
        (secs * 100.0).round() / 100.0
    }

    pub fn level(&self) -> String {
        self.level
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replace the active log filter. Accepts a bare level (`debug`) or an
    /// `EnvFilter` directive list (`dz6_mcp=debug,rmcp=info`).
    pub fn set_level(&self, level: &str) -> Result<String, String> {
        let level = validate_filter(level)?;
        let filter = EnvFilter::try_new(&level).map_err(|e| format!("invalid log level: {e}"))?;
        self.filter
            .reload(filter)
            .map_err(|e| format!("cannot change log level: {e}"))?;
        *self
            .level
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = level.clone();
        Ok(level)
    }

    pub fn log_file(&self) -> Option<&PathBuf> {
        self.log_file.as_ref()
    }

    pub fn buffer(&self) -> &LogBuffer {
        &self.buffer
    }

    /// Write one line to stderr (and the log file and ring buffer) regardless
    /// of the active filter. Used for lifecycle banners that should always be
    /// visible.
    pub fn notify(&self, message: &str) {
        let mut line = String::from(message);
        line.push('\n');
        let _ = io::stderr().write_all(line.as_bytes());
        if let Some(file) = &self.file
            && let Ok(mut file) = file.lock()
        {
            let _ = file.write_all(line.as_bytes());
        }
        self.buffer.push(message.to_string());
    }
}

/// Install the global subscriber and return the shared diagnostics handle.
///
/// `level` is the fallback filter when `RUST_LOG` is unset. Logs always go to
/// stderr; when `log_file` is set they are appended there too.
pub fn init(level: &str, log_file: Option<PathBuf>) -> anyhow::Result<Arc<Diagnostics>> {
    let level = validate_filter(level).map_err(anyhow::Error::msg)?;
    let filter = EnvFilter::try_new(&level)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("invalid log filter '{level}'"))?;
    let (filter, reload_handle) = reload::Layer::new(filter);

    let file = match &log_file {
        Some(path) => Some(Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("cannot open log file {}", path.display()))?,
        ))),
        None => None,
    };

    let buffer = Arc::new(LogBuffer::new(LOG_CAPACITY));
    let writer = TeeWriter {
        buffer: buffer.clone(),
        file: file.clone(),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_ansi(false).with_writer(writer))
        .init();

    Ok(Arc::new(Diagnostics {
        started: Instant::now(),
        buffer,
        filter: reload_handle,
        level: Mutex::new(level.to_string()),
        log_file,
        file,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_validation_normalises_levels() {
        assert_eq!(validate_filter("DEBUG").unwrap(), "debug");
        assert_eq!(validate_filter(" info ").unwrap(), "info");
        assert_eq!(
            validate_filter("dz6_mcp=debug,rmcp=info").unwrap(),
            "dz6_mcp=debug,rmcp=info"
        );
    }

    #[test]
    fn filter_validation_rejects_bad_input() {
        assert!(validate_filter("").is_err());
        assert!(validate_filter("verbose").is_err());
        assert!(validate_filter("dz6_mcp=nope").is_err());
    }

    #[test]
    fn ring_buffer_keeps_newest_lines() {
        let buffer = LogBuffer::new(3);
        for i in 0..5 {
            buffer.push(format!("line {i}"));
        }
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.tail(10), vec!["line 2", "line 3", "line 4"]);
        assert_eq!(buffer.tail(1), vec!["line 4"]);
        assert!(buffer.tail(0).is_empty());
        buffer.clear();
        assert_eq!(buffer.len(), 0);
    }
}
