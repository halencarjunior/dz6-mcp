//! Open-document registry.
//!
//! An MCP session is long-lived, so dz6's stateful editing model (in-memory
//! change buffer, comments, bookmarks, colored blocks) is kept per file. Files
//! are opened lazily: any tool that takes a `path` will open it on first use.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use dz6::app::App;

pub struct Document {
    pub app: App,
    pub path: PathBuf,
    /// The read-only mode that was requested when the file was opened. This is
    /// kept separately from `app.file_info.is_read_only` because opening for
    /// write can still fail (e.g. a write-protected file), and we want
    /// `open_file` to be idempotent in that case.
    pub requested_readonly: bool,
}

impl Document {
    pub fn canonical(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    pub fn size(&self) -> usize {
        self.app.file_info.size
    }

    /// Effective read-only state: true when the caller asked for it or when the
    /// file could not be opened for writing.
    pub fn readonly(&self) -> bool {
        self.app.file_info.is_read_only || self.app.file_info.file.is_none()
    }

    pub fn dirty(&self) -> bool {
        !self.app.hex_view.changed_bytes.is_empty()
    }

    pub fn file_type(&self) -> &'static str {
        if self.app.file_info.r#type.is_empty() {
            "raw"
        } else {
            self.app.file_info.r#type
        }
    }
}

pub struct ServerState {
    docs: HashMap<String, Document>,
    default_readonly: bool,
}

impl ServerState {
    pub fn new(default_readonly: bool) -> Self {
        Self {
            docs: HashMap::new(),
            default_readonly,
        }
    }

    fn canonicalize(path: &str) -> Result<String, String> {
        let p = Path::new(path);
        if !p.exists() {
            return Err(format!("file not found: {path}"));
        }
        std::fs::canonicalize(p)
            .map(|c| c.to_string_lossy().into_owned())
            .map_err(|e| format!("cannot resolve {path}: {e}"))
    }

    fn insert_new(&mut self, canonical: String, requested_readonly: bool) -> Result<(), String> {
        let mut app = App::new();
        app.load_file(&canonical, 0, requested_readonly)
            .map_err(|e| format!("cannot open {canonical}: {e}"))?;
        self.docs.insert(
            canonical.clone(),
            Document {
                app,
                path: PathBuf::from(&canonical),
                requested_readonly,
            },
        );
        tracing::info!(
            path = %canonical,
            requested_readonly,
            effective_readonly = self.docs[&canonical].readonly(),
            "opened document"
        );
        Ok(())
    }

    /// Open (or reuse) a document and return a mutable reference to it.
    ///
    /// When `readonly` is `Some` and differs from how the file was previously
    /// opened, the file is reopened with the requested mode, provided it has no
    /// pending edits.
    pub fn open_doc(
        &mut self,
        path: &str,
        readonly: Option<bool>,
    ) -> Result<&mut Document, String> {
        let canonical = Self::canonicalize(path)?;

        if !self.docs.contains_key(&canonical) {
            let ro = readonly.unwrap_or(self.default_readonly);
            self.insert_new(canonical.clone(), ro)?;
        } else if let Some(ro) = readonly {
            let current = self.docs[&canonical].requested_readonly;
            if current != ro {
                if self.docs[&canonical].dirty() {
                    return Err(format!(
                        "{canonical} is open with pending changes; save or discard them before changing its read-only mode"
                    ));
                }
                self.docs.remove(&canonical);
                self.insert_new(canonical.clone(), ro)?;
            }
        }

        Ok(self.docs.get_mut(&canonical).expect("just ensured"))
    }

    pub fn close(&mut self, path: &str) -> Result<bool, String> {
        let canonical = Self::canonicalize(path)?;
        Ok(self.docs.remove(&canonical).is_some())
    }

    pub fn docs(&self) -> impl Iterator<Item = &Document> {
        self.docs.values()
    }

    pub fn default_readonly(&self) -> bool {
        self.default_readonly
    }
}
