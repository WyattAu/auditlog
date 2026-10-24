//! A JSONL file as the storage backend: the desktop's durable trail.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;

use crate::entry::AuditEntry;
use crate::error::{AuditError, Result};
use crate::query::AuditQuery;
use crate::store::AuditStore;

/// A JSONL file as the storage backend: one serialized [`AuditEntry`] per
/// line, appended on write and read back in insertion order.
///
/// The desktop's durable trail: the file survives restarts, so the chain
/// (every entry hashing the one before it) keeps verifying across sessions —
/// open the same path again and the log continues from where it left off.
///
/// Appends are serialized behind a mutex and flushed to the OS on each write.
/// One process owns a trail file — concurrent writers are out of scope (a
/// lockfile, or the Postgres backend, covers that).
pub struct FileStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileStore {
    /// A store backed by the JSONL file at `path` (created on first append).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    /// The file this store appends to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock_store(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn read_entries(&self) -> Result<Vec<AuditEntry>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Persistence(e.to_string())),
        };
        let mut entries = Vec::new();
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            entries.push(
                serde_json::from_str(line)
                    .map_err(|e| AuditError::Serialization(format!("line {}: {e}", n + 1)))?,
            );
        }
        Ok(entries)
    }
}

#[async_trait]
impl AuditStore for FileStore {
    async fn append(&self, entry: AuditEntry) -> Result<()> {
        let _lock = self.lock_store();
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AuditError::Persistence(e.to_string()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| AuditError::Persistence(e.to_string()))?;
        let line = serde_json::to_string(&entry)?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|e| AuditError::Persistence(e.to_string()))
    }

    async fn last_entry(&self) -> Result<Option<AuditEntry>> {
        let _lock = self.lock_store();
        let mut entries = self.read_entries()?;
        Ok(entries.pop())
    }

    async fn all_entries(&self) -> Result<Vec<AuditEntry>> {
        let _lock = self.lock_store();
        self.read_entries()
    }

    async fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>> {
        let _lock = self.lock_store();
        let mut results: Vec<AuditEntry> = self
            .read_entries()?
            .iter()
            .filter(|e| query.matches(e))
            .cloned()
            .collect();
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }
        Ok(results)
    }

    async fn count(&self) -> Result<usize> {
        let _lock = self.lock_store();
        Ok(self.read_entries()?.len())
    }
}
