use async_trait::async_trait;

use crate::entry::AuditEntry;
use crate::error::Result;
use crate::query::AuditQuery;

/// Trait for audit log storage backends.
#[async_trait]
pub trait AuditStore: Send + Sync {
    /// Append an entry to the store.
    async fn append(&self, entry: AuditEntry) -> Result<()>;
    /// Return the most recently appended entry, if any.
    async fn last_entry(&self) -> Result<Option<AuditEntry>>;
    /// Return all entries in insertion order.
    async fn all_entries(&self) -> Result<Vec<AuditEntry>>;
    /// Return entries matching the given query.
    async fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>>;
    /// Return the total number of stored entries.
    async fn count(&self) -> Result<usize>;
}

/// In-memory storage backend.
pub struct InMemoryStore {
    entries: std::sync::Mutex<Vec<AuditEntry>>,
}

impl InMemoryStore {
    /// Create a new, empty in-memory store.
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Synchronously push an entry (used during construction).
    pub fn push_sync(&self, entry: AuditEntry) {
        self.lock_entries().push(entry);
    }

    /// Lock the entries mutex.
    ///
    /// # Panics
    /// Panics if the mutex is poisoned: a prior panic mid-append leaves the
    /// log chain inconsistent, so failing loudly is correct here.
    #[allow(clippy::unwrap_used)]
    fn lock_entries(&self) -> std::sync::MutexGuard<'_, Vec<AuditEntry>> {
        self.entries.lock().unwrap()
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditStore for InMemoryStore {
    async fn append(&self, entry: AuditEntry) -> Result<()> {
        self.lock_entries().push(entry);
        Ok(())
    }

    async fn last_entry(&self) -> Result<Option<AuditEntry>> {
        Ok(self.lock_entries().last().cloned())
    }

    async fn all_entries(&self) -> Result<Vec<AuditEntry>> {
        Ok(self.lock_entries().clone())
    }

    async fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>> {
        let entries = self.lock_entries();
        let mut results: Vec<AuditEntry> = entries
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
        Ok(self.lock_entries().len())
    }
}
