use crate::entry::AuditEntry;
use crate::error::Result;
use crate::query::AuditQuery;
use crate::store::{AuditStore, InMemoryStore};
use crate::verify::{AuditChain, VerificationResult};

/// A tamper-evident audit log.
///
/// Generic over the storage backend `S`. The default is [`InMemoryStore`].
pub struct AuditLog<S: AuditStore = InMemoryStore> {
    store: S,
}

impl AuditLog<InMemoryStore> {
    /// Creates a new in-memory audit log with a genesis entry.
    pub fn new() -> Self {
        let store = InMemoryStore::new();
        let genesis = AuditEntry::new(
            "system",
            "log.created",
            "audit_log",
            serde_json::json!({}),
            &"0".repeat(64),
        );
        store.push_sync(genesis);
        Self { store }
    }
}

impl<S: AuditStore> AuditLog<S> {
    /// Creates a new audit log with the given store backend.
    ///
    /// If the store is empty a genesis entry is inserted automatically.
    pub async fn with_store(store: S) -> Result<Self> {
        let log = Self { store };
        if log.store.count().await? == 0 {
            let genesis = AuditEntry::new(
                "system",
                "log.created",
                "audit_log",
                serde_json::json!({}),
                &"0".repeat(64),
            );
            log.store.append(genesis).await?;
        }
        Ok(log)
    }

    /// Appends a new entry to the log.
    pub async fn append(
        &self,
        actor: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        details: serde_json::Value,
    ) -> Result<AuditEntry> {
        let previous_hash = self
            .store
            .last_entry()
            .await?
            .map(|e| e.hash)
            .unwrap_or_else(|| "0".repeat(64));

        let entry = AuditEntry::new(actor, action, resource, details, &previous_hash);
        let entry_clone = entry.clone();
        self.store.append(entry).await?;
        Ok(entry_clone)
    }

    /// Returns all entries matching a query.
    pub async fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>> {
        self.store.query(query).await
    }

    /// Returns all entries whose actor matches the given value.
    pub async fn query_by_actor(&self, actor: &str) -> Result<Vec<AuditEntry>> {
        self.store
            .query(&AuditQuery::new().by_actor(actor))
            .await
    }

    /// Returns all entries whose action matches the given value.
    pub async fn query_by_action(&self, action: &str) -> Result<Vec<AuditEntry>> {
        self.store
            .query(&AuditQuery::new().by_action(action))
            .await
    }

    /// Returns all entries whose resource matches the given value.
    pub async fn query_by_resource(&self, resource: &str) -> Result<Vec<AuditEntry>> {
        self.store
            .query(&AuditQuery::new().by_resource(resource))
            .await
    }

    /// Verifies the integrity of the entire audit chain.
    pub async fn verify_chain(&self) -> Result<VerificationResult> {
        let entries = self.store.all_entries().await?;
        Ok(AuditChain::verify(&entries))
    }

    /// Returns the total number of entries (including genesis).
    pub async fn len(&self) -> Result<usize> {
        self.store.count().await
    }

    /// Returns true if the log has no entries.
    pub async fn is_empty(&self) -> Result<bool> {
        Ok(self.store.count().await? == 0)
    }

    /// Returns a clone of the last entry, if any.
    pub async fn last_entry(&self) -> Result<Option<AuditEntry>> {
        self.store.last_entry().await
    }

    /// Returns a reference to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }
}

impl Default for AuditLog<InMemoryStore> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_log_has_genesis() {
        let log = AuditLog::new();
        assert_eq!(log.len().await.unwrap(), 1);
        let entries = log.store.all_entries().await.unwrap();
        assert_eq!(entries[0].action, "log.created");
    }

    #[tokio::test]
    async fn test_append_creates_chained_entry() {
        let log = AuditLog::new();
        let genesis = log.store.all_entries().await.unwrap();
        let entry = log
            .append(
                "alice",
                "create",
                "user/1",
                serde_json::json!({"name": "Alice"}),
            )
            .await
            .unwrap();

        assert_eq!(log.len().await.unwrap(), 2);
        assert_eq!(entry.previous_hash, genesis[0].hash);
        assert!(entry.verify_hash());
    }

    #[tokio::test]
    async fn test_verify_chain_valid() {
        let log = AuditLog::new();
        log.append("alice", "create", "user/1", serde_json::json!({}))
            .await
            .unwrap();
        log.append("bob", "update", "user/1", serde_json::json!({}))
            .await
            .unwrap();
        log.append("alice", "delete", "user/1", serde_json::json!({}))
            .await
            .unwrap();

        let result = log.verify_chain().await.unwrap();
        assert!(result.is_valid());
        assert_eq!(result.total_entries, 4);
    }

    #[tokio::test]
    async fn test_query_by_actor() {
        let log = AuditLog::new();
        log.append("alice", "create", "user/1", serde_json::json!({}))
            .await
            .unwrap();
        log.append("bob", "create", "user/2", serde_json::json!({}))
            .await
            .unwrap();
        log.append("alice", "update", "user/1", serde_json::json!({}))
            .await
            .unwrap();

        let alice_entries = log.query_by_actor("alice").await.unwrap();
        assert_eq!(alice_entries.len(), 2);

        let bob_entries = log.query_by_actor("bob").await.unwrap();
        assert_eq!(bob_entries.len(), 1);
    }

    #[tokio::test]
    async fn test_query_by_action() {
        let log = AuditLog::new();
        log.append("alice", "create", "user/1", serde_json::json!({}))
            .await
            .unwrap();
        log.append("bob", "update", "user/1", serde_json::json!({}))
            .await
            .unwrap();
        log.append("alice", "create", "user/2", serde_json::json!({}))
            .await
            .unwrap();

        let creates = log.query_by_action("create").await.unwrap();
        assert_eq!(creates.len(), 2);
    }

    #[tokio::test]
    async fn test_query_by_resource() {
        let log = AuditLog::new();
        log.append("alice", "create", "user/1", serde_json::json!({}))
            .await
            .unwrap();
        log.append("bob", "update", "user/1", serde_json::json!({}))
            .await
            .unwrap();
        log.append("alice", "create", "user/2", serde_json::json!({}))
            .await
            .unwrap();

        let user1 = log.query_by_resource("user/1").await.unwrap();
        assert_eq!(user1.len(), 2);
    }

    #[tokio::test]
    async fn test_structured_query() {
        let log = AuditLog::new();
        log.append("alice", "create", "user/1", serde_json::json!({}))
            .await
            .unwrap();
        log.append("alice", "update", "user/1", serde_json::json!({}))
            .await
            .unwrap();
        log.append("bob", "create", "user/2", serde_json::json!({}))
            .await
            .unwrap();

        let query = AuditQuery::new().by_actor("alice").by_action("create");
        let results = log.query(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].actor, "alice");
        assert_eq!(results[0].action, "create");
    }

    #[tokio::test]
    async fn test_genesis_entry_previous_hash() {
        let log = AuditLog::new();
        let entries = log.store.all_entries().await.unwrap();
        let genesis = &entries[0];
        assert_eq!(genesis.previous_hash, "0".repeat(64));
    }
}
