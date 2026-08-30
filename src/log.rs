use std::collections::HashMap;

use crate::entry::AuditEntry;
use crate::error::Result;
use crate::query::AuditQuery;
use crate::verify::{AuditChain, VerificationResult};

/// An in-memory tamper-evident audit log.
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    /// Index: actor -> entry indices.
    actor_index: HashMap<String, Vec<usize>>,
    /// Index: action -> entry indices.
    action_index: HashMap<String, Vec<usize>>,
    /// Index: resource -> entry indices.
    resource_index: HashMap<String, Vec<usize>>,
}

impl AuditLog {
    /// Creates a new empty audit log with a genesis entry.
    pub fn new() -> Self {
        let genesis = AuditEntry::new(
            "system",
            "log.created",
            "audit_log",
            serde_json::json!({}),
            &"0".repeat(64),
        );

        let mut log = Self {
            entries: Vec::new(),
            actor_index: HashMap::new(),
            action_index: HashMap::new(),
            resource_index: HashMap::new(),
        };

        log.add_entry(genesis);
        log
    }

    /// Appends a new entry to the log.
    pub fn append(
        &mut self,
        actor: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        details: serde_json::Value,
    ) -> Result<AuditEntry> {
        let previous_hash = self
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let entry = AuditEntry::new(actor, action, resource, details, &previous_hash);
        let entry_clone = entry.clone();
        self.add_entry(entry);
        Ok(entry_clone)
    }

    /// Internal: adds an entry and updates indices.
    fn add_entry(&mut self, entry: AuditEntry) {
        let idx = self.entries.len();

        self.actor_index
            .entry(entry.actor.clone())
            .or_default()
            .push(idx);
        self.action_index
            .entry(entry.action.clone())
            .or_default()
            .push(idx);
        self.resource_index
            .entry(entry.resource.clone())
            .or_default()
            .push(idx);

        self.entries.push(entry);
    }

    /// Returns all entries matching a query.
    pub fn query(&self, query: &AuditQuery) -> Vec<&AuditEntry> {
        let mut results: Vec<&AuditEntry> = self
            .entries
            .iter()
            .filter(|e| query.matches(e))
            .collect();

        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        results
    }

    /// Queries entries by actor.
    pub fn query_by_actor(&self, actor: &str) -> Vec<&AuditEntry> {
        self.actor_index
            .get(actor)
            .map(|indices| indices.iter().map(|&i| &self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// Queries entries by action.
    pub fn query_by_action(&self, action: &str) -> Vec<&AuditEntry> {
        self.action_index
            .get(action)
            .map(|indices| indices.iter().map(|&i| &self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// Queries entries by resource.
    pub fn query_by_resource(&self, resource: &str) -> Vec<&AuditEntry> {
        self.resource_index
            .get(resource)
            .map(|indices| indices.iter().map(|&i| &self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// Verifies the integrity of the entire audit chain.
    pub fn verify_chain(&self) -> VerificationResult {
        AuditChain::verify(&self.entries)
    }

    /// Returns the total number of entries (including genesis).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a reference to the last entry.
    pub fn last_entry(&self) -> Option<&AuditEntry> {
        self.entries.last()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_log_has_genesis() {
        let log = AuditLog::new();
        assert_eq!(log.len(), 1);
        assert_eq!(log.entries[0].action, "log.created");
    }

    #[test]
    fn test_append_creates_chained_entry() {
        let mut log = AuditLog::new();
        let entry = log.append("alice", "create", "user/1", serde_json::json!({"name": "Alice"})).unwrap();

        assert_eq!(log.len(), 2);
        assert_eq!(entry.previous_hash, log.entries[0].hash);
        assert!(entry.verify_hash());
    }

    #[test]
    fn test_verify_chain_valid() {
        let mut log = AuditLog::new();
        log.append("alice", "create", "user/1", serde_json::json!({})).unwrap();
        log.append("bob", "update", "user/1", serde_json::json!({})).unwrap();
        log.append("alice", "delete", "user/1", serde_json::json!({})).unwrap();

        let result = log.verify_chain();
        assert!(result.is_valid());
        assert_eq!(result.total_entries, 4);
    }

    #[test]
    fn test_query_by_actor() {
        let mut log = AuditLog::new();
        log.append("alice", "create", "user/1", serde_json::json!({})).unwrap();
        log.append("bob", "create", "user/2", serde_json::json!({})).unwrap();
        log.append("alice", "update", "user/1", serde_json::json!({})).unwrap();

        let alice_entries = log.query_by_actor("alice");
        assert_eq!(alice_entries.len(), 2);

        let bob_entries = log.query_by_actor("bob");
        assert_eq!(bob_entries.len(), 1);
    }

    #[test]
    fn test_query_by_action() {
        let mut log = AuditLog::new();
        log.append("alice", "create", "user/1", serde_json::json!({})).unwrap();
        log.append("bob", "update", "user/1", serde_json::json!({})).unwrap();
        log.append("alice", "create", "user/2", serde_json::json!({})).unwrap();

        let creates = log.query_by_action("create");
        assert_eq!(creates.len(), 2);
    }

    #[test]
    fn test_query_by_resource() {
        let mut log = AuditLog::new();
        log.append("alice", "create", "user/1", serde_json::json!({})).unwrap();
        log.append("bob", "update", "user/1", serde_json::json!({})).unwrap();
        log.append("alice", "create", "user/2", serde_json::json!({})).unwrap();

        let user1 = log.query_by_resource("user/1");
        assert_eq!(user1.len(), 2);
    }

    #[test]
    fn test_structured_query() {
        let mut log = AuditLog::new();
        log.append("alice", "create", "user/1", serde_json::json!({})).unwrap();
        log.append("alice", "update", "user/1", serde_json::json!({})).unwrap();
        log.append("bob", "create", "user/2", serde_json::json!({})).unwrap();

        let query = AuditQuery::new().by_actor("alice").by_action("create");
        let results = log.query(&query);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].actor, "alice");
        assert_eq!(results[0].action, "create");
    }

    #[test]
    fn test_genesis_entry_previous_hash() {
        let log = AuditLog::new();
        let genesis = &log.entries[0];
        assert_eq!(genesis.previous_hash, "0".repeat(64));
    }
}
