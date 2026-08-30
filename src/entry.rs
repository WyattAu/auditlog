use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// A single immutable audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEntry {
    /// Unique identifier for this entry.
    pub id: Uuid,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// The entity that performed the action.
    pub actor: String,
    /// The action that was performed.
    pub action: String,
    /// The resource that was acted upon.
    pub resource: String,
    /// Free-form details about the action.
    pub details: serde_json::Value,
    /// SHA-256 hash of the previous entry (hex-encoded).
    pub previous_hash: String,
    /// SHA-256 hash of this entry (hex-encoded).
    pub hash: String,
}

impl AuditEntry {
    /// Creates a new audit entry with computed hash.
    ///
    /// For the genesis entry, pass `"0".repeat(64)` as `previous_hash`.
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        details: serde_json::Value,
        previous_hash: &str,
    ) -> Self {
        let entry = Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            actor: actor.into(),
            action: action.into(),
            resource: resource.into(),
            details,
            previous_hash: previous_hash.to_string(),
            hash: String::new(), // computed below
        };

        Self {
            hash: entry.compute_hash(),
            ..entry
        }
    }

    /// Computes the SHA-256 hash of this entry.
    ///
    /// The hash covers: id, timestamp, actor, action, resource, details, and previous_hash.
    pub fn compute_hash(&self) -> String {
        let data = self.hash_data();
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex_encode(&hasher.finalize())
    }

    /// Returns the bytes that are hashed.
    fn hash_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.id.as_bytes());
        data.extend_from_slice(self.timestamp.to_rfc3339().as_bytes());
        data.extend_from_slice(self.actor.as_bytes());
        data.extend_from_slice(self.action.as_bytes());
        data.extend_from_slice(self.resource.as_bytes());
        data.extend_from_slice(
            serde_json::to_string(&self.details)
                .unwrap_or_default()
                .as_bytes(),
        );
        data.extend_from_slice(self.previous_hash.as_bytes());
        data
    }

    /// Verifies that this entry's hash is correct.
    pub fn verify_hash(&self) -> bool {
        self.hash == self.compute_hash()
    }
}

/// Hex-encode a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_entry() {
        let genesis_hash = "0".repeat(64);
        let entry = AuditEntry::new("admin", "system.start", "system", serde_json::json!({}), &genesis_hash);

        assert!(!entry.id.is_nil());
        assert!(entry.verify_hash());
        assert_eq!(entry.previous_hash, genesis_hash);
    }

    #[test]
    fn test_chained_entry() {
        let genesis_hash = "0".repeat(64);
        let entry1 = AuditEntry::new("admin", "create", "user/1", serde_json::json!({}), &genesis_hash);

        let entry2 = AuditEntry::new("admin", "update", "user/1", serde_json::json!({"name": "Alice"}), &entry1.hash);

        assert!(entry1.verify_hash());
        assert!(entry2.verify_hash());
        assert_eq!(entry2.previous_hash, entry1.hash);
        assert_ne!(entry1.hash, entry2.hash);
    }

    #[test]
    fn test_hash_detection() {
        let genesis_hash = "0".repeat(64);
        let mut entry = AuditEntry::new("admin", "create", "user/1", serde_json::json!({}), &genesis_hash);

        // Tamper with the entry
        entry.action = "delete".to_string();
        assert!(!entry.verify_hash());
    }
}
