use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entry::AuditEntry;

/// Query filters for searching audit log entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Filter by actor.
    pub actor: Option<String>,
    /// Filter by action.
    pub action: Option<String>,
    /// Filter by resource.
    pub resource: Option<String>,
    /// Filter by time range (start, inclusive).
    pub time_start: Option<DateTime<Utc>>,
    /// Filter by time range (end, exclusive).
    pub time_end: Option<DateTime<Utc>>,
    /// Maximum number of results to return.
    pub limit: Option<usize>,
}

impl AuditQuery {
    /// Creates a new empty query.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by actor.
    pub fn by_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Filter by action.
    pub fn by_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Filter by resource.
    pub fn by_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Filter by time range.
    pub fn by_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.time_start = Some(start);
        self.time_end = Some(end);
        self
    }

    /// Set the maximum number of results.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Returns true if an entry matches this query.
    pub fn matches(&self, entry: &AuditEntry) -> bool {
        if let Some(ref actor) = self.actor {
            if &entry.actor != actor {
                return false;
            }
        }

        if let Some(ref action) = self.action {
            if &entry.action != action {
                return false;
            }
        }

        if let Some(ref resource) = self.resource {
            if &entry.resource != resource {
                return false;
            }
        }

        if let Some(start) = self.time_start {
            if entry.timestamp < start {
                return false;
            }
        }

        if let Some(end) = self.time_end {
            if entry.timestamp >= end {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry(actor: &str, action: &str, resource: &str) -> AuditEntry {
        AuditEntry::new(
            actor,
            action,
            resource,
            serde_json::json!({}),
            &"0".repeat(64),
        )
    }

    #[test]
    fn test_query_by_actor() {
        let query = AuditQuery::new().by_actor("alice");
        assert!(query.matches(&test_entry("alice", "read", "file/1")));
        assert!(!query.matches(&test_entry("bob", "read", "file/1")));
    }

    #[test]
    fn test_query_by_action() {
        let query = AuditQuery::new().by_action("delete");
        assert!(query.matches(&test_entry("alice", "delete", "file/1")));
        assert!(!query.matches(&test_entry("alice", "read", "file/1")));
    }

    #[test]
    fn test_query_combined() {
        let query = AuditQuery::new()
            .by_actor("alice")
            .by_action("update")
            .by_resource("user/1");

        assert!(query.matches(&test_entry("alice", "update", "user/1")));
        assert!(!query.matches(&test_entry("alice", "update", "user/2")));
        assert!(!query.matches(&test_entry("bob", "update", "user/1")));
    }
}
