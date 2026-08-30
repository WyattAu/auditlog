#![forbid(unsafe_code)]
//! Tamper-evident audit logging for Rust.
//!
//! `auditlog` provides an immutable, SHA-256 chained audit log with
//! queryable entries and chain verification.
//!
//! # Quick Start
//!
//! ```rust
//! use auditlog::AuditLog;
//!
//! let mut log = AuditLog::new();
//!
//! log.append("alice", "create", "user/1", serde_json::json!({"name": "Alice"})).unwrap();
//! log.append("bob", "update", "user/1", serde_json::json!({"name": "Alice Smith"})).unwrap();
//!
//! // Verify chain integrity
//! let result = log.verify_chain();
//! assert!(result.is_valid());
//!
//! // Query by actor
//! let alice_entries = log.query_by_actor("alice");
//! assert_eq!(alice_entries.len(), 1);
//! ```

pub mod entry;
pub mod error;
pub mod log;
pub mod query;
pub mod verify;

pub use entry::AuditEntry;
pub use error::{AuditError, Result};
pub use log::AuditLog;
pub use query::AuditQuery;
pub use verify::{AuditChain, VerificationResult};
