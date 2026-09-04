#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Tamper-evident audit logging for Rust.
//!
//! `auditlog` provides an immutable, SHA-256 chained audit log with
//! queryable entries and chain verification.
//!
//! # Quick Start
//!
//! ```rust
//! # #[tokio::main]
//! # async fn main() -> tamper_audit::Result<()> {
//! use tamper_audit::AuditLog;
//!
//! let log = AuditLog::new();
//!
//! log.append("alice", "create", "user/1", serde_json::json!({"name": "Alice"})).await?;
//! log.append("bob", "update", "user/1", serde_json::json!({"name": "Alice Smith"})).await?;
//!
//! // Verify chain integrity
//! let result = log.verify_chain().await?;
//! assert!(result.is_valid());
//!
//! // Query by actor
//! let alice_entries = log.query_by_actor("alice").await?;
//! assert_eq!(alice_entries.len(), 1);
//! # Ok(())
//! # }
//! ```

/// Audit log entry types.
pub mod entry;
/// Error types.
pub mod error;
/// Audit log implementation.
pub mod log;
/// Query types for audit logs.
pub mod query;
/// Storage backends.
pub mod store;
/// Chain verification.
pub mod verify;

#[cfg(feature = "persistence")]
/// PostgreSQL storage backend.
pub mod postgres;

pub use entry::AuditEntry;
pub use error::{AuditError, Result};
pub use log::AuditLog;
pub use query::AuditQuery;
pub use store::{AuditStore, InMemoryStore};
pub use verify::{AuditChain, VerificationResult};

#[cfg(feature = "persistence")]
pub use postgres::PostgresStore;
