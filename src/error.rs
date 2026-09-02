/// Errors that can occur in audit log operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// A serialization error occurred.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// The audit chain is broken.
    #[error("Chain broken at entry {index}: {reason}")]
    ChainBroken {
        /// Index of the broken entry.
        index: usize,
        /// Reason for the break.
        reason: String,
    },

    /// The requested entry was not found.
    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(String),
}

/// A convenience result type for audit log operations.
pub type Result<T> = std::result::Result<T, AuditError>;

impl From<serde_json::Error> for AuditError {
    fn from(e: serde_json::Error) -> Self {
        AuditError::Serialization(e.to_string())
    }
}
