/// Errors that can occur in audit log operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// A serialization error occurred.
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// A persistence error occurred.
    #[error("Persistence error: {0}")]
    Persistence(String),
}

/// A convenience result type for audit log operations.
pub type Result<T> = std::result::Result<T, AuditError>;

impl From<serde_json::Error> for AuditError {
    fn from(e: serde_json::Error) -> Self {
        AuditError::Serialization(e.to_string())
    }
}
