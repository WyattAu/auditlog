use sqlx::PgPool;

use crate::entry::AuditEntry;
use crate::error::{AuditError, Result};
use crate::query::AuditQuery;
use crate::store::AuditStore;

/// PostgreSQL-backed audit log store.
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Open (or create) a Postgres-backed audit log using the given pool.
    ///
    /// Runs migrations and inserts a genesis entry when the table is empty.
    pub async fn open(pool: PgPool) -> Result<Self> {
        Self::migrate(&pool).await?;
        let store = Self { pool };
        store.ensure_genesis().await?;
        Ok(store)
    }

    /// Create the `audit_entries` table and indexes if they do not exist.
    pub async fn migrate(pool: &PgPool) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_entries (
                id UUID PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                details JSONB NOT NULL,
                previous_hash TEXT NOT NULL,
                hash TEXT NOT NULL,
                sequence BIGINT GENERATED ALWAYS AS IDENTITY
            )",
        )
        .execute(pool)
        .await
        .map_err(|e| AuditError::Persistence(format!("migration failed: {e}")))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_entries (actor)")
            .execute(pool)
            .await
            .map_err(|e| AuditError::Persistence(format!("migration failed: {e}")))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_entries (action)")
            .execute(pool)
            .await
            .map_err(|e| AuditError::Persistence(format!("migration failed: {e}")))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_entries (resource)")
            .execute(pool)
            .await
            .map_err(|e| AuditError::Persistence(format!("migration failed: {e}")))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_entries (sequence)")
            .execute(pool)
            .await
            .map_err(|e| AuditError::Persistence(format!("migration failed: {e}")))?;

        Ok(())
    }

    async fn ensure_genesis(&self) -> Result<()> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_entries")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AuditError::Persistence(format!("genesis check: {e}")))?;
        if count.0 == 0 {
            let genesis = AuditEntry::new(
                "system",
                "log.created",
                "audit_log",
                serde_json::json!({}),
                &"0".repeat(64),
            );
            self.append(genesis).await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl AuditStore for PostgresStore {
    async fn append(&self, entry: AuditEntry) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_entries (id, timestamp, actor, action, resource, details, previous_hash, hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(entry.id)
        .bind(entry.timestamp)
        .bind(&entry.actor)
        .bind(&entry.action)
        .bind(&entry.resource)
        .bind(&entry.details)
        .bind(&entry.previous_hash)
        .bind(&entry.hash)
        .execute(&self.pool)
        .await
        .map_err(|e| AuditError::Persistence(format!("append: {e}")))?;
        Ok(())
    }

    async fn last_entry(&self) -> Result<Option<AuditEntry>> {
        Ok(sqlx::query_as::<_, AuditEntry>(
            "SELECT id, timestamp, actor, action, resource, details, previous_hash, hash
             FROM audit_entries ORDER BY sequence DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuditError::Persistence(format!("last_entry: {e}")))?)
    }

    async fn all_entries(&self) -> Result<Vec<AuditEntry>> {
        Ok(sqlx::query_as::<_, AuditEntry>(
            "SELECT id, timestamp, actor, action, resource, details, previous_hash, hash
             FROM audit_entries ORDER BY sequence ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuditError::Persistence(format!("all_entries: {e}")))?)
    }

    async fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>> {
        let all = self.all_entries().await?;
        let mut results: Vec<AuditEntry> = all.into_iter().filter(|e| query.matches(e)).collect();
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }
        Ok(results)
    }

    async fn count(&self) -> Result<usize> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_entries")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AuditError::Persistence(format!("count: {e}")))?;
        Ok(row.0 as usize)
    }
}
