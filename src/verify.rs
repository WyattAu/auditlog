use crate::entry::AuditEntry;

/// Result of verifying an audit chain.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationResult {
    /// Total number of entries checked.
    pub total_entries: usize,
    /// Number of valid entries.
    pub valid_entries: usize,
    /// Index of the first broken entry, if any.
    pub broken_at: Option<usize>,
    /// Description of the failure, if any.
    pub error: Option<String>,
}

impl VerificationResult {
    /// Returns true if the entire chain is valid.
    pub fn is_valid(&self) -> bool {
        self.broken_at.is_none()
    }
}

/// Verifies the integrity of an audit log chain.
pub struct AuditChain;

impl AuditChain {
    /// Verifies a sequence of audit entries.
    ///
    /// Checks that:
    /// 1. Each entry's hash is correctly computed
    /// 2. Each entry's `previous_hash` matches the prior entry's `hash`
    /// 3. The genesis entry's `previous_hash` is the zero hash
    pub fn verify(entries: &[AuditEntry]) -> VerificationResult {
        let zero_hash = "0".repeat(64);

        if entries.is_empty() {
            return VerificationResult {
                total_entries: 0,
                valid_entries: 0,
                broken_at: None,
                error: None,
            };
        }

        let mut valid_count = 0;

        for (i, entry) in entries.iter().enumerate() {
            // Check hash computation
            if !entry.verify_hash() {
                return VerificationResult {
                    total_entries: entries.len(),
                    valid_entries: valid_count,
                    broken_at: Some(i),
                    error: Some(format!(
                        "Entry {i}: hash mismatch (expected '{}', got '{}')",
                        entry.compute_hash(),
                        entry.hash
                    )),
                };
            }

            // Check chain linkage
            if i == 0 {
                // Genesis entry must have zero previous hash
                if entry.previous_hash != zero_hash {
                    return VerificationResult {
                        total_entries: entries.len(),
                        valid_entries: valid_count,
                        broken_at: Some(i),
                        error: Some(format!(
                            "Entry {i}: genesis entry has non-zero previous_hash '{}'",
                            entry.previous_hash
                        )),
                    };
                }
            } else {
                // Non-genesis entries must link to the previous entry's hash
                let expected_prev = entries[i - 1].hash.clone();
                if entry.previous_hash != expected_prev {
                    return VerificationResult {
                        total_entries: entries.len(),
                        valid_entries: valid_count,
                        broken_at: Some(i),
                        error: Some(format!(
                            "Entry {i}: previous_hash '{}' does not match entry {} hash '{}'",
                            entry.previous_hash,
                            i - 1,
                            expected_prev
                        )),
                    };
                }
            }

            valid_count += 1;
        }

        VerificationResult {
            total_entries: entries.len(),
            valid_entries: valid_count,
            broken_at: None,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis_entry() -> AuditEntry {
        AuditEntry::new("system", "start", "system", serde_json::json!({}), &"0".repeat(64))
    }

    fn chained_entry(prev: &AuditEntry, actor: &str, action: &str) -> AuditEntry {
        AuditEntry::new(actor, action, "resource", serde_json::json!({}), &prev.hash)
    }

    #[test]
    fn test_valid_chain() {
        let e1 = genesis_entry();
        let e2 = chained_entry(&e1, "alice", "create");
        let e3 = chained_entry(&e2, "bob", "update");

        let result = AuditChain::verify(&[e1, e2, e3]);
        assert!(result.is_valid());
        assert_eq!(result.total_entries, 3);
        assert_eq!(result.valid_entries, 3);
    }

    #[test]
    fn test_empty_chain() {
        let result = AuditChain::verify(&[]);
        assert!(result.is_valid());
        assert_eq!(result.total_entries, 0);
    }

    #[test]
    fn test_tampered_entry() {
        let mut e1 = genesis_entry();
        let e2 = chained_entry(&e1, "alice", "create");

        // Tamper with e1 after e2 was created
        e1.action = "destroy".to_string();

        let result = AuditChain::verify(&[e1, e2]);
        assert!(!result.is_valid());
        assert_eq!(result.broken_at, Some(0));
    }

    #[test]
    fn test_broken_chain_link() {
        let e1 = genesis_entry();
        let e2 = chained_entry(&e1, "alice", "create");

        // Create an entry that claims to follow e1 but with wrong previous_hash
        let mut e3 = AuditEntry::new("bob", "update", "resource", serde_json::json!({}), &"0".repeat(64));
        e3.previous_hash = "wrong_hash".to_string();
        e3.hash = e3.compute_hash();

        let result = AuditChain::verify(&[e1, e2, e3]);
        assert!(!result.is_valid());
        assert_eq!(result.broken_at, Some(2));
    }
}
