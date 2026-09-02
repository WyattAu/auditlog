//! Property-based tests for tamper-audit crate.

use proptest::prelude::*;

use tamper_audit::{AuditEntry, AuditLog};

#[test]
fn entry_hash_always_64_hex_chars() {
    proptest!(|(
        actor in "[a-z]{1,20}",
        action in "[a-z]{1,20}",
        resource in "[a-z0-9/]{1,30}",
    )| {
        let genesis = "0".repeat(64);
        let entry = AuditEntry::new(
            &actor, &action, &resource,
            serde_json::json!({}), &genesis,
        );
        prop_assert_eq!(entry.hash.len(), 64);
        prop_assert!(entry.hash.chars().all(|c| c.is_ascii_hexdigit()));
    });
}

#[test]
fn entry_always_verifies_own_hash() {
    proptest!(|(
        actor in "[a-z]{1,20}",
        action in "[a-z]{1,20}",
        resource in "[a-z0-9/]{1,30}",
    )| {
        let genesis = "0".repeat(64);
        let entry = AuditEntry::new(
            &actor, &action, &resource,
            serde_json::json!({}), &genesis,
        );
        prop_assert!(entry.verify_hash());
    });
}

#[test]
fn chained_entries_form_valid_chain() {
    proptest!(|(actions in prop::collection::vec("[a-z]{1,10}", 1..20))| {
        let mut log = AuditLog::new();
        for action in &actions {
            log.append(
                "test-user", action, "resource/1",
                serde_json::json!({"seq": actions.len()}),
            ).unwrap();
        }
        let result = log.verify_chain();
        prop_assert!(result.is_valid());
    });
}

#[test]
fn tampered_entry_fails_verification() {
    proptest!(|(
        actor in "[a-z]{1,20}",
        action in "[a-z]{1,20}",
        resource in "[a-z0-9/]{1,30}",
        new_action in "[a-z]{1,20}",
    )| {
        prop_assume!(action != new_action);
        let genesis = "0".repeat(64);
        let mut entry = AuditEntry::new(
            &actor, &action, &resource,
            serde_json::json!({}), &genesis,
        );
        // Tamper without recomputing: verify_hash should fail
        entry.action = new_action;
        prop_assert!(!entry.verify_hash(),
            "tampered entry must fail hash verification");
    });
}

#[test]
fn entry_previous_hash_preserved() {
    proptest!(|(
        actor in "[a-z]{1,20}",
        action in "[a-z]{1,20}",
        resource in "[a-z0-9/]{1,30}",
    )| {
        let genesis = "0".repeat(64);
        let entry = AuditEntry::new(
            &actor, &action, &resource,
            serde_json::json!({}), &genesis,
        );
        prop_assert_eq!(entry.previous_hash, genesis);
    });
}

#[test]
fn entry_id_always_valid_uuid() {
    proptest!(|(
        actor in "[a-z]{1,20}",
        action in "[a-z]{1,20}",
    )| {
        let genesis = "0".repeat(64);
        let entry = AuditEntry::new(
            &actor, &action, "resource",
            serde_json::json!({}), &genesis,
        );
        prop_assert!(!entry.id.is_nil());
        let uuid_str = entry.id.to_string();
        prop_assert_eq!(uuid_str.len(), 36);
    });
}
