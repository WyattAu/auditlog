//! FileStore tests: the durable desktop trail — append, read back, verify
//! the chain across a reopen, and query. Unwrap/expect are the test signal
//! here; a poisoned lock in a single-threaded-per-file backend is the bug.

use std::path::PathBuf;

use tamper_audit::{AuditLog, AuditQuery, FileStore};

fn trail_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tamper-audit-file-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("trail.jsonl")
}

fn entry(actor: &str, action: &str) -> tamper_audit::AuditEntry {
    tamper_audit::AuditEntry::new(actor, action, "doc.pdf", serde_json::json!({"n": 1}), "0")
}

#[tokio::test]
async fn appends_are_json_lines_read_back_in_order() {
    let path = trail_path("roundtrip");
    let log = AuditLog::with_store(FileStore::new(path.clone())).await.expect("log opens");
    log.append("alice", "doc.opened", "doc.pdf", serde_json::json!({})).await.expect("append 1");
    log.append("bob", "doc.exported", "doc.pdf", serde_json::json!({})).await.expect("append 2");

    // The genesis anchor plus the two appends.
    assert_eq!(log.len().await.expect("len"), 3);

    // A fresh log over the same file sees every entry: the trail survives restarts.
    let reopened = AuditLog::with_store(FileStore::new(path.clone())).await.expect("reopens");
    assert_eq!(reopened.len().await.expect("len"), 3);
    let last = reopened.last_entry().await.expect("last").expect("an entry");
    assert_eq!(last.actor, "bob");
    assert_eq!(last.action, "doc.exported");

    // The raw file is JSONL: one JSON object per line.
    let raw = std::fs::read_to_string(&path).expect("read");
    assert_eq!(raw.lines().count(), 3, "one JSON object per line: {raw}");
    for line in raw.lines() {
        assert!(line.starts_with('{') && line.ends_with('}'), "JSON object per line: {line}");
    }
}

#[tokio::test]
async fn the_chain_verifies_across_a_reopen() {
    let path = trail_path("verify");
    {
        let log = AuditLog::with_store(FileStore::new(path.clone())).await.expect("log opens");
        for action in ["doc.opened", "doc.edited", "doc.exported"] {
            log.append("alice", action, "doc.pdf", serde_json::json!({})).await.expect("append");
        }
    }
    // A brand-new log over the same file: the chain still verifies end to end.
    let reopened = AuditLog::with_store(FileStore::new(path)).await.expect("reopens");
    let verification = reopened.verify_chain().await.expect("verify runs");
    assert!(verification.is_valid(), "{verification:?}");
}

#[tokio::test]
async fn queries_filter_actor_action_and_limit() {
    let path = trail_path("query");
    let log = AuditLog::with_store(FileStore::new(path)).await.expect("log opens");
    for (actor, action) in [("alice", "doc.opened"), ("alice", "doc.exported"), ("bob", "doc.opened")] {
        log.append(actor, action, "doc.pdf", serde_json::json!({})).await.expect("append");
    }

    let by_actor = log
        .query(&AuditQuery { actor: Some("alice".into()), ..Default::default() })
        .await
        .expect("query");
    assert_eq!(by_actor.len(), 2, "alice's two entries");

    let by_action = log
        .query(&AuditQuery { action: Some("doc.opened".into()), ..Default::default() })
        .await
        .expect("query");
    assert_eq!(by_action.len(), 2, "both opens");

    let limited = log
        .query(&AuditQuery { actor: Some("alice".into()), limit: Some(1), ..Default::default() })
        .await
        .expect("query");
    assert_eq!(limited.len(), 1, "the limit truncates");
}

#[tokio::test]
async fn a_missing_file_is_an_empty_log_and_the_parent_directory_is_created() {
    let dir = std::env::temp_dir().join(format!("tamper-audit-file-new-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("nested").join("trail.jsonl");

    let log = AuditLog::with_store(FileStore::new(path.clone())).await.expect("log opens");
    // The log inserts the genesis anchor at once: an empty store is a one-entry log.
    assert_eq!(log.len().await.expect("len"), 1, "the genesis anchor");
    log.append("system", "doc.opened", "audit_log", serde_json::json!({})).await.expect("append");
    assert_eq!(log.len().await.expect("len"), 2);

    assert!(path.is_file(), "the append created the parent directories and the file");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_corrupt_line_is_a_serialization_error_naming_the_line() {
    let path = trail_path("corrupt");
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create");
    // Line 1: a real entry (serialized from the type). Line 2: not JSON.
    let real = entry("alice", "doc.opened");
    let real_line = serde_json::to_string(&real).expect("serialize");
    std::fs::write(&path, format!("{real_line}\nNOT-JSON\n")).expect("write");

    // The log refuses to open a corrupt trail, naming the offending line.
    let err = match AuditLog::with_store(FileStore::new(path)).await {
        Ok(_) => panic!("a corrupt trail is refused at open"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("line 2"), "{err}");
}
