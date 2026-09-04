use criterion::{Criterion, criterion_group, criterion_main};
use tamper_audit::{AuditChain, AuditEntry, AuditLog, AuditQuery};

fn bench_audit_entry_creation(c: &mut Criterion) {
    let genesis_hash = "0".repeat(64);
    c.bench_function("audit_entry_creation", |b| {
        b.iter(|| {
            AuditEntry::new(
                "alice",
                "create",
                "user/1",
                serde_json::json!({"name": "Alice"}),
                &genesis_hash,
            )
        });
    });
}

fn bench_audit_entry_compute_hash(c: &mut Criterion) {
    let entry = AuditEntry::new(
        "alice",
        "create",
        "user/1",
        serde_json::json!({}),
        &"0".repeat(64),
    );
    c.bench_function("audit_entry_compute_hash", |b| {
        b.iter(|| entry.compute_hash());
    });
}

fn bench_audit_entry_verify_hash(c: &mut Criterion) {
    let entry = AuditEntry::new(
        "alice",
        "create",
        "user/1",
        serde_json::json!({}),
        &"0".repeat(64),
    );
    c.bench_function("audit_entry_verify_hash", |b| {
        b.iter(|| entry.verify_hash());
    });
}

fn bench_audit_log_new(c: &mut Criterion) {
    c.bench_function("audit_log_new", |b| {
        b.iter(|| AuditLog::new());
    });
}

fn bench_audit_log_append(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    c.bench_function("audit_log_append", |b| {
        b.iter(|| {
            rt.block_on(async {
                let log = AuditLog::new();
                log.append("alice", "create", "user/1", serde_json::json!({}))
                    .await
                    .unwrap();
            });
        });
    });
}

fn bench_audit_log_append_chained(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    c.bench_function("audit_log_append_chained", |b| {
        b.iter(|| {
            rt.block_on(async {
                let log = AuditLog::new();
                log.append("alice", "create", "user/1", serde_json::json!({}))
                    .await
                    .unwrap();
                log.append(
                    "bob",
                    "update",
                    "user/1",
                    serde_json::json!({"name": "Bob"}),
                )
                .await
                .unwrap();
            });
        });
    });
}

fn bench_audit_chain_verify_small(c: &mut Criterion) {
    let entries = create_chain(10);
    c.bench_function("audit_chain_verify_small", |b| {
        b.iter(|| AuditChain::verify(&entries));
    });
}

fn bench_audit_chain_verify_medium(c: &mut Criterion) {
    let entries = create_chain(100);
    c.bench_function("audit_chain_verify_medium", |b| {
        b.iter(|| AuditChain::verify(&entries));
    });
}

fn bench_audit_chain_verify_large(c: &mut Criterion) {
    let entries = create_chain(1000);
    c.bench_function("audit_chain_verify_large", |b| {
        b.iter(|| AuditChain::verify(&entries));
    });
}

fn bench_audit_query_by_actor(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let log = rt.block_on(async {
        let log = AuditLog::new();
        for i in 0..100 {
            let actor = if i % 2 == 0 { "alice" } else { "bob" };
            log.append(actor, "create", "resource", serde_json::json!({}))
                .await
                .unwrap();
        }
        log
    });
    c.bench_function("audit_query_by_actor", |b| {
        b.iter(|| rt.block_on(log.query_by_actor("alice")));
    });
}

fn bench_audit_query_by_action(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let log = rt.block_on(async {
        let log = AuditLog::new();
        for i in 0..100 {
            let action = if i % 3 == 0 {
                "create"
            } else if i % 3 == 1 {
                "update"
            } else {
                "delete"
            };
            log.append("user", action, "resource", serde_json::json!({}))
                .await
                .unwrap();
        }
        log
    });
    c.bench_function("audit_query_by_action", |b| {
        b.iter(|| rt.block_on(log.query_by_action("create")));
    });
}

fn bench_audit_query_by_resource(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let log = rt.block_on(async {
        let log = AuditLog::new();
        for i in 0..100 {
            let resource = format!("resource/{}", i % 10);
            log.append("user", "update", resource, serde_json::json!({}))
                .await
                .unwrap();
        }
        log
    });
    c.bench_function("audit_query_by_resource", |b| {
        b.iter(|| rt.block_on(log.query_by_resource("resource/5")));
    });
}

fn bench_audit_structured_query(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let log = rt.block_on(async {
        let log = AuditLog::new();
        for _i in 0..100 {
            log.append("alice", "create", "user/1", serde_json::json!({}))
                .await
                .unwrap();
            log.append("bob", "update", "user/2", serde_json::json!({}))
                .await
                .unwrap();
        }
        log
    });
    let query = AuditQuery::new().by_actor("alice").by_action("create");
    c.bench_function("audit_structured_query", |b| {
        b.iter(|| rt.block_on(log.query(&query)));
    });
}

fn create_chain(length: usize) -> Vec<AuditEntry> {
    let mut entries = Vec::with_capacity(length + 1);
    let genesis = AuditEntry::new(
        "system",
        "log.created",
        "audit_log",
        serde_json::json!({}),
        &"0".repeat(64),
    );
    entries.push(genesis);

    for i in 0..length {
        let prev_hash = entries.last().unwrap().hash.clone();
        let entry = AuditEntry::new(
            "user",
            "action",
            format!("resource/{i}"),
            serde_json::json!({}),
            &prev_hash,
        );
        entries.push(entry);
    }
    entries
}

criterion_group!(
    benches,
    bench_audit_entry_creation,
    bench_audit_entry_compute_hash,
    bench_audit_entry_verify_hash,
    bench_audit_log_new,
    bench_audit_log_append,
    bench_audit_log_append_chained,
    bench_audit_chain_verify_small,
    bench_audit_chain_verify_medium,
    bench_audit_chain_verify_large,
    bench_audit_query_by_actor,
    bench_audit_query_by_action,
    bench_audit_query_by_resource,
    bench_audit_structured_query,
);
criterion_main!(benches);
