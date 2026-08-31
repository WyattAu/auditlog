# tamper-audit

Tamper-evident audit logging for Rust — SHA-256 chain, immutable entries, and queryable audit trail.

## Features

- **SHA-256 chain** — Each entry's hash links to the previous, creating a tamper-evident chain
- **Immutable entries** — Once created, entries cannot be modified without detection
- **Queryable** — Index-based lookups by actor, action, and resource
- **Chain verification** — Walk the entire chain to validate integrity
- **Zero dependencies** beyond `sha2`, `serde`, `chrono`, and `uuid`

## How It Works

Each audit entry contains:

1. A unique ID and timestamp
2. The actor, action, resource, and details
3. The SHA-256 hash of the **previous** entry
4. Its own SHA-256 hash (computed over all fields)

This creates a blockchain-like chain where modifying any entry breaks the hash linkage.

```
Entry 0 (genesis)          Entry 1                     Entry 2
┌─────────────────┐       ┌─────────────────┐        ┌─────────────────┐
│ previous: 000..0│       │ previous: hash0 │        │ previous: hash1 │
│ hash: hash0     │──────▶│ hash: hash1     │───────▶│ hash: hash2     │
│ actor: system   │       │ actor: alice    │        │ actor: bob      │
│ action: create  │       │ action: create  │        │ action: update  │
└─────────────────┘       └─────────────────┘        └─────────────────┘
```

## Quick Start

```rust
use auditlog::AuditLog;

let mut log = AuditLog::new();

// Append entries
log.append("alice", "login", "session/abc", serde_json::json!({"ip": "192.168.1.1"})).unwrap();
log.append("alice", "read", "document/42", serde_json::json!({})).unwrap();
log.append("alice", "logout", "session/abc", serde_json::json!({})).unwrap();

// Verify chain integrity
assert!(log.verify_chain().is_valid());

// Query entries
let alice_entries = log.query_by_actor("alice");
assert_eq!(alice_entries.len(), 3);

let logins = log.query_by_action("login");
assert_eq!(logins.len(), 1);
```

## Querying

```rust
use auditlog::{AuditLog, AuditQuery};

let mut log = AuditLog::new();
log.append("alice", "create", "user/1", serde_json::json!({})).unwrap();
log.append("bob", "update", "user/1", serde_json::json!({})).unwrap();
log.append("alice", "delete", "user/2", serde_json::json!({})).unwrap();

// Structured query
let query = AuditQuery::new()
    .by_actor("alice")
    .by_action("create");

let results = log.query(&query);
assert_eq!(results.len(), 1);
```

## Chain Verification

```rust
use auditlog::AuditLog;

let mut log = AuditLog::new();
log.append("alice", "create", "doc/1", serde_json::json!({})).unwrap();
log.append("bob", "update", "doc/1", serde_json::json!({})).unwrap();

let result = log.verify_chain();
assert!(result.is_valid());
assert_eq!(result.total_entries, 3); // includes genesis
```

## Tamper Detection

If an attacker modifies any entry, chain verification fails:

```rust
use auditlog::AuditLog;

let mut log = AuditLog::new();
log.append("alice", "create", "doc/1", serde_json::json!({})).unwrap();
log.append("bob", "update", "doc/1", serde_json::json!({})).unwrap();

// Verify chain is valid
assert!(log.verify_chain().is_valid());
```

Modifying an entry would cause the hash to mismatch, detected by `verify_chain()`.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
