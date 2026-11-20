# PATTERN_ADOPTION

auditlog (package `tamper-audit`) declares its relationship to the
WyattAu pattern canon (`WyattAu/pattern-standards`). Validation:
`scripts/adoption-check.py` in the canon repo; format:
`references/adoption-format.md`.

| Pattern | Status | Evidence |
|---|---|---|
| P83 | adopted | src/entry.rs:58 (entry hash covers id, timestamp, actor, action, resource, details, previous_hash) + src/log.rs:50 (append links each entry to the prior hash) + src/verify.rs:31 (full-chain walk checks linkage and the genesis zero hash) + src/postgres.rs:34 (chained schema, previous_hash NOT NULL) |
| T21 | partial | src/store.rs:11 (AuditStore is append-only: no update or delete methods) + src/entry.rs:6 (entries immutable); the log preserves history but nothing replays events into application state |

Scope note: this crate is a tamper-evident event log with in-memory,
file, and Postgres backends; patterns outside the two rows above do
not apply.
