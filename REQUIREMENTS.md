# Requirements — auditlog

Numbered, testable requirements. Every requirement maps to at least one named
test or doc-comment contract; security-relevant items cite threat-model rows.

Scope: Tamper-evident audit log (`tamper-audit`) — hash-chained, append-only event records

## Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-TA-001 | Each record's hash chains from its predecessor; `verify` detects any single-record mutation | MUST |
| REQ-TA-002 | Append is atomic under concurrent writers (poison-tolerant locking) | MUST |
| REQ-TA-003 | Verification over a truncated chain reports the first bad index | MUST |

## Security

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-TA-100 | Chain hashes use SHA-256; genesis record is fixed and verifiable | MUST |
| REQ-TA-101 | Events serialize attacker-controlled payloads as opaque bytes (no execution context) | MUST |

## Observability & API hygiene

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-TA-900 | All fallible public APIs return typed errors; production `unwrap`/`expect` is denied or explicitly justified with an invariant comment | MUST |
| REQ-TA-901 | Public items carry doc comments with runnable examples where practical | SHOULD |
