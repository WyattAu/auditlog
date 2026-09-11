# Threat Model — auditlog

Reference: STRIDE. Scope: the crate's public API surface. Trust boundary:
(1) bytes/inputs entering public constructors and parsers, (2) concurrent
callers sharing interior state. auditlog is an in-process library — it opens
no sockets and inherits the embedding process's trust domain.

Purpose: Tamper-evident audit log (`tamper-audit`) — hash-chained, append-only event records

## Assets

| ID | Asset | Exposed via |
|----|-------|-------------|
| A1 | integrity/detectability of the audit chain | hostile input, concurrent callers |
| A2 | availability of append under concurrency | hostile input, concurrent callers |

## STRIDE Analysis

| # | Threat | Category | Surface | Mitigation | Residual risk |
|---|--------|----------|---------|------------|---------------|
| T1 | Silent record tampering | Tampering | `stored chain` | SHA-256 hash chaining; `verify` walks the full chain (mutation detectable unless hashes recomputed through head) | documented |
| T2 | Chain truncation (delete recent history) | Repudiation | `storage` | truncation is detectable by verifier holding the earlier head hash | documented |
| T3 | Lock poisoning stalls audit writes | DoS | `in-memory log` | poison-tolerant lock acquisition (`.unwrap_or_else(into_inner)` semantics) | documented |
| T4 | Deny: attacker rewrites entire chain including head | Tampering | `storage host` | **Not mitigated** — storage-level compromise requires external anchoring (out of scope, documented) | documented |

## Repudiation

The crate keeps no audit trail; attribution of calls to callers is out of
scope for an in-process library.

## Out of Scope

- Network transport security (the crate never opens sockets).
- Storage-host compromise: an attacker who controls the host can bypass all
  in-process mitigations.
- Denial of service via resource exhaustion of the host process beyond the
  bounds enforced above.

Reviewed: 2026-09-11
