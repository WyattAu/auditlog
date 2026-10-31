# Changelog

All notable changes are documented here.

## [0.2.3] - 2026-10-24

### Added

- `FileStore`: a JSONL file backend for the audit store; the desktop's
  durable trail. One serialized entry per line; appends are O(1) and
  flushed per write; a corrupt line is refused at log open, naming the
  line. `AuditLog::with_store(FileStore::new(path))` continues an
  existing chain across restarts, and the chain verifies end to end
  after a reopen. Five integration tests cover the roundtrip, the
  cross-restart verification, queries, first-open directory creation,
  and the corrupt-line refusal.

## [0.2.0] - 2026-09-11

### Fixed

- 22-gate quality audit pass: documentation completeness
  (README badges, REQUIREMENTS/THREAT-MODEL coverage) and
  feature-gated test hygiene.


All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/); versions follow [semver](https://semver.org).

## [0.1.0] - 2026-06-07

### Added
- Initial public release.
