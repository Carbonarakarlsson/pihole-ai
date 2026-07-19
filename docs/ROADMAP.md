# Roadmap

PiHole-AI is moving from validated beta capabilities toward a stable local
Pi-hole companion appliance. The v0.5 line focuses on making the appliance
easy to install, operate, inspect, and trust on Raspberry Pi-class hardware.

For architecture and operational details, see:

- [Architecture](ARCHITECTURE.md)
- [CLI Reference](CLI_REFERENCE.md)
- [Database](DATABASE.md)
- [Operations](OPERATIONS.md)

## Completed Work

### Epic 3.2: SQLite Lifecycle

Epic 3.2 hardened the runtime database layer so appliance services can share
SQLite safely and predictably.

Delivered:

- centralized SQLite policy in `core/sqlite_policy.py`
- explicit read-only, read-write, and migration connection modes
- connection factory ownership for runtime and migration access
- WAL lifecycle ownership limited to migration mode
- migration locking and busy-timeout behavior
- deterministic connection cleanup
- schema and database diagnostics for health, doctor, setup, and status

### Epic 3.3: Threat Intelligence

Epic 3.3 made threat intelligence manageable as appliance data rather than a
manual import experiment.

Delivered:

- managed threat-intelligence feeds and source state
- generation-based activation, rollback, and unchanged-content handling
- reputation-aware classification integration
- dashboard visibility for feed state and intelligence summaries
- explain output that can show threat-intelligence evidence
- feedback and action audit linkage to stored decisions
- metrics and diagnostics for feed health, active indicators, and integrity

### Epic 3.4: AI Reliability

Epic 3.4 made AI-assisted decisions measurable, explainable, and comparable
without changing runtime classification policy.

Delivered:

- observational pipeline telemetry
- richer explainability for classifier timelines and AI invocation state
- persisted benchmark runs and deterministic regression comparison
- confidence calibration profiles for reporting
- reliability metrics for accuracy, confidence, latency, cache use, and AI use
- dashboard reliability views and read-only APIs
- official PiHole-AI branding across the dashboard, README, favicon, and wheel
- prepared `v0.5.0rc1` release-candidate documentation and validation

## Current Epic

### Epic 3.5: Operations & User Experience

Goal: transform PiHole-AI into a production-ready appliance that is easy to
install, configure, maintain, monitor, and upgrade.

Epic 3.5 is documentation-, operator-, and dashboard-heavy. Runtime behavior
changes should remain conservative and appliance-safe.

#### Phase 1: Configuration Center

Planned features:

- Phase 1A internal framework: typed schema registry, reusable validation,
  preserving `.env` parser/writer, atomic write primitives, masking,
  restart-impact metadata, and deterministic import/export primitives
- Phase 1B read-only CLI: `config show`, `config get`, `config validate`, and
  `config impact`
- Phase 1C1 safe editing CLI: `config set` and `config unset` with dry-run,
  confirmation, validation, backups, and restart-impact preview
- Phase 1C2 import/export CLI: deterministic JSON/env exports, explicit secure
  exports, validated imports, dry-run previews, backups, and rollback safety
- Phase 1C3 restart orchestration: optional `--restart` for successful config
  writes, affected-service planning, dry-run previews, and recovery guidance
- Phase 1D dashboard Configuration API: authenticated/CSRF-protected backend
  endpoints for inventory, validation, guarded writes, impact previews,
  normal exports, and imports
- Phase 1E dashboard Settings UI: category browsing, source/override display,
  secret replace/unset controls, validation, dry-run preview, guarded saves,
  optional restart, import/export, and revision-conflict recovery
- Phase 2A configuration migration support: version detection, ordered
  migration planning, legacy alias normalization, schema marker persistence,
  atomic writes, backups, CLI migration workflow, and dashboard
  migration-required errors
- Phase 2B installer and appliance integration: fresh schema-versioned config
  creation, install/upgrade validation gates, legacy migration-required aborts,
  config-aware status output, and explicit uninstall config preservation or
  removal
- Phase 2C appliance integration coverage: temporary-root lifecycle tests,
  CLI/dashboard consistency, migration round trips, import/export, secret
  masking, restart orchestration, partial-install recovery, and isolation
  assertions
- Phase 2D release hardening: administrator guide, release checklist, upgrade
  validation checklist, examples, changelog, packaging metadata review, and RC
  version alignment
- named configuration profiles
- restart-aware changes that clearly show when services must restart

Design: [Configuration Center Design](CONFIGURATION_DESIGN.md).

#### Phase 2: Maintenance

Planned features:

- backup command and dashboard visibility
- restore workflow with safety checks
- cleanup for bounded local data
- SQLite vacuum workflow
- integrity checks for database, feed, decision, and telemetry state

#### Phase 3: Monitoring

Planned features:

- live service status
- Ollama status
- processing queue depth
- cache metrics
- throughput summaries
- trend views for activity, latency, and reliability

#### Phase 4: Installer Experience

Planned features:

- guided install
- guided upgrade
- rollback assistance
- preflight and post-upgrade health checks
- clearer appliance readiness guidance

#### Phase 5: Dashboard Polish

Planned features:

- improved dashboard UX
- responsive layout refinement
- global and table-specific search
- filtering
- pagination
- notifications for settings, maintenance, and service events

## Future Epics

### Epic 3.6: Automation

Proposed work:

- scheduled maintenance
- scheduled reports
- automatic backups
- telemetry retention
- calibration and benchmark retention policies

### Epic 3.7: Plugin Architecture

Proposed work:

- external classifiers
- custom actions
- extension points for local workflows
- documented plugin contracts
- isolation and safety rules for third-party extensions

### Epic 3.8: Enterprise

Proposed work:

- multi-instance support
- remote management
- authentication improvements
- fleet management
- organization-level policy and reporting

## Version Roadmap

```text
v0.5.x
Operations & UX

↓

v0.6
Feature-complete beta

↓

v0.7
Performance & Scale

↓

v0.8
Release Candidate

↓

v1.0
Stable
```

## v1.0 Definition

PiHole-AI should reach v1.0 when:

- appliance install, upgrade, rollback, backup, and restore are documented and
  field-tested
- core dashboard workflows are usable on desktop and mobile
- runtime health and setup status are clear enough for non-developer operation
- database migrations remain additive, idempotent, and recoverable
- AI remains optional and local-first
- threat-intelligence and reputation behavior are explainable and auditable
- release artifacts can be installed cleanly from a stable appliance
  environment
