# Database

PiHole-AI stores runtime state in its own SQLite database. It reads the Pi-hole
FTL database as an external read-only input.

## Current Schema

Latest supported schema version: `13`.

Registered migrations:

| Version | Name |
| --- | --- |
| 1 | `baseline_current_schema` |
| 2 | `decision_evidence` |
| 3 | `decision_records` |
| 4 | `action_audit_decision_ref` |
| 5 | `immutable_decision_history` |
| 6 | `threat_intel_feed_management` |
| 7 | `threat_intel_reactivation_audit` |
| 8 | `threat_intel_remote_generation_state` |
| 9 | `repair_remote_generation_identity` |
| 10 | `threat_intel_operational_metadata` |
| 11 | `ai_reliability_pipeline_telemetry` |
| 12 | `ai_benchmark_history` |
| 13 | `ai_confidence_calibration` |

The migration registry lives in `core/migrations.py`. Versions must be unique,
ascending, non-empty, and contiguous unless a gap is explicitly documented.

## PiHole-AI Tables

- `events`: normalized DNS query events copied from Pi-hole.
- `domain_memory`: observed domain history.
- `analysis`: compatibility table for latest per-domain analysis.
- `decision_records`: latest structured final decision per domain, kept as a
  compatibility projection.
- `decision_evidence`: latest bounded supporting evidence, kept as a
  compatibility projection.
- `decision_history`: append-only immutable historical decisions.
- `decision_history_evidence`: evidence linked to one immutable decision ID.
- `action_audit`: actions, feedback, and decision references.
- `domain_rules`: manual allow/block rules.
- `domain_reputation`: learned local reputation.
- `threat_intel`: compatibility table for manually imported indicators.
- `threat_intel_sources`: configured threat-intelligence feeds.
- `threat_intel_source_state`: active generation, remote representation
  generation, validators, update status, HTTP status, parse counters, and
  last-update operational metadata per feed.
- `threat_intel_generations`: immutable imported feed generations.
- `threat_intel_generation_entries`: domains linked to one generation, with
  optional expiration metadata.
- `threat_intel_update_audit`: feed update/rollback/reactivation audit trail.
- `pipeline_telemetry_runs`: sidecar analysis/cache run telemetry.
- `pipeline_telemetry_stages`: sidecar per-classifier execution telemetry.
- `benchmark_runs`: persisted offline evaluation runs, fixture digests, model
  and prompt identity, threshold metadata, status, and summary metrics.
- `benchmark_results`: per-sample benchmark predictions, correctness flags,
  latency, classifier source, and optional telemetry linkage.
- `calibration_profiles`: reporting-only confidence calibration profiles built
  from completed benchmark runs.
- `calibration_bins`: persisted per-profile confidence bins with observed
  accuracy, calibration error inputs, and Brier components.
- `schema_migrations`: applied migration history.
- `app_state`: small runtime state values.

## Migration Behavior

Migrations run transactionally. Future schema versions are rejected rather than
downgraded. Lifecycle rollback does not automatically downgrade database
schemas.

## Evidence And Legacy Behavior

Fresh v0.5 decisions persist append-only immutable history first, then update
the latest compatibility projection. Legacy rows in `analysis` remain readable;
explain output marks them as legacy when no structured decision record exists.

Each new decision receives an opaque `dec_<uuid4hex>` identifier. Feedback and
action audit rows reference that exact decision when available. Retention never
deletes the latest decision for a domain or decisions referenced by feedback.

## Backup

Back up `/var/lib/pihole-ai/events.db` before upgrade, purge, or manual schema
experiments. PiHole-AI does not currently provide an automatic backup/restore
command.

## Decision-History Retention

Retention is explicit:

```bash
pihole-ai maintenance decision-history --dry-run
pihole-ai maintenance decision-history
```

Defaults:

- `PIHOLE_AI_DECISION_HISTORY_RETENTION_DAYS=365`
- `PIHOLE_AI_DECISION_HISTORY_MAX_PER_DOMAIN=100`

Retention preserves the latest decision for each domain and any decision
referenced by feedback/audit rows. Evidence rows are deleted with their decision
transactionally.

## Threat-Intelligence Feeds

Threat-intelligence updates use generation-based activation. A downloaded feed
is parsed into a new generation, quality checks run before activation, and only
the active generation for enabled sources participates in classification.
Manual `intel import-hosts` remains supported and is mirrored into a managed
legacy generation so older workflows continue to work.

Source state intentionally separates `active_generation` from
`remote_generation_id`. The active generation is what classifiers read; the
remote generation is the last successfully fetched representation described by
HTTP validators. This allows rollback to a prior generation and later
HTTP-304 reactivation of the unchanged remote generation without duplicating
rows.

`core.db.check_threat_intel_integrity()`,
`core.db.threat_intel_stats()`, and `core.db.threat_intel_diagnostics()`
inspect managed feed state through read-only database connections. They are
used by status, health, doctor, and dashboard views; they do not initialize,
migrate, repair, fetch feeds, or mutate data.

## AI Reliability Data

Pipeline telemetry and benchmark history are sidecar data. They measure how a
decision was produced, but they do not alter classifier ordering, thresholds,
AI invocation rules, cache behavior, or enforcement actions.

Confidence calibration profiles are also reporting-only. A profile records raw
confidence bins from a completed benchmark run and the observed accuracy in
each bin. Active profiles are used by explain, reliability metrics, and the
dashboard to show calibrated confidence alongside the original raw confidence.
The raw confidence remains the authoritative runtime value.

Profile activation is scoped by classifier source, model, and prompt version so
separate reporting profiles can coexist where enough benchmark samples exist.
Feedback-based calibration is intentionally unavailable until feedback rows have
trustworthy labeled-sample linkage.
