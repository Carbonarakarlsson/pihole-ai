# Epic 3.3: Threat Intelligence Feed Management

## Objective

Make managed threat-intelligence feeds appliance-ready for automatic,
multi-source operation. The current implementation already has the core
generation-based feed engine; Epic 3.3 should close the operational gaps that
make a fresh appliance report `threat_intel: 0` until a user manually adds and
updates sources.

This document began as the implementation-ready design plan. The production
implementation now follows the phased approach below.

## Implementation Status

Implemented in the `v0.5-epic3.3` development branch:

- schema migration 10, `threat_intel_operational_metadata`
- per-source operational metadata for HTTP status, byte counts, parser counts,
  warnings, duration, and optional indicator expiration
- read-only `pihole-ai intel sources` and `pihole-ai intel stats`
- single-source positional update support with existing `--source`
  compatibility
- read-only threat-intelligence stats and diagnostics helpers
- health, doctor, status, and dashboard visibility for feed freshness,
  failures, active indicators, and integrity issues

## Current-State Analysis

Verified implementation files:

- `pihole_ai/intel.py`
- `pihole_ai/intel_feeds.py`
- `pihole_ai/intel_models.py`
- `pihole_ai/cli.py`
- `core/db.py`
- `core/migrations.py`
- `core/sqlite_policy.py`
- `engine/classifiers/threat_intel.py`
- `engine/classifiers/pipeline.py`
- `pihole_ai/service.py`
- `core/config.py`
- `pihole_ai/defaults/pihole-ai.env`
- `.env.example`
- `pihole_ai/health.py`
- `pihole_ai/doctor.py`
- `ui/dashboard.py`
- `docs/adr/0003-generation-based-threat-intelligence.md`
- `docs/DATABASE.md`
- `docs/CONFIGURATION.md`
- `tests/test_intel.py`
- `tests/test_db.py`
- `tests/test_classifiers.py`
- `tests/test_migrations.py`
- `tests/test_cli.py`
- `tests/test_service.py`

Existing capabilities verified:

- Legacy manual import: `pihole-ai intel import-hosts`.
- Managed source table: `threat_intel_sources`.
- Per-source state table: `threat_intel_source_state`.
- Immutable generation table: `threat_intel_generations`.
- Generation entry table: `threat_intel_generation_entries`.
- Update audit table: `threat_intel_update_audit`.
- Migration version 6 creates managed feed tables.
- Migration versions 7-9 repair/update generation audit and remote-generation identity.
- Source metadata includes source ID, name, URL, format, enabled, category,
  confidence, refresh interval, stale interval, timeout, max bytes,
  expected content type, HTTP opt-in, created/updated timestamps.
- Source state includes status, last attempt, last success, next update, ETag,
  Last-Modified, content SHA-256, entry count, active generation,
  remote generation ID, last error, and consecutive failure count.
- Feed fetch sends `If-None-Match` and `If-Modified-Since` when validators exist.
- HTTP 304 is supported and can reactivate the remote generation after rollback.
- Feed replacement is generation-based and transactional.
- Failed downloads/parses preserve the last active generation.
- Identical downloaded content suppresses duplicate generation creation.
- Rollback restores a previous generation.
- Source enable/disable exists through `pihole-ai intel source enable|disable`.
- Single-source and multi-source updates exist through `pihole-ai intel update`
  with `--source`, `--all`, `--dry-run`, and `--non-interactive`.
- The appliance generates `pihole-ai-intel-update.service` and
  `pihole-ai-intel-update.timer`.
- The timer runs the oneshot command:
  `python -m pihole_ai.cli intel update --all --non-interactive`.
- `PIHOLE_AI_INTEL_AUTO_UPDATE_ENABLED` gates automatic timer-triggered updates.
- `PIHOLE_AI_INTEL_ALLOW_HTTP=false` rejects HTTP by default.
- `PIHOLE_AI_INTEL_HTTP_TIMEOUT_SECONDS` sets explicit network timeout.
- `ThreatIntelClassifier` reads active generations from enabled sources.
- Classifier pipeline runs manual rules, reputation, threat intel, heuristics,
  then AI.
- Dashboard Intelligence page shows source count, enabled count, failed/stale
  count, and `/api/intel/sources`.
- Read-only diagnostics helper exists:
  `core.db.check_threat_intel_integrity()`.

## Identified Gaps

1. No default curated feed source catalog is configured during install, so a
   clean appliance can correctly report `threat_intel: 0`.
2. CLI naming does not expose the desired top-level plural workflows exactly:
   `pihole-ai intel sources` and `pihole-ai intel stats` do not exist. Existing
   commands are `intel source list` and `intel status`.
3. There is no first-class feed statistics command aggregating sources,
   entries, active generations, failures, stale sources, audit outcomes, and
   last update timing.
4. Health and doctor do not yet surface threat-intel freshness, integrity,
   source failures, empty active generations, or timer state as first-class
   diagnostics.
5. Dashboard visibility is read-only and minimal. It does not expose source
   actions, stats, last HTTP status, validators, or update/audit history.
6. `threat_intel_source_state` does not store `last_http_status`; HTTP status is
   only present in audit rows.
7. `threat_intel_source_state` does not persist last downloaded byte count,
   parsed/rejected/duplicate counts, or last warning summary.
8. There is no explicit per-entry expiration model. Entries only have
   `first_seen` and `last_seen`, and classification freshness uses source-level
   `stale_after_seconds`.
9. No pruning/retention exists for old inactive generations or expired entries.
10. `next_update_at` exists but is not consistently populated by update paths.
11. Automatic update behavior is disabled by default and the timer may be
    enabled but effectively no-op, which is safe but confusing without clear
    setup/status messaging.
12. Source enable/disable currently changes source config but does not record an
    explicit source-control audit event.

## Proposed Schema Changes

Recommended migration: **version 10**, e.g.
`threat_intel_operational_metadata`.

Add columns to `threat_intel_source_state`:

```sql
last_http_status INTEGER;
last_downloaded_bytes INTEGER NOT NULL DEFAULT 0;
last_parsed_entries INTEGER NOT NULL DEFAULT 0;
last_accepted_entries INTEGER NOT NULL DEFAULT 0;
last_rejected_entries INTEGER NOT NULL DEFAULT 0;
last_duplicate_entries INTEGER NOT NULL DEFAULT 0;
last_warnings_json TEXT NOT NULL DEFAULT '[]';
last_update_duration_ms INTEGER NOT NULL DEFAULT 0;
```

Add optional expiration metadata to `threat_intel_generation_entries`:

```sql
expires_at REAL;
```

Add optional generation lifecycle metadata:

```sql
-- threat_intel_generations
pruned_at REAL;
```

Add indexes:

```sql
CREATE INDEX IF NOT EXISTS idx_threat_intel_entries_expires_at
ON threat_intel_generation_entries(expires_at);

CREATE INDEX IF NOT EXISTS idx_threat_intel_state_status
ON threat_intel_source_state(status, last_success_at);
```

Do not remove or rewrite existing generation rows during migration. New columns
must be nullable/defaulted so upgrade is safe.

## Migration Strategy

1. Add migration 10 after `repair_remote_generation_identity`.
2. Use additive `ALTER TABLE` guarded by `PRAGMA table_info`.
3. Backfill operational counters from the most recent audit row per source where
   practical.
4. Leave `expires_at` null for existing entries.
5. Keep migration transactional under `core.migrations.migrate_connection`.
6. Use only migration-mode connections via `core/sqlite_policy.py`.
7. Add tests proving upgrades from schema 9 preserve active generations,
   validators, rollback pointers, and audit history.

## Connection And Transaction Strategy

- All SQLite access must continue through `core/db.py`, `core/migrations.py`,
  and `core/sqlite_policy.py`.
- Runtime read commands must use `readonly_database()` or explicit read-only
  helpers.
- Update operations should perform network fetch, parse, and quality gates
  before opening a write transaction.
- The only write transaction in a successful update should persist generation,
  entries, source state, and audit outcome.
- Failed fetch/parse paths should open a short write transaction only to update
  source state and audit.
- No network calls, DNS resolution, sleeps, or dashboard rendering should occur
  inside a write transaction.
- Migration mode remains the only mode allowed to establish persistent WAL
  settings.

## Download And Update Algorithm

For each enabled source:

1. Load source and source state with a read-only or short read connection.
2. Skip when not due unless `--all` or an explicit source is requested.
3. Validate URL using the existing security policy:
   - HTTPS required by default.
   - HTTP allowed only when the source or global config explicitly opts in.
   - Credentials rejected.
   - private/local addresses rejected.
4. Build conditional request headers from source state:
   - `If-None-Match: <etag>`
   - `If-Modified-Since: <last_modified>`
5. Fetch with `source.timeout_seconds` and max byte limit.
6. If HTTP 304:
   - Resolve the remote generation from `remote_generation_id`, content hash,
     or latest valid HTTP 200 audit.
   - Reactivate it if rollback made it inactive.
   - Otherwise mark not modified.
7. If HTTP 200:
   - Parse according to source format.
   - Apply quality gates.
   - Compute content SHA-256.
   - If content equals active generation, update validators/state only.
   - If content matches a valid inactive generation for the same source,
     reactivate it.
   - Otherwise create a new staging generation and atomically activate it.
8. Persist source-state operational fields and audit rows.

## Atomic Replacement Behavior

Feed replacement must remain generation-based:

- Insert new generation as `staging`.
- Insert all accepted entries for that generation.
- Mark previous active generation `inactive`.
- Mark new generation `active`.
- Update `threat_intel_source_state.active_generation`,
  `remote_generation_id`, validators, content hash, entry count, timestamps,
  and counters.
- Commit once after all of the above succeeds.
- Roll back all partial rows on any exception.

The previous successful generation must remain active after any download,
parse, quality, validation, or database failure before activation commit.

## Failure And Retry Behavior

- Failed update records:
  - `status='failed'`
  - `last_attempt_at`
  - `last_error_code`
  - `last_error_summary`
  - incremented `consecutive_failures`
  - audit row
- Failed update must not clear `active_generation`, validators, content hash, or
  entry count.
- Application-level retries should not be added broadly. SQLite busy timeout
  remains the primary DB lock wait mechanism.
- Future retry policy may be source-level and bounded, but only for fetches
  before a write transaction starts.
- Automatic timer runs should continue to be safe no-ops when auto-update is
  disabled.

## Pruning Semantics

Two pruning concepts should remain separate:

1. **Indicator expiration**
   - If `expires_at` is null, the indicator never expires independently.
   - If `expires_at <= now`, classifier reads should ignore that entry.
   - Source-level staleness remains advisory and affects diagnostics/evidence.

2. **Generation retention**
   - Never delete the active generation.
   - Never delete the `previous_generation` rollback target unless rollback is
     intentionally disabled for that source.
   - Keep at least the last N successful generations per source, default 2 or 3.
   - Prune only inactive generations older than a configured retention window.

Initial Epic 3.3 should add stats and diagnostics first. Destructive pruning can
be a later phase or require an explicit command such as:

```bash
pihole-ai intel prune --dry-run
pihole-ai intel prune
```

## CLI Changes

Preserve all existing commands:

```bash
pihole-ai intel import-hosts
pihole-ai intel list
pihole-ai intel source list
pihole-ai intel source show
pihole-ai intel source add
pihole-ai intel source update
pihole-ai intel source enable
pihole-ai intel source disable
pihole-ai intel update
pihole-ai intel status
pihole-ai intel rollback
pihole-ai intel audit
```

Add backward-compatible command forms aligned with desired workflows:

```bash
pihole-ai intel sources
pihole-ai intel stats
```

Recommended behavior:

- `intel sources` should be an alias-like top-level command for
  `intel source list`, not a replacement.
- `intel stats` should return aggregate JSON/text:
  - total sources
  - enabled sources
  - disabled sources
  - active sources
  - failed sources
  - stale sources
  - total active indicators
  - total generations
  - active generations
  - inactive generations
  - last successful update
  - last failed update
  - consecutive failure totals
  - audit counts by result
- `intel update` should keep current semantics:
  - no flag: update due enabled sources
  - `--all`: update all enabled sources
  - `--source SOURCE_ID`: update one source
  - `--dry-run`: fetch/parse/plan but do not mutate
- Do not add conflicting aliases that shadow `intel source`.

## Systemd Integration

Current generated units already include:

- `pihole-ai-intel-update.service`
- `pihole-ai-intel-update.timer`

Keep the oneshot service as timer-triggered:

```text
python -m pihole_ai.cli intel update --all --non-interactive
```

Epic 3.3 should improve visibility rather than alter service structure:

- `pihole-ai setup status` should distinguish:
  - timer active but auto-update disabled
  - timer inactive and auto-update enabled
  - last update failed
  - no sources configured
  - no active indicators
- `pihole-ai service status`/doctor should continue treating the oneshot as
  healthy when inactive after success.

## Health And Doctor Additions

Add read-only diagnostics:

- `threat_intel_sources_configured`
- `threat_intel_enabled_sources`
- `threat_intel_active_indicators`
- `threat_intel_failed_sources`
- `threat_intel_stale_sources`
- `threat_intel_last_success_at`
- `threat_intel_last_attempt_at`
- `threat_intel_integrity_issues`
- `threat_intel_timer_expected`
- `threat_intel_timer_active`

Severity proposal:

- Healthy: at least one enabled source has active, non-expired indicators and no
  integrity issues.
- Degraded: no sources configured, no indicators, stale sources, failed source
  with last known-good still active, or auto-update disabled intentionally.
- Unhealthy: integrity issues that break active generation pointers, no active
  generation for an enabled source after successful import, or auto-update
  enabled while timer is disabled/inactive.

Doctor remediation examples:

- `pihole-ai intel source add ...`
- `pihole-ai intel update --all`
- `sudo pihole-ai enable`
- `journalctl -u pihole-ai-intel-update.service`

## Dashboard And API Changes

Keep the lightweight Flask/plain HTML/CSS/JS stack.

Existing endpoint:

```text
GET /api/intel/sources
```

Proposed additions:

```text
GET /api/intel/stats
GET /api/intel/audit?source=<source_id>&limit=<n>
POST /api/intel/update
POST /api/intel/source/<source_id>/enable
POST /api/intel/source/<source_id>/disable
```

Dashboard Intelligence page should show:

- configured sources table
- enabled/disabled status
- active entry count
- last success and last attempt
- last HTTP status
- last error
- ETag/Last-Modified presence, not raw long values by default
- source confidence/category
- update status and audit summary

Actions from dashboard should require authentication and CSRF, following the
existing settings/service action pattern. If update requires elevated system
access in an appliance context, show the exact CLI command instead of failing
with a traceback.

## Security Considerations

- Keep HTTPS as the default required transport.
- Continue rejecting feed URLs with credentials.
- Continue rejecting private, loopback, link-local, multicast, and unspecified
  addresses to reduce SSRF risk.
- Preserve `PIHOLE_AI_INTEL_ALLOW_HTTP=false` default.
- Do not display full secret-bearing URLs; current URL validation rejects
  credentials, but dashboard should still avoid unnecessary URL expansion.
- Enforce max download bytes before buffering unbounded content.
- Keep explicit network timeouts.
- Use the configured user agent.
- Do not add new dependencies unless standard library behavior proves
  insufficient.
- Do not fetch feeds during dashboard render or health checks.
- Avoid storing raw feed content in SQLite.

## Test Plan

Schema/migration:

- Migration 10 adds all new columns and indexes.
- Migration from schema 9 preserves active generations, rollback, validators,
  and audit history.
- Future schema is still rejected.

DB/transactions:

- Successful update persists state counters atomically.
- Parse failure preserves active generation and validators.
- Activation failure rolls back staging generation and entries.
- Expired indicators are ignored by active lookup when `expires_at` is set.
- Pruning dry-run reports candidates without mutation.
- Pruning never deletes active generation.

Fetch/update:

- ETag header sent when stored.
- Last-Modified header sent when stored.
- HTTP 304 unchanged path updates attempt metadata without duplicate rows.
- HTTP 304 after rollback reactivates remote generation.
- HTTP 200 identical SHA suppresses duplicate generation.
- HTTP status is persisted to source state.
- Download timeout and max-size failures preserve known-good indicators.

CLI:

- `intel sources` matches `intel source list`.
- `intel stats --json` returns stable aggregate contract.
- `intel update`, `--all`, `--source`, and `--dry-run` preserve existing
  behavior.
- Confidence remains validated as integer 0-100.
- HTTP is rejected unless explicitly allowed.

Systemd/setup:

- Generated timer remains unchanged unless config interval is intentionally
  wired into generation.
- Setup status reports timer/auto-update combinations correctly.
- Oneshot inactive-success is not treated as failed.

Dashboard/API:

- Intelligence page renders stats and source metadata.
- Update/enable/disable buttons post with CSRF.
- Read endpoints do not migrate or write.
- Empty state remains clear when no sources or indicators exist.

Resource safety:

- Full suite passes.
- ResourceWarning suite passes.
- Package build, twine check, package audit, wheel smoke, repository audit pass.

## Phased Implementation Plan

### Phase 1: Stats And Diagnostics

- Add read-only stats helper in `core/db.py`.
- Add `pihole-ai intel stats`.
- Add health/doctor threat-intel diagnostics.
- Add dashboard `GET /api/intel/stats`.
- No schema change if using existing tables only.

### Phase 2: Operational Metadata Migration

- Add migration 10 for source-state counters and optional `expires_at`.
- Persist `last_http_status`, parse counters, duration, and warnings on update.
- Backfill from latest audit rows where safe.

### Phase 3: Dashboard Visibility And Controls

- Expand Intelligence page source table.
- Add audit view.
- Add authenticated update/enable/disable actions.
- Preserve no-poll explain behavior and existing dashboard style.

### Phase 4: Default Source Catalog And Onboarding

- Add packaged default source catalog if maintainers approve specific feeds.
- Add CLI/import command to install recommended disabled-by-default or
  enabled-by-default sources.
- Update first-run/setup messaging so `threat_intel: 0` has a clear next step.

### Phase 5: Expiration And Pruning

- Apply `expires_at` semantics in active lookup.
- Add explicit `intel prune --dry-run` and `intel prune`.
- Add retention config only if needed; avoid excessive tuning.

## Acceptance Criteria

- A clean appliance can explain why `threat_intel` is zero and show the next
  action.
- Multiple enabled sources update independently and preserve per-source state.
- `intel update --all` updates all enabled sources safely.
- Failed update never destroys the previous successful generation.
- HTTP 304 and identical-content cases do not duplicate generations.
- Source stats are available via CLI, API, dashboard, health, and doctor.
- Health/doctor report failed/stale/empty feed states with actionable
  remediation.
- All runtime SQLite access uses `core/sqlite_policy.py`.
- Runtime read commands do not migrate implicitly.
- Network calls have explicit timeouts and respect URL security policy.
- Full unit, ResourceWarning, build, package audit, wheel smoke, and repository
  audit validations pass.

## Maintainer Decisions Needed

1. Should PiHole-AI ship a default curated source catalog? If yes, which feeds
   are acceptable for licensing, availability, false-positive risk, and
   appliance bandwidth?
2. Should default sources be enabled automatically, disabled until opt-in, or
   enabled only during onboarding?
3. Should automatic updates default to enabled once at least one source exists?
4. What is the retention policy for inactive generations: keep last 2, last 3,
   age-based, or manual-only pruning?
5. Should dashboard update actions execute feed updates directly, or show CLI
   commands only on appliance installs?
6. Should `intel status` remain source-state focused while `intel stats` becomes
   aggregate, or should `status` include aggregate sections too?
