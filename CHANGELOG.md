# Changelog

## Unreleased

- No unreleased changes yet.

## v0.5.0rc1

Release-candidate hardening for Epic 3.5 Configuration Center and appliance
operations.

Package version: `0.5.0rc1`. Planned Git tag: `v0.5.0-rc1`.

### Added

- Added structured evidence models and a central decision engine.
- Classifiers can now contribute risk, safety, neutral, or decisive evidence.
- Fresh decisions persist supporting evidence in `decision_evidence` for
  `pihole-ai explain` and dashboard/API consumers.
- Added `decision_records` persistence and a polished dashboard Explain panel
  for final decisions, evidence groups, classifier traces, conflicts, and legacy
  decisions.
- Added feedback audit provenance linking feedback to the stored decision
  visible at submission time.
- Added repository cleanup, repository audit, CLI, configuration, database,
  security, operations, development, and technical-debt documentation.
- Added immutable append-only decision history with opaque decision IDs,
  historical evidence rows, explain history/decision/compare flows, and
  explicit retention maintenance.
- Added managed threat-intelligence feed sources with safe fetching,
  generation-based activation, rollback, update audit history, CLI management,
  dashboard status, and updater systemd units.
- Added typed threat-intelligence source models, managed source registry,
  source status APIs, source update CLI, rollback, audit records, and
  generation-aware classifier evidence.
- Added AI pipeline telemetry, read-only telemetry stats, and richer explain
  timelines for classifier stages, cache hits, AI attempts, skips, timeouts,
  and parse failures.
- Added persisted benchmark runs, fixture digest protection, benchmark history,
  and deterministic regression comparison.
- Added reporting-only confidence calibration profiles from completed
  benchmark runs.
- Added reliability CLI metrics and dashboard views for confidence
  distributions, observed accuracy, latency, AI/cache utilization, benchmark
  history, and telemetry volume diagnostics.
- Added the Configuration Center framework with schema-backed setting
  metadata, validation, source attribution, masking, restart-impact metadata,
  import/export primitives, and preserving env-file parsing.
- Added configuration CLI commands: `config show`, `config get`,
  `config validate`, `config impact`, `config set`, `config unset`,
  `config export`, `config import`, and `config migrate`.
- Added dashboard Configuration API endpoints and the authenticated Settings
  page for validation, guarded writes, import/export, secret replace/unset,
  revision conflict handling, and optional Save & Restart.
- Added schema-v1 configuration migration for legacy/unversioned env files.
- Added installer/lifecycle integration for config validation, migration
  refusal, config-aware status, and uninstall config preservation/removal.
- Added appliance integration coverage for install, migration, CLI/dashboard
  consistency, import/export, secrets, restart orchestration, and partial
  install recovery.
- Added administrator, testing, release checklist, upgrade guidance, and
  secret-free example configuration files.

### Changed

- Manual rules and high-confidence threat intelligence are resolved by decisive
  precedence before lower-priority classifiers run.
- Current active installation examples now use version-neutral wheel patterns.
- Latest-decision tables are now compatibility projections over immutable
  history for fresh v0.5 decisions.
- Threat-intelligence classification now reads enabled sources through active
  feed generations while preserving manual import compatibility.
- Managed feed sources can now be edited in place with
  `pihole-ai intel source update`, preserving active/prior generations and
  resetting validators only for URL or fetch-setting changes.
- Threat-intelligence updates now distinguish unchanged active content,
  reactivated historical generations, and newly created generations.
- Threat-intelligence source state now tracks the remote representation
  generation separately from the classifier-active generation.
- Threat-intelligence remote-generation repair now prefers latest successful
  HTTP 200 update history over rollback-active state.
- Read-only threat-intelligence commands now use read-only database access.
- Source confidence CLI input is standardized as integer percentage `0-100`.
- Explain output now reports raw and calibrated confidence separately when a
  matching active calibration profile exists.
- Appliance install and upgrade now validate managed configuration before
  service mutation. Legacy/unversioned configuration must be migrated
  explicitly with `pihole-ai config migrate`.
- Configuration writes are atomic, backed up when replacing existing files,
  and do not restart services unless `--restart` or dashboard Save & Restart
  is explicitly requested.
- Normal configuration exports omit secrets. Secure exports are CLI-only and
  require explicit `--secure`.

### Fixed

- Fixed setup readiness classification so warning-only operational systems are
  degraded-ready instead of installed-unconfigured.
- Fixed packaged alert-log defaults to use `/var/log/pihole-ai/alerts.log`.
- Fixed A -> B -> rollback A -> update B feed cycles so matching inactive
  generations are reactivated instead of reported unchanged or duplicated.
- Fixed HTTP 304 updates after rollback so unchanged remote content can
  reactivate the stored remote generation instead of reporting the active
  rollback generation unchanged.
- Fixed migration backfill for rolled-back sources so `remote_generation_id`
  is repaired from fetch history instead of the currently active generation.
- Fixed misleading dry-run generation output, managed-source listing gaps,
  unchanged-content duplicate suppression, updater lock path, timer lifecycle
  integration, and automatic-disabled timer behavior.
- Modernized package license metadata to avoid setuptools license-table
  deprecation warnings.
- Fixed lifecycle dry-run and failure boundaries so invalid or legacy
  configuration prevents later service mutation.

### Security

- Documented the protected appliance configuration model, dashboard
  authentication, CSRF, session, proxy-trust, and exposure guidance.
- Added secret masking across configuration CLI, API, Settings UI, imports,
  exports, migration previews, and restart failure responses.

### Migration Notes

- Configuration schema remains `1`.
- Existing unversioned `/etc/pihole-ai/pihole-ai.env` files are treated as
  legacy schema `0`.
- Run `pihole-ai config migrate --dry-run`, then
  `sudo pihole-ai config migrate --yes`, then `pihole-ai config validate`.
- Migration preserves comments, unknown keys, and secrets; rewrites known
  aliases to canonical keys; creates a migration-specific backup; and never
  restarts services automatically.

### Upgrade Notes

```bash
sudo /opt/pihole-ai/venv/bin/pip install --upgrade dist/pihole_ai-0.5.0rc1-py3-none-any.whl
sudo /usr/local/bin/pihole-ai upgrade
sudo /usr/local/bin/pihole-ai restart
```

If upgrade reports configuration migration required, run the migration
workflow first and retry `sudo /usr/local/bin/pihole-ai upgrade`.

### Breaking Changes

- No database downgrade support is added.
- Dashboard secure configuration export is intentionally not supported; use
  CLI `pihole-ai config export --secure`.
- Legacy/unversioned configuration is no longer silently accepted by
  installer/lifecycle mutation paths; migrate it explicitly first.

### Testing Summary

- `666` normal unit/integration tests passed.
- `666` ResourceWarning tests passed.
- Appliance configuration integration tests use temporary roots and mocked
  service control; they do not touch real `/etc`, systemd, Pi-hole DBs, or
  Ollama.

### Known Limitations

- Database backup/restore commands and long-term retention policy are not yet
  implemented.
- Feedback-based confidence calibration remains deferred until feedback rows
  have trustworthy labeled-sample linkage.
- Telemetry/calibration retention is not yet automatic.
- Physical Raspberry Pi/systemd validation remains required before promoting
  the release candidate to a stable release.

## v0.4.0rc1

Release-candidate hardening for PiHole-AI as a local Pi-hole companion appliance.

- Added unified health checks, doctor diagnostics, and setup/onboarding status.
- Added SQLite schema versioning with transactional baseline migrations.
- Centralized typed configuration, validation, safe display, and runtime paths.
- Added Linux appliance lifecycle management for install, upgrade, uninstall, service control, logs, and systemd unit generation.
- Added dedicated `pihole-ai` service identity handling and conservative Pi-hole database read-access checks.
- Added first-run setup guidance and safe dashboard setup visibility.
- Added dashboard authentication, secure signed sessions, CSRF protection, login throttling, security headers, and minimal public `/live`.
- Added local reputation, threat-intelligence import support, classifier metrics, explain views, and feedback flows.

Known limitations:

- Dashboard is single-administrator only; no multi-user management.
- Privileged lifecycle operations remain CLI-controlled.
- Database migrations are not downgraded during rollback.
- Ollama is optional and must be installed/model-managed separately.
- Real Raspberry Pi/Pi-hole host field validation is still required before final v0.4.
