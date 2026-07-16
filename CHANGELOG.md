# Changelog

## Unreleased

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

### Security

- Documented the protected appliance configuration model, dashboard
  authentication, CSRF, session, proxy-trust, and exposure guidance.

### Known Limitations

- Database backup/restore commands and long-term retention policy are not yet
  implemented.

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
