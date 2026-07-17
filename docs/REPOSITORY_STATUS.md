# Repository Status

- Package version: `0.5.0b5`
- Active branch: `v0.5-epic3.3`
- Stable appliance baseline: v0.5 beta milestone preparation
- Current epic: Epic 3.4 AI reliability, evaluation, and explainability
- Test suite: unittest discovery under `tests`
- Latest schema version: `13`
- Final automated test count: 529 normal / 529 ResourceWarning
- Supported Python: 3.13+
- Supported deployment: Linux/systemd appliance, Raspberry Pi target

## Appliance Paths

- config: `/etc/pihole-ai/pihole-ai.env`
- data: `/var/lib/pihole-ai/events.db`
- app log: `/var/log/pihole-ai/pihole-ai.log`
- alert log: `/var/log/pihole-ai/alerts.log`
- launcher: `/usr/local/bin/pihole-ai`
- recommended venv: `/opt/pihole-ai/venv`

## Epic Status

- Epic 1, evidence-based decision engine: complete.
- Epic 2, managed threat-intelligence feed lifecycle: complete and physically
  field-validated on a Raspberry Pi-class appliance.
- Epic 3, domain and device behavioral intelligence: planned.

## Completed Capabilities

- appliance lifecycle management
- protected config and service identity repair
- dashboard authentication, sessions, CSRF, and security headers
- health, doctor, setup, install status, and database diagnostics
- schema migrations through v13
- evidence-based decision aggregation
- stored explain evidence for CLI/API/dashboard
- feedback audit linkage to stored decisions
- immutable decision history, selected decision explain, and comparison
- managed threat-intelligence source registry
- safe source update CLI
- generation activation, rollback, historical generation reuse, and HTTP 304
  reactivation
- updater systemd oneshot service and timer
- read-only threat-intelligence list/status/audit/show commands
- AI pipeline telemetry, explain timeline output, persisted benchmark run
  history with regression comparison, and reporting-only confidence calibration
- Reliability dashboard/API surfaces for accuracy, latency, confidence bands,
  benchmark history, classifier usage, and telemetry volume diagnostics

## Systemd Updater

- `pihole-ai-intel-update.service` is a `Type=oneshot` updater.
- The updater runs as `pihole-ai:pihole-ai`.
- `pihole-ai-intel-update.timer` participates in appliance enable/disable.
- Runtime `start`, `stop`, and `restart` remain scoped to collector, engine,
  and dashboard daemons.
- Timer behavior includes `Persistent=true`, `RandomizedDelaySec=15min`, a
  bounded start timeout, and a lock under `/run/pihole-ai`.
- Automatic-disabled mode exits cleanly without mutating feeds.

## Known Limitations

- no privileged dashboard feed mutation
- no automatic mass reclassification
- source metadata edit auditing remains limited
- generation/audit retention policy needs refinement
- controlled field validation used a small deterministic feed
- backup/restore command remains future work
- feedback-based confidence calibration is deferred until feedback rows have
  trustworthy labeled-sample linkage

## Next Planned Epic

Epic 3.4 Phase 5: reliability retention and operational hardening.

## Release Recommendation

Epic 3.4 Phases 1-4 are implementation-complete and validated for the
`0.5.0b5` beta artifact. The repository should not be tagged until the
maintainer accepts the generated artifacts.
