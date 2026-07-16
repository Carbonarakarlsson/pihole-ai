# Repository Status

- Package version: `0.5.0b1`
- Active branch: `v2-refactor`
- Stable appliance baseline: v0.5 beta milestone preparation
- Current epic: Epic 2 complete; Epic 3 planning
- Test suite: unittest discovery under `tests`
- Latest schema version: `9`
- Final automated test count: `446`
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
- schema migrations through v9
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

## Next Planned Epic

Epic 3: Domain and device behavioral intelligence.

## Release Recommendation

Epic 2 threat-intelligence generation lifecycle is accepted. The repository is
ready for v0.5 milestone tagging after final versioned artifact validation and
tag decision.
