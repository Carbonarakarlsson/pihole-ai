# Repository Status

- Package version: `0.4.0rc3`
- Active branch: `v2-refactor`
- Stable release baseline: v0.4 release candidate line
- Current epic: v0.5 threat-intelligence feed management
- Test suite: unittest discovery under `tests`
- Latest schema version: `9`
- Supported Python: 3.13+
- Supported deployment: Linux/systemd appliance, Raspberry Pi target

## Appliance Paths

- config: `/etc/pihole-ai/pihole-ai.env`
- data: `/var/lib/pihole-ai/events.db`
- app log: `/var/log/pihole-ai/pihole-ai.log`
- alert log: `/var/log/pihole-ai/alerts.log`
- launcher: `/usr/local/bin/pihole-ai`
- recommended venv: `/opt/pihole-ai/venv`

## Completed Capabilities

- appliance lifecycle management
- protected config and service identity repair
- dashboard authentication, sessions, CSRF, and security headers
- health, doctor, setup, install status, and database diagnostics
- schema migrations through v6
- evidence-based decision aggregation
- stored explain evidence for CLI/API/dashboard
- feedback audit linkage to stored decisions
- immutable decision history, selected decision explain, and comparison
- automatic threat-intelligence feed source registry, generation activation,
  rollback, audit trail, and updater systemd timer

## Known Limitations

- no first-class database backup/restore command
- single dashboard administrator
- no automatic Ollama/model installation
- final release promotion still needs physical-host validation

## Next Planned Epic

Continue v0.5 hardening around feed diagnostics, backup/restore, retention, and
field validation.

## Release Blockers

No active repository cleanup blocker is known after the v0.5 synchronization
pass. Physical Raspberry Pi validation remains required for release promotion.
