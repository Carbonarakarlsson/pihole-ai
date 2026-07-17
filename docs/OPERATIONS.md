# Operations

This document covers appliance operation for PiHole-AI on a Linux/systemd host.

## Runtime Layout

```text
/etc/pihole-ai/pihole-ai.env       protected configuration
/var/lib/pihole-ai/events.db       PiHole-AI SQLite database
/var/log/pihole-ai/pihole-ai.log   application log
/var/log/pihole-ai/alerts.log      alert log
/usr/local/bin/pihole-ai           global launcher
/opt/pihole-ai/venv                recommended appliance environment
```

Production services run as `pihole-ai:pihole-ai`.

Expected protected configuration metadata:

```text
/etc/pihole-ai                  root:pihole-ai 0750
/etc/pihole-ai/pihole-ai.env    root:pihole-ai 0640
```

## Install

```bash
sudo python3 -m venv /opt/pihole-ai/venv
sudo /opt/pihole-ai/venv/bin/pip install dist/pihole_ai-*-py3-none-any.whl
sudo /opt/pihole-ai/venv/bin/pihole-ai install --no-start
sudo /usr/local/bin/pihole-ai dashboard auth set-password
sudo /usr/local/bin/pihole-ai start
```

`pihole-ai install` installs managed files, enables services, and starts them.
`pihole-ai install --no-start` installs and enables services but leaves them
stopped. `pihole-ai install --no-enable` installs files without enabling boot
startup.

## Upgrade

Install the new wheel into `/opt/pihole-ai/venv`, then run:

```bash
sudo /usr/local/bin/pihole-ai upgrade
sudo /usr/local/bin/pihole-ai restart
```

Upgrade preserves administrator configuration and runtime data, repairs managed
metadata, and refuses unsafe symlink substitutions.

## Service Management

```bash
sudo /usr/local/bin/pihole-ai enable
sudo /usr/local/bin/pihole-ai disable
sudo /usr/local/bin/pihole-ai start
sudo /usr/local/bin/pihole-ai stop
sudo /usr/local/bin/pihole-ai restart
/usr/local/bin/pihole-ai status
/usr/local/bin/pihole-ai logs --lines 80
/usr/local/bin/pihole-ai logs --follow
```

The managed units are:

- `pihole-ai-collector.service`
- `pihole-ai-engine.service`
- `pihole-ai-dashboard.service`

## Uninstall

```bash
sudo /usr/local/bin/pihole-ai uninstall
```

Default uninstall removes managed service files and the matching global
launcher. It preserves configuration, database, learned reputation, rules,
feedback, and logs. Destructive data removal requires `--purge` and
`--confirm-purge`.

## Database Ownership

`/var/lib/pihole-ai` and PiHole-AI-owned SQLite files are service-writable by
`pihole-ai:pihole-ai`. The Pi-hole FTL database remains Pi-hole-owned and is
opened read-only by the collector.

## Firewall Requirements

Pi-hole must allow local read access to its FTL database. The dashboard listens
on `0.0.0.0:8080` by default for appliance access; restrict LAN/firewall access
or place it behind a trusted local reverse proxy. Keep authentication enabled
when binding outside loopback.

## Backup Expectations

Back up before upgrade or purge:

- `/etc/pihole-ai/pihole-ai.env`
- `/var/lib/pihole-ai/events.db`
- any external threat-intelligence source files you import manually

PiHole-AI does not currently include a first-class backup/restore command.

## Configuration Center Planning

Epic 3.5 Phase 1 will expand configuration management beyond the current
`config check`, `config show`, setup, and narrow dashboard settings flows. The
implementation-ready design is in
[Configuration Center Design](CONFIGURATION_DESIGN.md).

The first safe editing commands are now available:

```bash
pihole-ai config set KEY VALUE --dry-run
sudo pihole-ai config set KEY VALUE --yes
sudo pihole-ai config unset KEY --yes
```

Use `--dry-run` to preview validation, effective source, and restart impact
without creating temp files or backups. Writes are atomic and create
`pihole-ai.env.bak` when replacing an existing file. Editing does not restart
services; restart the reported PiHole-AI service manually when ready.

If a process environment variable overrides a persisted value, the preview
warns that the file will change while the effective runtime value remains
controlled by the environment. Secret values are masked in output, but passing
secrets as command-line arguments may leave them in shell history or process
inspection output.

## Threat-Intelligence Source Edits

Use supported CLI edits instead of direct SQLite changes:

```bash
pihole-ai intel source update SOURCE_ID --url https://example.test/feed.txt
```

The command preserves the source ID, active generation, prior generations,
entries, and audit history. It does not fetch content or activate a new
generation. URL and fetch-setting changes clear ETag/Last-Modified validators;
display-only changes preserve validators. Run `pihole-ai intel update --source
SOURCE_ID` separately when ready.

For routine visibility:

```bash
pihole-ai intel sources
pihole-ai intel stats
```

Both commands are read-only and report managed-feed freshness, active
indicator counts, failed/stale source counts, and integrity issue totals.

For deterministic field tests, prefer immutable URLs such as commit-pinned raw
files. Branch-based raw URLs can be cached upstream and may not reflect the
expected fixture generation immediately.

## Diagnostics

```bash
pihole-ai health
pihole-ai doctor
pihole-ai setup status
pihole-ai db status
pihole-ai install status
```

Use `--json` on commands that support machine-readable output.

## AI Reliability And Calibration

Benchmark and calibration commands are appliance diagnostics. They help measure
model and prompt behavior without changing runtime decisions.

```bash
pihole-ai benchmark run fixtures/domains.json --name "local check" --json
pihole-ai benchmark list
pihole-ai benchmark compare BASELINE_RUN_ID CANDIDATE_RUN_ID
pihole-ai calibration build --benchmark RUN_ID --name "local calibration"
pihole-ai calibration activate PROFILE_ID
pihole-ai reliability metrics --window 7d
```

Calibration profiles are reporting-only. Explain output and the dashboard show
raw confidence beside calibrated confidence when an active matching profile
exists. The raw classifier confidence remains the value used by the engine, and
profile activation does not alter blocking, allowing, cache, AI retry, timeout,
or rate-limit behavior.

`calibration build --feedback` is intentionally unavailable until feedback rows
have reliable labeled-sample linkage. Use completed benchmark runs for
calibration profiles.

## Reboot Validation

After install or upgrade:

```bash
sudo reboot
systemctl status pihole-ai-collector.service
systemctl status pihole-ai-engine.service
systemctl status pihole-ai-dashboard.service
pihole-ai health
pihole-ai setup status
```

Field-test permission checks:

```bash
sudo -u pihole-ai test -x /etc/pihole-ai
sudo -u pihole-ai test -r /etc/pihole-ai/pihole-ai.env
```

## Privilege Model

Read-only diagnostics should work for ordinary administrators where file
permissions allow. Mutating lifecycle, protected config writes, ownership
repair, and service control require root privileges.
