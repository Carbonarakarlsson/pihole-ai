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
sudo /opt/pihole-ai/venv/bin/pip install dist/pihole_ai-0.5.0rc1-py3-none-any.whl
sudo /opt/pihole-ai/venv/bin/pihole-ai install --no-start
sudo /usr/local/bin/pihole-ai dashboard auth set-password
sudo /usr/local/bin/pihole-ai start
```

`pihole-ai install` installs managed files, enables services, and starts them.
`pihole-ai install --no-start` installs and enables services but leaves them
stopped. `pihole-ai install --no-enable` installs files without enabling boot
startup.

Install validates Configuration Center state before writing systemd units,
enabling services, or starting services. A fresh appliance gets a current
schema `1` env file. Existing current-schema files are preserved and validated.
Legacy or unversioned files stop install with migration guidance:

```bash
pihole-ai config migrate --dry-run
sudo pihole-ai config migrate --yes
```

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
`--confirm-purge`. Configuration is preserved by default; pass
`--remove-config` only when you explicitly want to delete the managed env file.
Use `--keep-config` to make preservation explicit in scripts.

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

## Configuration Center

Epic 3.5 adds appliance-grade configuration management across the CLI,
dashboard API, Settings UI, migration workflow, and installer lifecycle. The
implementation design and status are in [Configuration Center
Design](CONFIGURATION_DESIGN.md).

The first safe editing commands are now available:

```bash
pihole-ai config set KEY VALUE --dry-run
sudo pihole-ai config set KEY VALUE --yes
sudo pihole-ai config set KEY VALUE --yes --restart
sudo pihole-ai config unset KEY --yes
pihole-ai config export --output backup.json
pihole-ai config import backup.json --dry-run
```

Use `--dry-run` to preview validation, effective source, and restart impact
without creating temp files or backups. Writes are atomic and create
`pihole-ai.env.bak` when replacing an existing file. Editing does not restart
services; restart the reported PiHole-AI service manually when ready.

Example non-secret configuration files are available in `examples/`.

If a process environment variable overrides a persisted value, the preview
warns that the file will change while the effective runtime value remains
controlled by the environment. Secret values are masked in output, but passing
secrets as command-line arguments may leave them in shell history or process
inspection output.

Configuration commands never restart services unless `--restart` is supplied.
When `--restart` is used, PiHole-AI restarts only the affected PiHole-AI
services after the file write succeeds. It does not invoke `sudo`, `pkexec`, or
restart Pi-hole itself. If restart authorization fails, the configuration stays
saved and output includes manual recovery commands such as:

```bash
sudo systemctl restart pihole-ai-engine.service
```

Restart failure does not restore the backup automatically. Use the reported
backup path if you need to recover the previous file.

Configuration exports are JSON by default and include schema/version metadata.
Use `--format env` for a generated managed-env representation. Normal exports
omit secrets and mask sensitive values. `--secure` includes schema-approved
secrets and should be written only to protected storage:

```bash
sudo pihole-ai config export --secure --output /root/pihole-ai-secure-backup.json
```

Imports validate schema compatibility, aliases, setting values, cross-setting
rules, and restart impact before writing. Unknown settings are warnings by
default and become errors with `--strict`. Always preview first with
`--dry-run`; successful imports write atomically and create a `.bak` backup
when replacing an existing env file. On persistence failure, the original file
is left unchanged and temporary files are cleaned up.

The dashboard exposes a backend Configuration API for authenticated operators.
It uses the same validation, masking, revision, import/export, and restart
orchestration primitives as the CLI. Mutating requests require CSRF, writes and
imports require the current file revision, and secrets are never returned in
plaintext by default. Secure exports remain CLI-only. See
[API Reference](API_REFERENCE.md) for endpoint details.

The dashboard Settings page is available at `/settings` and in the dashboard
sidebar. It loads configuration from `/api/config`, groups settings by category,
shows the effective source of each value, and warns when a process environment
override may hide a persisted edit. Use Preview changes for a backend dry-run,
Save to write without restarting, and Save & Restart only when you want
PiHole-AI to restart the affected services after a successful write.

Configured secrets are shown only as configured/unconfigured state. To change a
secret, choose Replace secret or Unset secret; the current secret is never
displayed. Dashboard exports omit secrets. Use the CLI secure export command
for explicit secret-inclusive backups.

If configuration saves but restart fails, the page reports that the write
succeeded, lists affected or failed services, and shows backend recovery
commands such as `sudo systemctl restart pihole-ai-engine.service`. The saved
configuration is not rolled back automatically.

### Configuration Migration

Legacy or unversioned env files can be migrated to the current Configuration
Center schema with:

```bash
pihole-ai config migrate --dry-run
sudo pihole-ai config migrate --yes
pihole-ai config validate
pihole-ai restart
```

The migration command adds `PIHOLE_AI_CONFIG_SCHEMA_VERSION=1`, normalizes
known legacy aliases such as `OLLAMA_HOST` and `OLLAMA_MODEL`, preserves
comments, blank lines, unknown keys, and secrets, creates a migration backup,
and writes atomically. It does not restart services automatically.

Appliance install and upgrade do not silently run this migration. They report
the current schema state, validation result, and required migration command,
then stop before service mutation when migration is required or validation
fails.

Phase 2C appliance integration tests exercise this sequence end to end with
temporary roots and mocked service control: legacy refusal, migration dry-run,
atomic migration write, backup verification, retrying install/upgrade, and
status confirmation. See [Testing](TESTING.md).

If the dashboard Settings page sees a legacy env file, it shows a
migration-required API error instead of attempting to migrate during page load.
Run the CLI migration command from a shell with appropriate permissions.

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
pihole-ai status
```

Use `--json` on commands that support machine-readable output. `pihole-ai
status` includes configuration schema version, validation state, migration
requirement, config source, and warnings alongside service and database state.

The integration test harness verifies lifecycle commands do not call real
`systemctl`, `sudo`, or `pkexec`, and that config is preserved unless
`--remove-config` is explicitly supplied.

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
