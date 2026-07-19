# PiHole-AI v0.5.0rc1 Release Notes

`v0.5.0rc1` is the Configuration Center and appliance-operations release
candidate for PiHole-AI v0.5.

## Highlights

- Completed Epic 3.5 Configuration Center across CLI, dashboard API, and
  Settings UI.
- Added schema-backed configuration inventory, validation, source attribution,
  masking, restart-impact metadata, atomic writes, backups, and deterministic
  import/export.
- Added `pihole-ai config migrate` for legacy/unversioned env files.
- Integrated configuration validation into install, upgrade, enable, start,
  restart, and status workflows.
- Added explicit uninstall config preservation and `--remove-config`.
- Added administrator, testing, release checklist, upgrade, and example
  configuration documentation.

## Configuration Migration

Configuration schema remains `1`.

Legacy or unversioned files are treated as schema `0`. Lifecycle commands do
not silently migrate them. Use:

```bash
pihole-ai config migrate --dry-run
sudo pihole-ai config migrate --yes
pihole-ai config validate
sudo pihole-ai restart
```

Migration preserves comments, blank lines, unknown keys, and secrets, rewrites
known aliases to canonical keys, validates before writing, and creates a
migration-specific backup.

## Upgrade

```bash
sudo /opt/pihole-ai/venv/bin/pip install --upgrade dist/pihole_ai-0.5.0rc1-py3-none-any.whl
sudo /usr/local/bin/pihole-ai upgrade
sudo /usr/local/bin/pihole-ai restart
```

If upgrade reports migration required, run the migration workflow and retry
upgrade.

## New And Hardened Commands

- `pihole-ai config show`
- `pihole-ai config get`
- `pihole-ai config validate`
- `pihole-ai config impact`
- `pihole-ai config set`
- `pihole-ai config unset`
- `pihole-ai config export`
- `pihole-ai config import`
- `pihole-ai config migrate`
- `pihole-ai uninstall --keep-config`
- `pihole-ai uninstall --remove-config`

## Dashboard

The Settings page is now backed by the same Configuration Center operations as
the CLI. It supports category navigation, backend validation, dry-run previews,
guarded saves, import/export, secret replace/unset flows, revision conflict
handling, and optional Save & Restart.

Secure secret-inclusive exports remain CLI-only.

## Testing

Release-candidate validation includes:

- full unit/integration suite
- ResourceWarning suite
- appliance configuration integration tests
- lifecycle integration tests
- dashboard configuration API tests
- dashboard Settings tests
- build validation

## Known Limitations

- Database backup/restore commands are still future work.
- Telemetry/calibration retention is not automatic.
- Feedback-based calibration remains deferred.
- Physical Raspberry Pi/systemd validation is still required before stable
  promotion.
