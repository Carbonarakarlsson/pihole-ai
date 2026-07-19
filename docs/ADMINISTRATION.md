# Administrator Guide

This guide is for operating PiHole-AI as a Linux/systemd appliance. It assumes
the package is installed into a stable virtual environment such as
`/opt/pihole-ai/venv` and managed with the global `/usr/local/bin/pihole-ai`
launcher.

## First Installation

Build or copy the release wheel to the Pi-hole host, then install it into the
appliance environment:

```bash
sudo python3 -m venv /opt/pihole-ai/venv
sudo /opt/pihole-ai/venv/bin/pip install dist/pihole_ai-0.5.0rc1-py3-none-any.whl
sudo /opt/pihole-ai/venv/bin/pihole-ai install --no-start
```

The installer creates:

- `/etc/pihole-ai/pihole-ai.env`
- `/var/lib/pihole-ai/events.db`
- `/var/log/pihole-ai/pihole-ai.log`
- `/usr/local/bin/pihole-ai`
- managed systemd units for collector, engine, dashboard, and the intel timer

`pihole-ai install` enables and starts services. `pihole-ai install
--no-start` enables boot startup but leaves services stopped. `pihole-ai
install --no-enable` installs files without enabling boot startup.

Set the dashboard administrator password before starting the dashboard:

```bash
sudo /usr/local/bin/pihole-ai dashboard auth set-password
sudo /usr/local/bin/pihole-ai start
```

Open `http://<pi-host>:8080`. The default username is `admin`. There is no
default password.

## Upgrades

Install the new wheel into the same appliance environment, then run:

```bash
sudo /opt/pihole-ai/venv/bin/pip install --upgrade dist/pihole_ai-0.5.0rc1-py3-none-any.whl
sudo /usr/local/bin/pihole-ai upgrade
sudo /usr/local/bin/pihole-ai restart
```

Upgrade preserves configuration, database content, rules, feedback, learned
reputation, threat-intelligence state, telemetry, benchmarks, and logs. It
refreshes managed unit files, repairs protected configuration metadata, applies
database migrations when required, and refuses unsafe symlink substitutions.

## Configuration Migration Workflow

Managed env files use schema marker:

```text
PIHOLE_AI_CONFIG_SCHEMA_VERSION=1
```

Legacy or unversioned env files are schema version `0`. Install, upgrade,
enable, start, and restart validate configuration before mutating services.
When migration is required, lifecycle commands stop and print the migration
commands.

Preview first:

```bash
pihole-ai config migrate --dry-run
```

Apply after review:

```bash
sudo pihole-ai config migrate --yes
pihole-ai config validate
sudo pihole-ai restart
```

Migration preserves comments, blank lines, unknown keys, and secrets; rewrites
known aliases to canonical names; adds the schema marker; validates before
writing; creates a migration-specific backup; and writes atomically.

## Backup And Restore

Back up these paths before upgrade, migration, or purge:

```text
/etc/pihole-ai/pihole-ai.env
/var/lib/pihole-ai/events.db
/var/log/pihole-ai/pihole-ai.log
```

For configuration-only backups:

```bash
pihole-ai config export --output pihole-ai-config.json
sudo pihole-ai config export --secure --output /root/pihole-ai-secure-config.json
```

Normal exports omit secrets. Secure exports include schema-approved secrets and
should be stored with restrictive permissions.

Restore a config backup:

```bash
sudo cp /etc/pihole-ai/pihole-ai.env.bak /etc/pihole-ai/pihole-ai.env
sudo pihole-ai config validate
sudo pihole-ai restart
```

For migration backups, use the exact path printed by `config migrate`, for
example:

```bash
sudo cp /etc/pihole-ai/pihole-ai.env.migration-v0-to-v1.bak /etc/pihole-ai/pihole-ai.env
sudo pihole-ai restart
```

PiHole-AI does not yet provide first-class database backup/restore commands.

## Service Management

```bash
sudo pihole-ai enable
sudo pihole-ai disable
sudo pihole-ai start
sudo pihole-ai stop
sudo pihole-ai restart
pihole-ai status
pihole-ai logs --lines 80
pihole-ai logs --follow
```

Runtime `start`, `stop`, and `restart` manage:

- `pihole-ai-collector.service`
- `pihole-ai-engine.service`
- `pihole-ai-dashboard.service`

`enable` and `disable` also manage `pihole-ai-intel-update.timer`. The
updater service is a `Type=oneshot` unit and is healthy when inactive after a
successful timer-triggered run.

## Configuration Editing

Use CLI dry-runs before writes:

```bash
pihole-ai config show
pihole-ai config get ollama_model --details
pihole-ai config set ollama_model llama3.2:1b --dry-run
sudo pihole-ai config set ollama_model llama3.2:1b --yes
sudo pihole-ai config unset ollama_model --yes
```

Dashboard settings are available at `/settings`. The page uses the same
backend validation and persistence layer as the CLI. It does not embed raw
configuration data in initial HTML and never returns configured secrets in
plaintext by default.

## Import And Export

Preview imports:

```bash
pihole-ai config import backup.json --dry-run
```

Apply after review:

```bash
sudo pihole-ai config import backup.json --yes
```

Use `--format env` for generated env exports and `--strict` to reject unknown
imported settings instead of warning and ignoring them.

Example files are available in:

- `examples/pihole-ai.env`
- `examples/pihole-ai.json`

They contain no secrets and should be treated as templates, not live
configuration.

## Restart Behavior

Configuration writes do not restart services unless `--restart` is supplied or
the dashboard Save & Restart action is used.

Restart orchestration order is deterministic:

1. `pihole-ai-collector.service`
2. `pihole-ai-engine.service`
3. `pihole-ai-dashboard.service`
4. `pihole-ai-intel-update.timer`

PiHole-AI does not invoke `sudo`, `pkexec`, or a shell internally for restart
orchestration. If restart fails after a successful write, the saved
configuration remains in place and output includes recovery commands such as:

```bash
sudo systemctl restart pihole-ai-engine.service
```

## Troubleshooting

Check status:

```bash
pihole-ai status
pihole-ai health
pihole-ai doctor
pihole-ai setup status
pihole-ai db status
```

Common cases:

- `configuration_migration_required`: run `pihole-ai config migrate --dry-run`,
  then `sudo pihole-ai config migrate --yes`.
- Configuration invalid: run `pihole-ai config validate`, fix reported keys,
  and retry lifecycle commands.
- Dashboard cannot save: reload Settings to get the latest revision, then
  retry.
- Restart failed after save: use the printed `sudo systemctl restart ...`
  command after fixing service authorization or systemd availability.
- Pi-hole DB unreadable: add the `pihole-ai` service user to the Pi-hole DB
  read group or repair Pi-hole DB permissions safely.

## Failed Migration Recovery

Migration validates before writing. If validation fails, the original file is
unchanged and no backup is created. If writing fails, the original file remains
in place where possible and temporary files are cleaned up.

If a completed migration needs rollback, restore the printed migration backup:

```bash
sudo cp /etc/pihole-ai/pihole-ai.env.migration-v0-to-v1.bak /etc/pihole-ai/pihole-ai.env
sudo pihole-ai config validate
sudo pihole-ai restart
```

## Failed Restart Recovery

A failed restart does not roll back configuration automatically. Review the
reported failed services, run the recovery commands, and check logs:

```bash
sudo systemctl restart pihole-ai-engine.service
pihole-ai logs --lines 120
pihole-ai status
```

If needed, restore the `.bak` file printed by the config command and restart
again.

## Uninstall Options

Default uninstall removes managed services and the matching launcher while
preserving configuration, database, runtime data, reputation, rules, feedback,
and logs:

```bash
sudo pihole-ai uninstall
```

Make config preservation explicit in automation:

```bash
sudo pihole-ai uninstall --keep-config
```

Remove the managed config only when intentionally decommissioning the
appliance:

```bash
sudo pihole-ai uninstall --remove-config
```

Runtime log purge requires explicit confirmation:

```bash
sudo pihole-ai uninstall --purge --confirm-purge
```
