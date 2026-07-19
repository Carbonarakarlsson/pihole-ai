# Upgrading

This guide covers safe PiHole-AI appliance upgrades and configuration
migration. Package versions, database schema versions, and configuration schema
versions are separate.

## Configuration Schema

The current configuration schema version is:

```text
1
```

Managed env files use this marker:

```text
PIHOLE_AI_CONFIG_SCHEMA_VERSION=1
```

Existing unversioned `.env` files are treated as legacy schema version `0`.
They remain loadable by runtime configuration code where they were previously
valid, but dashboard configuration editing requires migration first.

`pihole-ai install` and `pihole-ai upgrade` are migration-aware but do not
silently rewrite legacy configuration. If the managed appliance env file is
legacy or unversioned, lifecycle commands stop before service creation,
enablement, or startup and print the migration commands to run.

## Recommended Sequence

Preview the migration:

```bash
pihole-ai config migrate --dry-run
```

Apply it to the appliance config:

```bash
sudo pihole-ai config migrate --yes
```

Validate the result:

```bash
pihole-ai config validate
```

Restart PiHole-AI after review:

```bash
pihole-ai restart
```

The migration command does not invoke `sudo`, `pkexec`, `systemctl`, or service
restart commands internally.

After migration, rerun the lifecycle command that was blocked:

```bash
sudo pihole-ai install --no-start
# or
sudo pihole-ai upgrade
```

## What Migration Does

The schema `0 -> 1` migration:

- adds `PIHOLE_AI_CONFIG_SCHEMA_VERSION=1`
- renames supported legacy aliases to canonical names, for example
  `OLLAMA_HOST` to `PIHOLE_AI_OLLAMA_URL`
- preserves comments and blank lines
- preserves unknown keys
- preserves secret values without printing them
- validates known settings before writing
- writes through a temporary file and atomic rename
- creates a migration-specific backup before replacing the env file

If both an alias and canonical key exist for the same setting, migration fails
before writing. PiHole-AI does not guess which value should win.

## Backups And Restore

Migration backups are named like:

```text
pihole-ai.env.migration-v0-to-v1.bak
```

If that file already exists, PiHole-AI chooses a collision-safe suffix such as
`.bak.1`. Backups are never deleted automatically.

To restore manually:

```bash
sudo cp /etc/pihole-ai/pihole-ai.env.migration-v0-to-v1.bak /etc/pihole-ai/pihole-ai.env
sudo pihole-ai restart
```

Use the exact backup path printed by the migration command.

## Unsupported Future Versions

If a config file contains a future schema marker, PiHole-AI refuses to rewrite
it:

```text
This configuration was created for schema version 3, but this PiHole-AI build supports up to version 1.
```

Upgrade PiHole-AI before editing that file.

## Dashboard Behavior

The dashboard Settings page does not migrate configuration during page load.
For legacy/unversioned env files, configuration API endpoints return a
`configuration_migration_required` error and do not write the file. Run the CLI
migration command, then reload the dashboard.

## Import And Export

JSON exports include the current schema version. ENV exports include the
canonical `PIHOLE_AI_CONFIG_SCHEMA_VERSION=1` marker. Normal exports omit
secrets; use `pihole-ai config export --secure` only when writing to protected
storage.

Imports ignore the schema marker as runtime configuration input and validate
the destination settings before writing. Newer unsupported import schema
versions are rejected.
