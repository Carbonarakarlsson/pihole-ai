# CLI Reference

All commands are available through `pihole-ai`. Commands that mutate systemd,
protected configuration, runtime ownership, or service state require root on an
appliance. JSON output is available only where noted.

## Top-Level Commands

| Command | Purpose | Mode | Privilege | JSON |
| --- | --- | --- | --- | --- |
| `collect` | run continuous Pi-hole query collector | mutating | service/root in appliance | no |
| `collector` | alias for `collect` | mutating | service/root in appliance | no |
| `run-engine` | run continuous analysis engine | mutating | service/root in appliance | no |
| `engine` | alias for `run-engine` | mutating | service/root in appliance | no |
| `engine-once` | process one engine batch | mutating | service/root in appliance | no |
| `dashboard` | run dashboard web server | mutating server | service/root in appliance | no |
| `status` | show service state and project/database stats | read-only | user | no |
| `health` | run unified health checks | read-only | user | `--json` |
| `doctor` | run read-only appliance diagnostics | read-only | user | `--json` |
| `setup` | first-run setup guidance/status | mixed | user/root for mutations | `--json` |
| `config` | inspect and validate configuration | read-only | user | subcommands |
| `db` | inspect or migrate PiHole-AI schema | mixed | user/root depending path | subcommands |
| `install` | install appliance files/services | mutating | root | `--json` |
| `upgrade` | refresh managed appliance files | mutating | root | `--json` |
| `uninstall` | remove managed services/launcher | mutating | root | `--json` |
| `enable` | enable services at boot | mutating | root | no |
| `disable` | disable services at boot | mutating | root | no |
| `start` | start all services now | mutating | root | no |
| `stop` | stop all services now | mutating | root | no |
| `restart` | restart all services | mutating | root | no |
| `logs` | show journal logs | read-only | user with journal access | no |
| `explain` | explain local evidence for a domain | read-only | user | `--json` |
| `feedback` | record human feedback | mutating | user with DB write access | no |
| `rules` | manage manual allow/block rules | mutating/read-only | user with DB write access | no |
| `intel` | import/list local threat intelligence | mutating/read-only | user with DB write access | no |
| `evaluate` | benchmark classifiers against fixtures | read-only | user | `--json` |
| `maintenance` | trim/vacuum the events database | mutating | user with DB write access | no |
| `export` | export rows from local datasets | read-only/write output | user | format option |
| `learn` | update local reputation from history | mutating | user with DB write access | no |
| `config-path` | print active config path | read-only | user | no |
| `data-path` | print active database path | read-only | user | no |
| `log-path` | print active log path | read-only | user | no |
| `service` | compatibility install/uninstall namespace | mutating | root | no |

## Subcommands And Syntax

```bash
pihole-ai dashboard [--host HOST] [--port PORT]
pihole-ai dashboard auth status [--json]
pihole-ai dashboard auth set-password [--password-stdin] [--json]
pihole-ai dashboard auth enable [--json]
pihole-ai dashboard auth disable --confirm-disable-auth [--json]

pihole-ai config check [--mode syntax|install|runtime] [--json]
pihole-ai config show [--json]

pihole-ai setup [status] [--json] [--non-interactive] [--dry-run]
                [--install] [--start] [--enable] [--skip-ollama-check]

pihole-ai db status [--json]
pihole-ai db migrate [--json]

pihole-ai install [status] [--dry-run] [--json] [--no-enable] [--no-start]
pihole-ai upgrade [--dry-run] [--json]
pihole-ai uninstall [--dry-run] [--json] [--purge] [--confirm-purge]
pihole-ai service install [--dry-run]
pihole-ai service uninstall [--dry-run]

pihole-ai logs [--lines N] [--follow|-f] [--dry-run]
pihole-ai status [--ollama] [--dry-run]
pihole-ai health [--json]
pihole-ai doctor [--json]

pihole-ai explain DOMAIN [--json]
pihole-ai feedback DOMAIN safe|bad|false-positive|false-negative|noisy
                  [--reason TEXT] [--promote] [--apply]

pihole-ai rules list [--limit N] [--q TEXT] [--decision allow|block]
pihole-ai rules allow DOMAIN [--reason TEXT]
pihole-ai rules block DOMAIN [--reason TEXT] [--apply]
pihole-ai rules remove DOMAIN

pihole-ai intel import-hosts PATH --source NAME [--category NAME]
                              [--confidence 0-100]
pihole-ai intel list [--limit N] [--q TEXT] [--source NAME] [--category NAME]

pihole-ai evaluate PATH [--risk-tolerance N] [--include-ai] [--json]
pihole-ai export analysis|events|actions|reputations
                 [--format json|csv] [--output PATH] [--limit N]
                 [--q TEXT] [--min-risk N] [--category NAME]
pihole-ai maintenance [--keep-latest N] [--vacuum]
pihole-ai learn [--limit N] [--min-score N] [--no-audit]
```

## Exit-Code Notes

- `health`: `0` healthy, non-zero degraded/unhealthy/unknown.
- `setup status`: `0` ready or degraded-ready, non-zero when required setup is
  incomplete or blocked.
- `config check`: non-zero for validation failures.
- `db status`/`db migrate`: `2` incompatible schema, `3` access error, `1`
  migration failure.
- lifecycle commands: `1` for preflight or system command failures.

## Security-Sensitive Input

Use `dashboard auth set-password --password-stdin` for automation. Do not place
passwords, hashes, session secrets, CSRF tokens, or raw model payloads in command
history or documentation.
