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
| `intel` | manage threat-intelligence imports and feeds | mutating/read-only | user with DB write access | selected subcommands |
| `evaluate` | benchmark classifiers against fixtures | read-only | user | `--json` |
| `telemetry` | inspect pipeline telemetry statistics | read-only | user | subcommands |
| `benchmark` | persist and compare offline benchmark runs | mixed | user with DB write access for `run` | subcommands |
| `calibration` | build and select reporting-only confidence calibration profiles | mixed | user with DB write access for mutations | subcommands |
| `reliability` | inspect AI reliability, benchmark, and calibration metrics | read-only | user | subcommands |
| `maintenance` | trim/vacuum events or retain decision history | mutating | user with DB write access | `decision-history --json` |
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
pihole-ai config show [--json] [--category CATEGORY] [--source SOURCE]
pihole-ai config get KEY [--json] [--details]
pihole-ai config validate [--json]
pihole-ai config impact KEY [KEY ...] [--json]
pihole-ai config set KEY VALUE [--dry-run] [--json] [--yes] [--restart]
                     [--config-file PATH]
pihole-ai config unset KEY [--dry-run] [--json] [--yes] [--restart]
                       [--config-file PATH]
pihole-ai config export [--output PATH] [--format json|env] [--secure]
                        [--json]
pihole-ai config import FILE [--dry-run] [--yes] [--json] [--strict]
                        [--restart]
                        [--config-file PATH]
pihole-ai config migrate [--dry-run] [--yes] [--json]
                         [--config-file PATH] [--target-version VERSION]

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
pihole-ai explain DOMAIN --history [--json]
pihole-ai explain DOMAIN --decision DECISION_ID [--json]
pihole-ai explain DOMAIN --compare OLDER_ID NEWER_ID [--json]
pihole-ai feedback DOMAIN safe|bad|false-positive|false-negative|noisy
                  [--reason TEXT] [--promote] [--apply]

pihole-ai rules list [--limit N] [--q TEXT] [--decision allow|block]
pihole-ai rules allow DOMAIN [--reason TEXT]
pihole-ai rules block DOMAIN [--reason TEXT] [--apply]
pihole-ai rules remove DOMAIN

pihole-ai intel import-hosts PATH --source NAME [--category NAME]
                              [--confidence 0-100]
pihole-ai intel list [--limit N] [--q TEXT] [--source NAME] [--category NAME] [--json]
pihole-ai intel source list [--json]
pihole-ai intel source show SOURCE_ID [--json]
pihole-ai intel source add SOURCE_ID --name NAME --url URL
                            [--format hosts|domains|text]
                            [--category NAME] [--confidence 0-100]
                            [--disabled] [--allow-http]
pihole-ai intel source update SOURCE_ID [--name NAME] [--url URL]
                               [--format hosts|domains|text]
                               [--category NAME] [--confidence 0-100]
                               [--refresh-interval-seconds N]
                               [--stale-after-seconds N]
                               [--timeout-seconds N]
                               [--max-download-bytes N]
                               [--expected-content-type MIME]
                               [--allow-http|--disallow-http]
                               [--enable|--disable] [--json]
pihole-ai intel source remove SOURCE_ID
pihole-ai intel source enable SOURCE_ID
pihole-ai intel source disable SOURCE_ID
pihole-ai intel sources [--json]
pihole-ai intel update [SOURCE_ID] [--source SOURCE_ID] [--all] [--dry-run]
                       [--non-interactive] [--json]
pihole-ai intel status [--json]
pihole-ai intel stats [--json]
pihole-ai intel rollback --source SOURCE_ID [--json]
pihole-ai intel audit [--source SOURCE_ID] [--limit N] [--json]

pihole-ai evaluate PATH [--risk-tolerance N] [--include-ai] [--json]
pihole-ai telemetry stats [--json]
pihole-ai benchmark run FIXTURE [--name NAME] [--model NAME]
                         [--prompt-version VERSION]
                         [--risk-tolerance N] [--threshold KEY=VALUE]
                         [--notes TEXT] [--include-ai] [--no-persist]
                         [--baseline RUN_ID] [--fail-on-regression] [--json]
pihole-ai benchmark list [--limit N] [--json]
pihole-ai benchmark show RUN_ID [--json]
pihole-ai benchmark compare BASELINE_RUN_ID CANDIDATE_RUN_ID
                             [--allow-different-fixture]
                             [--max-accuracy-drop N] [--max-f1-drop N]
                             [--max-false-positive-rate-increase N]
                             [--max-false-negative-rate-increase N]
                             [--max-latency-increase N]
                             [--max-abstention-rate-increase N]
                             [--json]
pihole-ai calibration build --benchmark RUN_ID [--name NAME]
                             [--classifier-source SOURCE]
                             [--model NAME] [--prompt-version VERSION]
                             [--bins N] [--notes TEXT] [--json]
pihole-ai calibration build --feedback [--json]
pihole-ai calibration list [--json]
pihole-ai calibration show PROFILE_ID [--json]
pihole-ai calibration activate PROFILE_ID [--json]
pihole-ai calibration deactivate PROFILE_ID [--json]
pihole-ai reliability metrics [--window 24h|7d|30d|all] [--json]
pihole-ai export analysis|events|actions|reputations
                 [--format json|csv] [--output PATH] [--limit N]
                 [--q TEXT] [--min-risk N] [--category NAME]
pihole-ai maintenance [--keep-latest N] [--vacuum]
pihole-ai maintenance decision-history [--dry-run] [--json]
pihole-ai learn [--limit N] [--min-score N] [--no-audit]
```

## Exit-Code Notes

- `health`: `0` healthy, non-zero degraded/unhealthy/unknown.
- `setup status`: `0` ready or degraded-ready, non-zero when required setup is
  incomplete or blocked.
- `config check`: non-zero for validation failures.
- `config show`, `config get`, and `config impact`: `0` on success, `2` for
  unknown keys or invalid filters, `3` when configuration cannot be read or a
  resolved value is invalid.
- `config validate`: `0` when valid, `3` when configuration validation fails.
- `config set` and `config unset`: `0` for a write, no-op, or successful
  dry-run; `1` for permission, confirmation-declined, or persistence failures;
  `2` for unknown keys or invalid command usage; `3` for parse or validation
  failures.
- `config export`: `0` on success, `1` when the output file cannot be written,
  `3` when configuration cannot be read.
- `config import`: `0` for a write, no-op, or successful dry-run; `1` for
  permission, confirmation-declined, or persistence failures; `2` for strict
  unknown-key rejection or invalid command usage; `3` for malformed input,
  unsupported schema, parse, or validation failures.
- `config set --restart`, `config unset --restart`, and
  `config import --restart`: `0` only when the configuration write/no-op/dry-run
  succeeds and every requested restart succeeds. If configuration is saved but
  any requested restart fails, the command exits `1` and reports recovery
  commands. The saved configuration is not rolled back automatically.
- Epic 3.5 Configuration Center command contracts are documented in
  [Configuration Center Design](CONFIGURATION_DESIGN.md).
- `db status`/`db migrate`: `2` incompatible schema, `3` access error, `1`
  migration failure.
- lifecycle commands: `1` for preflight or system command failures.
- `benchmark compare`: `0` when the candidate passes configured tolerances,
  `1` for regressions or invalid comparisons such as fixture digest mismatch.
- `calibration build --feedback`: currently returns non-zero because feedback
  rows do not yet provide trustworthy labeled calibration samples.

## Configuration Inspection

Epic 3.5 exposes configuration inspection and the first safe editing commands.
Inspection commands do not write `.env` files, restart services, or call
`systemctl`. `config set` and `config unset` write only the selected env file
after validation and confirmation. Secret values are masked by default and no
`--show-secrets` option is provided in this phase.

Examples:

```bash
pihole-ai config show
pihole-ai config show --category Dashboard
pihole-ai config show --source environment --json
pihole-ai config get PIHOLE_AI_OLLAMA_MODEL
pihole-ai config get ollama_model --details
pihole-ai config validate
pihole-ai config impact PIHOLE_AI_OLLAMA_URL
pihole-ai config set PIHOLE_AI_OLLAMA_MODEL llama3.2:1b --dry-run
pihole-ai config set PIHOLE_AI_OLLAMA_MODEL llama3.2:1b --yes
pihole-ai config set PIHOLE_AI_OLLAMA_MODEL llama3.2:1b --yes --restart
pihole-ai config unset PIHOLE_AI_OLLAMA_MODEL --dry-run
pihole-ai config export --output backup.json
pihole-ai config export --format env
pihole-ai config export --secure --output secure-backup.json
pihole-ai config import backup.json --dry-run
pihole-ai config import backup.json --yes
pihole-ai config migrate --dry-run
pihole-ai config migrate --yes
```

`config show` prints settings in schema order with the canonical key, safe
value, source, category, and restart impact. JSON output uses a deterministic
`schema_version` and `settings` payload.

`config get` accepts canonical keys, environment-variable names, and supported
aliases such as `LOG_LEVEL`.

`config validate` validates the resolved configuration through the new
configuration framework and existing runtime validation rules. It exits `3`
when validation fails.

`config impact` accepts one or more hypothetical changed settings, deduplicates
them, and reports the affected PiHole-AI services without inspecting or
changing live service state.

`config set` accepts canonical keys, environment-variable names, and aliases.
It validates the proposed value, previews the persisted and effective result,
reports affected services, and prompts with `Apply this change? [y/N]`.
Non-interactive runs must use `--yes` or `--dry-run`. JSON write mode also
requires `--yes` or `--dry-run` so scripts never hang on a prompt.

`config unset` removes only the explicit persisted key from the selected env
file. It does not remove process-environment overrides. Unsetting an already
absent key is an idempotent no-op and does not rewrite the file.

`config migrate` upgrades legacy/unversioned env files to the current
configuration schema. It plans ordered migration steps, normalizes known
aliases, adds `PIHOLE_AI_CONFIG_SCHEMA_VERSION`, validates the transformed
file, creates a migration-specific backup, and writes atomically. It never
restarts services in Phase 2A; restart explicitly after reviewing the result.

`--dry-run` performs validation and restart-impact calculation without
creating files, temp files, or backups. Successful writes are atomic and create
a `.bak` backup when the target file already existed. Backups can be used for
manual recovery:

```bash
sudo cp /etc/pihole-ai/pihole-ai.env.bak /etc/pihole-ai/pihole-ai.env
```

Configuration editing does not restart services automatically. After changing
a setting with restart impact, run the shown service restart command manually,
for example:

```bash
sudo pihole-ai restart
```

Alternatively, pass `--restart` with `config set`, `config unset`, or
`config import` to restart only the affected PiHole-AI services after the
configuration write succeeds. No restart occurs by default, no `sudo` or
`pkexec` is invoked internally, and Pi-hole itself is never restarted.
Dry-runs with `--restart` show the exact affected service plan without calling
`systemctl`.

Restart order is deterministic:

1. `pihole-ai-collector.service`
2. `pihole-ai-engine.service`
3. `pihole-ai-dashboard.service`
4. `pihole-ai-intel-update.timer`

If restart fails after a successful write, the new configuration remains in
place. Output shows failed services, safe manual restart commands such as
`sudo systemctl restart pihole-ai-engine.service`, and the backup path when one
was created.

If a process environment variable currently overrides the persisted value, the
preview warns that the file will change but the effective value remains
controlled by the process environment.

Secret settings remain masked in human and JSON output. Supplying secrets as
command-line arguments can leave them in shell history or process listings;
future phases may add stdin or prompt-based secret entry.

`config export` writes a deterministic JSON export by default. JSON exports
include schema version, PiHole-AI package version, export timestamp, format,
secure-export marker, and schema-ordered settings. Normal exports omit secrets
and mask sensitive non-secret values. `--format env` emits a generated
managed-env representation with canonical environment names. `--secure` is an
explicit opt-in that includes schema-approved secrets; protect secure exports
with restrictive file permissions and avoid sharing them.

`config import` accepts JSON or env exports, validates the schema version,
resolves aliases, validates every imported setting, previews changed settings,
reports restart impact, and writes atomically only after confirmation or
`--yes`. Use `--dry-run` first:

```bash
pihole-ai config import backup.json --dry-run
sudo pihole-ai config import backup.json --yes
```

Unknown imported settings are reported as warnings by default and ignored so
older compatible imports remain usable. `--strict` turns unknown settings into
an error. Newer unsupported schema versions are rejected with the imported and
supported versions shown.

On write failure, the original configuration remains unchanged and temporary
files are removed. If a backup has already been created, it is retained for
manual recovery.

## Threat-Intel Source Updates

`intel source update` is a partial metadata edit. Only provided fields change.
It preserves the source ID, active generation, previous generations, entries,
update audit history, and immutable decisions. It does not fetch content,
activate a generation, or delete entries.

Changing `--url` or fetch-related settings clears ETag and Last-Modified
validators so the next explicit `intel update` refetches safely. Display-only
changes such as `--name` preserve validators and the active source state.
Source URL credentials are rejected. HTTP URLs are denied by default unless
`--allow-http` is used for an explicitly trusted local/test feed.

`--confidence` is an integer percentage from `0` to `100`. Decimal, negative,
and above-range values are rejected.

Dry-run updates preview the proposed generation and do not mutate source state,
generations, validators, entries, or audit rows.

`intel update` accepts either a positional `SOURCE_ID` or `--source SOURCE_ID`
for a single source. It reports whether downloaded content left the active
generation unchanged, reactivated an existing inactive generation, or created a
new generation. JSON output includes `content_unchanged`, `reused_generation`,
and `created_generation`; 304 reactivation output also includes
`not_modified`, `trigger=http_not_modified`, and `remote_generation`. Text
output names the reactivated generation and previous active generation when
reuse occurs.

`intel sources` shows configured feed sources with operational state such as
enabled status, active entry count, last HTTP status, and last successful
update. `intel stats` summarizes enabled sources, active indicators,
failed/stale sources, and integrity issue counts. Both commands are read-only.

Rollback changes the classifier-active generation but preserves the remote
generation represented by current validators, so a later HTTP 304 may reactivate
an inactive historical generation without creating duplicates.

Read-only intel commands such as `source list`, `source show`, `sources`,
`status`, `stats`, `audit`, and `list` use read-only database access and do not
run migrations.
Mutating commands such as `source add`, `source update`, `update`, `rollback`,
and `source remove` may initialize or migrate the runtime database.

## AI Reliability And Calibration

`telemetry stats` summarizes observed pipeline runs and stages. `benchmark`
commands persist offline fixture evaluation runs and compare candidates against
baselines. `calibration build --benchmark RUN_ID` creates a reporting-only
confidence calibration profile from a completed benchmark run; it never changes
runtime classifier decisions, thresholds, AI calls, cache behavior, or actions.

Calibration profile activation selects which profile explain/reliability views
use for reporting. Activation is scoped by classifier source, model, and prompt
version, allowing independent reporting profiles where enough benchmark samples
exist. Raw confidence remains visible and authoritative.

`reliability metrics` is read-only. It reports confidence distribution,
observed accuracy by band, calibration error, Brier score, false-positive and
false-negative counts, AI invocation rate, cache-hit rate, latency, classifier
usage, benchmark history, and telemetry volume diagnostics.

## Security-Sensitive Input

Use `dashboard auth set-password --password-stdin` for automation. Do not place
passwords, hashes, session secrets, CSRF tokens, or raw model payloads in command
history or documentation.
