# Configuration Center Design

Epic 3.5 Phase 1 will turn PiHole-AI configuration into an appliance-grade
Configuration Center for CLI and dashboard users. This document inventories the
current state and defines the target design before implementation.

Phase 1A status: implemented as an internal framework. The schema registry,
validation primitives, preserving `.env` model, atomic writer, masking helpers,
restart-impact metadata, and import/export primitives live in:

- `core/config_schema.py`
- `core/config_validation.py`
- `core/config_manager.py`

These primitives are infrastructure only. Public CLI commands, dashboard
Settings pages, config audit surfaces, and automatic service restarts remain
deferred to later Phase 1 work.

Phase 1B status: implemented as a read-only CLI surface:

- `pihole-ai config show`
- `pihole-ai config get <key>`
- `pihole-ai config validate`
- `pihole-ai config impact <key> [<key> ...]`

These commands expose schema-backed inspection, lookup, validation, masking,
source attribution, and restart-impact previews. They do not write `.env`
files, expose secrets, restart services, import/export configuration, or add
dashboard Settings APIs.

Phase 1C1 status: implemented as the first safe write-capable CLI surface:

- `pihole-ai config set <key> <value>`
- `pihole-ai config unset <key>`

Both commands support `--dry-run`, `--json`, `--yes`, and `--config-file`.
They validate the selected schema entry, preserve comments/blank lines/unknown
keys, write atomically with backups, preview restart impact, and never restart
services. JSON write mode requires `--dry-run` or `--yes`. Secret values remain
masked, and process-environment overrides are called out explicitly in
previews.

Phase 1C2 status: implemented as safe import/export CLI operations:

- `pihole-ai config export`
- `pihole-ai config import <file>`

Exports support JSON, env format, output files, and explicit `--secure`
exports. Normal exports omit secrets and mask sensitive values. Imports support
JSON/env detection, schema-version checks, alias resolution, unknown-key
warnings with `--strict`, dry-run previews, confirmation, atomic writes,
backups, and rollback-on-failure behavior. Automatic restarts and dashboard
integration remain deferred.

Phase 1C3 status: implemented as explicit restart orchestration for successful
configuration writes:

- `pihole-ai config set ... --restart`
- `pihole-ai config unset ... --restart`
- `pihole-ai config import ... --restart`

Restarts are opt-in, privilege-aware, and limited to affected PiHole-AI
services from the typed restart-impact model. Configuration persistence happens
before service restart. Restart failures are reported independently and never
silently roll back a valid configuration write.

Related documentation:

- [Configuration](CONFIGURATION.md)
- [Operations](OPERATIONS.md)
- [CLI Reference](CLI_REFERENCE.md)
- [Architecture](ARCHITECTURE.md)
- [Database](DATABASE.md)

## Goals

- Keep one authoritative persisted appliance configuration.
- Preserve backward compatibility with `/etc/pihole-ai/pihole-ai.env` and
  existing environment variables.
- Provide safe CLI and dashboard editing with validation before writes.
- Preserve unknown keys and comments during upgrades.
- Never expose secrets in dashboard APIs, logs, telemetry, or default exports.
- Preview restart impact before saving.

## Current-State Inventory

Current configuration is spread across these sources:

| Source | Current role | Files |
| --- | --- | --- |
| Managed appliance env file | Main appliance configuration | `/etc/pihole-ai/pihole-ai.env`, `pihole_ai/defaults/pihole-ai.env` |
| Project `.env` | Development fallback | `.env`, `.env.example` |
| Process environment | Runtime override for all parsed settings | `core/config.py` |
| Python defaults | Final fallback for parsed settings and runtime constants | `core/config.py`, `pihole_ai/service.py`, CLI modules |
| CLI flags | Command-scoped overrides, mostly not persisted | `pihole_ai/cli.py` |
| Dashboard settings API | Narrow persisted env-file edits | `ui/dashboard.py` |
| Setup/auth writers | Narrow persisted env-file edits for onboarding | `pihole_ai/setup.py`, `pihole_ai/dashboard_auth.py`, `pihole_ai/service.py` |
| Systemd units | Load the managed env file and define service commands | `pihole_ai/service.py` |
| Database-backed settings | Source-specific threat-intelligence configuration and runtime state | `core/db.py`, `pihole_ai/intel.py` |
| App state | Small runtime state/counters, not user configuration | `app_state` table |

### Current Precedence

`core.config.load_config()` currently reads:

1. `/etc/pihole-ai/pihole-ai.env`
2. project `.env`
3. process environment
4. Python defaults

Later env files override earlier env-file values, and process environment
overrides env files. CLI flags are command-local and usually bypass persisted
configuration. The dashboard Settings page persists only a narrow allowlist:

- `AI_ENABLED`
- `AI_MAX_CALLS_PER_MINUTE`
- `AI_COOLDOWN_SECONDS`
- `AI_TIMEOUT_SECONDS`
- `PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS`
- `DEV_ACCESS_LOGS`

### Current Problems And Risks

- Multiple writers can edit the same env file with separate allowlists.
- CLI flags can obscure whether a value is persisted or temporary.
- There is no complete machine-readable settings schema.
- Dashboard settings cover only a small subset of safe operational settings.
- Restart impact is implicit rather than previewable.
- Unknown env keys are preserved by some writers, but not governed by one
  shared serialization contract.
- Secrets exist in the same file as operational settings.
- Database-backed threat-intelligence source configuration is separate from
  env-backed appliance configuration and needs clear ownership boundaries.

## Setting Categories

Target Configuration Center categories:

- General
- Pi-hole integration
- Database
- Collector
- Engine and classification
- Ollama and AI
- Threat intelligence
- Telemetry and reliability
- Dashboard
- Authentication
- Logging
- Maintenance
- Services and lifecycle
- Development-only

## Settings Inventory

Sensitivity:

- `public`: safe to show everywhere.
- `operational`: safe to show to authenticated operators; may reveal paths,
  hosts, ports, or policy.
- `sensitive`: must be masked by default; may be included in secure export.
- `secret`: never returned in plaintext by default, never logged, never stored
  in telemetry, excluded from normal exports.

Restart impact:

- `none`: live reload or next command invocation is feasible.
- `dashboard`: restart `pihole-ai-dashboard.service`.
- `collector`: restart `pihole-ai-collector.service`.
- `engine`: restart `pihole-ai-engine.service`.
- `intel-timer`: restart/reload `pihole-ai-intel-update.timer`.
- `all`: restart collector, engine, and dashboard.
- `install`: install/upgrade action required; dashboard must not mutate
  directly.

| Canonical key | Environment variable | Default | Type | Source | Main consumers | Documented | Dashboard exposure | Sensitivity | Restart impact | Export |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `project_root` | `PIHOLE_AI_PROJECT_ROOT` | source checkout | path | `core/config.py` | service/install/dev | alias only | no | operational | install | no |
| `data_dir` | `PIHOLE_AI_DATA_DIR` | `/var/lib/pihole-ai` | path | `core/config.py` | service/layout | alias only | read-only | operational | all | yes |
| `log_dir` | `PIHOLE_AI_LOG_DIR` | `/var/log/pihole-ai` | path | `core/config.py` | service/layout | alias only | read-only | operational | all | yes |
| `config_file` | `PIHOLE_AI_CONFIG_FILE` | `/etc/pihole-ai/pihole-ai.env` | path | `core/config.py` | config loader | alias only | read-only | operational | all | no |
| `events_db` | `EVENTS_DB_PATH`, `PIHOLE_AI_EVENTS_DB` | `/var/lib/pihole-ai/events.db` | path | env/default | all DB users | yes | read-only initially | operational | all | yes |
| `pihole_db` | `PIHOLE_AI_PIHOLE_DB` | `/etc/pihole/pihole-FTL.db` | path | env/default | collector, health | yes | yes | operational | collector | yes |
| `log_file` | `LOG_PATH`, `PIHOLE_AI_LOG_FILE` | `/var/log/pihole-ai/pihole-ai.log` | path | env/default | logging | yes | yes | operational | all | yes |
| `alert_log` | `PIHOLE_AI_ALERT_LOG` | `/var/log/pihole-ai/alerts.log` | path | env/default | actions/alerts | yes | yes | operational | engine | yes |
| `db_timeout_seconds` | `PIHOLE_AI_DB_TIMEOUT_SECONDS` | `30` | int seconds | env/default | SQLite policy | yes | yes | operational | all | yes |
| `db_migration_timeout_seconds` | `PIHOLE_AI_DB_MIGRATION_TIMEOUT_SECONDS` | `60` | int seconds | env/default | migrations | yes | yes | operational | next migration | yes |
| `db_busy_timeout_ms` | `PIHOLE_AI_DB_BUSY_TIMEOUT_MS` | `30000` | int ms | env/default | SQLite policy | yes | yes | operational | all | yes |
| `collect_batch_size` | `PIHOLE_AI_COLLECT_BATCH_SIZE` | `200` | int | env/default | collector | yes | yes | operational | collector | yes |
| `collect_interval` | `PIHOLE_AI_COLLECT_INTERVAL` | `2` | int seconds | env/default | collector | yes | yes | operational | collector | yes |
| `engine_batch_size` | `PIHOLE_AI_ENGINE_BATCH_SIZE` | `500` | int | env/default | engine | yes | yes | operational | engine | yes |
| `engine_interval` | `PIHOLE_AI_ENGINE_INTERVAL` | `5` | int seconds | env/default | engine | yes | yes | operational | engine | yes |
| `high_risk_threshold` | `PIHOLE_AI_HIGH_RISK_THRESHOLD` | `70` | int 0-100 | env/default | classifier/action policy | yes | yes | operational | engine | yes |
| `alert_threshold` | `PIHOLE_AI_ALERT_THRESHOLD` | `50` | int 0-100 | env/default | actions/alerts | yes | yes | operational | engine | yes |
| `action_mode` | `PIHOLE_AI_ACTION_MODE` | `dry-run` | enum | env/default | action policy | yes | yes | operational | engine | yes |
| `beacon_history` | `PIHOLE_AI_BEACON_HISTORY` | `100` | int | code default | heuristics | alias only | advanced | operational | engine | yes |
| `beacon_min_events` | `PIHOLE_AI_BEACON_MIN_EVENTS` | `10` | int | code default | heuristics | alias only | advanced | operational | engine | yes |
| `beacon_repeat_threshold` | `PIHOLE_AI_BEACON_REPEAT_THRESHOLD` | `3` | int | code default | heuristics | alias only | advanced | operational | engine | yes |
| `cache_ttl` | `PIHOLE_AI_CACHE_TTL` | `86400` | int seconds | env/default | engine cache | yes | yes | operational | engine | yes |
| `keep_latest_events` | `PIHOLE_AI_KEEP_LATEST_EVENTS` | `100000` | int | env/default | maintenance | yes | yes | operational | none | yes |
| `decision_history_retention_days` | `PIHOLE_AI_DECISION_HISTORY_RETENTION_DAYS` | `365` | int days | env/default | maintenance | yes | yes | operational | none | yes |
| `decision_history_max_per_domain` | `PIHOLE_AI_DECISION_HISTORY_MAX_PER_DOMAIN` | `100` | int | env/default | maintenance | yes | yes | operational | none | yes |
| `ai_enabled` | `AI_ENABLED`, `PIHOLE_AI_ENABLED` | `true` | bool | env/default | AI classifier, health | yes | yes | operational | engine | yes |
| `ai_max_calls_per_minute` | `AI_MAX_CALLS_PER_MINUTE` | `2` | int | env/default | AI classifier | yes | yes | operational | engine | yes |
| `ai_cooldown_seconds` | `AI_COOLDOWN_SECONDS` | `60` | int seconds | env/default | AI classifier | yes | yes | operational | engine | yes |
| `ai_timeout_seconds` | `AI_TIMEOUT_SECONDS` | `20` | int seconds | env/default | AI classifier | yes | yes | operational | engine | yes |
| `ai_minimum_score` | `PIHOLE_AI_AI_MINIMUM_SCORE` | `70` | int 0-100 | code default | AI result policy | alias only | advanced | operational | engine | yes |
| `ollama_url` | `PIHOLE_AI_OLLAMA_URL` | `http://127.0.0.1:11434` | URL | env/default | AI, health, status | yes | yes, redacted | sensitive if host is private | engine | secure export |
| `ollama_model` | `PIHOLE_AI_OLLAMA_MODEL` | `llama3.2:1b` | string | env/default | AI, health, status | yes | yes | operational | engine | yes |
| `http_timeout` | `PIHOLE_AI_HTTP_TIMEOUT` | `60` | int seconds | code default | HTTP helpers | alias only | advanced | operational | engine | yes |
| `intel_auto_update_enabled` | `PIHOLE_AI_INTEL_AUTO_UPDATE_ENABLED` | `false` | bool | env/default | updater service | yes | yes | operational | intel-timer | yes |
| `intel_update_interval_seconds` | `PIHOLE_AI_INTEL_UPDATE_INTERVAL_SECONDS` | `86400` | int seconds | env/default | timer/updater | yes | yes | operational | intel-timer | yes |
| `intel_http_timeout_seconds` | `PIHOLE_AI_INTEL_HTTP_TIMEOUT_SECONDS` | `20` | int seconds | env/default | feed downloader | yes | yes | operational | engine/updater | yes |
| `intel_max_download_bytes` | `PIHOLE_AI_INTEL_MAX_DOWNLOAD_BYTES` | `2000000` | int bytes | env/default | feed downloader | yes | yes | operational | engine/updater | yes |
| `intel_stale_after_seconds` | `PIHOLE_AI_INTEL_STALE_AFTER_SECONDS` | `172800` | int seconds | env/default | diagnostics | yes | yes | operational | none | yes |
| `intel_allow_http` | `PIHOLE_AI_INTEL_ALLOW_HTTP` | `false` | bool | env/default | source add/fetch default | yes | yes with warning | operational | none | yes |
| `intel_user_agent` | `PIHOLE_AI_INTEL_USER_AGENT` | `PiHole-AI threat-intel updater` | string | env/default | feed downloader | yes | yes | operational | updater/engine | yes |
| `dashboard_host` | `PIHOLE_AI_DASHBOARD_HOST` | `0.0.0.0` | host/IP | code default | dashboard CLI/service | partially | yes | operational | dashboard | yes |
| `dashboard_port` | `PIHOLE_AI_DASHBOARD_PORT` | `8080` | TCP port | env/default | dashboard | yes | yes | operational | dashboard | yes |
| `dashboard_poll_interval_ms` | `PIHOLE_AI_DASHBOARD_POLL_INTERVAL_MS` | `10000` | int ms | env/default | dashboard JS | yes | yes | operational | dashboard | yes |
| `dashboard_overview_poll_interval_ms` | `PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS` | `5000` | int ms | env/default | dashboard JS/settings API | yes | yes | operational | dashboard | yes |
| `dashboard_metrics_poll_interval_ms` | `PIHOLE_AI_DASHBOARD_METRICS_POLL_INTERVAL_MS` | `15000` | int ms | env/default | dashboard JS | yes | yes | operational | dashboard | yes |
| `dashboard_tables_poll_interval_ms` | `PIHOLE_AI_DASHBOARD_TABLES_POLL_INTERVAL_MS` | `10000` | int ms | env/default | dashboard JS | yes | yes | operational | dashboard | yes |
| `dashboard_slow_poll_interval_ms` | `PIHOLE_AI_DASHBOARD_SLOW_POLL_INTERVAL_MS` | `30000` | int ms | env/default | dashboard JS | yes | yes | operational | dashboard | yes |
| `dev_access_logs` | `DEV_ACCESS_LOGS` | `false` | bool | env/default | dashboard logging | yes | yes | operational | dashboard | yes |
| `dashboard_auth_enabled` | `PIHOLE_AI_DASHBOARD_AUTH_ENABLED` | `true` | bool | env/default | dashboard auth | yes | yes with guardrails | sensitive policy | dashboard | secure export |
| `dashboard_username` | `PIHOLE_AI_DASHBOARD_USERNAME` | `admin` | string | env/default | dashboard auth | yes | yes | sensitive | dashboard | secure export |
| `dashboard_password_hash` | `PIHOLE_AI_DASHBOARD_PASSWORD_HASH` | empty | hash | env/setup | dashboard auth | yes | masked only | secret | dashboard | secure export only |
| `dashboard_secret_key` | `PIHOLE_AI_DASHBOARD_SECRET_KEY` | generated on install | string | env/install | Flask sessions/CSRF | yes | configured/masked only | secret | dashboard | secure export only |
| `dashboard_session_lifetime_minutes` | `PIHOLE_AI_DASHBOARD_SESSION_LIFETIME_MINUTES` | `480` | int minutes | env/default | dashboard auth | yes | yes | operational | dashboard | yes |
| `dashboard_trust_proxy` | `PIHOLE_AI_DASHBOARD_TRUST_PROXY` | `false` | bool | env/default | dashboard/proxy fix | yes | yes with warning | operational | dashboard | yes |
| `debug` | `PIHOLE_AI_DEBUG` | `false` | bool | code default | development/logging | alias only | no | operational | all | no |
| `log_level` | `PIHOLE_AI_LOG_LEVEL`, `LOG_LEVEL` | `INFO` | enum | env/default | logging | yes | yes | operational | all | yes |

### Database-Backed Threat-Intelligence Source Settings

Threat-intelligence sources are user-managed records, not global appliance
configuration. They should remain database-backed.

| Setting | Storage | Consumers | Dashboard exposure | Export |
| --- | --- | --- | --- | --- |
| `source_id`, `name`, `url`, `format`, `category`, `confidence`, `enabled` | `threat_intel_sources` | intel CLI, updater, classifier | yes, URL redacted if credentials ever become possible | separate threat-intel export |
| `refresh_interval_seconds`, `stale_after_seconds`, `timeout_seconds`, `max_download_bytes`, `allow_http`, `expected_content_type` | `threat_intel_sources` | updater/downloader/diagnostics | yes | separate threat-intel export |
| `etag`, `last_modified`, hashes, active generation, remote generation | state/audit tables | updater/classifier/diagnostics | read-only | diagnostics/export only |

### CLI-Only Overrides And Operational Flags

CLI flags such as `dashboard --host`, `dashboard --port`, `status --ollama`,
`install --dry-run`, `install --no-start`, `intel update --dry-run`, benchmark
tolerances, and export filters are command inputs. They must not be persisted
as appliance configuration unless a future command explicitly says so.

`core.config` also exposes module-level compatibility names such as
`OLLAMA_URL` and `OLLAMA_MODEL` for older imports. These are not env-file keys
and should not become canonical configuration names.

## Proposed Architecture

Target precedence:

```text
command override
→ managed appliance env file
→ development .env
→ process environment for explicit advanced overrides
→ application defaults
```

Rationale:

- The managed env file should be the single persisted appliance truth.
- Command overrides should affect only that command invocation.
- Development `.env` remains useful for source checkouts.
- Process environment overrides remain supported for tests and advanced
  service managers, but the dashboard should show when a value is overridden
  outside the managed file and refuse to pretend it can persist that value.

Implementation can keep current runtime precedence initially, but the
Configuration Center should display source attribution and warn when process
environment overrides hide persisted values.

## Settings Schema

Add a metadata-only settings registry before adding writers. Each setting entry
should include:

- canonical key
- env names and aliases
- category
- type
- default
- allowed values/ranges
- parser/serializer
- validator
- sensitivity
- dashboard visibility/editability
- export policy
- restart impact
- service impact
- documentation text
- source attribution in effective config

The registry is now code-owned in `core/config_schema.py`. Documentation
generation remains deferred.

## Validation Model

Validation must support both CLI and dashboard previews.

Rules:

- booleans: accept `true/false`, `1/0`, `yes/no`, `on/off`; serialize as
  `true` or `false`
- integers: enforce positive, zero-or-positive, or bounded ranges
- ports: `1-65535`
- risk/confidence thresholds: `0-100`
- session lifetime: `1-1440` minutes
- URLs: `http` or `https`, hostname required, embedded credentials prohibited
- model names: non-empty when AI is enabled; printable non-control text
- paths: absolute for appliance paths; parent existence/writability in runtime
  validation; no directory where a file is required
- Pi-hole DB: existing readable regular file in runtime validation
- database path: absolute, not a directory, writable parent, no symlink escape
  in protected appliance mode
- dashboard host: parseable hostname/IP; non-loopback bind warns and requires
  authentication
- authentication: exposed dashboard cannot disable auth; password hash and
  secret key required in runtime mode
- log level: Python logging enum such as `DEBUG`, `INFO`, `WARNING`, `ERROR`,
  `CRITICAL`
- action mode: `off`, `dry-run`, or `block`
- HTTP threat-intel: HTTP disabled by default; enabling requires explicit
  warning
- mutually dependent settings: AI enabled requires model; dashboard auth
  disabled requires loopback bind; proxy trust should warn on exposed bind

Phase 1A includes reusable primitive validators for booleans, integers,
floats, ports, URLs, hostnames/IPs, filesystem paths, enums, Ollama model
names, and numeric ranges. Cross-setting runtime validation remains in
`core/config.py` until public config-editing commands are added.

Validation modes:

- `syntax`: type and format only
- `install`: tolerate missing runtime directories that install will create
- `runtime`: require all runtime paths and credentials needed by active services
- `preview`: validate proposed updates before writing

## Persistence Model

Target format: managed `.env` remains the persisted appliance format.

Reasons:

- already compatible with systemd `EnvironmentFile=`
- human-readable
- easy to recover manually
- already protected by `/etc/pihole-ai` permissions
- no new dependency required
- smallest architecture that preserves current appliance behavior

Writer requirements:

- operate only on verified managed paths
- reject symlink substitution
- preserve unknown keys, comments, and ordering where possible
- deterministic serialization for known keys
- atomic write with same metadata as current file
- backup before replacement
- validate proposed content before replacement
- repair final permissions to `root:pihole-ai 0640` for the file and
  `root:pihole-ai 0750` for the directory
- support dry-run and impact preview
- never silently delete unknown keys
- record audit rows for dashboard/CLI configuration changes where feasible

Phase 1A provides the internal preserving writer and atomic replacement
primitive. Managed-path ownership repair, dashboard/CLI validation before
write, and audit rows remain deferred until the public write surfaces are
implemented.

Rejected alternatives for Phase 1:

- TOML: cleaner schema but incompatible with systemd without an env-generation
  layer.
- JSON: less operator-friendly and still incompatible with systemd.
- database-backed global config: difficult to use before DB migration and not
  directly consumable by systemd services.

## Secret-Handling Model

True secrets today:

- `PIHOLE_AI_DASHBOARD_PASSWORD_HASH`
- `PIHOLE_AI_DASHBOARD_SECRET_KEY`

Sensitive operational values:

- dashboard auth enablement and username
- Ollama host URL when it reveals private topology
- filesystem paths in public contexts
- source URLs if future credential-bearing URLs are ever allowed

Rules:

- default CLI and dashboard output returns masked values or boolean
  `configured` flags for secrets
- normal export excludes secrets
- secure export may include secrets only with explicit `--include-secrets`
  or equivalent dashboard confirmation
- secrets are never logged
- secrets are never stored in telemetry
- secrets are never returned in API validation errors
- imports containing secrets require protected file permissions and explicit
  confirmation

## Restart-Impact Matrix

| Category | Example settings | Impact |
| --- | --- | --- |
| Database path/policy | `EVENTS_DB_PATH`, DB timeouts | all services |
| Pi-hole DB path | `PIHOLE_AI_PIHOLE_DB` | collector |
| Collector cadence | collect batch/interval | collector |
| Engine policy | engine batch/interval, thresholds, action mode, cache TTL | engine |
| AI/Ollama | AI enabled/rate/cooldown/timeout/model/URL | engine |
| Threat-intel global updater | auto update, interval | intel timer/updater |
| Threat-intel fetch defaults | timeout, max bytes, user agent, HTTP policy | updater and engine where used |
| Dashboard bind/auth/session/polling | dashboard host/port/auth/session/poll intervals | dashboard |
| Logging | log path/level/access logs | affected service or all if global |
| Maintenance retention defaults | keep latest, decision retention | none until maintenance command runs |
| Protected paths/service identity | config/data/log dirs, service user/group | install/upgrade only |

The UI and CLI must show impact before saving:

```text
Changing PIHOLE_AI_OLLAMA_URL will require:
- restart pihole-ai-engine.service
```

No configuration action should restart Pi-hole itself.

## CLI Contract

Future commands:

### `pihole-ai config show [--json] [--include-secrets]`

- Shows effective configuration with source attribution.
- Secrets masked by default.
- Exit `0` on success, `3` on inaccessible/malformed config.

### `pihole-ai config get <key> [--json] [--include-secret]`

- Reads one canonical key or environment variable alias.
- Secret values masked unless explicitly requested.
- Exit `0` found, `2` unknown key, `3` config read error.

### `pihole-ai config set <key> <value> [--dry-run] [--json] [--restart]`

- Validates the proposed update and writes the managed env file only on
  success.
- Shows restart impact.
- Does not restart services unless `--restart` is provided.
- Exit `0` saved or dry-run valid, `1` validation failed, `2` unknown key,
  `3` permission/config access error.

### `pihole-ai config unset <key> [--dry-run] [--json]`

- Removes a known key from the managed file, causing lower precedence/defaults
  to apply.
- Refuses to unset required secrets in unsafe states unless replacement is
  provided.

### `pihole-ai config validate [--mode syntax|install|runtime|preview] [--json]`

- Preferred future name for current `config check`.
- Current `config check` should remain as a compatibility alias.

### `pihole-ai config export [--output PATH] [--json] [--include-secrets]`

- Exports known non-secret settings by default.
- Unknown keys included in a preserved `unknown` section.
- Secure export requires explicit secret flag and warns about file handling.

### `pihole-ai config import <file> [--dry-run] [--json] [--restart]`

- Validates, previews diff, preserves unknown managed keys unless explicitly
  replaced, writes atomically.
- Does not restart unless requested.

### `pihole-ai config impact [--set KEY=VALUE ...] [--json]`

- Computes restart impact for current config or proposed updates.
- Read-only.

JSON responses should use stable fields:

```json
{
  "ok": true,
  "changed": true,
  "validation": {"valid": true, "issues": []},
  "restart_required": true,
  "restart_services": ["pihole-ai-engine.service"],
  "masked": ["PIHOLE_AI_DASHBOARD_SECRET_KEY"]
}
```

## Dashboard/API Contract

Dashboard page goals:

- grouped settings sections
- source attribution and override warnings
- validation before save
- impact preview before save
- clear restart-required state
- no secret plaintext in responses

Endpoints:

### `GET /api/config`

Returns effective configuration, schema metadata, source attribution, masks,
revision, and restart impact for current unsatisfied changes.

Secrets return:

```json
{"configured": true, "masked": true, "value": null}
```

### `POST /api/config/validate`

Validates partial updates without writing.

Request:

```json
{"updates": {"AI_ENABLED": "false"}, "mode": "preview"}
```

Response includes normalized values, validation issues, and restart impact.

### `PUT /api/config`

Writes partial updates after CSRF and authorization checks.

Request requires the current revision to avoid overwriting concurrent edits:

```json
{"revision": "sha256:...", "updates": {"AI_ENABLED": "false"}}
```

Response includes changed keys, backup path, validation result, and restart
impact. It should not restart services automatically unless a later explicit
restart endpoint is used.

### `GET /api/config/export`

Exports non-secret config by default. Secure export requires an explicit query
or POST confirmation in a later design.

### `POST /api/config/import`

Accepts a config payload or uploaded file, validates, previews, and optionally
writes. CSRF required.

### `GET /api/config/impact`

Read-only impact preview for current config or proposed query payload.

Dashboard authorization:

- all endpoints require authenticated admin
- mutating endpoints require CSRF
- mutating endpoints require root-capable deployment or return exact sudo CLI
  command guidance

Audit:

- record actor, timestamp, changed keys, validation mode, restart impact, and
  whether secrets changed
- never store secret values

## Profiles

Profiles should be metadata presets in Phase 1, not hidden modes.

Recommended initial profiles:

- `conservative`: AI enabled with low call rate, dry-run actions, safer
  dashboard exposure defaults
- `balanced`: current packaged defaults
- `low-resource`: AI disabled or more constrained, slower polling, smaller
  batches
- `privacy-focused`: local-only dashboard bind, conservative retention/export
  posture

Profiles should display the exact resulting key/value changes before apply.
If implementation time is tight, defer profile application but keep profile
schema and documentation so the UI can show "coming later" without ambiguity.

## Migration Strategy

No database schema migration is required for Phase 1 if the managed `.env`
remains authoritative.

Implementation steps:

1. Add a settings metadata registry. Done in Phase 1A.
2. Add internal validation, env-file preservation, atomic-write, masking,
   restart-impact, and import/export primitives. Done in Phase 1A.
3. Add read-only CLI inspection commands for show, get, validate, and impact.
   Done in Phase 1B.
4. Add safe write-capable CLI commands for set and unset. Done in Phase 1C1.
5. Generate inventory/docs from the registry where possible.
6. Replace narrow dashboard settings writer with registry-backed validation.
7. Keep current `config check` and `config show` compatibility.
8. Add import/export CLI commands as wrappers around the registry and env
   writer. Done in Phase 1C2.
9. Add explicit restart orchestration for successful configuration writes.
   Done in Phase 1C3.
10. Add dashboard/API endpoints.
11. Add audit events without storing secrets.
12. Later, optionally add profile presets.

Existing `/etc/pihole-ai/pihole-ai.env` files must continue to load unchanged.

## Testing Strategy

Future implementation tests:

- settings schema completeness for every parsed setting
- precedence tests for env file, `.env`, process environment, and CLI override
- round-trip serialization
- unknown-key and comment preservation
- atomic-write failure recovery
- managed-path and symlink rejection
- file ownership and permission repair
- secret masking in CLI and dashboard JSON
- normal export excludes secrets
- secure export includes secrets only when explicitly requested
- import validation and malformed input handling
- restart impact for each category
- CLI JSON output contracts
- dashboard authorization
- CSRF enforcement
- concurrent edit/revision conflict handling
- migration from existing `.env` and appliance env files
- systemd `EnvironmentFile=` compatibility
- no secret values in logs, telemetry, or audit details

## Explicit Decisions

- The managed `.env` file remains the persisted appliance format for Epic 3.5
  Phase 1.
- Database-backed threat-intelligence source configuration remains separate
  from global appliance configuration.
- `config check` remains compatible; `config validate` can be added as the
  clearer future command.
- Profiles should not obscure resulting values.
- Dashboard APIs must never expose secret plaintext.
- Service restarts must be explicit, not automatic on every save.

## Open Questions

- Should process environment continue to override the managed appliance file in
  production, or should that become an explicit "external override" mode?
- Should secure exports be CLI-only initially?
- Should profile presets be shipped as static metadata or generated from the
  settings registry?
- Which configuration changes should write action-audit rows versus a new
  dedicated config-audit table?
- Should dashboard restart actions require password re-entry for sensitive
  changes?
