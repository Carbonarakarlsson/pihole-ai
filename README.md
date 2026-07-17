<div align="center">
  <img src="assets/branding/logo-transparent.png" alt="PiHole-AI logo" height="96">
  <h1>PiHole-AI</h1>
  <p><strong>AI-powered local DNS intelligence for Pi-hole</strong></p>
</div>

PiHole-AI is a local companion appliance for Pi-hole. It reads Pi-hole DNS
query history, stores normalized events in its own SQLite database, classifies
domains with deterministic evidence first, and uses local Ollama AI only as an
optional fallback.

The project is preparing the `0.5.0b5` beta after completing the
evidence-based decision engine, physically validating managed
threat-intelligence feed lifecycles, and adding AI reliability, benchmark,
calibration, and dashboard diagnostics for Epic 3.4.
Remaining v0.5 work is tracked under
`Unreleased` in [CHANGELOG.md](CHANGELOG.md).

## Supported Target

- Raspberry Pi OS or another Linux host with systemd
- Python 3.13 or newer
- Pi-hole with readable `pihole-FTL.db`
- Optional Ollama on `127.0.0.1:11434`

## What Works

- appliance install, upgrade, uninstall, enable, start, stop, restart, logs
- protected config at `/etc/pihole-ai/pihole-ai.env`
- runtime data at `/var/lib/pihole-ai/events.db`
- logs at `/var/log/pihole-ai/pihole-ai.log`
- authenticated Flask dashboard
- password bootstrap with no default password
- health, doctor, setup, status, and database diagnostics
- evidence-based decisions with stored explain output
- immutable decision history and decision comparison
- AI pipeline telemetry, persisted benchmarks, confidence calibration, and
  reliability dashboard diagnostics
- manual rules, local reputation, threat-intelligence imports, and feedback

## Appliance Install

Install the built wheel into a stable appliance virtual environment:

```bash
sudo python3 -m venv /opt/pihole-ai/venv
sudo /opt/pihole-ai/venv/bin/pip install dist/pihole_ai-*-py3-none-any.whl
sudo /opt/pihole-ai/venv/bin/pihole-ai install --no-start
```

Lifecycle contract: `pihole-ai install` installs files, enables services, and
starts services. `pihole-ai install --no-start` installs files and enables
services without starting them. `pihole-ai install --no-enable` installs files
without boot enablement.

Bootstrap the dashboard administrator password:

```bash
sudo /usr/local/bin/pihole-ai dashboard auth set-password
sudo /usr/local/bin/pihole-ai start
```

Then open:

```text
http://<pi-host>:8080
```

The default username is `admin`. There is no default password.

## Primary Commands

```bash
pihole-ai health
pihole-ai doctor
pihole-ai setup status
pihole-ai status
pihole-ai db status
pihole-ai explain example.com
pihole-ai feedback example.com safe --reason "known service"
sudo pihole-ai install
sudo pihole-ai upgrade
sudo pihole-ai restart
pihole-ai logs --lines 80
```

Lifecycle commands that change systemd, protected config, runtime ownership, or
service state require root privileges.

## Evidence-Based Decisions

Classifiers emit structured evidence. A central decision engine applies decisive
precedence, aggregates signed risk/safety evidence, persists the final decision,
and stores bounded evidence for `pihole-ai explain`, `GET /api/explain/<domain>`,
and the dashboard Explain panel.

Current classifier order:

1. manual/domain rules
2. learned reputation
3. threat intelligence
4. heuristics
5. optional Ollama AI fallback

Manual block/allow, local infrastructure, and high-confidence threat-intel hits
are decisive. AI is skipped when deterministic evidence is decisive or
sufficient, and disabled/rate-limited/timeout paths persist safe unknown results.

## Threat Intelligence Feeds

Manual `pihole-ai intel import-hosts` remains supported. v0.5 also adds managed
feed sources with safe HTTPS fetching, size/time limits, generation-based
activation, rollback, and update audit history. Classification only uses enabled
sources with an active generation, so failed downloads do not replace the last
known-good feed.

Successful updates have three outcomes: active content unchanged, an existing
inactive historical generation reactivated, or a newly created generation
activated. When downloaded content matches a valid inactive generation, PiHole-AI
reuses that generation instead of duplicating entries.
HTTP validators track the last fetched remote representation separately from the
classifier-active generation, so rollback can be followed by a 304-triggered
reactivation of the unchanged remote generation.

Use `pihole-ai intel source update <source-id>` to edit a configured source
without deleting its generations. URL or fetch-setting changes clear HTTP
validators so the next explicit update refetches content, but the active
generation, prior generations, entries, and rollback history remain intact until
`pihole-ai intel update` or `pihole-ai intel rollback` is run.

Use `pihole-ai intel sources` for per-source operational state and
`pihole-ai intel stats` for feed counts, active indicators, stale/failed source
counts, and integrity diagnostics. Single-source updates can be run as either
`pihole-ai intel update <source-id>` or `pihole-ai intel update --source
<source-id>`.

For deterministic field tests, prefer immutable feed URLs such as commit-pinned
raw files rather than branch URLs, which can be cached by upstream providers.

The appliance installer writes managed `pihole-ai-intel-update.service` and
`pihole-ai-intel-update.timer` units and includes the timer in enable/disable
lifecycle commands. Unattended timer updates are still opt-in through
`PIHOLE_AI_INTEL_AUTO_UPDATE_ENABLED`; manual `pihole-ai intel update` commands
remain operator-controlled.

## Ollama Optionality

PiHole-AI remains useful without Ollama. Set `AI_ENABLED=false` to disable local
AI. Raspberry Pi-safe defaults limit calls, cooldown after slow or invalid
responses, and enforce timeouts.

## Configuration

Appliance defaults are installed to:

```text
/etc/pihole-ai/pihole-ai.env
```

Important defaults:

```text
EVENTS_DB_PATH=/var/lib/pihole-ai/events.db
PIHOLE_AI_DB_TIMEOUT_SECONDS=30
PIHOLE_AI_DB_MIGRATION_TIMEOUT_SECONDS=60
PIHOLE_AI_DB_BUSY_TIMEOUT_MS=30000
LOG_PATH=/var/log/pihole-ai/pihole-ai.log
PIHOLE_AI_ALERT_LOG=/var/log/pihole-ai/alerts.log
AI_ENABLED=true
AI_MAX_CALLS_PER_MINUTE=2
AI_COOLDOWN_SECONDS=60
AI_TIMEOUT_SECONDS=20
PIHOLE_AI_INTEL_AUTO_UPDATE_ENABLED=false
PIHOLE_AI_INTEL_UPDATE_INTERVAL_SECONDS=86400
PIHOLE_AI_INTEL_MAX_DOWNLOAD_BYTES=2000000
PIHOLE_AI_DASHBOARD_AUTH_ENABLED=true
PIHOLE_AI_DASHBOARD_USERNAME=admin
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the full variable
inventory.

## Setup And Readiness

`pihole-ai setup status` derives readiness from install state, configuration,
database schema, services, runtime health, and optional Ollama status.

Decision IDs use an opaque `dec_<uuid4hex>` format. Fresh classifications append
to `decision_history` and update latest compatibility projections for existing
callers. History is not created by dashboard reads, explain reads, health/status
checks, or cache hits.

`ready=true` means all required setup steps are complete. `overall_stage=degraded`
means PiHole-AI is operational but warning-level or optional diagnostics need
attention. For example, a securely authenticated dashboard bound outside
loopback is degraded but ready.

## Project Roadmap

The published `v0.5.0b5` prerelease completed Epic 3.4: AI reliability,
benchmarking, confidence calibration, reliability dashboard work, and official
branding. Epic 3.5, Operations & User Experience, is now underway.

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full v0.5.x to v1.0
development plan.

Epic 3.5 has begun with read-only configuration inspection:

```bash
pihole-ai config show
pihole-ai config get PIHOLE_AI_OLLAMA_MODEL
pihole-ai config validate
pihole-ai config impact PIHOLE_AI_OLLAMA_URL
pihole-ai config set PIHOLE_AI_OLLAMA_MODEL llama3.2:1b --dry-run
pihole-ai config set PIHOLE_AI_OLLAMA_MODEL llama3.2:1b --yes --restart
pihole-ai config unset PIHOLE_AI_OLLAMA_MODEL --dry-run
pihole-ai config export --output backup.json
pihole-ai config import backup.json --dry-run
```

Configuration writes require confirmation unless `--yes` is supplied, create a
backup when replacing an existing file, and never restart services
automatically. Use `--restart` only when you want PiHole-AI to restart the
affected services after a successful write.

The dashboard Settings page now uses the same configuration framework as the
CLI. It supports category browsing, backend validation, dry-run previews,
revision-guarded saves, optional Save & Restart, normal import/export, and
explicit secret replace/unset flows while keeping secrets masked by default.
Secure secret-inclusive exports remain CLI-only. See
[docs/API_REFERENCE.md](docs/API_REFERENCE.md) for endpoint details.

## Detailed Documentation

- [Operations](docs/OPERATIONS.md): install, upgrade, uninstall, services,
  permissions, diagnostics, backup expectations, and field checks
- [Security](docs/SECURITY.md): authentication, sessions, CSRF, protected config,
  service identity, and exposure guidance
- [CLI Reference](docs/CLI_REFERENCE.md): command inventory, privileges, JSON
  support, and exit-code notes
- [Configuration](docs/CONFIGURATION.md): supported environment variables and
  defaults
- [Configuration Center Design](docs/CONFIGURATION_DESIGN.md): Epic 3.5
  configuration inventory, ownership, validation, and API plan
- [API Reference](docs/API_REFERENCE.md): dashboard configuration API contract
- [Database](docs/DATABASE.md): schema versions, migrations, tables, and backup
  expectations
- [Architecture](docs/ARCHITECTURE.md): process model, evidence contract,
  lifecycle, and trust boundaries
- [Development](docs/DEVELOPMENT.md): local setup, tests, build, audits, and
  contribution workflow
- [Technical Debt](docs/TECHNICAL_DEBT.md): known deferred work
- [Repository Status](docs/REPOSITORY_STATUS.md): current snapshot for the next
  epic

## Validated Limitations

- Dashboard is single-administrator only.
- Decision-history retention is explicit maintenance, not automatic cleanup.
- PiHole-AI does not automatically install or manage Ollama models.
- Database migrations do not downgrade schemas during rollback.
- Physical Raspberry Pi/systemd field tests remain required before final
  promotion of a release candidate.
