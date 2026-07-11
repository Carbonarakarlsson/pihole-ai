# PiHole-AI

Local AI-assisted DNS analysis for Pi-hole, powered by deterministic classifiers first and Ollama as the local LLM fallback.

PiHole-AI reads Pi-hole query events, stores them in a local SQLite database, classifies domains, caches analysis results, and exposes a small dashboard/API for inspecting activity.

## Current Status

The project is in an active v0.4 appliance hardening phase.

Working today:

- Pi-hole FTL query ingestion
- local SQLite event and analysis storage
- persisted collector progress
- classifier pipeline with a shared `BaseClassifier`
- deterministic rule engine
- local reputation classifier
- heuristic classifier
- Ollama-backed AI fallback
- AI response validation and safe fallback handling
- cache confidence and TTL policy
- metadata-aware analysis requests
- durable action audit log
- manual allow/block domain rules
- Flask dashboard and JSON API
- first-run setup status and onboarding guidance
- unit tests for classifier, collector, engine, dashboard, and compatibility entrypoints

The project is intentionally local-first. ChatGPT/OpenAI API integration is not part of the current path; Ollama remains the AI backend.

## Architecture

```text
Pi-hole FTL database
        |
        v
collector/scan.py
        |
        v
core.db SQLite database
        |
        v
engine.engine.AnalysisEngine
        |
        v
engine.analyzer.Analyzer
        |
        v
ClassifierPipeline
        |
        +--> RuleEngine
        +--> ReputationClassifier
        +--> ThreatIntelClassifier
        +--> HeuristicsEngine
        +--> AIClassifier (Ollama)
        |
        v
analysis cache
        |
        v
action audit
        |
        v
ui/dashboard.py
```

Only domains that are not handled by deterministic classifiers reach Ollama.

## Classifier Pipeline

Classifiers implement `engine.classifiers.base.BaseClassifier`.

Current order:

1. `RuleEngine`
   Handles known safe infrastructure such as localhost, `.local`, `.home.arpa`, and reverse DNS lookup domains.

2. `ReputationClassifier`
   Uses manual allow/block rules and learned `domain_reputation` scores before probabilistic heuristics or Ollama.

3. `ThreatIntelClassifier`
   Uses imported known-bad feed indicators from `threat_intel`.

4. `HeuristicsEngine`
   Scores suspicious patterns such as punycode, long domains, high entropy, suspicious TLDs, phishing keywords, repeated hyphens, deep subdomains, random-looking hostnames, and high query frequency.

5. `AIClassifier`
   Uses Ollama for domains that remain unknown after deterministic checks.

## Database

The main database is configured by `EVENTS_DB_PATH` and defaults to:

```text
/var/lib/pihole-ai/events.db
```

Tables:

- `events`
- `domain_memory`
- `analysis`
- `app_state`
- `action_audit`
- `domain_rules`
- `domain_reputation`
- `threat_intel`
- `schema_migrations`

The collector stores the last processed Pi-hole query ID in `app_state` as:

```text
collector.last_query_id
```

PiHole-AI uses ordered SQLite schema migrations. `schema_migrations`
records the applied versions, and the current baseline schema is version `1`.
Migrations are transactional and apply only to the PiHole-AI events database;
the Pi-hole FTL database is read as an input source and is never migrated.

Inspect schema state:

```bash
pihole-ai db status
pihole-ai db status --json
```

Apply pending migrations:

```bash
pihole-ai db migrate
pihole-ai db migrate --json
```

Health checks report the current schema version, latest supported version, and
pending migration count. A database created by a newer PiHole-AI release is
reported as incompatible instead of being modified.

## Analysis Cache

Analysis results include:

- `risk`
- `confidence`
- `category`
- `reason`
- `model`
- `analyzed_at`

Cache policy:

- `confidence > 0` and not expired means the cache entry is reused.
- `confidence == 0` is treated as retryable.
- `PIHOLE_AI_CACHE_TTL` controls expiration in seconds.
- `PIHOLE_AI_CACHE_TTL=0` disables expiration for positive-confidence entries.

This prevents temporary Ollama failures from permanently caching `unknown` results.

## Action Policy

After a fresh analysis is saved, the engine applies a small action policy and records the decision in `action_audit`.

Default behavior is dry-run:

```text
PIHOLE_AI_ACTION_MODE=dry-run
PIHOLE_AI_ALERT_THRESHOLD=50
PIHOLE_AI_HIGH_RISK_THRESHOLD=70
```

Modes:

- `off`: do not create action decisions
- `dry-run`: audit alerts and suggested blocks without changing DNS behavior
- `block`: write high-risk domains to the local blocklist helper

Dry-run decisions use:

- `alert` for risk at or above `PIHOLE_AI_ALERT_THRESHOLD`
- `suggest_block` for risk at or above `PIHOLE_AI_HIGH_RISK_THRESHOLD`
- `review` for zero-confidence analysis results

Manual rules are checked before risk thresholds:

- `allow` rules suppress alert/block suggestions for that domain
- `block` rules are recorded as explicit rule matches
- `pihole-ai rules block --apply` also writes the domain to the local blocklist helper

## Local Learning

PiHole-AI can build a local reputation list from observed DNS history:

```bash
pihole-ai learn
pihole-ai learn --limit 1000 --min-score 60
pihole-ai learn --no-audit
```

Learning updates `domain_reputation` and can create learned `alert` or `suggest_block` audit records. It does not block domains automatically.

Current learning signals include:

- query volume
- recent query spikes
- multi-device visibility
- previous analysis risk
- previous action audit suggestions
- entropy and suspicious TLDs
- manual allow/block rules

High learned scores are used by `ReputationClassifier` before Ollama is called. Lower scores remain visible as reputation data and audit signals.

## Categories

Canonical categories are defined in `engine.models.DomainCategory`:

- `benign`
- `infrastructure`
- `advertising`
- `analytics`
- `tracking`
- `suspicious`
- `malware`
- `phishing`
- `command-and-control`
- `unknown`

AI responses are rejected if they use categories outside this set.

## Ollama

The AI fallback uses the local Ollama Python client.

Default settings:

```text
AI_ENABLED=true
AI_MAX_CALLS_PER_MINUTE=2
AI_COOLDOWN_SECONDS=60
AI_TIMEOUT_SECONDS=20
PIHOLE_AI_OLLAMA_URL=http://127.0.0.1:11434
PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b
```

PiHole-AI limits Ollama fallback calls to two per minute by default. If AI is
disabled, rate-limited, or cooling down after invalid/slow responses, the engine
saves a safe unknown result instead of calling Ollama.

If Ollama is unavailable, the AI classifier returns a safe fallback result:

```text
risk=50
confidence=0
category=unknown
reason="AI backend unavailable."
```

The engine saves the fallback and marks the domain processed, but because confidence is `0`, the cache entry is retried later.

## Dashboard And API

The dashboard is served by Flask from `ui/dashboard.py`.

Default port:

```text
PIHOLE_AI_DASHBOARD_PORT=8080
```

Run:

```bash
python -m ui.dashboard
```

Endpoints:

- `GET /login`
- `POST /login`
- `POST /logout`
- `GET /live`
- `GET /`
- `GET /api/stats`
- `GET /api/events`
- `GET /api/analysis`
- `GET /api/devices`
- `GET /api/actions`
- `GET /api/rules`
- `GET /api/reputations`
- `GET /api/explain/<domain>`
- `GET /api/metrics/decisions`
- `GET /api/setup`
- `POST /api/feedback`
- `POST /api/rules`
- `DELETE /api/rules/<domain>`
- `GET /api/health`
- `GET /data`

`/data` is kept as a compatibility route.
`/live` is intentionally public and returns only `{"status":"alive"}`.
All dashboard pages and detailed JSON APIs require authentication when
dashboard auth is enabled. All state-changing dashboard requests require CSRF.

Useful query parameters:

- `limit`: maximum rows to return, clamped between 1 and 500
- `q`: search domains and/or devices
- `processed`: `0` or `1`, supported by `/api/events`
- `min_risk`: minimum risk score, supported by `/api/analysis`
- `category`: exact category, supported by `/api/analysis`
- `action`: exact action, supported by `/api/actions`
- `status`: exact status, supported by `/api/actions`
- `decision`: exact rule decision, supported by `/api/rules`
- `min_score`: minimum score, supported by `/api/reputations`
- `ollama`: `1`, supported by `/api/health` to include Ollama status

The dashboard can promote action audit entries into manual `allow` or `block` rules and remove active rules.

Dashboard authentication is local-appliance only:

```bash
pihole-ai dashboard auth status
pihole-ai dashboard auth status --json
pihole-ai dashboard auth set-password
pihole-ai dashboard auth set-password --password-stdin
pihole-ai dashboard auth enable
pihole-ai dashboard auth disable --confirm-disable-auth
```

Authentication is enabled by default for appliance mode. There is no default
administrator password. After install, set the first password with:

```bash
sudo pihole-ai dashboard auth set-password
sudo pihole-ai restart
```

To reset a forgotten password, run the same `set-password` command from the
terminal. Password hashes are stored with Werkzeug's password hashing helpers;
plaintext passwords are never stored or printed. The dashboard secret key is
generated during install or password setup and is not shown by `config show`,
doctor, setup, health, or JSON status output.

Authentication may be disabled only for loopback-only development. Disabling it
on `0.0.0.0` or another non-loopback bind is rejected by configuration
validation. Sessions use signed Flask cookies, `HttpOnly`, `SameSite=Lax`, an
explicit timeout, and CSRF tokens for writes. Reverse-proxy trust is disabled by
default; enable it only behind a trusted local HTTPS reverse proxy. Do not expose
the dashboard directly to the public internet.

## Configuration

Configuration lives in `core/config.py` and is controlled with environment variables.

Common variables:

```text
EVENTS_DB_PATH=/var/lib/pihole-ai/events.db
PIHOLE_AI_PIHOLE_DB=/etc/pihole/pihole-FTL.db
PIHOLE_AI_COLLECT_BATCH_SIZE=200
PIHOLE_AI_COLLECT_INTERVAL=2
PIHOLE_AI_ENGINE_BATCH_SIZE=500
PIHOLE_AI_ENGINE_INTERVAL=5
PIHOLE_AI_CACHE_TTL=86400
PIHOLE_AI_KEEP_LATEST_EVENTS=100000
PIHOLE_AI_ALERT_THRESHOLD=50
PIHOLE_AI_HIGH_RISK_THRESHOLD=70
PIHOLE_AI_ACTION_MODE=dry-run
AI_ENABLED=true
AI_MAX_CALLS_PER_MINUTE=2
AI_COOLDOWN_SECONDS=60
AI_TIMEOUT_SECONDS=20
PIHOLE_AI_OLLAMA_URL=http://127.0.0.1:11434
PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b
PIHOLE_AI_DASHBOARD_PORT=8080
PIHOLE_AI_DASHBOARD_POLL_INTERVAL_MS=10000
PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS=5000
PIHOLE_AI_DASHBOARD_METRICS_POLL_INTERVAL_MS=15000
PIHOLE_AI_DASHBOARD_TABLES_POLL_INTERVAL_MS=10000
PIHOLE_AI_DASHBOARD_SLOW_POLL_INTERVAL_MS=30000
PIHOLE_AI_DASHBOARD_AUTH_ENABLED=true
PIHOLE_AI_DASHBOARD_USERNAME=admin
PIHOLE_AI_DASHBOARD_PASSWORD_HASH=
PIHOLE_AI_DASHBOARD_SECRET_KEY=
PIHOLE_AI_DASHBOARD_SESSION_LIFETIME_MINUTES=480
PIHOLE_AI_DASHBOARD_TRUST_PROXY=false
DEV_ACCESS_LOGS=false
LOG_PATH=/var/log/pihole-ai/pihole-ai.log
LOG_LEVEL=INFO
PIHOLE_AI_LOG_LEVEL=INFO
```

## Running

Install dependencies:

```bash
python -m pip install -e .
```

Create a local environment file:

```bash
cp .env.example .env
```

Edit `.env` for your install path, Pi-hole database path, Ollama model, and dashboard port.

Run the collector:

```bash
pihole-ai collector
```

Run the continuous analysis worker:

```bash
pihole-ai engine
```

Run one analysis cycle:

```bash
pihole-ai engine-once
```

Run the dashboard:

```bash
pihole-ai dashboard
```

Print runtime status:

```bash
pihole-ai status
```

Include the Ollama health check:

```bash
pihole-ai status --ollama
```

Validate the effective configuration:

```bash
pihole-ai config check
pihole-ai config check --mode syntax
pihole-ai config check --json
```

Show safe effective configuration values:

```bash
pihole-ai config show
pihole-ai config show --json
```

Run read-only appliance diagnostics:

```bash
pihole-ai doctor
pihole-ai doctor --json
```

`.env` remains supported. `config show` displays normalized effective values
instead of raw `.env` source text and redacts URL credentials. Health checks
report current state, while `doctor` combines configuration validation, health,
database schema status, runtime metadata, and systemd presence with remediation
guidance. `doctor` does not migrate databases, create directories, change
permissions, start services, stop services, or modify Pi-hole.

On an installed appliance, `/etc/pihole-ai/pihole-ai.env` is intentionally
protected because it contains secrets:

```text
/etc/pihole-ai      root:pihole-ai 0750
/etc/pihole-ai/pihole-ai.env root:pihole-ai 0640
```

Read-only commands do not mutate the database or system, but commands that need
the protected appliance configuration should be run with sudo unless your user
has explicit read access through the `pihole-ai` group:

```bash
sudo pihole-ai health
sudo pihole-ai doctor
sudo pihole-ai setup status
sudo pihole-ai config check
sudo pihole-ai config show
```

When the protected config cannot be read, PiHole-AI reports
`config.appliance.permission_denied` with sudo guidance instead of silently
falling back to defaults. Development checkouts with a readable project `.env`
can still run unprivileged.

After install or upgrade, verify the appliance service identity can reach the
protected config while ordinary users remain excluded:

```bash
sudo -u pihole-ai test -x /etc/pihole-ai
sudo -u pihole-ai test -r /etc/pihole-ai/pihole-ai.env
stat -c '%U:%G %a %n' /etc/pihole-ai /etc/pihole-ai/pihole-ai.env
```

## First-Run Setup

The setup command gives a guided view over installation, configuration, database
schema, services, health, and optional Ollama state:

```bash
pihole-ai setup
pihole-ai setup status
pihole-ai setup status --json
pihole-ai setup --dry-run
pihole-ai setup --non-interactive
```

For automation, setup never mutates implicitly in non-interactive mode. Add
explicit flags for lifecycle work:

```bash
pihole-ai setup --non-interactive --install --enable --start
pihole-ai setup --non-interactive --skip-ollama-check
```

Readiness is derived from live state, not from an “onboarding complete” flag.
If configuration becomes invalid, services stop, schema becomes incompatible,
Pi-hole DB access disappears, or required health checks fail, setup status
changes automatically.

Required readiness checks:

- compatible managed or recognized installation
- valid runtime configuration
- dashboard authentication configured when exposed
- readable Pi-hole FTL database
- writable/readable PiHole-AI events database
- current supported schema
- dedicated service identity
- collector, engine, and dashboard services active
- required health checks healthy

Optional or degraded checks:

- Ollama unavailable when AI is enabled
- Ollama check skipped during automation
- no learned reputation yet
- no threat-intelligence rows yet
- collector idle with no new DNS queries

Ollama is optional. Interactive setup can keep deterministic-only operation by
setting `AI_ENABLED=false`; it does not install Ollama or download models.

The dashboard exposes `GET /api/setup` and shows a setup banner plus ordered
steps when setup is incomplete. Dashboard setup is diagnostic/read-only for
privileged lifecycle actions because the dashboard does not yet have
authentication or CSRF protection suitable for a web installer. Use the CLI to
resume after fixing a blocked step:

```bash
pihole-ai setup status
sudo pihole-ai install
sudo pihole-ai dashboard auth set-password
sudo pihole-ai start
pihole-ai setup status
```

Explain local evidence for a domain:

```bash
pihole-ai explain example.com
pihole-ai explain example.com --json
```

Record human feedback:

```bash
pihole-ai feedback example.com safe --reason "Known business app" --promote
pihole-ai feedback bad.example false-negative --reason "Confirmed bad" --promote --apply
pihole-ai feedback noisy.example noisy --reason "Too chatty"
```

Benchmark classifiers against labeled fixtures:

```bash
pihole-ai evaluate benchmarks/sample_domains.json
pihole-ai evaluate benchmarks/sample_domains.json --risk-tolerance 20 --json
pihole-ai evaluate benchmarks/sample_domains.json --include-ai
```

Benchmark fixtures can be JSON or CSV and should include `domain`, expected `category`, and expected `risk`. Optional metadata fields include `query_count`, `device_count`, and `recent_queries`.

Run database maintenance:

```bash
pihole-ai maintenance --vacuum
```

By default, maintenance keeps the newest `PIHOLE_AI_KEEP_LATEST_EVENTS` events.

Update local reputation learning:

```bash
pihole-ai learn
```

Import local threat-intelligence feeds:

```bash
pihole-ai intel import-hosts feeds/hosts.txt --source urlhaus
pihole-ai intel list --source urlhaus
```

Manage manual allow/block rules:

```bash
pihole-ai rules list
pihole-ai rules allow example.com --reason "Known safe"
pihole-ai rules block bad.example --reason "Confirmed unwanted"
pihole-ai rules block bad.example --apply
pihole-ai rules remove example.com
```

Export analysis, events, actions, or reputations:

```bash
pihole-ai export analysis --format json --output exports/analysis.json
pihole-ai export events --format csv --output exports/events.csv
pihole-ai export actions --format csv --output exports/actions.csv
pihole-ai export reputations --format csv --output exports/reputations.csv
```

Exports support `--limit`, `--q`, `--min-risk`, and `--category`.

## Systemd Deployment

PiHole-AI can generate and manage Linux systemd services from the current project directory and current Python interpreter.

Standard Linux runtime layout:

```text
/etc/pihole-ai/pihole-ai.env
/var/lib/pihole-ai/events.db
/var/log/pihole-ai/pihole-ai.log
/usr/local/bin/pihole-ai
```

## v0.4 Release-Candidate Verification

Local verification commands:

```bash
python -m unittest discover -s tests
python -W error::ResourceWarning -m unittest discover -s tests
python -m build
python -m twine check dist/*
python scripts/package_audit.py dist/*
python scripts/smoke_wheel.py dist/*.whl
```

`build` and `twine` are development tools available through the `dev` optional
dependency group:

```bash
python -m pip install -e ".[dev]"
```

Supported v0.4 installation mode is the Linux appliance layout:

```text
/etc/pihole-ai/pihole-ai.env
/var/lib/pihole-ai/events.db
/var/log/pihole-ai/pihole-ai.log
/usr/local/bin/pihole-ai
```

Initial dashboard authentication has no default password. Bootstrap it with:

```bash
sudo pihole-ai dashboard auth set-password
sudo pihole-ai restart
```

Ollama is optional. If unavailable or disabled, deterministic classifiers still
run and AI status is reported as degraded/skipped. SQLite migrations are applied
only to the PiHole-AI events database; Pi-hole FTL data is read-only. Lifecycle
rollback restores service/unit state where practical, but database migrations
are not downgraded.

Before final v0.4, validate on a real Raspberry Pi/Pi-hole host. Do not expose
the dashboard directly to the public internet; use a trusted local reverse proxy
with HTTPS for remote LAN access.

Path helpers:

```bash
pihole-ai config-path
pihole-ai data-path
pihole-ai log-path
```

Preview generated unit files and systemctl commands:

```bash
pihole-ai install --dry-run
pihole-ai upgrade --dry-run
pihole-ai enable --dry-run
pihole-ai start --dry-run
pihole-ai status --dry-run
pihole-ai logs --dry-run
pihole-ai logs --lines 120 --dry-run
```

Inspect installation state without root:

```bash
pihole-ai install status
pihole-ai install status --json
```

Install the wheel into a stable appliance virtual environment first. The
installer validates that its selected interpreter can import `pihole_ai` before
writing unit files:

```bash
sudo python3 -m venv /opt/pihole-ai/venv
sudo /opt/pihole-ai/venv/bin/pip install dist/pihole_ai-0.4.0rc3-py3-none-any.whl
sudo /opt/pihole-ai/venv/bin/pihole-ai install --dry-run
```

Install service files and the global `/usr/local/bin/pihole-ai` launcher from
that validated environment:

```bash
sudo /opt/pihole-ai/venv/bin/pihole-ai install
sudo /opt/pihole-ai/venv/bin/pihole-ai install --no-start
sudo /opt/pihole-ai/venv/bin/pihole-ai install --no-enable
```

Install creates `/etc/pihole-ai`, `/var/lib/pihole-ai`, and `/var/log/pihole-ai`.
If `/etc/pihole-ai/pihole-ai.env` does not exist, it is created from
`.env.example` plus the runtime database and log paths. If `data/events.db`
exists and `/var/lib/pihole-ai/events.db` does not, install copies the database
there and leaves the old project copy untouched.
Install and upgrade repair ownership on the managed runtime directories and the
SQLite database files only:

```text
/var/lib/pihole-ai          pihole-ai:pihole-ai 0750
/var/lib/pihole-ai/events.db pihole-ai:pihole-ai service-writable
/var/lib/pihole-ai/events.db-wal pihole-ai:pihole-ai service-writable
/var/lib/pihole-ai/events.db-shm pihole-ai:pihole-ai service-writable
```

Health, doctor, setup status, install status, status, config show/check, and
database status use read-only database access. They do not initialize the
database, create migration metadata, migrate schema, create directories, or
write cursor/service state. Use explicit mutating commands such as
`sudo pihole-ai db migrate`, `sudo pihole-ai install`, and
`sudo pihole-ai upgrade` for lifecycle changes.

Mutating lifecycle commands run a blocking preflight before changing anything.
If a blocking issue is found, no files are written, no database migration runs,
and no mutating `systemctl` command is invoked. Install, upgrade, uninstall,
enable, disable, start, stop, and restart also take an OS-backed lifecycle lock
at `/run/pihole-ai/lifecycle.lock` so concurrent appliance changes fail cleanly.
If the selected interpreter cannot import PiHole-AI, preflight reports
`install.executable.package_not_importable`; install the built wheel into
`/opt/pihole-ai/venv` and rerun install from that environment.

Production appliance units run as the dedicated `pihole-ai:pihole-ai` identity.
During privileged install, the installer creates that system group and user when
missing, using a no-login shell and `/var/lib/pihole-ai` as the service home.
Pi-hole FTL database permissions are not relaxed: the installer inspects the
existing database group and, when group read/traverse access is present, adds
`pihole-ai` to that existing group instead of chmodding or chowning Pi-hole data.

Install and upgrade write managed files atomically and refuse to overwrite
unrelated unit files. Existing administrator configuration is preserved during
upgrade. Managed unit files are backed up before replacement when their content
changes.

Refresh a managed appliance installation:

```bash
sudo pihole-ai upgrade
sudo pihole-ai upgrade --json
```

`upgrade` preserves the active configuration and data, refreshes managed
systemd unit files, runs explicit PiHole-AI database migrations, reloads
systemd, and restores previously enabled/running service state where practical.

The launcher and systemd units use the same validated appliance environment,
for example `/opt/pihole-ai/venv/bin/pihole-ai` and
`/opt/pihole-ai/venv/bin/python`. Source checkouts and developer `.venv`
paths are rejected for appliance mode unless explicit development mode is
enabled with `PIHOLE_AI_DEVELOPMENT_MODE=true`.

Enable automatic startup at boot:

```bash
sudo /usr/local/bin/pihole-ai enable
```

Manage services:

```bash
sudo /usr/local/bin/pihole-ai start
/usr/local/bin/pihole-ai status
/usr/local/bin/pihole-ai logs
/usr/local/bin/pihole-ai logs -f
sudo /usr/local/bin/pihole-ai stop
sudo /usr/local/bin/pihole-ai restart
sudo /usr/local/bin/pihole-ai disable
```

`pihole-ai logs` prints the last 80 journal lines by default. Use `--lines N` to change the count and `--follow`/`-f` for a live tail.

Uninstall services:

```bash
sudo /usr/local/bin/pihole-ai uninstall
sudo /usr/local/bin/pihole-ai uninstall --json
```

Default uninstall preserves `/etc/pihole-ai/pihole-ai.env`,
`/var/lib/pihole-ai/events.db`, learned reputation, rules, feedback, and other
persistent data. Runtime-only files may be removed with `--purge`, but purge
requires `--confirm-purge` and never removes the Pi-hole FTL database.

Generated services:

```text
pihole-ai-collector.service
pihole-ai-engine.service
pihole-ai-dashboard.service
```

Generated unit commands:

```text
/opt/pihole-ai/venv/bin/python -m pihole_ai.cli collect
/opt/pihole-ai/venv/bin/python -m pihole_ai.cli run-engine
/opt/pihole-ai/venv/bin/python -m pihole_ai.cli dashboard --host 0.0.0.0 --port 8080
```

Example install flow on a Pi-hole host:

```bash
python -m build --no-isolation
sudo python3 -m venv /opt/pihole-ai/venv
sudo /opt/pihole-ai/venv/bin/pip install dist/pihole_ai-0.4.0rc3-py3-none-any.whl
sudo /opt/pihole-ai/venv/bin/pihole-ai install --no-start
sudo /usr/local/bin/pihole-ai dashboard auth set-password
sudo /usr/local/bin/pihole-ai enable
sudo /usr/local/bin/pihole-ai start
```

## Tests

The test suite uses the Python standard library `unittest`.

Run:

```bash
python -W error::ResourceWarning -m unittest discover -s tests
```

Compile check:

```bash
python -m compileall core engine collector actions ui tests
```

Current coverage includes:

- classifier rules and heuristics
- AI response parsing and fallback paths
- collector state, fetch, and batch processing
- metadata-aware engine requests
- cache confidence and TTL behavior
- local reputation learning
- dashboard API endpoints
- `engine.run_engine` compatibility wrapper

## Project Structure

```text
actions/
    alerts.py
    blocklist.py
    policy.py

collector/
    scan.py

benchmarks/
    sample_domains.json

core/
    config.py
    db.py
    logger.py
    maintenance.py
    models.py

engine/
    analyzer.py
    engine.py
    models.py
    ollama_client.py
    prompts.py
    run_engine.py

    classifiers/
        base.py
        pipeline.py
        rule_engine.py
        reputation.py
        threat_intel.py
        heuristics.py
        ai_classifier.py

pihole_ai/
    cli.py
    evaluate.py
    explain.py
    export.py
    feedback.py
    intel.py
    learn.py
    rules.py
    service.py
    status.py

ui/
    dashboard.py

tests/
    test_classifiers.py
    test_collector.py
    test_dashboard.py
    test_engine.py
    test_run_engine.py
```

## Legacy Modules

These modules are currently retained only as historical reference:

- `engine/scoring.py`
- `engine/anomaly.py`

Useful scoring ideas have been folded into `HeuristicsEngine`. Beacon detection should be reintroduced later as a database-backed classifier or processor.

## Roadmap

Near-term:

- add more database-level tests
- improve dashboard filtering/search
- formalize cache cleanup and retention
- add Docker or Raspberry Pi deployment notes

Longer-term:

- threat intelligence enrichment
- local reputation learning from observed DNS behavior
- scheduled re-analysis
- device behavior clustering
- whitelist/blacklist management
- plugin architecture
- richer reporting

## License

MIT
