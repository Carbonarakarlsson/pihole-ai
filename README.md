# PiHole-AI

Local AI-assisted DNS analysis for Pi-hole, powered by deterministic classifiers first and Ollama as the local LLM fallback.

PiHole-AI reads Pi-hole query events, stores them in a local SQLite database, classifies domains, caches analysis results, and exposes a small dashboard/API for inspecting activity.

## Current Status

The project is in an active v0.3 hardening phase.

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

3. `HeuristicsEngine`
   Scores suspicious patterns such as punycode, long domains, high entropy, suspicious TLDs, phishing keywords, repeated hyphens, deep subdomains, random-looking hostnames, and high query frequency.

4. `AIClassifier`
   Uses Ollama for domains that remain unknown after deterministic checks.

## Database

The main database is configured by `PIHOLE_AI_EVENTS_DB` and defaults to:

```text
data/events.db
```

Tables:

- `events`
- `domain_memory`
- `analysis`
- `app_state`
- `action_audit`
- `domain_rules`
- `domain_reputation`

The collector stores the last processed Pi-hole query ID in `app_state` as:

```text
collector.last_query_id
```

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
PIHOLE_AI_OLLAMA_URL=http://127.0.0.1:11434
PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b
```

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

- `GET /`
- `GET /api/stats`
- `GET /api/events`
- `GET /api/analysis`
- `GET /api/devices`
- `GET /api/actions`
- `GET /api/rules`
- `POST /api/rules`
- `DELETE /api/rules/<domain>`
- `GET /api/health`
- `GET /data`

`/data` is kept as a compatibility route.

Useful query parameters:

- `limit`: maximum rows to return, clamped between 1 and 500
- `q`: search domains and/or devices
- `processed`: `0` or `1`, supported by `/api/events`
- `min_risk`: minimum risk score, supported by `/api/analysis`
- `category`: exact category, supported by `/api/analysis`
- `action`: exact action, supported by `/api/actions`
- `status`: exact status, supported by `/api/actions`
- `decision`: exact rule decision, supported by `/api/rules`
- `ollama`: `1`, supported by `/api/health` to include Ollama status

The dashboard can promote action audit entries into manual `allow` or `block` rules and remove active rules.

## Configuration

Configuration lives in `core/config.py` and is controlled with environment variables.

Common variables:

```text
PIHOLE_AI_EVENTS_DB=data/events.db
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
PIHOLE_AI_OLLAMA_URL=http://127.0.0.1:11434
PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b
PIHOLE_AI_DASHBOARD_PORT=8080
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

Skip the Ollama health check:

```bash
pihole-ai status --no-ollama
```

Run database maintenance:

```bash
pihole-ai maintenance --vacuum
```

By default, maintenance keeps the newest `PIHOLE_AI_KEEP_LATEST_EVENTS` events.

Update local reputation learning:

```bash
pihole-ai learn
```

Manage manual allow/block rules:

```bash
pihole-ai rules list
pihole-ai rules allow example.com --reason "Known safe"
pihole-ai rules block bad.example --reason "Confirmed unwanted"
pihole-ai rules block bad.example --apply
pihole-ai rules remove example.com
```

Export analysis or events:

```bash
pihole-ai export analysis --format json --output exports/analysis.json
pihole-ai export events --format csv --output exports/events.csv
pihole-ai export actions --format csv --output exports/actions.csv
```

Exports support `--limit`, `--q`, `--min-risk`, and `--category`.

## Systemd Deployment

Example systemd unit files live in:

```text
deploy/systemd/
```

They assume the project is installed at:

```text
/opt/pihole-ai
```

and that the virtual environment is:

```text
/opt/pihole-ai/.venv
```

Example install flow:

```bash
sudo mkdir -p /opt/pihole-ai
sudo cp -R . /opt/pihole-ai
cd /opt/pihole-ai
python -m venv .venv
.venv/bin/python -m pip install -e .
cp .env.example .env
```

Install services:

```bash
sudo cp deploy/systemd/pihole-ai-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pihole-ai-collector
sudo systemctl enable --now pihole-ai-engine
sudo systemctl enable --now pihole-ai-dashboard
sudo systemctl enable --now pihole-ai-maintenance.timer
```

Check status:

```bash
systemctl status pihole-ai-collector
systemctl status pihole-ai-engine
systemctl status pihole-ai-dashboard
systemctl status pihole-ai-maintenance.timer
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
        heuristics.py
        ai_classifier.py

pihole_ai/
    cli.py
    export.py
    learn.py
    rules.py
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
