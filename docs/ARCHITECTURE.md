# PiHole-AI Architecture

PiHole-AI is a local appliance-style companion for Pi-hole. It reads Pi-hole FTL query history, stores normalized events in its own SQLite database, classifies domains with deterministic checks before optional local AI, and exposes CLI/dashboard diagnostics.

## Main Processes

- `collector`: reads the Pi-hole FTL database and records DNS query events.
- `engine`: processes unclassified events, applies the classifier pipeline, caches analysis, and records actions.
- `dashboard`: Flask application for authenticated inspection, explanation, feedback, rules, setup, and health views.
- `pihole-ai` CLI: operational entrypoint for runtime commands, diagnostics, setup, lifecycle management, and auth bootstrap.

## Evidence-Based Decision Pipeline

The classifier pipeline is deterministic first, evidence-based, and centrally
decided:

1. Manual/domain rules
2. Learned reputation
3. Threat-intelligence indicators
4. Heuristics
5. Optional Ollama AI fallback

Classifiers contribute structured evidence instead of independently owning the
final verdict. Evidence records include polarity, score, confidence, summary,
safe metadata, and optional decisive precedence. The central `DecisionEngine`
then produces the final compatible analysis result.

Decisive evidence wins by precedence:

- manual block
- manual allow
- local infrastructure
- high-confidence threat intelligence

Non-decisive evidence is aggregated with diminishing weight for repeated
signals from the same classifier/type. AI-only decisions have a confidence
ceiling, and AI is skipped when local deterministic evidence is decisive or
sufficient.

Fresh decisions persist their supporting evidence in `decision_evidence`.
Legacy rows in `analysis` remain readable, and explain views mark them as legacy
when no stored evidence is available.

## Configuration

`core.config` is the public configuration API. It loads env files and environment overrides into typed settings, validates them by mode, and exposes safe serialization that redacts secrets and credential-bearing URLs.

Appliance defaults:

- config: `/etc/pihole-ai/pihole-ai.env`
- data: `/var/lib/pihole-ai/events.db`
- logs: `/var/log/pihole-ai/pihole-ai.log`
- launcher: `/usr/local/bin/pihole-ai`

## SQLite And Migrations

PiHole-AI writes only to its own events database. The Pi-hole FTL database is read-only input. Schema state is tracked in `schema_migrations`; migrations are transactional and are not downgraded during lifecycle rollback.

Current appliance schema includes:

- v1 baseline runtime tables
- v2 `decision_evidence` for explainable decision traces

## Health, Doctor, And Setup

- `health` runs direct runtime health probes.
- `doctor` combines diagnostics and remediation guidance without mutation.
- `setup` derives onboarding readiness from actual configuration, install, schema, service, health, and optional Ollama state.

Readiness is not stored as a boolean.

## Lifecycle

`pihole_ai.service` owns appliance lifecycle APIs. It builds install plans, performs preflight checks, writes managed systemd units, handles dedicated service identity, takes lifecycle locks, and preserves configuration/data by default.

Mutating lifecycle actions stay in the CLI. The dashboard does not perform privileged installation or service management without sudo guidance.

## Dashboard Trust Boundary

The dashboard uses local admin authentication, Werkzeug password hashes, signed Flask sessions, CSRF tokens for writes, security headers, and a minimal public `/live` endpoint. Detailed health/setup/status APIs require authentication.

Reverse-proxy trust is disabled by default. If remote LAN access is needed, terminate HTTPS at a trusted local reverse proxy and enable proxy trust narrowly.

## Service Identity And Permissions

Production services run as `pihole-ai:pihole-ai`. Runtime data/log directories are owned by that identity. Pi-hole database permissions are not weakened; the installer detects existing group-readable access and can add the service user to that group.

## Dependency Direction

CLI and UI layers call into `pihole_ai.*` orchestration modules. Orchestration modules call into `core.*`, `collector`, `engine`, and `actions` as needed. Configuration, validation, and model helpers should remain below mutation-heavy lifecycle or dashboard layers to avoid circular imports and import-time side effects.
