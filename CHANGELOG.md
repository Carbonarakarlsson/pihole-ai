# Changelog

## Unreleased

v0.5 development:

- Added structured evidence models and a central decision engine.
- Classifiers can now contribute risk, safety, neutral, or decisive evidence.
- Manual rules and high-confidence threat intelligence are resolved by decisive
  precedence before lower-priority classifiers run.
- Fresh decisions persist supporting evidence in `decision_evidence` for
  `pihole-ai explain` and dashboard/API consumers.
- Added `decision_records` persistence and a polished dashboard Explain panel
  for final decisions, evidence groups, classifier traces, conflicts, and legacy
  decisions.
- Added feedback audit provenance linking feedback to the stored decision
  visible at submission time.

## v0.4.0rc1

Release-candidate hardening for PiHole-AI as a local Pi-hole companion appliance.

- Added unified health checks, doctor diagnostics, and setup/onboarding status.
- Added SQLite schema versioning with transactional baseline migrations.
- Centralized typed configuration, validation, safe display, and runtime paths.
- Added Linux appliance lifecycle management for install, upgrade, uninstall, service control, logs, and systemd unit generation.
- Added dedicated `pihole-ai` service identity handling and conservative Pi-hole database read-access checks.
- Added first-run setup guidance and safe dashboard setup visibility.
- Added dashboard authentication, secure signed sessions, CSRF protection, login throttling, security headers, and minimal public `/live`.
- Added local reputation, threat-intelligence import support, classifier metrics, explain views, and feedback flows.

Known limitations:

- Dashboard is single-administrator only; no multi-user management.
- Privileged lifecycle operations remain CLI-controlled.
- Database migrations are not downgraded during rollback.
- Ollama is optional and must be installed/model-managed separately.
- Real Raspberry Pi/Pi-hole host field validation is still required before final v0.4.
