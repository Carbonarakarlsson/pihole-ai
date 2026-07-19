# PiHole-AI Release Checklist

Target release candidate tag: `v0.5.0-rc1`

Python package version: `0.5.0rc1`

## Automated Checks

- [ ] Clean working tree before tagging
- [ ] Version consistency across `pyproject.toml`, `pihole-ai --version`,
      health, doctor, setup, install status, managed headers, README,
      changelog, release notes, and examples
- [ ] Configuration schema remains `1`
- [ ] `python -m unittest discover -s tests`
- [ ] `python -W error::ResourceWarning -m unittest discover -s tests`
- [ ] `python -m build`
- [ ] `python -m twine check dist/*`
- [ ] `python scripts/package_audit.py dist/*`
- [ ] `python scripts/smoke_wheel.py dist/*.whl`
- [ ] `python scripts/repository_audit.py`
- [ ] `python scripts/clean.py --dry-run`
- [ ] `python -m unittest tests.test_appliance_config_integration`
- [ ] `python -m unittest tests.test_lifecycle_integration`
- [ ] `python -m unittest tests.test_dashboard_config_api`
- [ ] `python -m unittest tests.test_dashboard_settings`
- [ ] Package content inspection confirms no `.env`, databases, logs, caches, `.git`, local venvs, or secrets
- [ ] Configuration defaults, docs, and `examples/` are synchronized
- [ ] CLI reference matches the parser tree
- [ ] API reference matches dashboard routes
- [ ] Migration registry versions are unique, ascending, and current
- [ ] Config migration from schema `0` to `1` is dry-run safe and backup safe
- [ ] Dashboard login and CSRF regression tests pass
- [ ] Non-loopback auth-disabled validation test passes
- [ ] Lifecycle preflight failure test passes
- [ ] Appliance lifecycle integration tests pass:
      `python -m unittest -v tests.test_appliance_lifecycle_integration`

## Appliance Lifecycle Integration Tests

The appliance lifecycle integration module exercises install dry-run planning,
temporary-path installation, idempotent reinstall, upgrade refresh/rollback
behavior, service command ordering, uninstall preservation, protected
configuration checks, database compatibility, and JSON command contracts. It
uses temporary directories for appliance paths and mocked privileged commands,
so it must not touch the host `/etc`, `/var`, `/run`, `/opt`, `/usr/local/bin`,
or systemd state.

Epic 3.5 appliance configuration integration also covers CLI/dashboard
consistency, Settings API revision conflicts, import/export, secret masking,
restart orchestration failure recovery, uninstall config preservation, and
partial installation recovery.

## Upgrade Validation

Follow [Upgrade Validation](UPGRADE_VALIDATION.md) and record results for:

- [ ] legacy installation -> migration -> upgrade
- [ ] fresh install
- [ ] uninstall -> reinstall with preserved config
- [ ] uninstall -> reinstall after `--remove-config`
- [ ] CLI configuration edit workflow
- [ ] dashboard Settings workflow
- [ ] Configuration API workflow
- [ ] JSON/env import and export
- [ ] restart orchestration and failed restart recovery
- [ ] rollback from config or migration backup

These tests do not replace physical-host release validation. A real Raspberry
Pi/systemd host is still required to verify actual service identity ownership,
journal behavior, boot enablement, Pi-hole FTL database access, network binding,
and dashboard reachability under the target OS.

## Manual Hardware Checks

- [ ] Clean Raspberry Pi installation
- [ ] Legacy source-checkout upgrade test
- [ ] Database backup and restore test
- [ ] Systemd hardening verification on target Raspberry Pi OS
- [ ] Pi-hole FTL database read-access verification
- [ ] Collector reads real Pi-hole query history
- [ ] Engine processes real events without Ollama
- [ ] Ollama unavailable/degraded verification
- [ ] Ollama available verification with configured model
- [ ] Dashboard login over local network
- [ ] HTTPS reverse-proxy test if remote LAN access is required
- [ ] Documentation review
- [ ] Administrator guide reviewed
- [ ] Changelog updated
- [ ] Release notes updated
- [ ] GitHub prerelease drafted
- [ ] Release artifacts verified
- [ ] Tag and release notes prepared
