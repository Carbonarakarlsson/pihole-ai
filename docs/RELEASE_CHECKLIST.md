# PiHole-AI Release Checklist

## Automated Checks

- [ ] Clean working tree before tagging
- [ ] Version consistency across `pyproject.toml`, `pihole-ai --version`, health, doctor, setup, install status, and managed headers
- [ ] `python -m unittest discover -s tests`
- [ ] `python -W error::ResourceWarning -m unittest discover -s tests`
- [ ] `python -m build`
- [ ] `python -m twine check dist/*`
- [ ] `python scripts/package_audit.py dist/*`
- [ ] `python scripts/smoke_wheel.py dist/*.whl`
- [ ] `python scripts/repository_audit.py`
- [ ] `python scripts/clean.py --dry-run`
- [ ] Package content inspection confirms no `.env`, databases, logs, caches, `.git`, local venvs, or secrets
- [ ] Configuration defaults, docs, and examples are synchronized
- [ ] CLI reference matches the parser tree
- [ ] Migration registry versions are unique, ascending, and current
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
- [ ] Tag and release notes prepared
