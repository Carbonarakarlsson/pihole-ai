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
- [ ] Package content inspection confirms no `.env`, databases, logs, caches, `.git`, local venvs, or secrets
- [ ] Dashboard login and CSRF regression tests pass
- [ ] Non-loopback auth-disabled validation test passes
- [ ] Lifecycle preflight failure test passes

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
