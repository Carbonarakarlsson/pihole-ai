# Tests

PiHole-AI uses Python `unittest` and keeps standard discovery:

```bash
python -m unittest discover -s tests
python -W error::ResourceWarning -m unittest discover -s tests
```

## Groups

- CLI and lifecycle: `test_cli.py`, `test_service.py`,
  `test_appliance_lifecycle_integration.py`
- Configuration, setup, health, doctor, status: `test_config.py`,
  `test_setup.py`, `test_health.py`, `test_doctor.py`, `test_status.py`
- Database and migrations: `test_db.py`, `test_migrations.py`
- Classifiers and engine: `test_classifiers.py`, `test_engine.py`,
  `test_evidence_engine.py`
- Dashboard and security: `test_dashboard.py`, `test_dashboard_security.py`
- Repository/release checks: `test_release_hardening.py`

## Conventions

Use temporary directories and mocks for systemd, appliance paths, and protected
configuration. Tests must not mutate `/etc`, `/var`, `/run`, `/opt`, or real
systemd state. Add regression tests for demonstrated defects and keep fixtures
small enough to inspect in review.

Packaging validation is run with:

```bash
python -m build
python -m twine check dist/*
python scripts/package_audit.py dist/*
python scripts/smoke_wheel.py dist/*.whl
```

Physical Raspberry Pi/systemd field tests are release validation, not a
replacement for the mocked unit suite.
