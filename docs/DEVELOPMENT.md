# Development

## Local Environment

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
```

Use `.env` for local overrides. Do not commit `.env`, local databases, logs,
virtual environments, build artifacts, or appliance data.

## Tests

```bash
python -m unittest discover -s tests
python -W error::ResourceWarning -m unittest discover -s tests
```

The suite uses temporary directories and mocks for appliance/systemd behavior.
Do not add tests that mutate `/etc`, `/var`, `/run`, `/opt`, or real systemd
state.

## Build And Package Checks

```bash
python -m build
python -m twine check dist/*
python scripts/package_audit.py dist/*
python scripts/smoke_wheel.py dist/*.whl
```

## Repository Cleanup

```bash
python scripts/clean.py --dry-run
python scripts/clean.py
python scripts/repository_audit.py
```

`scripts/clean.py` removes only known generated artifacts under the repository
root. It never touches live appliance paths or protected defaults.

## Active Scripts

- `scripts/clean.py`: repository-local generated artifact cleanup.
- `scripts/package_audit.py`: built artifact content audit.
- `scripts/repository_audit.py`: lightweight repository hygiene and docs drift
  audit.
- `scripts/smoke_wheel.py`: install a built wheel into a temporary venv and run
  basic CLI/package smoke checks.

## Workflow

Keep changes focused, preserve unittest discovery, and add regression tests for
any demonstrated defect. Do not change classifier policy, migration history,
CLI contracts, dashboard auth/CSRF, or appliance paths during maintenance
cleanup.
