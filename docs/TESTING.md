# Testing

PiHole-AI includes appliance-style integration tests for Configuration Center
and lifecycle workflows. These tests use temporary roots, fake systemd
directories, mocked service control, isolated process environments, and Flask
test clients. They must not write to real `/etc`, invoke real `systemctl`, call
`sudo` or `pkexec`, contact Ollama, or read a real Pi-hole database.

## Appliance Configuration Tests

Run the focused Epic 3.5 Phase 2C suites with:

```bash
python -m unittest tests.test_appliance_config_integration
python -m unittest tests.test_lifecycle_integration
```

These suites cover:

- fresh install dry-run and real install lifecycle
- schema-v1 config creation and validation before service mutation
- legacy config refusal, dry-run migration, real migration, backup, and retry
- CLI-to-dashboard and dashboard-to-CLI consistency
- JSON/env import and export round trips
- secret masking and revision conflict handling
- restart orchestration ordering and failure reporting
- uninstall config preservation and explicit removal
- partial installation recovery without deleting user configuration

## Standard Validation

Run the normal suite and ResourceWarning suite before committing:

```bash
python -m unittest discover -s tests
python -W error::ResourceWarning -m unittest discover -s tests
git diff --check
```

The existing migration failure-path integration test intentionally raises
`MigrationError("boom")` to prove failed migrations roll back correctly. That
traceback is expected when the suite passes.
