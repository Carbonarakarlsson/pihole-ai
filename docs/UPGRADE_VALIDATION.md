# Upgrade Validation Checklist

Use this checklist for `v0.5.0rc1` appliance release-candidate validation.
Run it on a temporary test host first, then repeat the hardware-critical steps
on a Raspberry Pi/systemd appliance before stable promotion.

Record:

- PiHole-AI package version: `pihole-ai --version`
- Git tag or wheel name
- OS and Python version
- Pi-hole version
- Ollama availability and model, if used
- Start and end timestamps

## 1. Fresh Install

```bash
sudo python3 -m venv /opt/pihole-ai/venv
sudo /opt/pihole-ai/venv/bin/pip install dist/pihole_ai-0.5.0rc1-py3-none-any.whl
sudo /opt/pihole-ai/venv/bin/pihole-ai install --no-start
sudo /usr/local/bin/pihole-ai dashboard auth set-password
sudo /usr/local/bin/pihole-ai start
```

Verify:

- `/etc/pihole-ai/pihole-ai.env` exists and contains
  `PIHOLE_AI_CONFIG_SCHEMA_VERSION=1`
- `pihole-ai status` reports current, valid config and no migration required
- collector, engine, and dashboard services are active
- dashboard login works

## 2. Legacy Installation To Migration To Upgrade

Prepare a legacy env file without `PIHOLE_AI_CONFIG_SCHEMA_VERSION`.

```bash
sudo pihole-ai upgrade
```

Expected:

- upgrade refuses before service mutation
- output says migration is required
- original file bytes are unchanged

Preview and apply:

```bash
pihole-ai config migrate --dry-run
sudo pihole-ai config migrate --yes
pihole-ai config validate
sudo pihole-ai upgrade
sudo pihole-ai restart
```

Verify:

- migration backup contains original bytes
- aliases are canonical
- comments and unknown keys remain
- status reports schema `1`, valid config, no migration required

## 3. Uninstall And Reinstall

```bash
sudo pihole-ai uninstall
sudo pihole-ai install --no-start
```

Verify preserved config survives reinstall.

Then test explicit removal:

```bash
sudo pihole-ai uninstall --remove-config
sudo pihole-ai install --no-start
```

Verify a fresh schema-v1 config is created.

## 4. CLI Configuration Workflow

```bash
pihole-ai config show
pihole-ai config get ollama_model --details
pihole-ai config set ollama_model llama3.2:1b --dry-run
sudo pihole-ai config set ollama_model llama3.2:1b --yes
sudo pihole-ai config set ollama_model llama3.2:1b --yes --restart
```

Verify:

- dry-run writes nothing
- write creates a backup when replacing existing config
- restart happens only with `--restart`
- failed restart, if simulated, preserves written config and reports recovery
  commands

## 5. Dashboard Workflow

In the Settings page:

- load configuration
- preview a non-secret change
- save without restart
- save with restart
- replace a secret
- unset a non-required value
- trigger a revision conflict from a second session

Verify:

- raw secrets are never rendered
- stale writes return a recoverable conflict
- Save & Restart is explicit
- restart failure does not roll back a successful save

## 6. API Configuration Workflow

Use an authenticated dashboard session:

- `GET /api/config`
- `POST /api/config/validate`
- `PUT /api/config`
- `GET /api/config/impact`
- `GET /api/config/export`
- `POST /api/config/import`

Verify:

- mutating endpoints require CSRF
- normal export omits secrets
- secure dashboard export is rejected
- import preview writes nothing
- real import validates and writes atomically

## 7. Import And Export

```bash
pihole-ai config export --output config.json
pihole-ai config export --format env --output config.env
sudo pihole-ai config export --secure --output /root/secure-config.json
pihole-ai config import config.json --dry-run
sudo pihole-ai config import config.json --yes
pihole-ai config import config.env --dry-run
```

Verify:

- JSON and env exports are deterministic enough for review
- normal exports omit secrets
- secure export includes secrets only by explicit request
- imports preserve current settings and report restart impact

## 8. Rollback From Backup

After a config write or migration:

```bash
sudo cp <printed-backup-path> /etc/pihole-ai/pihole-ai.env
pihole-ai config validate
sudo pihole-ai restart
```

Verify restored settings are active and status remains valid.

## 9. Restart Orchestration

Validate:

- single-service restart impact
- multi-service restart impact
- no-impact change
- no-op change
- missing systemctl or authorization-required failure

Verify persistence always precedes restart and recovery commands include only
affected PiHole-AI services.

## 10. Final Diagnostics

```bash
pihole-ai status
pihole-ai health
pihole-ai doctor
pihole-ai setup status
pihole-ai db status
pihole-ai logs --lines 80
```

Record any degraded or warning state and whether it is expected for the test
environment.
