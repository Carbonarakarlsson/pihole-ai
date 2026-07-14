# Configuration

Configuration is loaded by `core.config`. In an appliance install the managed
environment file is `/etc/pihole-ai/pihole-ai.env`; local development may use
`.env`. Environment variables override file values.

Secrets are redacted from safe display output. Changes to service, AI,
dashboard, or logging settings generally require a service restart.

| Variable | Type | Default | Secret | Validation | Example | Applies |
| --- | --- | --- | --- | --- | --- | --- |
| `EVENTS_DB_PATH` | path | `/var/lib/pihole-ai/events.db` | no | absolute/file path | `/var/lib/pihole-ai/events.db` | all |
| `PIHOLE_AI_PIHOLE_DB` | path | `/etc/pihole/pihole-FTL.db` | no | readable SQLite path where required | `/etc/pihole/pihole-FTL.db` | all |
| `PIHOLE_AI_COLLECT_BATCH_SIZE` | integer | `200` | no | positive | `200` | all |
| `PIHOLE_AI_COLLECT_INTERVAL` | integer seconds | `2` | no | positive | `2` | all |
| `PIHOLE_AI_ENGINE_BATCH_SIZE` | integer | `500` | no | positive | `500` | all |
| `PIHOLE_AI_ENGINE_INTERVAL` | integer seconds | `5` | no | positive | `5` | all |
| `PIHOLE_AI_CACHE_TTL` | integer seconds | `86400` | no | zero or positive | `86400` | all |
| `PIHOLE_AI_KEEP_LATEST_EVENTS` | integer | `100000` | no | positive | `100000` | all |
| `PIHOLE_AI_ALERT_THRESHOLD` | integer | `50` | no | 0-100 | `50` | all |
| `PIHOLE_AI_HIGH_RISK_THRESHOLD` | integer | `70` | no | 0-100 | `70` | all |
| `PIHOLE_AI_ACTION_MODE` | enum | `dry-run` | no | `off`, `dry-run`, `block` | `dry-run` | all |
| `AI_ENABLED` | boolean | `true` | no | boolean | `false` | all |
| `AI_MAX_CALLS_PER_MINUTE` | integer | `2` | no | zero or positive | `2` | all |
| `AI_COOLDOWN_SECONDS` | integer seconds | `60` | no | zero or positive | `60` | all |
| `AI_TIMEOUT_SECONDS` | integer seconds | `20` | no | positive | `20` | all |
| `PIHOLE_AI_OLLAMA_URL` | URL | `http://127.0.0.1:11434` | possible | HTTP(S), no credentials | `http://127.0.0.1:11434` | all |
| `PIHOLE_AI_OLLAMA_MODEL` | string | `llama3.2:1b` | no | non-empty when AI enabled | `llama3.2:1b` | all |
| `PIHOLE_AI_DASHBOARD_PORT` | integer | `8080` | no | TCP port | `8080` | all |
| `PIHOLE_AI_DASHBOARD_POLL_INTERVAL_MS` | integer ms | `10000` | no | positive | `10000` | all |
| `PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS` | integer ms | `5000` | no | positive | `5000` | all |
| `PIHOLE_AI_DASHBOARD_METRICS_POLL_INTERVAL_MS` | integer ms | `15000` | no | positive | `15000` | all |
| `PIHOLE_AI_DASHBOARD_TABLES_POLL_INTERVAL_MS` | integer ms | `10000` | no | positive | `10000` | all |
| `PIHOLE_AI_DASHBOARD_SLOW_POLL_INTERVAL_MS` | integer ms | `30000` | no | positive | `30000` | all |
| `PIHOLE_AI_DASHBOARD_AUTH_ENABLED` | boolean | `true` | no | boolean | `true` | all |
| `PIHOLE_AI_DASHBOARD_USERNAME` | string | `admin` | no | non-empty | `admin` | all |
| `PIHOLE_AI_DASHBOARD_PASSWORD_HASH` | hash | empty | yes | Werkzeug hash or empty | empty until bootstrap | appliance |
| `PIHOLE_AI_DASHBOARD_SECRET_KEY` | string | empty | yes | generated/required for persistent sessions | empty until setup | appliance |
| `PIHOLE_AI_DASHBOARD_SESSION_LIFETIME_MINUTES` | integer minutes | `480` | no | 1-1440 | `480` | all |
| `PIHOLE_AI_DASHBOARD_TRUST_PROXY` | boolean | `false` | no | boolean | `false` | appliance |
| `DEV_ACCESS_LOGS` | boolean | `false` | no | boolean | `false` | development |
| `LOG_PATH` | path | `/var/log/pihole-ai/pihole-ai.log` | no | file path | `/var/log/pihole-ai/pihole-ai.log` | all |
| `PIHOLE_AI_ALERT_LOG` | path | `/var/log/pihole-ai/alerts.log` | no | file path | `/var/log/pihole-ai/alerts.log` | all |
| `LOG_LEVEL` | enum | `INFO` | no | Python log level | `INFO` | all |
| `PIHOLE_AI_LOG_LEVEL` | enum | `INFO` | no | Python log level | `INFO` | all |

Internal and compatibility aliases supported by code but not included in the
packaged defaults include `PIHOLE_AI_CONFIG`, `PIHOLE_AI_PROJECT_ROOT`,
`PIHOLE_AI_DATA_DIR`, `PIHOLE_AI_LOG_DIR`, `PIHOLE_AI_CONFIG_FILE`,
`PIHOLE_AI_EVENTS_DB`, `PIHOLE_AI_LOG_FILE`, `PIHOLE_AI_ENABLED`,
`PIHOLE_AI_DEBUG`, `OLLAMA_URL`, and `OLLAMA_MODEL`.
