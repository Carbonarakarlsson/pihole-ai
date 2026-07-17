# API Reference

This document describes dashboard HTTP APIs that are intended for the
lightweight Flask dashboard. All endpoints are local-appliance APIs, not public
internet APIs.

## Security Model

Dashboard APIs require the authenticated dashboard session unless test mode
explicitly disables authentication. Mutating requests require the dashboard
CSRF token in `X-CSRF-Token`.

Configuration API responses include:

- `Cache-Control: no-store`
- `Pragma: no-cache`
- `X-Content-Type-Options: nosniff`

Errors use this envelope:

```json
{
  "error": {
    "code": "unknown_config_key",
    "message": "Unknown configuration key: NOPE",
    "details": []
  }
}
```

Secrets are never returned in plaintext by default. Masked values returned by
read endpoints must not be sent back as replacement values.

## Configuration API

The configuration API is implemented in Epic 3.5 Phase 1D. It is a backend API
for the future Settings page; it does not add the UI itself.

### `GET /api/config`

Returns the schema-backed effective configuration.

Query parameters:

- `category`: optional case-insensitive category filter

Response fields:

- `schema_version`: configuration schema version
- `revision`: `sha256:` digest of the managed env-file bytes
- `settings`: deterministic schema-ordered settings

Each setting includes:

- `key`
- `env`
- `value`
- `configured`
- `masked`
- `source`
- `category`
- `description`
- `restart`
- `editable`
- `sensitivity`
- `valid`
- `errors`

Secret values are represented as:

```json
{
  "configured": true,
  "masked": true,
  "value": null
}
```

### `POST /api/config/validate`

Validates a partial change set without writing, creating backups, or restarting
services.

Request:

```json
{
  "revision": "sha256:...",
  "changes": {
    "ollama_model": "llama3.2:1b"
  }
}
```

Canonical keys and environment variable aliases are accepted. Duplicate
canonical targets are rejected.

Secret updates require explicit operations:

```json
{
  "dashboard_secret_key": {
    "operation": "replace",
    "value": "new-secret-value"
  }
}
```

Supported operations:

- `replace`
- `preserve`
- `unset`

Omitted secrets are preserved.

### `PUT /api/config`

Applies a partial configuration update.

Request:

```json
{
  "revision": "sha256:...",
  "changes": {
    "ollama_model": "llama3.2:3b"
  },
  "dry_run": false,
  "restart": false
}
```

Behavior:

- stale revisions return `409`
- no-op writes do not create backups or restart services
- `dry_run=true` validates and previews without writing
- `restart=true` restarts only affected PiHole-AI services after a successful
  write
- persistence failure prevents restart
- restart failure does not roll back a successful write

Responses include `changed`, `written`, `backup_path`, `revision`,
`affected_services`, `restart_attempted`, `restart_success`,
`service_results`, and `recovery_commands`.

### `GET /api/config/impact`

Previews service impact for one or more keys.

Example:

```text
/api/config/impact?key=OLLAMA_MODEL&key=dashboard_port
```

Response:

```json
{
  "keys": ["ollama_model", "dashboard_port"],
  "affected_services": [
    "pihole-ai-engine.service",
    "pihole-ai-dashboard.service"
  ]
}
```

This endpoint is read-only and never invokes `systemctl`.

### `GET /api/config/export`

Exports normal, non-secret configuration.

Query parameters:

- `format=json`
- `format=env`

Normal exports omit secrets and mask sensitive values. Secure exports are
CLI-only in Phase 1D and return `403` from the dashboard API.

The response body is the exported file content, not a JSON envelope. The
response includes `Content-Disposition` with a generated filename.

### `POST /api/config/import`

Validates and optionally applies imported configuration content.

Request:

```json
{
  "revision": "sha256:...",
  "format": "json",
  "content": "{\"schema_version\":1,\"settings\":{\"ollama_model\":\"llama3.2:1b\"}}",
  "dry_run": true,
  "restart": false,
  "strict": false
}
```

Behavior:

- no uploaded file is persisted
- malformed imports return `400`
- imports larger than the API limit return `413`
- newer unsupported schema versions return `400`
- unknown keys are warnings by default
- `strict=true` turns unknown keys into errors
- successful non-dry-run imports use the same atomic write and backup path as
  CLI configuration writes

