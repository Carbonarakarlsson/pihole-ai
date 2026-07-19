"""
Shared configuration operations for CLI and dashboard callers.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from core import service_control
from core.config import Settings, ValidationMode, ValidationSeverity, validate_config
from core.config_migrations import CURRENT_CONFIG_SCHEMA_VERSION
from core.config_migrations import ConfigMigrationError
from core.config_migrations import detect_config_version
from core.config_manager import (
    ConfigurationManager,
    EnvDocument,
    mask_value,
    runtime_config,
    write_env_document_atomic,
)
from core.config_schema import (
    CONFIG_SCHEMA,
    SCHEMA_VERSION,
    CONFIG_SCHEMA_ENV,
    CONFIG_SCHEMA_VERSION,
    ConfigExportPolicy,
    ConfigItem,
    ConfigSensitivity,
    affected_services,
    get_item,
)
from pihole_ai.version import get_version


MASKED_PLACEHOLDERS = {"********", "<masked>", "configured: ********"}


class ConfigOperationError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int = 400,
        details: list[dict[str, Any]] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.status = status
        self.details = details or []
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error": {
                "code": self.code,
                "message": self.message,
            }
        }
        if self.details:
            payload["error"]["details"] = self.details
        return payload


@dataclass(frozen=True)
class PreparedChange:
    item: ConfigItem
    operation: str
    value: str | None = None


def config_revision(
    config_file: Path | None = None,
) -> str:
    path = config_file or runtime_config.CONFIG_FILE
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        data = b""
    except OSError as exc:
        raise ConfigOperationError(
            "configuration_not_readable",
            "Configuration file cannot be read.",
            status=500,
        ) from exc
    return "sha256:" + hashlib.sha256(data).hexdigest()


def inspect_config(
    *,
    config_file: Path | None = None,
    category: str = "",
) -> dict[str, Any]:
    path = config_file or runtime_config.CONFIG_FILE
    _ensure_current_schema(path)
    rows = _resolved_rows(path)
    if category:
        categories = {row["category"].lower() for row in rows}
        wanted = category.lower()
        if wanted not in categories:
            raise ConfigOperationError(
                "invalid_config_filter",
                f"Unknown configuration category: {category}",
                status=400,
            )
        rows = [row for row in rows if row["category"].lower() == wanted]
    return {
        "schema_version": SCHEMA_VERSION,
        "revision": config_revision(path),
        "settings": rows,
    }


def validate_changes(
    changes: Mapping[str, Any],
    *,
    revision: str | None,
    config_file: Path | None = None,
) -> dict[str, Any]:
    return apply_changes(
        changes,
        revision=revision,
        config_file=config_file,
        dry_run=True,
        restart=False,
    )


def apply_changes(
    changes: Mapping[str, Any],
    *,
    revision: str | None,
    config_file: Path | None = None,
    dry_run: bool = False,
    restart: bool = False,
) -> dict[str, Any]:
    path = config_file or runtime_config.CONFIG_FILE
    _ensure_current_schema(path)
    _check_revision(path, revision)
    prepared = _prepare_changes(changes)
    document = _load_document(path)
    original_text = document.to_text()
    current_rows = {
        item.key: _row_for_item(item, path, document)
        for item in (change.item for change in prepared)
    }

    for change in prepared:
        persisted_key = _persisted_key_for_item(document, change.item)
        if change.operation == "unset":
            if persisted_key is not None:
                document.unset(persisted_key)
        elif change.operation == "replace":
            assert change.value is not None
            document.set(persisted_key or change.item.env_var, change.value)
        elif change.operation == "preserve":
            continue
        else:
            raise ConfigOperationError("invalid_operation", "Unsupported config operation.")

    changed = document.to_text() != original_text
    proposed_rows = {
        change.item.key: _row_for_item(change.item, path, document)
        for change in prepared
    }
    errors = _validate_document(path, document)
    services = affected_services([change.item.key for change in prepared]) if changed else []
    result: dict[str, Any] = {
        "changed": changed,
        "written": False,
        "dry_run": dry_run,
        "revision": config_revision(path),
        "backup_path": None,
        "changes": [
            {
                "key": change.item.key,
                "current": _safe_state(current_rows[change.item.key]),
                "proposed": _safe_state(proposed_rows[change.item.key]),
            }
            for change in prepared
        ],
        "affected_services": services,
        "warnings": [],
        "errors": errors,
        "restart_requested": restart,
        "restart_attempted": False,
        "restart_success": None,
        "service_results": [],
        "recovery_commands": _recovery_commands(services) if restart else [],
    }
    if errors:
        raise ConfigOperationError(
            "configuration_validation_failed",
            "The proposed configuration is invalid.",
            status=400,
            details=errors,
        )
    if not changed or dry_run:
        return result
    backup = write_env_document_atomic(path, document)
    result["written"] = True
    result["backup_path"] = str(backup) if backup else None
    result["revision"] = config_revision(path)
    if restart and services:
        service_results = service_control.restart_services(services)
        result["restart_attempted"] = True
        result["restart_success"] = all(item.success for item in service_results)
        result["service_results"] = [item.to_dict() for item in service_results]
        result["recovery_commands"] = _recovery_commands(
            [item.service for item in service_results if not item.success]
        )
    elif restart:
        result["restart_success"] = True
    return result


def impact(
    keys: list[str],
) -> dict[str, Any]:
    if not keys:
        raise ConfigOperationError(
            "empty_impact_request",
            "At least one configuration key is required.",
            status=400,
        )
    canonical: list[str] = []
    for key in keys:
        try:
            item = get_item(key)
        except KeyError as exc:
            raise ConfigOperationError(
                "unknown_config_key",
                f"Unknown configuration key: {key}",
                status=400,
            ) from exc
        if item.key not in canonical:
            canonical.append(item.key)
    return {
        "keys": canonical,
        "affected_services": affected_services(canonical),
    }


def export_config(
    *,
    export_format: str = "json",
    secure: bool = False,
    config_file: Path | None = None,
) -> tuple[str, str, str]:
    if export_format not in {"json", "env"}:
        raise ConfigOperationError(
            "unsupported_export_format",
            "Export format must be json or env.",
            status=400,
        )
    if secure:
        raise ConfigOperationError(
            "secure_export_cli_only",
            "Secure API export is not available yet. Use the CLI with --secure.",
            status=403,
        )
    path = config_file or runtime_config.CONFIG_FILE
    _ensure_current_schema(path)
    rows = _raw_rows(path)
    payload = _export_payload(rows, export_format=export_format, secure=False)
    if export_format == "env":
        return _export_env(rows, secure=False), "text/plain; charset=utf-8", "pihole-ai-config.env"
    return (
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        "application/json",
        "pihole-ai-config.json",
    )


def import_config(
    *,
    content: str,
    import_format: str,
    revision: str | None,
    config_file: Path | None = None,
    dry_run: bool = False,
    restart: bool = False,
    strict: bool = False,
) -> dict[str, Any]:
    if len(content.encode("utf-8")) > 64 * 1024:
        raise ConfigOperationError(
            "import_too_large",
            "Configuration import content is too large.",
            status=413,
        )
    if import_format not in {"json", "env"}:
        raise ConfigOperationError("unsupported_import_format", "Import format must be json or env.")
    path = config_file or runtime_config.CONFIG_FILE
    _ensure_current_schema(path)
    changes, warnings = _parse_import_content(content, import_format, strict=strict)
    result = apply_changes(
        changes,
        revision=revision,
        config_file=path,
        dry_run=dry_run,
        restart=restart,
    )
    result["warnings"] = [*warnings, *result.get("warnings", [])]
    return result


def _ensure_current_schema(path: Path) -> None:
    try:
        state = detect_config_version(path)
    except ConfigMigrationError as exc:
        raise ConfigOperationError(
            exc.code,
            exc.message,
            status=400,
            details=exc.details,
        ) from exc
    if state.version is None:
        return
    if state.version < CURRENT_CONFIG_SCHEMA_VERSION:
        raise ConfigOperationError(
            "configuration_migration_required",
            "The configuration must be migrated before it can be edited.",
            status=409,
            details=[
                {
                    "source_version": state.version,
                    "target_version": CURRENT_CONFIG_SCHEMA_VERSION,
                }
            ],
        )


def _check_revision(
    path: Path,
    revision: str | None,
) -> None:
    current = config_revision(path)
    if not revision:
        raise ConfigOperationError(
            "missing_revision",
            "Configuration revision is required.",
            status=400,
        )
    if revision != current:
        raise ConfigOperationError(
            "configuration_revision_conflict",
            "Configuration changed after it was loaded.",
            status=409,
            details=[{"current_revision": current}],
        )


def _prepare_changes(
    changes: Mapping[str, Any],
) -> list[PreparedChange]:
    if not changes:
        raise ConfigOperationError("empty_change_set", "No configuration changes were provided.")
    prepared: list[PreparedChange] = []
    seen: set[str] = set()
    for key, raw in changes.items():
        try:
            item = get_item(key)
        except KeyError as exc:
            raise ConfigOperationError("unknown_config_key", f"Unknown configuration key: {key}") from exc
        if item.key in seen:
            raise ConfigOperationError(
                "duplicate_config_key",
                f"Multiple changes target {item.key}.",
            )
        seen.add(item.key)
        operation = "replace"
        value = raw
        if isinstance(raw, dict):
            operation = str(raw.get("operation", "replace"))
            value = raw.get("value")
        if item.sensitivity == ConfigSensitivity.SECRET:
            if not isinstance(raw, dict):
                raise ConfigOperationError(
                    "secret_operation_required",
                    f"{item.key} requires an explicit secret operation.",
                )
            if operation == "preserve":
                prepared.append(PreparedChange(item=item, operation="preserve"))
                continue
            if operation not in {"replace", "unset"}:
                raise ConfigOperationError("invalid_secret_operation", "Unsupported secret operation.")
            if operation == "unset":
                prepared.append(PreparedChange(item=item, operation="unset"))
                continue
            if str(value) in MASKED_PLACEHOLDERS:
                raise ConfigOperationError(
                    "masked_secret_placeholder_rejected",
                    "Masked secret placeholders cannot be used as replacement values.",
                )
        elif isinstance(raw, dict) and operation == "unset":
            prepared.append(PreparedChange(item=item, operation="unset"))
            continue
        if operation not in {"replace", "unset", "preserve"}:
            raise ConfigOperationError("invalid_operation", "Unsupported config operation.")
        if operation in {"unset", "preserve"}:
            prepared.append(PreparedChange(item=item, operation=operation))
            continue
        validation = item.validator(item, str(value))
        if not validation.is_valid:
            raise ConfigOperationError(
                "configuration_validation_failed",
                "The proposed configuration is invalid.",
                details=[error.to_dict() for error in validation.errors],
            )
        prepared.append(
            PreparedChange(
                item=item,
                operation="replace",
                value=_serialize_config_value(validation.value),
            )
        )
    return prepared


def _load_document(path: Path) -> EnvDocument:
    try:
        return EnvDocument.parse(path.read_text(encoding="utf-8")) if path.exists() else EnvDocument.parse("")
    except OSError as exc:
        raise ConfigOperationError(
            "configuration_not_readable",
            "Configuration file cannot be read.",
            status=500,
        ) from exc


def _persisted_key_for_item(document: EnvDocument, item: ConfigItem) -> str | None:
    matches = [key for key in document.entry_keys() if key in item.env_names]
    if len(matches) > 1:
        raise ConfigOperationError(
            "duplicate_persisted_key",
            f"Refusing to edit {item.key}; duplicate persisted aliases exist.",
            status=400,
        )
    return matches[0] if matches else None


def _manager_for_document(path: Path, document: EnvDocument) -> ConfigurationManager:
    project_env = runtime_config.PROJECT_ROOT / ".env"
    return ConfigurationManager(
        env=None,
        env_files=[],
        env_file_values=[
            (path, document.values()),
            (project_env, EnvDocument.from_path(project_env).values()),
        ],
    )


def _row_for_item(item: ConfigItem, path: Path, document: EnvDocument) -> dict[str, Any]:
    value = _manager_for_document(path, document).resolve()[item.key]
    return _row_payload(item, value.env_name, value.raw_value, value.source, value.validation.is_valid, [error.to_dict() for error in value.validation.errors])


def _resolved_rows(path: Path) -> list[dict[str, Any]]:
    rows = []
    manager = ConfigurationManager(env_files=[path, runtime_config.PROJECT_ROOT / ".env"])
    for item in CONFIG_SCHEMA:
        value = manager.resolve()[item.key]
        rows.append(_row_payload(item, value.env_name, value.raw_value, value.source, value.validation.is_valid, [error.to_dict() for error in value.validation.errors]))
    return rows


def _raw_rows(path: Path) -> list[tuple[ConfigItem, str, str]]:
    manager = ConfigurationManager(env_files=[path, runtime_config.PROJECT_ROOT / ".env"])
    resolved = manager.resolve()
    return [(item, resolved[item.key].raw_value, resolved[item.key].source) for item in CONFIG_SCHEMA]


def _row_payload(
    item: ConfigItem,
    env_name: str,
    raw_value: str,
    source: str,
    valid: bool,
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    rendered = mask_value(item, raw_value)
    return {
        "key": item.key,
        "env": env_name,
        "value": rendered["value"],
        "configured": rendered["configured"],
        "masked": rendered["masked"],
        "source": source,
        "category": item.category,
        "description": item.description,
        "restart": affected_services([item.key]),
        "editable": item.export_policy != ConfigExportPolicy.EXCLUDE,
        "type": item.value_type.value,
        "allowed_values": list(item.allowed_values),
        "minimum": item.minimum,
        "maximum": item.maximum,
        "sensitivity": item.sensitivity.value,
        "valid": valid,
        "errors": errors,
    }


def _safe_state(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "value": row.get("value"),
        "source": row.get("source"),
        "masked": row.get("masked", False),
        "configured": row.get("configured", False),
        "valid": row.get("valid", True),
    }


def _validate_document(path: Path, document: EnvDocument) -> list[dict[str, Any]]:
    manager = _manager_for_document(path, document)
    errors = [error.to_dict() | {"severity": "error"} for error in manager.validate().errors]
    merged: dict[str, str] = {}
    project_env = runtime_config.PROJECT_ROOT / ".env"
    merged.update(document.values())
    merged.update(EnvDocument.from_path(project_env).values())
    try:
        config = Settings(env=merged, env_files=[])
        result = validate_config(config, mode=ValidationMode.INSTALL)
    except Exception:
        return errors
    for issue in result.issues:
        if issue.severity != ValidationSeverity.ERROR.value:
            continue
        if issue.code in {
            "config.events_db.parent_missing",
            "config.events_db.parent_not_writable",
            "config.log_file.parent_missing",
            "config.log_file.parent_not_writable",
            "config.pihole_db.missing",
            "config.pihole_db.not_readable",
            "config.dashboard.secret_key_missing",
            "config.dashboard.password_hash_missing",
        }:
            continue
        errors.append({"key": issue.setting, "code": issue.code, "message": issue.summary, "severity": issue.severity})
    return sorted(errors, key=lambda item: (str(item.get("key")), str(item.get("code"))))


def _export_payload(rows: list[tuple[ConfigItem, str, str]], *, export_format: str, secure: bool) -> dict[str, Any]:
    settings: list[dict[str, Any]] = []
    for item, raw_value, source in rows:
        if item.export_policy == ConfigExportPolicy.EXCLUDE:
            continue
        rendered = _export_value(item, raw_value, secure=secure)
        if rendered is None:
            continue
        settings.append({"key": item.key, "env": item.env_var, "value": rendered["value"], "masked": rendered["masked"], "source": source, "category": item.category})
    return {"schema_version": SCHEMA_VERSION, "pihole_ai_version": get_version(), "exported_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(), "format": export_format, "secure": secure, "contains_secrets": secure, "settings": settings}


def _export_env(rows: list[tuple[ConfigItem, str, str]], *, secure: bool) -> str:
    lines = [
        "# Generated PiHole-AI configuration export",
        f"# schema_version={SCHEMA_VERSION}",
        f"# pihole_ai_version={get_version()}",
        "# secure=false",
        f"{CONFIG_SCHEMA_ENV}={CONFIG_SCHEMA_VERSION}",
    ]
    for item, raw_value, _source in rows:
        if item.export_policy == ConfigExportPolicy.EXCLUDE:
            continue
        rendered = _export_value(item, raw_value, secure=secure)
        if rendered is None:
            continue
        if rendered["masked"]:
            lines.append(f"# {item.env_var}=<masked>")
        else:
            lines.append(f"{item.env_var}={_serialize_config_value(rendered['value'])}")
    return "\n".join(lines) + "\n"


def _export_value(item: ConfigItem, raw_value: str, *, secure: bool) -> dict[str, Any] | None:
    if item.sensitivity == ConfigSensitivity.SECRET and not secure:
        return None
    if item.sensitivity == ConfigSensitivity.SENSITIVE and not secure:
        rendered = mask_value(item, raw_value)
        return {"value": rendered["value"], "masked": rendered["masked"]}
    validation = item.validator(item, raw_value)
    value = validation.value if validation.is_valid else raw_value
    if isinstance(value, Path):
        value = str(value)
    return {"value": value, "masked": False}


def _parse_import_content(content: str, import_format: str, *, strict: bool) -> tuple[dict[str, Any], list[str]]:
    if import_format == "json":
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ConfigOperationError("malformed_json", "Malformed JSON import content.") from exc
        if not isinstance(payload, dict):
            raise ConfigOperationError("malformed_json", "JSON import content must be an object.")
        try:
            version = int(payload.get("schema_version", 0))
        except (TypeError, ValueError) as exc:
            raise ConfigOperationError("malformed_json", "JSON import schema_version must be an integer.") from exc
        if version > SCHEMA_VERSION:
            raise ConfigOperationError("unsupported_schema_version", f"Unsupported schema version. Import: {version}. Supported: {SCHEMA_VERSION}.")
        settings = payload.get("settings", [])
        if isinstance(settings, dict):
            entries = list(settings.items())
        elif isinstance(settings, list):
            entries = [
                (entry.get("key") or entry.get("env"), entry.get("value"))
                for entry in settings
                if isinstance(entry, dict) and not entry.get("masked")
            ]
        else:
            raise ConfigOperationError("malformed_json", "JSON import settings must be an object or list.")
    else:
        entries = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in line:
                raise ConfigOperationError("malformed_env", "Malformed ENV import content.")
            key, value = line.split("=", 1)
            entries.append((key.strip(), value.strip().strip("\"'")))
    changes: dict[str, Any] = {}
    warnings: list[str] = []
    seen: set[str] = set()
    for key, value in entries:
        if str(key) == CONFIG_SCHEMA_ENV:
            continue
        try:
            item = get_item(str(key))
        except KeyError as exc:
            if strict:
                raise ConfigOperationError("unknown_config_key", f"Unknown configuration key: {key}") from exc
            warnings.append(f"Unknown import setting ignored: {key}")
            continue
        if item.key in seen:
            raise ConfigOperationError("duplicate_config_key", f"Multiple changes target {item.key}.")
        seen.add(item.key)
        changes[item.key] = value
    return changes, warnings


def _serialize_config_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def _recovery_commands(services: list[str]) -> list[str]:
    return [f"sudo systemctl restart {service}" for service in services]
