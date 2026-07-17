"""
CLI helpers for configuration inspection and validation.
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Any

from core.config import (
    ConfigurationParseError,
    ProtectedConfigurationAccessError,
    Settings,
    ValidationMode,
    ValidationSeverity,
    load_config,
    load_config_with_result,
    validate_config,
)
from core.config_manager import ConfigurationManager
from core.config_manager import EnvDocument
from core.config_manager import changed_key_impact
from core.config_manager import mask_value
from core.config_manager import write_env_document_atomic
from core.config_manager import runtime_config
from core.config_schema import CONFIG_SCHEMA
from core.config_schema import SCHEMA_VERSION
from core.config_schema import ConfigExportPolicy
from core.config_schema import ConfigItem
from core.config_schema import ConfigSensitivity
from core.config_schema import affected_services
from core.config_schema import get_item
from pihole_ai.version import get_version


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INVALID_CONFIG = 3


def print_config_check(
    mode: str = ValidationMode.RUNTIME.value,
    as_json: bool = False,
) -> int:
    """
    Print configuration validation results.
    """

    config, result = load_config_with_result(
        mode=mode,
    )

    if as_json:
        payload = result.to_dict()

        if config is not None:
            payload["config"] = config.to_safe_dict()

        print(
            json.dumps(
                payload,
                sort_keys=True,
            )
        )

    else:
        print(f"PiHole-AI configuration check ({result.mode})")

        if not result.issues:
            print("No configuration issues found.")

        else:
            grouped: dict[str, list[Any]] = defaultdict(list)

            for issue in result.issues:
                grouped[issue.severity].append(issue)

            for severity in (
                ValidationSeverity.ERROR.value,
                ValidationSeverity.WARNING.value,
                ValidationSeverity.INFO.value,
            ):
                issues = grouped.get(severity, [])

                if not issues:
                    continue

                print(f"{severity}:")

                for issue in issues:
                    print(f"  [{issue.code}] {issue.setting}: {issue.summary}")
                    print(f"    fix: {issue.remediation}")

    if config is None:
        return 3

    if result.error_count:
        return 2

    if result.warning_count:
        return 1

    return 0


def print_config_show(
    as_json: bool = False,
    category: str = "",
    source: str = "",
) -> int:
    """
    Print safe effective configuration in schema order.
    """

    try:
        rows = _resolved_rows()

    except ProtectedConfigurationAccessError as exc:
        issue = exc.issue()
        if as_json:
            print(
                json.dumps(
                    {
                        "error": exc.__class__.__name__,
                        "issues": [
                            {
                                "code": issue.code,
                                "severity": issue.severity,
                                "setting": issue.setting,
                                "summary": issue.summary,
                                "remediation": issue.remediation,
                                "details": issue.details or {},
                            }
                        ],
                    },
                    sort_keys=True,
                )
            )
        else:
            print("Appliance configuration is protected.")
            print("Re-run with sudo: sudo pihole-ai config show")

        return EXIT_INVALID_CONFIG

    except ConfigurationParseError as exc:
        if as_json:
            print(
                json.dumps(
                    {
                        "error": exc.__class__.__name__,
                        "issues": [
                            {
                                "code": issue.code,
                                "severity": issue.severity,
                                "setting": issue.setting,
                                "summary": issue.summary,
                                "remediation": issue.remediation,
                            }
                            for issue in exc.issues
                        ],
                    },
                    sort_keys=True,
                )
            )
        else:
            print("Configuration could not be parsed.")
            print("Run: pihole-ai config check")

        return EXIT_INVALID_CONFIG

    try:
        rows = _filter_rows(
            rows,
            category=category,
            source=source,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE

    if as_json:
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "settings": [_row_to_json(row) for row in rows],
                },
                sort_keys=True,
            )
        )
    else:
        print("PiHole-AI effective configuration")
        for row in rows:
            rendered = _render_value(row["item"], row["raw_value"])
            value = rendered["value"] if rendered["value"] is not None else "<configured>"
            if not rendered["configured"]:
                value = "<unset>"
            if rendered["masked"]:
                value = str(value) if value != "<configured>" else "<configured, masked>"
            print(
                f"{row['item'].key}: {value} "
                f"(source={row['source']}, category={row['item'].category}, "
                f"restart={_restart_label(row['services'])})"
            )

    return EXIT_OK


def print_config_get(
    key: str,
    *,
    as_json: bool = False,
    details: bool = False,
) -> int:
    """
    Print one safely rendered setting value.
    """

    try:
        item = get_item(key)
        rows_by_key = {
            row["item"].key: row
            for row in _resolved_rows()
        }
        row = rows_by_key[item.key]
    except KeyError:
        print(f"Unknown configuration key: {key}", file=sys.stderr)
        return EXIT_USAGE
    except (ProtectedConfigurationAccessError, ConfigurationParseError) as exc:
        print(f"Configuration could not be read: {exc.__class__.__name__}", file=sys.stderr)
        return EXIT_INVALID_CONFIG

    payload = _row_to_json(row)
    if as_json:
        print(json.dumps(payload if details else {"value": payload["value"]}, sort_keys=True))
    elif details:
        print(f"key: {payload['key']}")
        print(f"env: {payload['env']}")
        print(f"value: {payload['value'] if payload['value'] is not None else '<configured>'}")
        print(f"masked: {str(payload['masked']).lower()}")
        print(f"source: {payload['source']}")
        print(f"category: {payload['category']}")
        print(f"restart: {_restart_label(payload['restart'])}")
        print(f"valid: {str(payload['valid']).lower()}")
        for error in payload["errors"]:
            print(f"error: [{error['code']}] {error['message']}")
    else:
        value = payload["value"]
        if value is None and payload["configured"]:
            print("<configured>")
        elif value is None:
            print("<unset>")
        else:
            print(value)

    return EXIT_INVALID_CONFIG if not payload["valid"] else EXIT_OK


def print_config_validate(
    *,
    as_json: bool = False,
) -> int:
    """
    Validate the complete resolved configuration.
    """

    errors: list[dict[str, str]] = []

    try:
        manager = ConfigurationManager()
        manager_result = manager.validate()
        for error in manager_result.errors:
            errors.append(
                {
                    "key": error.key,
                    "code": error.code,
                    "message": error.message,
                    "severity": "error",
                }
            )
    except ProtectedConfigurationAccessError as exc:
        issue = exc.issue()
        errors.append(
            {
                "key": issue.setting,
                "code": issue.code,
                "message": issue.summary,
                "severity": issue.severity,
            }
        )

    config, result = load_config_with_result(mode=ValidationMode.RUNTIME)
    for issue in result.issues:
        if issue.severity != ValidationSeverity.ERROR.value:
            continue
        errors.append(
            {
                "key": issue.setting,
                "code": issue.code,
                "message": issue.summary,
                "severity": issue.severity,
            }
        )

    errors = _dedupe_errors(errors)
    valid = not errors and config is not None

    if as_json:
        print(
            json.dumps(
                {
                    "valid": valid,
                    "errors": errors,
                },
                sort_keys=True,
            )
        )
    elif valid:
        print("Configuration is valid.")
    else:
        print("Configuration is invalid.")
        for error in errors:
            print(
                f"- {error['key']} [{error['severity']}] "
                f"{error['code']}: {error['message']}"
            )

    return EXIT_OK if valid else EXIT_INVALID_CONFIG


def print_config_impact(
    keys: list[str],
    *,
    as_json: bool = False,
) -> int:
    """
    Print restart impact for hypothetical changed settings.
    """

    canonical: list[str] = []
    for key in keys:
        try:
            item = get_item(key)
        except KeyError:
            print(f"Unknown configuration key: {key}", file=sys.stderr)
            return EXIT_USAGE
        if item.key not in canonical:
            canonical.append(item.key)

    services = affected_services(canonical)
    payload = {
        "changed_keys": canonical,
        "restart_required": bool(services),
        "services": services,
    }

    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print("Changed settings:")
        for key in canonical:
            print(f"- {key}")
        print()
        if services:
            print("Restart required:")
            for service in services:
                print(f"- {service}")
        else:
            print("No service restart is required.")

    return EXIT_OK


def print_config_set(
    key: str,
    value: str,
    *,
    dry_run: bool = False,
    as_json: bool = False,
    yes: bool = False,
    config_file: str = "",
) -> int:
    return _run_config_edit(
        operation="set",
        key=key,
        value=value,
        dry_run=dry_run,
        as_json=as_json,
        yes=yes,
        config_file=config_file,
    )


def print_config_unset(
    key: str,
    *,
    dry_run: bool = False,
    as_json: bool = False,
    yes: bool = False,
    config_file: str = "",
) -> int:
    return _run_config_edit(
        operation="unset",
        key=key,
        value=None,
        dry_run=dry_run,
        as_json=as_json,
        yes=yes,
        config_file=config_file,
    )


def print_config_export(
    *,
    output: str = "",
    export_format: str = "json",
    secure: bool = False,
    as_json: bool = False,
) -> int:
    """
    Export effective configuration in JSON or env format.
    """

    if as_json:
        export_format = "json"
    try:
        rows = _resolved_rows()
    except (ProtectedConfigurationAccessError, ConfigurationParseError) as exc:
        print(f"Configuration could not be read: {exc.__class__.__name__}", file=sys.stderr)
        return EXIT_INVALID_CONFIG

    if secure:
        print(
            "warning: secure configuration export includes secrets; protect the output file.",
            file=sys.stderr,
        )

    payload = _export_payload(rows, export_format=export_format, secure=secure)
    content = (
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if export_format == "json"
        else _export_env(rows, secure=secure)
    )

    if output:
        try:
            _write_output_file(Path(output), content)
        except OSError as exc:
            print(f"Could not write export file: {exc.__class__.__name__}", file=sys.stderr)
            return EXIT_ERROR
        print(f"Wrote configuration export to {output}.", file=sys.stderr)
    else:
        sys.stdout.write(content)
    return EXIT_OK


def print_config_import(
    import_path: str,
    *,
    dry_run: bool = False,
    yes: bool = False,
    as_json: bool = False,
    strict: bool = False,
    config_file: str = "",
) -> int:
    """
    Import known configuration settings from JSON or env input.
    """

    if as_json and not (dry_run or yes):
        print(
            "JSON import mode requires --dry-run or --yes.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    source_path = Path(import_path)
    target_file = Path(config_file).expanduser() if config_file else runtime_config.CONFIG_FILE
    try:
        updates, warnings = _parse_import_file(source_path, strict=strict)
        document = _load_edit_document(target_file)
        original_text = document.to_text()
        current_rows = {
            item.key: _resolved_row_for_item(item, target_file, document)
            for item in CONFIG_SCHEMA
        }
        for item in updates:
            _persisted_key_for_item(document, item)
        for item, serialized in updates.items():
            persisted_key = _persisted_key_for_item(document, item)
            document.set(persisted_key or item.env_var, serialized)
    except ConfigEditError as exc:
        _print_edit_error(exc, as_json=as_json)
        return exc.exit_code

    changed_keys = [
        item.key
        for item in updates
        if current_rows[item.key] != _resolved_row_for_item(item, target_file, document)
        or document.to_text() != original_text
    ]
    changed = document.to_text() != original_text
    services = affected_services([item.key for item in updates]) if changed else []
    proposed_rows = {
        item.key: _resolved_row_for_item(item, target_file, document)
        for item in updates
    }
    errors = _validate_proposed_document(target_file, document)
    result = {
        "operation": "import",
        "schema_version": SCHEMA_VERSION,
        "source_file": str(source_path),
        "target_file": str(target_file),
        "changed": changed,
        "changed_settings": [
            {
                "key": item.key,
                "current": _safe_state(current_rows[item.key]),
                "proposed": _safe_state(proposed_rows[item.key]),
            }
            for item in updates
            if current_rows[item.key] != proposed_rows[item.key]
            or changed
        ],
        "affected_services": services,
        "warnings": warnings,
        "errors": errors,
        "dry_run": dry_run,
        "written": False,
        "backup_path": None,
    }

    if errors:
        _print_import_result(result, as_json=as_json)
        return EXIT_INVALID_CONFIG
    if not changed:
        _print_import_result(result, as_json=as_json)
        return EXIT_OK
    if dry_run:
        _print_import_result(result, as_json=as_json)
        return EXIT_OK
    if not yes:
        if not _confirm_change():
            result["declined"] = True
            _print_import_result(result, as_json=as_json)
            return EXIT_ERROR
    try:
        backup_path = write_env_document_atomic(target_file, document)
    except (OSError, PermissionError) as exc:
        _print_edit_error(
            ConfigEditError(
                "Configuration could not be written.",
                EXIT_ERROR,
                exc.__class__.__name__,
            ),
            as_json=as_json,
        )
        return EXIT_ERROR
    result["written"] = True
    result["backup_path"] = str(backup_path) if backup_path is not None else None
    _print_import_result(result, as_json=as_json)
    return EXIT_OK


def _print_dict(
    values: dict[str, Any],
    indent: int = 0,
) -> None:
    prefix = " " * indent

    for key, value in values.items():
        if isinstance(value, dict):
            print(f"{prefix}{key}:")
            _print_dict(
                value,
                indent=indent + 2,
            )
        else:
            print(f"{prefix}{key}: {value}")


def _export_payload(
    rows: list[dict[str, Any]],
    *,
    export_format: str,
    secure: bool,
) -> dict[str, Any]:
    settings: list[dict[str, Any]] = []
    for row in rows:
        item: ConfigItem = row["item"]
        if item.export_policy == ConfigExportPolicy.EXCLUDE:
            continue
        rendered = _render_export_value(item, row["raw_value"], secure=secure)
        if rendered is None:
            continue
        settings.append(
            {
                "key": item.key,
                "env": item.env_var,
                "value": rendered["value"],
                "masked": rendered["masked"],
                "source": row["source"],
                "category": item.category,
                "type": item.value_type.value,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "pihole_ai_version": get_version(),
        "exported_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "format": export_format,
        "secure": secure,
        "contains_secrets": secure,
        "settings": settings,
    }


def _export_env(
    rows: list[dict[str, Any]],
    *,
    secure: bool,
) -> str:
    lines = [
        "# Generated PiHole-AI configuration export",
        f"# schema_version={SCHEMA_VERSION}",
        f"# pihole_ai_version={get_version()}",
        f"# secure={'true' if secure else 'false'}",
    ]
    for row in rows:
        item: ConfigItem = row["item"]
        if item.export_policy == ConfigExportPolicy.EXCLUDE:
            continue
        rendered = _render_export_value(item, row["raw_value"], secure=secure)
        if rendered is None:
            continue
        if rendered["masked"]:
            lines.append(f"# {item.env_var}=<masked>")
        else:
            lines.append(f"{item.env_var}={_serialize_env_for_export(_serialize_config_value(rendered['value']))}")
    return "\n".join(lines) + "\n"


def _render_export_value(
    item: ConfigItem,
    raw_value: str,
    *,
    secure: bool,
) -> dict[str, Any] | None:
    if item.sensitivity == ConfigSensitivity.SECRET and not secure:
        return None
    if item.sensitivity == ConfigSensitivity.SENSITIVE and not secure:
        rendered = mask_value(item, raw_value)
        return {
            "value": rendered["value"],
            "masked": rendered["masked"],
        }
    return {
        "value": _typed_export_value(item, raw_value),
        "masked": False,
    }


def _typed_export_value(
    item: ConfigItem,
    raw_value: str,
) -> Any:
    validation = item.validator(item, raw_value)
    if validation.is_valid:
        value = validation.value
        if isinstance(value, Path):
            return str(value)
        return value
    return raw_value


def _write_output_file(
    path: Path,
    content: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    import tempfile

    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        raise


def _parse_import_file(
    path: Path,
    *,
    strict: bool,
) -> tuple[dict[ConfigItem, str], list[str]]:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigEditError(
            f"Import file cannot be read: {path}",
            EXIT_ERROR,
            exc.__class__.__name__,
        ) from exc
    stripped = content.lstrip()
    if path.suffix.lower() == ".json" or stripped.startswith("{"):
        return _parse_import_json(content, strict=strict)
    return _parse_import_env(content, strict=strict)


def _parse_import_json(
    content: str,
    *,
    strict: bool,
) -> tuple[dict[ConfigItem, str], list[str]]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ConfigEditError(
            "Malformed JSON import file.",
            EXIT_INVALID_CONFIG,
            "config.import.malformed_json",
        ) from exc
    if not isinstance(payload, dict):
        raise ConfigEditError(
            "JSON import must contain an object.",
            EXIT_INVALID_CONFIG,
            "config.import.invalid_json",
        )
    schema_version = int(payload.get("schema_version", 0))
    if schema_version > SCHEMA_VERSION:
        raise ConfigEditError(
            f"Unsupported schema version.\nImport: {schema_version}\nSupported: {SCHEMA_VERSION}\nUpgrade PiHole-AI and retry.",
            EXIT_INVALID_CONFIG,
            "config.import.unsupported_schema_version",
        )
    raw_settings = payload.get("settings", [])
    if isinstance(raw_settings, dict):
        entries = [
            {"key": key, "value": value}
            for key, value in raw_settings.items()
        ]
    elif isinstance(raw_settings, list):
        entries = raw_settings
    else:
        raise ConfigEditError(
            "JSON import settings must be a list or object.",
            EXIT_INVALID_CONFIG,
            "config.import.invalid_settings",
        )
    updates: dict[ConfigItem, str] = {}
    warnings: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ConfigEditError(
                "JSON import contains a malformed setting entry.",
                EXIT_INVALID_CONFIG,
                "config.import.invalid_setting_entry",
            )
        if entry.get("masked"):
            continue
        key = str(entry.get("key") or entry.get("env") or "")
        if not key:
            raise ConfigEditError(
                "JSON import contains a setting without a key.",
                EXIT_INVALID_CONFIG,
                "config.import.missing_key",
            )
        value = entry.get("value")
        _add_import_update(updates, warnings, key, value, strict=strict)
    return updates, warnings


def _parse_import_env(
    content: str,
    *,
    strict: bool,
) -> tuple[dict[ConfigItem, str], list[str]]:
    updates: dict[ConfigItem, str] = {}
    warnings: list[str] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(content.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in raw:
            raise ConfigEditError(
                f"Malformed ENV import line {line_number}.",
                EXIT_INVALID_CONFIG,
                "config.import.malformed_env",
            )
        key, raw_value = raw.split("=", 1)
        key = key.strip()
        if key in seen:
            raise ConfigEditError(
                f"Duplicate ENV import key: {key}",
                EXIT_INVALID_CONFIG,
                "config.import.duplicate_key",
            )
        seen.add(key)
        value_text = raw_value.strip()
        if len(value_text) >= 2 and value_text[0] == value_text[-1] and value_text[0] in {"'", '"'}:
            value_text = value_text[1:-1]
        _add_import_update(updates, warnings, key, value_text, strict=strict)
    return updates, warnings


def _add_import_update(
    updates: dict[ConfigItem, str],
    warnings: list[str],
    key: str,
    value: Any,
    *,
    strict: bool,
) -> None:
    try:
        item = get_item(key)
    except KeyError as exc:
        message = f"Unknown import setting ignored: {key}"
        if strict:
            raise ConfigEditError(
                f"Unknown import setting: {key}",
                EXIT_USAGE,
                "config.import.unknown_key",
            ) from exc
        warnings.append(message)
        return
    if item in updates:
        raise ConfigEditError(
            f"Duplicate import setting for {item.key}.",
            EXIT_INVALID_CONFIG,
            "config.import.duplicate_key",
        )
    if value is None:
        value = ""
    validation = item.validator(item, str(value))
    if not validation.is_valid:
        first = validation.errors[0]
        raise ConfigEditError(
            f"Invalid import value for {item.key}: {first.message}",
            EXIT_INVALID_CONFIG,
            first.code,
        )
    updates[item] = _serialize_config_value(validation.value)


def _serialize_env_for_export(
    value: str,
) -> str:
    if value == "":
        return '""'
    if any(char.isspace() for char in value) or "#" in value or '"' in value:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


def _run_config_edit(
    *,
    operation: str,
    key: str,
    value: str | None,
    dry_run: bool,
    as_json: bool,
    yes: bool,
    config_file: str,
) -> int:
    if as_json and not (dry_run or yes):
        print(
            "JSON write mode requires --dry-run or --yes.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        item = get_item(key)
    except KeyError:
        print(f"Unknown configuration key: {key}", file=sys.stderr)
        return EXIT_USAGE

    target_file = Path(config_file).expanduser() if config_file else runtime_config.CONFIG_FILE
    try:
        document = _load_edit_document(target_file)
        persisted_key = _persisted_key_for_item(document, item)
    except ConfigEditError as exc:
        _print_edit_error(exc, as_json=as_json)
        return exc.exit_code

    original_text = document.to_text()
    current = _resolved_row_for_item(item, target_file, document)
    warnings: list[str] = []

    if operation == "set":
        assert value is not None
        validation = item.validator(item, value)
        if not validation.is_valid:
            result = _edit_payload(
                operation=operation,
                item=item,
                target_file=target_file,
                changed=False,
                written=False,
                dry_run=dry_run,
                current=current,
                proposed=None,
                effective_after=current,
                affected_services=[],
                backup_path=None,
                warnings=[],
                errors=[error.to_dict() for error in validation.errors],
            )
            _print_edit_result(result, as_json=as_json)
            return EXIT_INVALID_CONFIG
        serialized = _serialize_config_value(validation.value)
        document.set(persisted_key or item.env_var, serialized)
    else:
        if persisted_key is None:
            proposed = _resolved_row_for_item(item, target_file, document)
            result = _edit_payload(
                operation=operation,
                item=item,
                target_file=target_file,
                changed=False,
                written=False,
                dry_run=dry_run,
                current=current,
                proposed=proposed,
                effective_after=proposed,
                affected_services=[],
                backup_path=None,
                warnings=[],
                errors=[],
            )
            _print_edit_result(result, as_json=as_json)
            return EXIT_OK
        document.unset(persisted_key)

    changed = document.to_text() != original_text
    proposed = _resolved_row_for_item(item, target_file, document)
    effective_after = proposed
    services = affected_services([item.key]) if changed else []

    if current["source"] == "environment" or proposed["source"] == "environment":
        warnings.append(
            "Persisted value will change, but the effective value is controlled "
            f"by process environment {proposed['env']}."
        )

    errors = _validate_proposed_document(target_file, document)
    result = _edit_payload(
        operation=operation,
        item=item,
        target_file=target_file,
        changed=changed,
        written=False,
        dry_run=dry_run,
        current=current,
        proposed=proposed,
        effective_after=effective_after,
        affected_services=services,
        backup_path=None,
        warnings=warnings,
        errors=errors,
    )

    if errors:
        _print_edit_result(result, as_json=as_json)
        return EXIT_INVALID_CONFIG

    if not changed:
        _print_edit_result(result, as_json=as_json)
        return EXIT_OK

    if dry_run:
        _print_edit_result(result, as_json=as_json)
        return EXIT_OK

    if not yes:
        if not _confirm_change():
            result["declined"] = True
            _print_edit_result(result, as_json=as_json)
            return EXIT_ERROR

    try:
        backup_path = write_env_document_atomic(target_file, document)
    except (OSError, PermissionError) as exc:
        _print_edit_error(
            ConfigEditError(
                "Configuration could not be written.",
                EXIT_ERROR,
                exc.__class__.__name__,
            ),
            as_json=as_json,
        )
        return EXIT_ERROR

    result["written"] = True
    result["backup_path"] = str(backup_path) if backup_path is not None else None
    _print_edit_result(result, as_json=as_json)
    return EXIT_OK


def _resolved_rows() -> list[dict[str, Any]]:
    manager = ConfigurationManager()
    resolved = manager.resolve()
    rows: list[dict[str, Any]] = []
    for item in CONFIG_SCHEMA:
        value = resolved[item.key]
        rows.append(
            {
                "item": item,
                "env": value.env_name,
                "raw_value": value.raw_value,
                "value": value.value,
                "source": value.source,
                "validation": value.validation,
                "services": affected_services([item.key]),
            }
        )
    return rows


class ConfigEditError(RuntimeError):
    def __init__(
        self,
        message: str,
        exit_code: int = EXIT_ERROR,
        code: str = "config_edit_error",
    ) -> None:
        self.message = message
        self.exit_code = exit_code
        self.code = code
        super().__init__(message)


def _load_edit_document(
    path: Path,
) -> EnvDocument:
    if path.is_symlink():
        raise ConfigEditError(
            f"Refusing to edit symlink configuration file: {path}",
            EXIT_ERROR,
            "config.symlink",
        )
    if path.exists():
        try:
            return EnvDocument.parse(path.read_text(encoding="utf-8"))
        except OSError as exc:
            if path == runtime_config.CONFIG_FILE:
                raise ConfigEditError(
                    "Appliance configuration is protected. Re-run with sudo.",
                    EXIT_ERROR,
                    "config.appliance.permission_denied",
                ) from exc
            raise ConfigEditError(
                f"Configuration file cannot be read: {path}",
                EXIT_ERROR,
                exc.__class__.__name__,
            ) from exc
    try:
        return EnvDocument.from_path(path)
    except ProtectedConfigurationAccessError as exc:
        raise ConfigEditError(
            "Appliance configuration is protected. Re-run with sudo.",
            EXIT_ERROR,
            exc.issue().code,
        ) from exc
    except OSError as exc:
        raise ConfigEditError(
            f"Configuration file cannot be read: {path}",
            EXIT_ERROR,
            exc.__class__.__name__,
        ) from exc


def _persisted_key_for_item(
    document: EnvDocument,
    item: ConfigItem,
) -> str | None:
    matches = [
        key
        for key in document.entry_keys()
        if key in item.env_names
    ]
    if len(matches) > 1:
        raise ConfigEditError(
            f"Refusing to edit {item.key}; duplicate persisted aliases exist.",
            EXIT_ERROR,
            "config.duplicate_persisted_key",
        )
    return matches[0] if matches else None


def _resolved_row_for_item(
    item: ConfigItem,
    target_file: Path,
    document: EnvDocument,
) -> dict[str, Any]:
    manager = _manager_for_document(target_file, document)
    resolved = manager.resolve()[item.key]
    services = affected_services([item.key])
    return _row_to_json(
        {
            "item": item,
            "env": resolved.env_name,
            "raw_value": resolved.raw_value,
            "value": resolved.value,
            "source": resolved.source,
            "validation": resolved.validation,
            "services": services,
        }
    )


def _manager_for_document(
    target_file: Path,
    document: EnvDocument,
) -> ConfigurationManager:
    project_env = runtime_config.PROJECT_ROOT / ".env"
    project_values = EnvDocument.from_path(project_env).values()
    return ConfigurationManager(
        env=dict(os.environ),
        env_files=[],
        env_file_values=[
            (target_file, document.values()),
            (project_env, project_values),
        ],
    )


def _validate_proposed_document(
    target_file: Path,
    document: EnvDocument,
) -> list[dict[str, str]]:
    manager = _manager_for_document(target_file, document)
    manager_result = manager.validate()
    errors = [
        {
            "key": error.key,
            "code": error.code,
            "message": error.message,
            "severity": "error",
        }
        for error in manager_result.errors
    ]

    merged: dict[str, str] = {}
    project_env = runtime_config.PROJECT_ROOT / ".env"
    merged.update(document.values())
    merged.update(EnvDocument.from_path(project_env).values())
    merged.update(dict(os.environ))
    try:
        config = Settings(env=merged, env_files=[])
        runtime_result = validate_config(config, mode=ValidationMode.INSTALL)
        for issue in runtime_result.issues:
            if issue.severity != ValidationSeverity.ERROR.value:
                continue
            if _is_deferred_runtime_issue(issue.code):
                continue
            errors.append(
                {
                    "key": issue.setting,
                    "code": issue.code,
                    "message": issue.summary,
                    "severity": issue.severity,
                }
            )
    except ConfigurationParseError as exc:
        for issue in exc.issues:
            errors.append(
                {
                    "key": issue.setting,
                    "code": issue.code,
                    "message": issue.summary,
                    "severity": issue.severity,
                }
            )
    return _dedupe_errors(errors)


def _is_deferred_runtime_issue(
    code: str,
) -> bool:
    return code in {
        "config.events_db.parent_missing",
        "config.events_db.parent_not_writable",
        "config.log_file.parent_missing",
        "config.log_file.parent_not_writable",
        "config.pihole_db.missing",
        "config.pihole_db.not_readable",
        "config.dashboard.secret_key_missing",
        "config.dashboard.password_hash_missing",
    }


def _edit_payload(
    *,
    operation: str,
    item: ConfigItem,
    target_file: Path,
    changed: bool,
    written: bool,
    dry_run: bool,
    current: dict[str, Any],
    proposed: dict[str, Any] | None,
    effective_after: dict[str, Any],
    affected_services: list[str],
    backup_path: str | None,
    warnings: list[str],
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "operation": operation,
        "key": item.key,
        "env": item.env_var,
        "target_file": str(target_file),
        "changed": changed,
        "written": written,
        "dry_run": dry_run,
        "current": _safe_state(current),
        "proposed": _safe_state(proposed) if proposed is not None else None,
        "effective_after": _safe_state(effective_after),
        "affected_services": affected_services,
        "backup_path": backup_path,
        "warnings": warnings,
        "errors": errors,
    }


def _safe_state(
    row: dict[str, Any],
) -> dict[str, Any]:
    return {
        "value": row.get("value"),
        "source": row.get("source"),
        "masked": row.get("masked", False),
        "configured": row.get("configured", False),
        "valid": row.get("valid", True),
    }


def _print_edit_result(
    result: dict[str, Any],
    *,
    as_json: bool,
) -> None:
    if as_json:
        print(json.dumps(result, sort_keys=True))
        return

    if result.get("errors"):
        print("Configuration change rejected.")
    elif not result["changed"]:
        print("No configuration change is required.")
    else:
        print("Configuration change preview")
    print()
    print("Target file:")
    print(f"  {result['target_file']}")
    print()
    print("Setting:")
    print(f"  {result['key']}")
    print()
    _print_state("Current", result["current"])
    if result["proposed"] is not None:
        _print_state("Proposed", result["proposed"])
    _print_state("Effective after", result["effective_after"])
    if result["affected_services"]:
        print("Restart required:")
        for service in result["affected_services"]:
            print(f"  {service}")
    else:
        print("Restart required:")
        print("  none")
    print()
    for warning in result["warnings"]:
        print(f"warning: {warning}")
    for error in result["errors"]:
        print(f"error: [{error['code']}] {error['key']}: {error['message']}")
    if result["dry_run"]:
        print("Dry run: no file was written.")
    elif result["written"]:
        print("Configuration written.")
        if result["backup_path"]:
            print(f"Backup: {result['backup_path']}")
    elif result.get("declined"):
        print("Change declined; no file was written.")


def _print_import_result(
    result: dict[str, Any],
    *,
    as_json: bool,
) -> None:
    if as_json:
        print(json.dumps(result, sort_keys=True))
        return

    if result.get("errors"):
        print("Configuration import rejected.")
    elif not result["changed"]:
        print("No configuration change is required.")
    else:
        print("Configuration import preview")
    print()
    print("Source file:")
    print(f"  {result['source_file']}")
    print("Target file:")
    print(f"  {result['target_file']}")
    print()
    if result["changed_settings"]:
        print("Settings changing:")
        for change in result["changed_settings"]:
            print(f"- {change['key']}")
            print(f"  current: {_state_label(change['current'])}")
            print(f"  proposed: {_state_label(change['proposed'])}")
    else:
        print("Settings changing:")
        print("  none")
    print()
    if result["affected_services"]:
        print("Restart required:")
        for service in result["affected_services"]:
            print(f"  {service}")
    else:
        print("Restart required:")
        print("  none")
    print()
    for warning in result["warnings"]:
        print(f"warning: {warning}")
    for error in result["errors"]:
        print(f"error: [{error['code']}] {error['key']}: {error['message']}")
    if result["dry_run"]:
        print("Dry run: no file was written.")
    elif result["written"]:
        print("Configuration import written.")
        if result["backup_path"]:
            print(f"Backup: {result['backup_path']}")
    elif result.get("declined"):
        print("Import declined; no file was written.")


def _state_label(
    state: dict[str, Any],
) -> str:
    if state.get("value") is None and state.get("configured"):
        return "configured: ********"
    if state.get("value") is None:
        return "<unset>"
    return str(state["value"])


def _print_state(
    label: str,
    state: dict[str, Any],
) -> None:
    value = state["value"]
    if value is None and state.get("configured"):
        value = "configured: ********"
    elif value is None:
        value = "<unset>"
    print(f"{label}:")
    print(f"  {value}")
    print(f"  source: {state['source']}")
    print()


def _print_edit_error(
    exc: ConfigEditError,
    *,
    as_json: bool,
) -> None:
    if as_json:
        print(
            json.dumps(
                {
                    "error": exc.code,
                    "message": exc.message,
                },
                sort_keys=True,
            )
        )
    else:
        print(exc.message, file=sys.stderr)


def _confirm_change() -> bool:
    if not sys.stdin.isatty():
        print(
            "Confirmation required. Re-run with --yes or --dry-run.",
            file=sys.stderr,
        )
        return False
    answer = input("Apply this change? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


def _serialize_config_value(
    value: Any,
) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _filter_rows(
    rows: list[dict[str, Any]],
    *,
    category: str = "",
    source: str = "",
) -> list[dict[str, Any]]:
    filtered = rows
    if category:
        categories = {row["item"].category.lower() for row in rows}
        wanted = category.lower()
        if wanted not in categories:
            raise ValueError(f"Unknown configuration category: {category}")
        filtered = [
            row
            for row in filtered
            if row["item"].category.lower() == wanted
        ]
    if source:
        wanted = source.lower()
        sources = {row["source"].lower() for row in rows}
        source_kinds = {
            row["source"].split(":", 1)[0].lower()
            for row in rows
        }
        if wanted not in sources and wanted not in source_kinds:
            raise ValueError(f"Unknown configuration source: {source}")
        filtered = [
            row
            for row in filtered
            if row["source"].lower() == wanted
            or row["source"].split(":", 1)[0].lower() == wanted
        ]
    return filtered


def _row_to_json(
    row: dict[str, Any],
) -> dict[str, Any]:
    item: ConfigItem = row["item"]
    rendered = _render_value(item, row["raw_value"])
    return {
        "key": item.key,
        "env": row["env"],
        "value": rendered["value"],
        "configured": rendered["configured"],
        "masked": rendered["masked"],
        "source": row["source"],
        "category": item.category,
        "restart": row["services"],
        "restart_impact": item.restart_impact.value,
        "valid": row["validation"].is_valid,
        "errors": [
            error.to_dict()
            for error in row["validation"].errors
        ],
    }


def _render_value(
    item: ConfigItem,
    raw_value: str,
) -> dict[str, Any]:
    if item.sensitivity in {
        ConfigSensitivity.SENSITIVE,
        ConfigSensitivity.SECRET,
    }:
        return mask_value(item, raw_value)
    rendered = mask_value(item, raw_value)
    if rendered["value"] is not None:
        rendered["value"] = str(rendered["value"])
    return rendered


def _restart_label(
    services: list[str],
) -> str:
    return ",".join(services) if services else "none"


def _dedupe_errors(
    errors: list[dict[str, str]],
) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, str]] = []
    for error in sorted(errors, key=lambda item: (item["key"], item["code"])):
        identity = (error["key"], error["code"])
        if identity in seen:
            continue
        seen.add(identity)
        deduped.append(error)
    return deduped
