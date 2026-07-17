"""
CLI helpers for configuration inspection and validation.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import Any

from core.config import (
    ConfigurationParseError,
    ProtectedConfigurationAccessError,
    ValidationMode,
    ValidationSeverity,
    load_config,
    load_config_with_result,
)
from core.config_manager import ConfigurationManager
from core.config_manager import changed_key_impact
from core.config_manager import mask_value
from core.config_schema import CONFIG_SCHEMA
from core.config_schema import SCHEMA_VERSION
from core.config_schema import ConfigItem
from core.config_schema import ConfigSensitivity
from core.config_schema import affected_services
from core.config_schema import get_item


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
