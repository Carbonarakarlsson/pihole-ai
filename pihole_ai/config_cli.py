"""
CLI helpers for configuration inspection and validation.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from core.config import (
    ConfigurationParseError,
    ValidationMode,
    ValidationSeverity,
    load_config,
    load_config_with_result,
)


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
) -> int:
    """
    Print safe effective configuration.
    """

    try:
        config = load_config(
            validate=False,
        )

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

        return 3

    payload = config.to_safe_dict()

    if as_json:
        print(
            json.dumps(
                payload,
                sort_keys=True,
            )
        )
    else:
        print("PiHole-AI effective configuration")
        _print_dict(payload)

    return 0


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
