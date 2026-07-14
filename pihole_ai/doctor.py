"""
Read-only PiHole-AI appliance diagnostics.
"""

from __future__ import annotations

import json
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from core.config import (
    ValidationMode,
    ValidationSeverity,
    load_config_with_result,
)
from core.migrations import (
    MigrationError,
    UnsupportedSchemaVersion,
    database_status,
)
from pihole_ai.health import (
    HealthStatus,
    check_disk_space,
    check_events_database,
    check_ollama,
    check_pihole_ftl_database,
    exit_code_for_status,
)
from pihole_ai.service import installation_status
from pihole_ai.version import get_version


@dataclass(frozen=True)
class Diagnostic:
    name: str
    status: str
    summary: str
    details: dict[str, Any]
    remediation: str | None = None


@dataclass(frozen=True)
class DoctorReport:
    overall_status: str
    diagnostics: list[Diagnostic]
    version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_doctor() -> DoctorReport:
    """
    Run read-only appliance diagnostics.
    """

    diagnostics = [
        _safe_diagnostic("configuration", _configuration_diagnostic),
        _safe_diagnostic("dashboard_auth", _dashboard_auth_diagnostic),
        _safe_diagnostic("dashboard_exposure", _dashboard_exposure_diagnostic),
        _safe_diagnostic("database_schema", _database_diagnostic),
        _safe_diagnostic(
            "events_database",
            lambda: _health_diagnostic("events_database", check_events_database),
        ),
        _safe_diagnostic(
            "pihole_ftl_database",
            lambda: _health_diagnostic("pihole_ftl_database", check_pihole_ftl_database),
        ),
        _safe_diagnostic(
            "disk_space",
            lambda: _health_diagnostic("disk_space", check_disk_space),
        ),
        _safe_diagnostic("ollama", lambda: _health_diagnostic("ollama", check_ollama)),
        _safe_diagnostic("runtime", _runtime_diagnostic),
        _safe_diagnostic("installation", _systemd_diagnostic),
    ]

    return DoctorReport(
        overall_status=_overall_status(diagnostics),
        diagnostics=diagnostics,
        version=get_version(),
    )


def _safe_diagnostic(
    name: str,
    diagnostic: Any,
) -> Diagnostic:
    try:
        return diagnostic()
    except Exception as exc:
        return Diagnostic(
            name=name,
            status=HealthStatus.UNKNOWN.value,
            summary="Diagnostic could not be completed.",
            details={"error": exc.__class__.__name__},
            remediation="Run: sudo pihole-ai doctor",
        )


def print_doctor(
    as_json: bool = False,
) -> int:
    """
    Print doctor report.
    """

    try:
        report = run_doctor()

    except Exception as exc:
        if as_json:
            print(
                json.dumps(
                    {
                        "overall_status": HealthStatus.UNKNOWN.value,
                        "diagnostics": [],
                        "version": get_version(),
                        "error": exc.__class__.__name__,
                    },
                    sort_keys=True,
                )
            )
        else:
            print(f"PiHole-AI doctor: unknown ({exc.__class__.__name__})")

        return 3

    if as_json:
        print(
            json.dumps(
                report.to_dict(),
                sort_keys=True,
            )
        )
    else:
        print(f"PiHole-AI doctor: {report.overall_status}")
        print(f"version: {report.version}")

        for diagnostic in report.diagnostics:
            print(
                f"- {diagnostic.name}: {diagnostic.status} - "
                f"{diagnostic.summary}"
            )

            if diagnostic.remediation:
                print(f"  fix: {diagnostic.remediation}")

    return exit_code_for_status(report.overall_status)


def _configuration_diagnostic() -> Diagnostic:
    config, result = load_config_with_result(
        mode=ValidationMode.RUNTIME,
    )
    status = HealthStatus.HEALTHY
    remediation = None

    if config is None or result.error_count:
        status = HealthStatus.UNHEALTHY
        remediation = "Run: pihole-ai config check"
    elif result.warning_count:
        status = HealthStatus.DEGRADED
        remediation = "Review warnings from: pihole-ai config check"

    return Diagnostic(
        name="configuration",
        status=status.value,
        summary=(
            "Configuration has errors."
            if status == HealthStatus.UNHEALTHY
            else "Configuration has warnings."
            if status == HealthStatus.DEGRADED
            else "Configuration is valid."
        ),
        details=result.to_dict(),
        remediation=remediation,
    )


def _database_diagnostic() -> Diagnostic:
    config, result = load_config_with_result(
        mode=ValidationMode.SYNTAX,
    )

    if config is None:
        return Diagnostic(
            name="database_schema",
            status=HealthStatus.UNKNOWN.value,
            summary="Database schema could not be checked because configuration did not parse.",
            details=result.to_dict(),
            remediation="Run: pihole-ai config check",
        )

    try:
        status = database_status(config.events_db)

    except UnsupportedSchemaVersion as exc:
        return Diagnostic(
            name="database_schema",
            status=HealthStatus.UNHEALTHY.value,
            summary="Events database schema is newer than this PiHole-AI version.",
            details={"error": exc.__class__.__name__},
            remediation="Upgrade PiHole-AI before using this database.",
        )

    except MigrationError as exc:
        return Diagnostic(
            name="database_schema",
            status=HealthStatus.UNHEALTHY.value,
            summary="Events database schema is incompatible.",
            details={"error": exc.__class__.__name__},
            remediation="Run: pihole-ai db status",
        )

    doctor_status = (
        HealthStatus.DEGRADED
        if status.pending_migration_count
        else HealthStatus.HEALTHY
    )

    return Diagnostic(
        name="database_schema",
        status=doctor_status.value,
        summary=(
            "Events database has pending migrations."
            if status.pending_migration_count
            else "Events database schema is current."
        ),
        details=asdict(status),
        remediation=(
            "Run: pihole-ai db migrate"
            if status.pending_migration_count
            else None
        ),
    )


def _dashboard_auth_diagnostic() -> Diagnostic:
    config, result = load_config_with_result(
        mode=ValidationMode.RUNTIME,
    )
    if config is None:
        return Diagnostic(
            name="dashboard_auth",
            status=HealthStatus.UNHEALTHY.value,
            summary="Dashboard authentication configuration could not be parsed.",
            details={"configured": False},
            remediation="Run: pihole-ai config check",
        )

    dashboard_issues = [
        issue
        for issue in result.issues
        if issue.code.startswith("config.dashboard.")
        and issue.code not in {
            "config.dashboard.non_loopback_bind",
            "config.dashboard.proxy_trust_unsafe",
        }
    ]
    status = HealthStatus.HEALTHY.value
    remediation = None
    if any(issue.severity == ValidationSeverity.ERROR.value for issue in dashboard_issues):
        status = HealthStatus.UNHEALTHY.value
        remediation = "Run: pihole-ai dashboard auth set-password"
    elif dashboard_issues:
        status = HealthStatus.DEGRADED.value
        remediation = "Review: pihole-ai config check"

    return Diagnostic(
        name="dashboard_auth",
        status=status,
        summary=(
            "Dashboard authentication needs attention."
            if status != HealthStatus.HEALTHY.value
            else "Dashboard authentication is configured."
        ),
        details={
            "enabled": config.dashboard_auth_enabled,
            "username": config.dashboard_username,
            "credentials_configured": bool(config.dashboard_password_hash.strip()),
            "secret_key_configured": bool(config.dashboard_secret_key.strip()),
            "dashboard_bind_exposed": config.dashboard_host
            not in {"127.0.0.1", "::1", "localhost"},
            "trust_proxy": config.dashboard_trust_proxy,
            "issues": [
                {
                    "code": issue.code,
                    "severity": issue.severity,
                    "summary": issue.summary,
                }
                for issue in dashboard_issues
            ],
        },
        remediation=remediation,
    )


def _dashboard_exposure_diagnostic() -> Diagnostic:
    config, result = load_config_with_result(
        mode=ValidationMode.RUNTIME,
    )
    if config is None:
        return Diagnostic(
            name="dashboard_exposure",
            status=HealthStatus.UNKNOWN.value,
            summary="Dashboard exposure could not be checked.",
            details={"configured": False},
            remediation="Run: pihole-ai config check",
        )

    exposure_issues = [
        issue
        for issue in result.issues
        if issue.code
        in {
            "config.dashboard.non_loopback_bind",
            "config.dashboard.proxy_trust_unsafe",
        }
    ]
    exposed = config.dashboard_host not in {"127.0.0.1", "::1", "localhost"}
    status = HealthStatus.DEGRADED.value if exposure_issues else HealthStatus.HEALTHY.value

    return Diagnostic(
        name="dashboard_exposure",
        status=status,
        summary=(
            "Dashboard is reachable outside loopback."
            if exposed
            else "Dashboard is loopback-only."
        ),
        details={
            "host": config.dashboard_host,
            "auth_enabled": config.dashboard_auth_enabled,
            "exposed": exposed,
            "issues": [
                {
                    "code": issue.code,
                    "severity": issue.severity,
                    "summary": issue.summary,
                }
                for issue in exposure_issues
            ],
        },
        remediation=(
            "Ensure authentication is enabled and firewall/network access is restricted."
            if exposure_issues
            else None
        ),
    )


def _health_diagnostic(
    name: str,
    check: Any,
) -> Diagnostic:
    result = check()

    return Diagnostic(
        name=name,
        status=result.status,
        summary=result.summary,
        details=result.details,
        remediation=_health_remediation(name, result.status),
    )


def _runtime_diagnostic() -> Diagnostic:
    return Diagnostic(
        name="runtime",
        status=HealthStatus.HEALTHY.value,
        summary="Runtime metadata collected.",
        details={
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "executable": sys.executable,
        },
    )


def _systemd_diagnostic() -> Diagnostic:
    systemctl = shutil.which("systemctl")
    install_status = installation_status()

    if systemctl is None:
        return Diagnostic(
            name="installation",
            status=HealthStatus.UNKNOWN.value,
            summary="systemctl is not available.",
            details=install_status.to_dict() | {"systemctl": None},
        )

    if install_status.state == "installed":
        status = HealthStatus.HEALTHY
        summary = "Expected systemd units are installed."
        remediation = None
    elif install_status.state in {"partial", "drifted", "legacy"}:
        status = HealthStatus.DEGRADED
        summary = "PiHole-AI installation needs attention."
        remediation = "Run: sudo pihole-ai install"
    else:
        status = HealthStatus.DEGRADED
        summary = "PiHole-AI systemd units are not installed."
        remediation = "Run: sudo pihole-ai install"

    return Diagnostic(
        name="installation",
        status=status.value,
        summary=summary,
        details=install_status.to_dict() | {"systemctl": systemctl},
        remediation=remediation,
    )


def _health_remediation(
    name: str,
    status: str,
) -> str | None:
    if status == HealthStatus.HEALTHY.value:
        return None

    return {
        "events_database": "Run: pihole-ai db status",
        "pihole_ftl_database": "Check PIHOLE_AI_PIHOLE_DB and file permissions.",
        "disk_space": "Free disk space or move PiHole-AI runtime paths.",
        "ollama": "Start Ollama or disable AI with AI_ENABLED=false.",
    }.get(name)


def _overall_status(
    diagnostics: list[Diagnostic],
) -> str:
    if any(
        diagnostic.status == HealthStatus.UNHEALTHY.value
        for diagnostic in diagnostics
    ):
        return HealthStatus.UNHEALTHY.value

    if any(
        diagnostic.status in {HealthStatus.DEGRADED.value, HealthStatus.UNKNOWN.value}
        for diagnostic in diagnostics
    ):
        return HealthStatus.DEGRADED.value

    return HealthStatus.HEALTHY.value
