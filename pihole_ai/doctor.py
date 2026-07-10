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
        _configuration_diagnostic(),
        _database_diagnostic(),
        _health_diagnostic("events_database", check_events_database),
        _health_diagnostic("pihole_ftl_database", check_pihole_ftl_database),
        _health_diagnostic("disk_space", check_disk_space),
        _health_diagnostic("ollama", check_ollama),
        _runtime_diagnostic(),
        _systemd_diagnostic(),
    ]

    return DoctorReport(
        overall_status=_overall_status(diagnostics),
        diagnostics=diagnostics,
        version=get_version(),
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
    status = installation_status()

    if systemctl is None:
        return Diagnostic(
            name="installation",
            status=HealthStatus.UNKNOWN.value,
            summary="systemctl is not available.",
            details=status.to_dict() | {"systemctl": None},
        )

    if status.state == "installed":
        status = HealthStatus.HEALTHY
        summary = "Expected systemd units are installed."
        remediation = None
    elif status.state in {"partial", "drifted", "legacy"}:
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
        details=installation_status().to_dict() | {"systemctl": systemctl},
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
