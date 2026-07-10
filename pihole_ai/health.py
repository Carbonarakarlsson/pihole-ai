"""
Unified health checks for PiHole-AI.
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from core.config import settings
from core.logger import get_logger


logger = get_logger(__name__)

VERSION = "0.4"
DISK_DEGRADED_BYTES = 1 * 1024 * 1024 * 1024
DISK_UNHEALTHY_BYTES = 250 * 1024 * 1024


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class HealthCheck:
    name: str
    status: str
    summary: str
    details: dict[str, Any]
    latency_ms: float | None
    checked_at: float


@dataclass(frozen=True)
class HealthReport:
    overall_status: str
    checks: list[HealthCheck]
    version: str
    checked_at: float


REQUIRED_CHECKS = {
    "configuration",
    "events_database",
    "pihole_ftl_database",
    "disk_space",
}


def run_health_checks() -> HealthReport:
    """
    Run every health check with failure isolation.
    """

    checked_at = time.time()
    checks = [
        _safe_check("configuration", check_configuration),
        _safe_check("events_database", check_events_database),
        _safe_check("pihole_ftl_database", check_pihole_ftl_database),
        _safe_check("ollama", check_ollama),
        _safe_check("collector_progress", check_collector_progress),
        _safe_check("disk_space", check_disk_space),
    ]

    return HealthReport(
        overall_status=overall_status(checks),
        checks=checks,
        version=VERSION,
        checked_at=checked_at,
    )


def _safe_check(
    name: str,
    check: Callable[[], HealthCheck],
) -> HealthCheck:
    try:
        return check()

    except Exception as exc:
        logger.warning(
            "Health check failed: %s: %s",
            name,
            exc,
        )
        return _check(
            name=name,
            status=(
                HealthStatus.UNHEALTHY
                if name in REQUIRED_CHECKS
                else HealthStatus.UNKNOWN
            ),
            summary="Health check failed.",
            details={"error": _safe_error(exc)},
            started_at=None,
        )


def _check(
    name: str,
    status: HealthStatus,
    summary: str,
    details: dict[str, Any] | None = None,
    started_at: float | None = None,
) -> HealthCheck:
    latency_ms = None

    if started_at is not None:
        latency_ms = round((time.perf_counter() - started_at) * 1000, 2)

    return HealthCheck(
        name=name,
        status=status.value,
        summary=summary,
        details=details or {},
        latency_ms=latency_ms,
        checked_at=time.time(),
    )


def _safe_error(exc: Exception) -> str:
    return exc.__class__.__name__


def _safe_url(value: str) -> str:
    parts = urlsplit(value)

    if "@" not in parts.netloc:
        return value

    host = parts.hostname or ""

    if parts.port is not None:
        host = f"{host}:{parts.port}"

    return urlunsplit(
        (
            parts.scheme,
            host,
            parts.path,
            parts.query,
            parts.fragment,
        )
    )


def check_configuration() -> HealthCheck:
    started_at = time.perf_counter()

    try:
        settings.validate()

    except Exception as exc:
        logger.warning("Configuration health check failed: %s", exc)
        return _check(
            name="configuration",
            status=HealthStatus.UNHEALTHY,
            summary="Configuration is invalid.",
            details={"error": _safe_error(exc)},
            started_at=started_at,
        )

    return _check(
        name="configuration",
        status=HealthStatus.HEALTHY,
        summary="Configuration loaded.",
        details={
            "events_db": str(settings.events_db),
            "pihole_db": str(settings.pihole_db),
            "ollama_host": _safe_url(settings.ollama_url),
            "ollama_model": settings.ollama_model,
        },
        started_at=started_at,
    )


def check_events_database() -> HealthCheck:
    started_at = time.perf_counter()

    try:
        from core import db

        with db.get_connection() as conn:
            conn.execute("SELECT 1").fetchone()
            schema_version = conn.execute("PRAGMA user_version").fetchone()[0]

    except Exception as exc:
        logger.warning("Events database health check failed: %s", exc)
        return _check(
            name="events_database",
            status=HealthStatus.UNHEALTHY,
            summary="Events database is unavailable.",
            details={
                "path": str(settings.events_db),
                "error": _safe_error(exc),
            },
            started_at=started_at,
        )

    return _check(
        name="events_database",
        status=HealthStatus.HEALTHY,
        summary="Events database opened.",
        details={
            "path": str(settings.events_db),
            "schema_version": schema_version,
        },
        started_at=started_at,
    )


def check_pihole_ftl_database() -> HealthCheck:
    started_at = time.perf_counter()
    path = Path(settings.pihole_db)

    if not path.exists():
        return _check(
            name="pihole_ftl_database",
            status=HealthStatus.UNHEALTHY,
            summary="Pi-hole FTL database is missing.",
            details={"path": str(path)},
            started_at=started_at,
        )

    try:
        with path.open("rb"):
            pass

    except OSError as exc:
        logger.warning("Pi-hole FTL database is not readable: %s", exc)
        return _check(
            name="pihole_ftl_database",
            status=HealthStatus.UNHEALTHY,
            summary="Pi-hole FTL database is not readable.",
            details={"path": str(path), "error": _safe_error(exc)},
            started_at=started_at,
        )

    return _check(
        name="pihole_ftl_database",
        status=HealthStatus.HEALTHY,
        summary="Pi-hole FTL database is readable.",
        details={"path": str(path)},
        started_at=started_at,
    )


def check_ollama() -> HealthCheck:
    started_at = time.perf_counter()

    try:
        from engine.ollama_client import OllamaClient

        result = OllamaClient().health()

    except Exception as exc:
        logger.warning("Ollama health check failed: %s", exc)
        return _check(
            name="ollama",
            status=HealthStatus.DEGRADED,
            summary="Ollama is unavailable.",
            details={
                "host": _safe_url(settings.ollama_url),
                "model": settings.ollama_model,
                "error": _safe_error(exc),
            },
            started_at=started_at,
        )

    status = (
        HealthStatus.HEALTHY
        if bool(result.get("available"))
        else HealthStatus.DEGRADED
    )

    return _check(
        name="ollama",
        status=status,
        summary=(
            "Ollama is available."
            if status == HealthStatus.HEALTHY
            else "Ollama is unavailable."
        ),
        details={
            "host": _safe_url(str(result.get("host", settings.ollama_url))),
            "model": result.get("model", settings.ollama_model),
        },
        started_at=started_at,
    )


def check_collector_progress() -> HealthCheck:
    started_at = time.perf_counter()

    try:
        from core.db import get_state

        last_query_id = get_state("collector.last_query_id")

    except Exception as exc:
        logger.warning("Collector progress health check failed: %s", exc)
        return _check(
            name="collector_progress",
            status=HealthStatus.UNKNOWN,
            summary="Collector progress is unknown.",
            details={"error": _safe_error(exc)},
            started_at=started_at,
        )

    if last_query_id is None:
        return _check(
            name="collector_progress",
            status=HealthStatus.DEGRADED,
            summary="Collector has not recorded progress yet.",
            details={"last_query_id": None},
            started_at=started_at,
        )

    return _check(
        name="collector_progress",
        status=HealthStatus.HEALTHY,
        summary="Collector progress is recorded.",
        details={"last_query_id": last_query_id},
        started_at=started_at,
    )


def check_disk_space() -> HealthCheck:
    started_at = time.perf_counter()
    path = Path(settings.events_db).parent

    try:
        usage = shutil.disk_usage(path)

    except OSError as exc:
        logger.warning("Disk space health check failed: %s", exc)
        return _check(
            name="disk_space",
            status=HealthStatus.UNHEALTHY,
            summary="Disk space could not be checked.",
            details={"path": str(path), "error": _safe_error(exc)},
            started_at=started_at,
        )

    free = int(usage.free)

    if free < DISK_UNHEALTHY_BYTES:
        status = HealthStatus.UNHEALTHY
        summary = "Disk space is critically low."
    elif free < DISK_DEGRADED_BYTES:
        status = HealthStatus.DEGRADED
        summary = "Disk space is low."
    else:
        status = HealthStatus.HEALTHY
        summary = "Disk space is sufficient."

    return _check(
        name="disk_space",
        status=status,
        summary=summary,
        details={
            "path": str(path),
            "free_bytes": free,
            "degraded_threshold_bytes": DISK_DEGRADED_BYTES,
            "unhealthy_threshold_bytes": DISK_UNHEALTHY_BYTES,
        },
        started_at=started_at,
    )


def overall_status(
    checks: list[HealthCheck],
) -> str:
    if not checks:
        return HealthStatus.UNKNOWN.value

    required = [
        check
        for check in checks
        if check.name in REQUIRED_CHECKS
    ]

    if any(check.status == HealthStatus.UNHEALTHY.value for check in required):
        return HealthStatus.UNHEALTHY.value

    if any(check.status == HealthStatus.DEGRADED.value for check in checks):
        return HealthStatus.DEGRADED.value

    if all(check.status == HealthStatus.HEALTHY.value for check in checks):
        return HealthStatus.HEALTHY.value

    if any(check.status == HealthStatus.UNHEALTHY.value for check in checks):
        return HealthStatus.DEGRADED.value

    if any(check.status == HealthStatus.UNKNOWN.value for check in checks):
        return HealthStatus.DEGRADED.value

    return HealthStatus.UNKNOWN.value


def report_to_dict(
    report: HealthReport,
) -> dict[str, Any]:
    return asdict(report)


def report_to_json(
    report: HealthReport,
) -> str:
    return json.dumps(
        report_to_dict(report),
        sort_keys=True,
    )


def print_report(
    report: HealthReport,
) -> None:
    print(f"PiHole-AI health: {report.overall_status}")
    print(f"version: {report.version}")

    for check in report.checks:
        latency = (
            "-"
            if check.latency_ms is None
            else f"{check.latency_ms}ms"
        )
        print(
            f"- {check.name}: {check.status} ({latency}) - {check.summary}"
        )


def exit_code_for_status(
    status: str,
) -> int:
    return {
        HealthStatus.HEALTHY.value: 0,
        HealthStatus.DEGRADED.value: 1,
        HealthStatus.UNHEALTHY.value: 2,
        HealthStatus.UNKNOWN.value: 3,
    }.get(status, 3)


def http_status_for_report(
    report: HealthReport,
) -> int:
    if report.overall_status == HealthStatus.UNHEALTHY.value:
        return 503

    if report.overall_status == HealthStatus.UNKNOWN.value:
        return 500

    return 200
