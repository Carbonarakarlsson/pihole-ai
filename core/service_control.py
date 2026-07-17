"""
Focused systemd service-control helpers for configuration changes.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import asdict
from dataclasses import dataclass

from core.config_schema import COLLECTOR_SERVICE
from core.config_schema import DASHBOARD_SERVICE
from core.config_schema import ENGINE_SERVICE
from core.config_schema import INTEL_TIMER_SERVICE
from core.config_schema import SERVICE_RESTART_ORDER


ALLOWED_RESTART_SERVICES = set(SERVICE_RESTART_ORDER)


@dataclass(frozen=True)
class ServiceRestartResult:
    service: str
    attempted: bool
    success: bool
    exit_code: int | None = None
    error_code: str = ""
    message: str = ""
    stderr_summary: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def ordered_services(
    service_names: list[str] | tuple[str, ...],
) -> list[str]:
    requested = set(service_names)
    unknown = sorted(requested - ALLOWED_RESTART_SERVICES)
    if unknown:
        raise ValueError(f"Unsupported PiHole-AI service: {unknown[0]}")
    return [
        service
        for service in SERVICE_RESTART_ORDER
        if service in requested
    ]


def restart_services(
    service_names: list[str] | tuple[str, ...],
    *,
    timeout_seconds: float = 30.0,
) -> list[ServiceRestartResult]:
    """
    Restart allowed PiHole-AI services with per-service structured results.
    """

    results: list[ServiceRestartResult] = []
    for service in ordered_services(service_names):
        command = ["systemctl", "restart", service]
        start = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            duration = time.monotonic() - start
            stderr = _safe_summary(completed.stderr)
            if completed.returncode == 0:
                results.append(
                    ServiceRestartResult(
                        service=service,
                        attempted=True,
                        success=True,
                        exit_code=0,
                        duration_seconds=duration,
                    )
                )
            else:
                error_code, message = _classify_failure(stderr, completed.stdout)
                results.append(
                    ServiceRestartResult(
                        service=service,
                        attempted=True,
                        success=False,
                        exit_code=completed.returncode,
                        error_code=error_code,
                        message=message,
                        stderr_summary=stderr,
                        duration_seconds=duration,
                    )
                )
        except FileNotFoundError:
            results.append(
                ServiceRestartResult(
                    service=service,
                    attempted=True,
                    success=False,
                    error_code="systemctl_unavailable",
                    message="systemctl is not available.",
                    duration_seconds=time.monotonic() - start,
                )
            )
        except subprocess.TimeoutExpired:
            results.append(
                ServiceRestartResult(
                    service=service,
                    attempted=True,
                    success=False,
                    error_code="timeout",
                    message="Service restart timed out.",
                    duration_seconds=timeout_seconds,
                )
            )
        except OSError as exc:
            results.append(
                ServiceRestartResult(
                    service=service,
                    attempted=True,
                    success=False,
                    error_code=exc.__class__.__name__,
                    message="Service restart could not be executed.",
                    duration_seconds=time.monotonic() - start,
                )
            )
    return results


def _classify_failure(
    stderr: str,
    stdout: str,
) -> tuple[str, str]:
    text = f"{stderr}\n{stdout}".lower()
    if "access denied" in text or "authentication" in text or "not authorized" in text or "permission" in text:
        return "authorization_required", "Restart authorization was denied."
    if "not found" in text or "could not be found" in text:
        return "service_not_found", "Service unit was not found."
    if "system has not been booted with systemd" in text or "failed to connect to bus" in text:
        return "systemd_unavailable", "systemd is not running or cannot be reached."
    return "systemctl_failed", "Service restart failed."


def _safe_summary(
    value: str,
) -> str:
    return " ".join(value.strip().split())[:240]
