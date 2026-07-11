"""
First-run setup state and onboarding helpers.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from core.config import (
    CONFIG_FILE,
    PROJECT_ROOT,
    RUNTIME_EVENTS_DB,
    ConfigurationValidationResult,
    ValidationMode,
    ValidationSeverity,
    load_config,
    load_config_with_result,
    redact_url,
)
from core.migrations import (
    MigrationError,
    UnsupportedSchemaVersion,
    database_status,
)
from pihole_ai.health import (
    HealthReport,
    HealthStatus,
    report_to_dict,
    run_health_checks,
)
from pihole_ai.service import (
    DEFAULT_SERVICE_GROUP,
    DEFAULT_SERVICE_USER,
    SERVICE_NAMES,
    InstallationStatus,
    installation_status,
    service_action,
    service_enable,
    service_install,
)
from pihole_ai.version import get_version


class SetupStage(str, Enum):
    NOT_INSTALLED = "not_installed"
    INSTALLED_UNCONFIGURED = "installed_unconfigured"
    CONFIGURED = "configured"
    SERVICES_INACTIVE = "services_inactive"
    DEGRADED = "degraded"
    READY = "ready"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class SetupAction:
    id: str
    label: str
    requires_sudo: bool = False


@dataclass(frozen=True)
class SetupStep:
    id: str
    title: str
    status: str
    required: bool
    summary: str
    remediation: str | None = None
    action: SetupAction | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SetupReport:
    overall_stage: str
    ready: bool
    steps: list[SetupStep]
    application_version: str
    generated_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PiholeDatabaseCandidate:
    path: str
    exists: bool
    readable: bool
    regular_file: bool
    service_user_accessible: bool

    @property
    def valid(self) -> bool:
        return (
            self.exists
            and self.readable
            and self.regular_file
            and self.service_user_accessible
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SUPPORTED_CONFIG_KEYS = {
    "AI_ENABLED",
    "AI_MAX_CALLS_PER_MINUTE",
    "AI_COOLDOWN_SECONDS",
    "AI_TIMEOUT_SECONDS",
    "PIHOLE_AI_OLLAMA_URL",
    "PIHOLE_AI_OLLAMA_MODEL",
    "PIHOLE_AI_DASHBOARD_HOST",
    "PIHOLE_AI_DASHBOARD_PORT",
    "PIHOLE_AI_DASHBOARD_AUTH_ENABLED",
    "PIHOLE_AI_DASHBOARD_USERNAME",
    "PIHOLE_AI_DASHBOARD_PASSWORD_HASH",
    "PIHOLE_AI_DASHBOARD_SECRET_KEY",
    "PIHOLE_AI_DASHBOARD_SESSION_LIFETIME_MINUTES",
    "PIHOLE_AI_DASHBOARD_TRUST_PROXY",
    "PIHOLE_AI_PIHOLE_DB",
    "EVENTS_DB_PATH",
    "LOG_PATH",
    "DEV_ACCESS_LOGS",
}

COMMON_PIHOLE_DB_PATHS = [
    Path("/etc/pihole/pihole-FTL.db"),
]


def evaluate_setup(
    *,
    skip_ollama_check: bool = False,
) -> SetupReport:
    """
    Translate existing subsystem results into a guided setup report.
    """

    generated_at = time.time()
    config, config_result = load_config_with_result(mode=ValidationMode.RUNTIME)
    install = installation_status()
    health = _health_report(skip_ollama_check=skip_ollama_check)
    candidates = detect_pihole_databases()
    steps = [
        _install_step(install),
        _configuration_step(config_result),
        _pihole_database_step(candidates),
        _events_database_step(health),
        _database_schema_step(config),
        _service_identity_step(install),
        _services_step(install),
        _ollama_step(config, health, skip_ollama_check=skip_ollama_check),
        _dashboard_step(install),
        _final_health_step(health),
    ]
    stage = _stage_for_steps(steps, install, config_result)

    return SetupReport(
        overall_stage=stage.value,
        ready=stage == SetupStage.READY,
        steps=steps,
        application_version=get_version(),
        generated_at=generated_at,
    )


def setup_exit_code(report: SetupReport) -> int:
    if report.overall_stage == SetupStage.READY.value:
        return 0
    if report.overall_stage == SetupStage.BLOCKED.value:
        return 2
    return 1


def print_setup_status(
    *,
    as_json: bool = False,
    skip_ollama_check: bool = False,
) -> int:
    try:
        report = evaluate_setup(skip_ollama_check=skip_ollama_check)
    except Exception as exc:
        if as_json:
            print(
                json.dumps(
                    {
                        "overall_stage": SetupStage.BLOCKED.value,
                        "ready": False,
                        "steps": [],
                        "application_version": get_version(),
                        "generated_at": time.time(),
                        "error": exc.__class__.__name__,
                    },
                    sort_keys=True,
                )
            )
        else:
            print(f"PiHole-AI setup status could not be determined: {exc.__class__.__name__}")
        return 3

    if as_json:
        print(json.dumps(report.to_dict(), sort_keys=True))
    else:
        print_setup_report(report)

    return setup_exit_code(report)


def print_setup_report(report: SetupReport) -> None:
    print(f"PiHole-AI setup: {report.overall_stage}")
    print(f"ready: {str(report.ready).lower()}")
    for step in report.steps:
        marker = {
            "complete": "[ok]",
            "pending": "[..]",
            "warning": "[!!]",
            "blocked": "[xx]",
            "skipped": "[--]",
        }.get(step.status, "[??]")
        required = "required" if step.required else "optional"
        print(f"{marker} {step.id}: {step.title} ({required})")
        print(f"    {step.summary}")
        if step.remediation:
            print(f"    fix: {step.remediation}")


def run_setup(
    *,
    non_interactive: bool = False,
    dry_run: bool = False,
    as_json: bool = False,
    install: bool = False,
    start: bool = False,
    enable: bool = False,
    skip_ollama_check: bool = False,
) -> int:
    """
    Guided setup orchestration. Mutations are only delegated to existing subsystems.
    """

    if non_interactive:
        return _run_non_interactive_setup(
            dry_run=dry_run,
            as_json=as_json,
            install=install,
            start=start,
            enable=enable,
            skip_ollama_check=skip_ollama_check,
        )

    return _run_interactive_setup(
        dry_run=dry_run,
        as_json=as_json,
        install=install,
        start=start,
        enable=enable,
        skip_ollama_check=skip_ollama_check,
    )


def detect_pihole_databases(
    configured_path: str | Path | None = None,
    *,
    common_paths: list[Path] | None = None,
    service_user: str = DEFAULT_SERVICE_USER,
    service_group: str = DEFAULT_SERVICE_GROUP,
) -> list[PiholeDatabaseCandidate]:
    """
    Read-only detection of likely Pi-hole FTL database paths.
    """

    paths: list[Path] = []

    if configured_path is not None:
        paths.append(Path(configured_path))
    else:
        config, _result = load_config_with_result(mode=ValidationMode.SYNTAX)
        if config is not None:
            paths.append(config.pihole_db)

    paths.extend(common_paths or COMMON_PIHOLE_DB_PATHS)

    seen: set[str] = set()
    candidates: list[PiholeDatabaseCandidate] = []
    for path in paths:
        normalized = str(Path(path).expanduser())
        if normalized in seen:
            continue
        seen.add(normalized)
        candidates.append(
            inspect_pihole_database_candidate(
                path,
                service_user=service_user,
                service_group=service_group,
            )
        )

    return candidates


def inspect_pihole_database_candidate(
    path: str | Path,
    *,
    service_user: str = DEFAULT_SERVICE_USER,
    service_group: str = DEFAULT_SERVICE_GROUP,
) -> PiholeDatabaseCandidate:
    candidate = Path(path)
    try:
        exists = candidate.exists()
        regular = candidate.is_file() if exists else False
        readable = os.access(candidate, os.R_OK) if exists else False
    except OSError:
        exists = False
        regular = False
        readable = False
    service_access = False

    if exists:
        try:
            file_stat = candidate.stat()
            parent_stat = candidate.parent.stat()
            service_access = _service_user_can_read(
                file_stat=file_stat,
                parent_stat=parent_stat,
                service_user=service_user,
                service_group=service_group,
            )
        except OSError:
            service_access = False

    return PiholeDatabaseCandidate(
        path=str(candidate),
        exists=exists,
        readable=readable,
        regular_file=regular,
        service_user_accessible=service_access,
    )


def update_setup_config(
    updates: dict[str, Any],
    *,
    path: str | Path | None = None,
) -> Path:
    """
    Safely update a narrow allowlist of setup-supported env settings.
    """

    env_path = _target_config_path(path)
    normalized = _normalize_config_updates(updates)
    existing_mode = 0o640
    existing_uid = None
    existing_gid = None

    if env_path.exists():
        current_stat = env_path.stat()
        existing_mode = stat.S_IMODE(current_stat.st_mode)
        existing_uid = current_stat.st_uid
        existing_gid = current_stat.st_gid

    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    proposed_lines = _update_env_lines(lines, normalized)
    proposed = "\n".join(proposed_lines).rstrip() + "\n"

    _validate_proposed_config(env_path, proposed)

    env_path.parent.mkdir(parents=True, exist_ok=True)
    if env_path.exists():
        _atomic_replace(
            env_path.with_suffix(env_path.suffix + ".bak"),
            env_path.read_text(encoding="utf-8"),
            mode=existing_mode,
            uid=existing_uid,
            gid=existing_gid,
        )
    _atomic_replace(
        env_path,
        proposed,
        mode=existing_mode,
        uid=existing_uid,
        gid=existing_gid,
    )
    return env_path


def _run_non_interactive_setup(
    *,
    dry_run: bool,
    as_json: bool,
    install: bool,
    start: bool,
    enable: bool,
    skip_ollama_check: bool,
) -> int:
    report = evaluate_setup(skip_ollama_check=skip_ollama_check)
    if as_json:
        print(json.dumps(report.to_dict(), sort_keys=True))
    else:
        print_setup_report(report)

    if _blocking_steps(report):
        return setup_exit_code(report)

    if dry_run:
        _print_plan(install=install, start=start, enable=enable, dry_run=True)
        return setup_exit_code(report)

    if install:
        service_install()
    if enable:
        service_enable()
    if start:
        service_action("start")

    return setup_exit_code(evaluate_setup(skip_ollama_check=skip_ollama_check))


def _run_interactive_setup(
    *,
    dry_run: bool,
    as_json: bool,
    install: bool,
    start: bool,
    enable: bool,
    skip_ollama_check: bool,
) -> int:
    report = evaluate_setup(skip_ollama_check=skip_ollama_check)
    if as_json:
        print(json.dumps(report.to_dict(), sort_keys=True))
    else:
        print_setup_report(report)

    if _blocking_steps(report):
        return setup_exit_code(report)

    _print_pihole_candidates()
    _offer_deterministic_mode(dry_run=dry_run)

    if not install:
        install = _confirm("Install or upgrade appliance services now?", default=False)
    if not enable:
        enable = _confirm("Enable services at boot?", default=False)
    if not start:
        start = _confirm("Start services now?", default=False)

    if dry_run:
        _print_plan(install=install, start=start, enable=enable, dry_run=True)
        return setup_exit_code(report)

    if install:
        service_install()
    if enable:
        service_enable()
    if start:
        service_action("start")

    final_report = evaluate_setup(skip_ollama_check=skip_ollama_check)
    if not as_json:
        print("")
        print("Final verification")
        print_setup_report(final_report)
    return setup_exit_code(final_report)


def _blocking_steps(report: SetupReport) -> list[SetupStep]:
    return [
        step
        for step in report.steps
        if step.required and step.status == "blocked"
    ]


def _print_plan(
    *,
    install: bool,
    start: bool,
    enable: bool,
    dry_run: bool,
) -> None:
    print("Setup plan")
    print(f"  dry_run: {str(dry_run).lower()}")
    print(f"  install_services: {str(install).lower()}")
    print(f"  enable_at_boot: {str(enable).lower()}")
    print(f"  start_now: {str(start).lower()}")


def _print_pihole_candidates() -> None:
    candidates = detect_pihole_databases()
    valid = [candidate for candidate in candidates if candidate.valid]
    if len(valid) == 1:
        print(f"Pi-hole database candidate: {valid[0].path}")
    elif len(valid) > 1:
        print("Multiple readable Pi-hole database candidates found.")
        for candidate in valid:
            print(f"  {candidate.path}")
    else:
        print("No readable Pi-hole database candidate was found.")


def _offer_deterministic_mode(*, dry_run: bool) -> None:
    config, _result = load_config_with_result(mode=ValidationMode.SYNTAX)
    if config is None or not config.ai_enabled:
        print("AI is disabled; deterministic classifiers will still run.")
        return

    if _confirm("Keep Ollama AI enabled?", default=True):
        return

    if dry_run:
        print("Would set AI_ENABLED=false.")
        return

    update_setup_config({"AI_ENABLED": "false"})
    print("Saved deterministic-only mode. Restart required.")


def _confirm(prompt: str, *, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{prompt} [{suffix}] ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def _health_report(*, skip_ollama_check: bool) -> HealthReport | None:
    try:
        report = run_health_checks()
    except Exception:
        return None

    if not skip_ollama_check:
        return report

    checks = [
        check
        for check in report.checks
        if check.name != "ollama"
    ]
    from pihole_ai.health import overall_status

    return HealthReport(
        overall_status=overall_status(checks),
        checks=checks,
        version=report.version,
        checked_at=report.checked_at,
    )


def _install_step(status: InstallationStatus) -> SetupStep:
    if status.state == "installed":
        return SetupStep(
            "install",
            "Appliance installation",
            "complete",
            True,
            "Managed systemd units are installed.",
            details=status.to_dict(),
        )
    if status.state in {"partial", "drifted", "legacy"}:
        return SetupStep(
            "install",
            "Appliance installation",
            "warning",
            True,
            f"Installation state is {status.state}.",
            "Run: sudo pihole-ai install or sudo pihole-ai upgrade",
            SetupAction("run_upgrade", "Install or upgrade services", True),
            status.to_dict(),
        )
    return SetupStep(
        "install",
        "Appliance installation",
        "pending",
        True,
        "Managed appliance services are not installed yet.",
        "Run: sudo pihole-ai install",
        SetupAction("run_install", "Install services", True),
        status.to_dict(),
    )


def _configuration_step(result: ConfigurationValidationResult) -> SetupStep:
    if result.error_count:
        return SetupStep(
            "configuration",
            "Configuration",
            "blocked",
            True,
            "Configuration has errors.",
            "Run: pihole-ai config check",
            SetupAction("edit_configuration", "Edit configuration"),
            result.to_dict(),
        )
    if result.warning_count:
        return SetupStep(
            "configuration",
            "Configuration",
            "warning",
            True,
            "Configuration is usable with warnings.",
            "Review: pihole-ai config check",
            SetupAction("edit_configuration", "Edit configuration"),
            result.to_dict(),
        )
    return SetupStep(
        "configuration",
        "Configuration",
        "complete",
        True,
        "Configuration is valid.",
        details=result.to_dict(),
    )


def _pihole_database_step(candidates: list[PiholeDatabaseCandidate]) -> SetupStep:
    valid = [candidate for candidate in candidates if candidate.valid]
    details = {"candidates": [candidate.to_dict() for candidate in candidates]}

    if valid:
        status = "complete" if len(valid) == 1 else "warning"
        summary = (
            f"Readable Pi-hole database detected at {valid[0].path}."
            if len(valid) == 1
            else "Multiple readable Pi-hole database candidates found."
        )
        remediation = None if len(valid) == 1 else "Set PIHOLE_AI_PIHOLE_DB explicitly."
        return SetupStep(
            "pihole_database",
            "Pi-hole FTL database",
            status,
            True,
            summary,
            remediation,
            SetupAction("edit_configuration", "Set Pi-hole database") if remediation else None,
            details,
        )

    return SetupStep(
        "pihole_database",
        "Pi-hole FTL database",
        "blocked",
        True,
        "No readable Pi-hole FTL database was detected.",
        "Set PIHOLE_AI_PIHOLE_DB to a readable pihole-FTL.db path.",
        SetupAction("edit_configuration", "Set Pi-hole database"),
        details,
    )


def _events_database_step(report: HealthReport | None) -> SetupStep:
    check = _health_check(report, "events_database")
    if check is None:
        return SetupStep(
            "events_database",
            "PiHole-AI events database",
            "blocked",
            True,
            "Events database health could not be checked.",
            "Run: pihole-ai health",
            SetupAction("run_doctor", "Run diagnostics"),
        )
    return _health_step(
        "events_database",
        "PiHole-AI events database",
        check,
        required=True,
        blocked_on_unhealthy=True,
    )


def _database_schema_step(config: Any) -> SetupStep:
    if config is None:
        return SetupStep(
            "database_schema",
            "Database schema",
            "blocked",
            True,
            "Database schema could not be checked because configuration is invalid.",
            "Run: pihole-ai config check",
        )
    try:
        status = database_status(config.events_db)
    except UnsupportedSchemaVersion:
        return SetupStep(
            "database_schema",
            "Database schema",
            "blocked",
            True,
            "Events database schema is newer than this PiHole-AI version.",
            "Upgrade PiHole-AI before using this database.",
            SetupAction("run_upgrade", "Upgrade PiHole-AI", True),
        )
    except MigrationError:
        return SetupStep(
            "database_schema",
            "Database schema",
            "blocked",
            True,
            "Events database schema is incompatible.",
            "Run: pihole-ai db status",
            SetupAction("run_doctor", "Run diagnostics"),
        )

    except Exception as exc:
        return SetupStep(
            "database_schema",
            "Database schema",
            "blocked",
            True,
            "Database schema could not be inspected.",
            "Run: sudo pihole-ai setup status",
            SetupAction("run_doctor", "Run diagnostics"),
            {"error": exc.__class__.__name__},
        )

    if status.pending_migration_count:
        return SetupStep(
            "database_schema",
            "Database schema",
            "pending",
            True,
            "Events database has pending migrations.",
            "Run: pihole-ai db migrate",
            SetupAction("run_migration", "Run database migration"),
            asdict(status),
        )
    return SetupStep(
        "database_schema",
        "Database schema",
        "complete",
        True,
        "Events database schema is current.",
        details=asdict(status),
    )


def _service_identity_step(status: InstallationStatus) -> SetupStep:
    if status.service_user == DEFAULT_SERVICE_USER and status.service_group == DEFAULT_SERVICE_GROUP:
        return SetupStep(
            "service_identity",
            "Service identity",
            "complete",
            True,
            "Services are configured to use the dedicated pihole-ai identity.",
            details={
                "service_user": status.service_user,
                "service_group": status.service_group,
            },
        )
    return SetupStep(
        "service_identity",
        "Service identity",
        "warning",
        True,
        "Services are not using the default dedicated appliance identity.",
        "Run: sudo pihole-ai install",
        SetupAction("run_install", "Regenerate services", True),
        {
            "service_user": status.service_user,
            "service_group": status.service_group,
        },
    )


def _services_step(status: InstallationStatus) -> SetupStep:
    if status.state != "installed":
        return SetupStep(
            "services",
            "Runtime services",
            "pending",
            True,
            "Services cannot be verified until installation is complete.",
            "Run: sudo pihole-ai install",
            SetupAction("run_install", "Install services", True),
        )

    inactive = [
        name
        for name, unit in status.unit_files.items()
        if unit.get("active") != "active"
    ]
    if inactive:
        return SetupStep(
            "services",
            "Runtime services",
            "blocked",
            True,
            "One or more required services are inactive.",
            "Run: sudo pihole-ai start",
            SetupAction("start_services", "Start services", True),
            {"inactive": inactive, "services": status.unit_files},
        )
    return SetupStep(
        "services",
        "Runtime services",
        "complete",
        True,
        "Collector, engine, and dashboard services are active.",
        details={"services": status.unit_files},
    )


def _ollama_step(config: Any, report: HealthReport | None, *, skip_ollama_check: bool) -> SetupStep:
    if config is not None and not config.ai_enabled:
        return SetupStep(
            "ollama",
            "Ollama AI",
            "skipped",
            False,
            "AI is disabled; deterministic classifiers remain available.",
            details={"state": "disabled"},
        )
    if skip_ollama_check:
        return SetupStep(
            "ollama",
            "Ollama AI",
            "skipped",
            False,
            "Ollama availability check was skipped.",
            "Run: pihole-ai setup status",
            SetupAction("check_ollama", "Check Ollama"),
        )
    check = _health_check(report, "ollama")
    if check is None:
        return SetupStep(
            "ollama",
            "Ollama AI",
            "warning",
            False,
            "Ollama status could not be checked.",
            "Start Ollama or set AI_ENABLED=false.",
            SetupAction("check_ollama", "Check Ollama"),
        )
    return _health_step(
        "ollama",
        "Ollama AI",
        check,
        required=False,
        blocked_on_unhealthy=False,
        optional_remediation="Start Ollama or set AI_ENABLED=false.",
    )


def _dashboard_step(status: InstallationStatus) -> SetupStep:
    dashboard = status.unit_files.get("pihole-ai-dashboard.service", {})
    if dashboard.get("exists") and dashboard.get("active") == "active":
        return SetupStep(
            "dashboard",
            "Dashboard service",
            "complete",
            True,
            "Dashboard service is active.",
            details=dashboard,
        )
    if dashboard.get("exists"):
        return SetupStep(
            "dashboard",
            "Dashboard service",
            "blocked",
            True,
            "Dashboard service is installed but inactive.",
            "Run: sudo pihole-ai start",
            SetupAction("start_services", "Start services", True),
            dashboard,
        )
    return SetupStep(
        "dashboard",
        "Dashboard service",
        "pending",
        True,
        "Dashboard service is not installed yet.",
        "Run: sudo pihole-ai install",
        SetupAction("run_install", "Install dashboard service", True),
        dashboard,
    )


def _final_health_step(report: HealthReport | None) -> SetupStep:
    if report is None:
        return SetupStep(
            "final_health",
            "Final health",
            "blocked",
            True,
            "Health checks could not run.",
            "Run: pihole-ai doctor",
            SetupAction("run_doctor", "Run diagnostics"),
        )
    if report.overall_status == HealthStatus.HEALTHY.value:
        return SetupStep(
            "final_health",
            "Final health",
            "complete",
            True,
            "Required health checks are healthy.",
            details=report_to_dict(report),
        )
    if report.overall_status == HealthStatus.DEGRADED.value:
        return SetupStep(
            "final_health",
            "Final health",
            "warning",
            True,
            "Health checks report a degraded but usable state.",
            "Run: pihole-ai health",
            SetupAction("run_doctor", "Run diagnostics"),
            report_to_dict(report),
        )
    return SetupStep(
        "final_health",
        "Final health",
        "blocked",
        True,
        "A required health check is unhealthy.",
        "Run: pihole-ai doctor",
        SetupAction("run_doctor", "Run diagnostics"),
        report_to_dict(report),
    )


def _health_step(
    step_id: str,
    title: str,
    check: Any,
    *,
    required: bool,
    blocked_on_unhealthy: bool,
    optional_remediation: str | None = None,
) -> SetupStep:
    if check.status == HealthStatus.HEALTHY.value:
        return SetupStep(
            step_id,
            title,
            "complete",
            required,
            check.summary,
            details=asdict(check),
        )
    if check.status == HealthStatus.UNHEALTHY.value and blocked_on_unhealthy:
        return SetupStep(
            step_id,
            title,
            "blocked",
            required,
            check.summary,
            "Run: pihole-ai doctor",
            SetupAction("run_doctor", "Run diagnostics"),
            asdict(check),
        )
    return SetupStep(
        step_id,
        title,
        "warning",
        required,
        check.summary,
        optional_remediation or "Run: pihole-ai health",
        SetupAction("run_doctor", "Run diagnostics"),
        asdict(check),
    )


def _health_check(report: HealthReport | None, name: str) -> Any | None:
    if report is None:
        return None
    return next((check for check in report.checks if check.name == name), None)


def _stage_for_steps(
    steps: list[SetupStep],
    install: InstallationStatus,
    config_result: ConfigurationValidationResult,
) -> SetupStage:
    required = [step for step in steps if step.required]

    if any(step.status == "blocked" for step in required):
        return SetupStage.BLOCKED
    if install.state == "not_installed":
        return SetupStage.NOT_INSTALLED
    if config_result.error_count or any(
        step.id in {"configuration", "pihole_database"}
        and step.status in {"pending", "warning"}
        for step in required
    ):
        return SetupStage.INSTALLED_UNCONFIGURED
    if any(step.id == "services" and step.status != "complete" for step in required):
        return SetupStage.SERVICES_INACTIVE
    if any(step.status == "pending" for step in required):
        return SetupStage.CONFIGURED
    if any(step.status == "warning" for step in steps):
        return SetupStage.DEGRADED
    return SetupStage.READY


def _service_user_can_read(
    *,
    file_stat: os.stat_result,
    parent_stat: os.stat_result,
    service_user: str,
    service_group: str,
) -> bool:
    file_mode = file_stat.st_mode
    parent_mode = parent_stat.st_mode
    if bool(file_mode & stat.S_IROTH) and bool(parent_mode & stat.S_IXOTH):
        return True

    gids = set()
    try:
        import pwd
        import grp

        user_info = pwd.getpwnam(service_user)
        gids.add(user_info.pw_gid)
        gids.update(
            group.gr_gid
            for group in grp.getgrall()
            if service_user in group.gr_mem
        )
    except Exception:
        pass

    try:
        import grp

        gids.add(grp.getgrnam(service_group).gr_gid)
    except Exception:
        pass

    return (
        file_stat.st_gid in gids
        and parent_stat.st_gid in gids
        and bool(file_mode & stat.S_IRGRP)
        and bool(parent_mode & stat.S_IXGRP)
    )


def _target_config_path(path: str | Path | None) -> Path:
    if path is not None:
        return Path(path)
    if CONFIG_FILE.exists():
        return CONFIG_FILE
    return PROJECT_ROOT / ".env"


def _normalize_config_updates(updates: dict[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in updates.items():
        if key not in SUPPORTED_CONFIG_KEYS:
            raise ValueError(f"Unsupported setup setting: {key}")
        if key == "PIHOLE_AI_OLLAMA_URL" and _url_contains_credentials(str(value)):
            raise ValueError("PIHOLE_AI_OLLAMA_URL must not contain credentials.")
        if isinstance(value, bool):
            normalized[key] = "true" if value else "false"
        else:
            normalized[key] = str(value)
    return normalized


def _url_contains_credentials(value: str) -> bool:
    parts = urlsplit(value)
    return bool(parts.username or parts.password)


def _update_env_lines(lines: list[str], updates: dict[str, str]) -> list[str]:
    remaining = dict(updates)
    output: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            output.append(line)
            continue
        key, _value = line.split("=", 1)
        normalized = key.strip()
        if normalized in remaining:
            output.append(f"{normalized}={remaining.pop(normalized)}")
        else:
            output.append(line)
    for key, value in remaining.items():
        output.append(f"{key}={value}")
    return output


def _validate_proposed_config(path: Path, content: str) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / path.name
        tmp_path.write_text(content, encoding="utf-8")
        config, result = load_config_with_result(
            env={},
            env_files=[tmp_path],
            mode=ValidationMode.SYNTAX,
        )
        if config is None or result.error_count:
            first = next(
                (
                    issue
                    for issue in result.issues
                    if issue.severity == ValidationSeverity.ERROR.value
                ),
                None,
            )
            summary = first.summary if first else "Configuration is invalid."
            raise ValueError(summary)


def _atomic_replace(
    path: Path,
    content: str,
    *,
    mode: int,
    uid: int | None,
    gid: int | None,
) -> None:
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=str(path.parent),
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        if uid is not None and gid is not None:
            try:
                os.chown(tmp_path, uid, gid)
            except PermissionError:
                pass
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def safe_effective_setup_config() -> dict[str, Any]:
    config = load_config(validate=False)
    return {
        "events_db": str(config.events_db),
        "pihole_db": str(config.pihole_db),
        "dashboard_host": config.dashboard_host,
        "dashboard_port": config.dashboard_port,
        "ai_enabled": config.ai_enabled,
        "ollama_url": redact_url(config.ollama_url),
        "ollama_model": config.ollama_model,
        "config_file": str(config.config_file),
    }
