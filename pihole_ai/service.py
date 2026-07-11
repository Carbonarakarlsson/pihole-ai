"""
Linux systemd service management for PiHole-AI.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
import os
import json
import tempfile
import hashlib
import sqlite3
import fcntl
import grp
import pwd
import stat
import secrets
from importlib import resources
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from core.config import ValidationMode, load_config_with_result
from core.migrations import (
    MigrationError,
    UnsupportedSchemaVersion,
    database_status,
    migrate_database,
)
from pihole_ai.version import get_version


SYSTEMD_DIR = Path("/etc/systemd/system")
WRAPPER_PATH = Path("/usr/local/bin/pihole-ai")
CONFIG_DIR = Path("/etc/pihole-ai")
CONFIG_FILE = CONFIG_DIR / "pihole-ai.env"
RUNTIME_DATA_DIR = Path("/var/lib/pihole-ai")
RUNTIME_LOG_DIR = Path("/var/log/pihole-ai")
RUNTIME_DB_PATH = RUNTIME_DATA_DIR / "events.db"
RUNTIME_LOG_PATH = RUNTIME_LOG_DIR / "pihole-ai.log"
RUNTIME_STATE_DIR = Path("/run/pihole-ai")
DEFAULT_SERVICE_USER = "pihole-ai"
DEFAULT_SERVICE_GROUP = "pihole-ai"
MANAGED_FILE_MARKER = "Managed by PiHole-AI"
MANAGED_FILE_HEADER = "\n".join(
    [
        "# PiHole-AI",
        f"# {MANAGED_FILE_MARKER}",
        f"# Application version: {get_version()}",
        "",
    ]
)

SERVICE_NAMES = [
    "pihole-ai-collector.service",
    "pihole-ai-engine.service",
    "pihole-ai-dashboard.service",
]
START_ORDER = SERVICE_NAMES
STOP_ORDER = list(reversed(SERVICE_NAMES))


@dataclass(frozen=True)
class ServiceDefinition:
    """
    One generated systemd service.
    """

    name: str
    description: str
    command: list[str]
    after: str


@dataclass(frozen=True)
class InstallationLayout:
    """
    Standard appliance filesystem layout.
    """

    config_dir: Path = CONFIG_DIR
    config_file: Path = CONFIG_FILE
    data_dir: Path = RUNTIME_DATA_DIR
    events_db: Path = RUNTIME_DB_PATH
    log_dir: Path = RUNTIME_LOG_DIR
    log_file: Path = RUNTIME_LOG_PATH
    runtime_dir: Path = RUNTIME_STATE_DIR
    systemd_dir: Path = SYSTEMD_DIR
    wrapper_path: Path = WRAPPER_PATH


@dataclass(frozen=True)
class InstallAction:
    """
    One planned installer action.
    """

    action: str
    path: str
    summary: str


@dataclass(frozen=True)
class InstallPlan:
    """
    Inspectable installation or upgrade plan.
    """

    layout: InstallationLayout
    project_dir: Path
    python_path: Path
    executable_path: Path
    executable_target: "ExecutableTarget"
    service_user: str
    service_group: str
    unit_paths: dict[str, Path]
    directories: list[Path]
    files_to_write: list[Path]
    files_to_preserve: list[Path]
    enable_services: bool
    start_services: bool
    daemon_reload: bool
    actions: list[InstallAction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["layout"] = {
            key: str(value)
            for key, value in asdict(self.layout).items()
        }
        payload["project_dir"] = str(self.project_dir)
        payload["python_path"] = str(self.python_path)
        payload["executable_path"] = str(self.executable_path)
        payload["executable_target"] = self.executable_target.to_dict()
        payload["unit_paths"] = {
            key: str(value)
            for key, value in self.unit_paths.items()
        }
        payload["directories"] = [str(path) for path in self.directories]
        payload["files_to_write"] = [str(path) for path in self.files_to_write]
        payload["files_to_preserve"] = [str(path) for path in self.files_to_preserve]
        return payload


@dataclass(frozen=True)
class PreflightIssue:
    code: str
    severity: str
    summary: str
    remediation: str
    details: dict[str, Any] = field(default_factory=dict)
    blocking: bool = False


@dataclass(frozen=True)
class PreflightResult:
    issues: list[PreflightIssue]

    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == "warning")

    @property
    def ok(self) -> bool:
        return self.blocking_count == 0

    @property
    def blocking_count(self) -> int:
        return sum(1 for issue in self.issues if issue.blocking)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "blocking_count": self.blocking_count,
            "issues": [asdict(issue) for issue in self.issues],
        }


@dataclass(frozen=True)
class InstallResult:
    command: str
    changed: bool
    dry_run: bool
    actions: list[str]
    preserved_paths: list[str]
    removed_paths: list[str] = field(default_factory=list)
    status: str = "ok"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InstallationStatus:
    state: str
    managed: bool
    version: str
    service_user: str
    service_group: str
    config_file: str
    data_dir: str
    events_db: str
    unit_files: dict[str, dict[str, Any]]
    database: dict[str, Any]
    legacy: dict[str, Any]
    executable: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExecutableTarget:
    executable_path: Path
    invocation: list[str]
    interpreter_path: Path
    package_importable: bool
    version: str | None
    source: str
    stable: bool
    reason: str
    references_checkout: bool = False
    references_developer_venv: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "executable_path": str(self.executable_path),
            "invocation": self.invocation,
            "interpreter_path": str(self.interpreter_path),
            "package_importable": self.package_importable,
            "version": self.version,
            "source": self.source,
            "stable": self.stable,
            "reason": self.reason,
            "references_checkout": self.references_checkout,
            "references_developer_venv": self.references_developer_venv,
        }


SERVICE_DEFINITIONS = [
    ServiceDefinition(
        name="pihole-ai-collector.service",
        description="PiHole-AI Collector",
        command=["collect"],
        after="network-online.target",
    ),
    ServiceDefinition(
        name="pihole-ai-engine.service",
        description="PiHole-AI Analysis Engine",
        command=["run-engine"],
        after="network-online.target ollama.service pihole-ai-collector.service",
    ),
    ServiceDefinition(
        name="pihole-ai-dashboard.service",
        description="PiHole-AI Dashboard",
        command=[
            "dashboard",
            "--host",
            "0.0.0.0",
            "--port",
            "8080",
        ],
        after="network-online.target pihole-ai-engine.service",
    ),
]


class ServiceError(RuntimeError):
    """
    Clean service-management error intended for CLI display.
    """


def generate_unit_file(
    service: ServiceDefinition,
    python_path: str | None = None,
    project_dir: str | Path | None = None,
    env_file: str | Path = CONFIG_FILE,
    user: str | None = None,
    group: str | None = None,
    layout: InstallationLayout | None = None,
) -> str:
    """
    Generate systemd unit content for one PiHole-AI service.
    """

    runtime_layout = layout or InstallationLayout()
    python = str(_absolute_path(python_path or sys.executable))
    working_directory = _absolute_path(project_dir or runtime_layout.data_dir)
    environment_file = Path(env_file)
    service_user = user or DEFAULT_SERVICE_USER
    service_group = group or DEFAULT_SERVICE_GROUP
    exec_start = " ".join(
        shlex.quote(part)
        for part in [
            python,
            "-m",
            "pihole_ai.cli",
            *service.command,
        ]
    )
    read_only_paths = "/etc/pihole" if service.name == "pihole-ai-collector.service" else ""
    hardening = [
        "TimeoutStopSec=30",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectKernelTunables=true",
        "ProtectKernelModules=true",
        "ProtectKernelLogs=true",
        "ProtectControlGroups=true",
        "RestrictSUIDSGID=true",
        "RestrictRealtime=true",
        "LockPersonality=true",
        "MemoryDenyWriteExecute=true",
        "StateDirectory=pihole-ai",
        "LogsDirectory=pihole-ai",
        "RuntimeDirectory=pihole-ai",
        f"ReadWritePaths={runtime_layout.data_dir} {runtime_layout.log_dir} {runtime_layout.runtime_dir}",
    ]

    if read_only_paths:
        hardening.append(f"ReadOnlyPaths={read_only_paths}")

    return MANAGED_FILE_HEADER + "\n".join(
        [
            "[Unit]",
            f"Description={service.description}",
            f"After={service.after}",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=simple",
            f"User={service_user}",
            f"Group={service_group}",
            f"WorkingDirectory={working_directory}",
            f"EnvironmentFile={environment_file}",
            f"ExecStart={exec_start}",
            "Restart=always",
            "RestartSec=5",
            *hardening,
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def generated_units(
    python_path: str | None = None,
    project_dir: str | Path | None = None,
    env_file: str | Path = CONFIG_FILE,
    user: str | None = None,
    group: str | None = None,
    layout: InstallationLayout | None = None,
) -> dict[str, str]:
    """
    Return all generated unit file contents.
    """

    return {
        service.name: generate_unit_file(
            service=service,
            python_path=python_path,
            project_dir=project_dir,
            env_file=env_file,
            user=user,
            group=group,
            layout=layout,
        )
        for service in SERVICE_DEFINITIONS
    }


def discover_executable_target(
    python_path: str | Path | None = None,
    project_dir: str | Path | None = None,
    development_mode: bool = False,
) -> ExecutableTarget:
    """
    Select and validate the Python environment used by appliance services.
    """

    explicit = os.getenv("PIHOLE_AI_APPLIANCE_PYTHON") or os.getenv(
        "PIHOLE_AI_PYTHON"
    )
    if python_path is not None or explicit:
        return _validate_interpreter(
            Path(python_path or explicit),
            source="explicit",
            project_dir=project_dir,
            development_mode=development_mode,
        )

    console = shutil.which("pihole-ai")
    if console:
        current = _validate_interpreter(
            Path(sys.executable),
            source="current_console_script",
            project_dir=project_dir,
            development_mode=development_mode,
            executable_path=Path(console),
        )
        if current.package_importable and current.stable:
            return current

    current = _validate_interpreter(
        Path(sys.executable),
        source="current_interpreter",
        project_dir=project_dir,
        development_mode=development_mode,
    )
    if current.package_importable and current.stable:
        return current

    dedicated = _validate_interpreter(
        Path("/opt/pihole-ai/venv/bin/python"),
        source="dedicated_appliance_venv",
        project_dir=project_dir,
        development_mode=development_mode,
    )
    if dedicated.package_importable and dedicated.stable:
        return dedicated

    if development_mode:
        development = _validate_interpreter(
            Path(project_dir or Path.cwd()) / ".venv" / "bin" / "python",
            source="development_checkout_venv",
            project_dir=project_dir,
            development_mode=True,
        )
        if development.package_importable:
            return development

    for candidate in (current, dedicated):
        if not candidate.package_importable:
            return candidate

    return current


def _validate_interpreter(
    interpreter_path: Path,
    source: str,
    project_dir: str | Path | None = None,
    development_mode: bool = False,
    executable_path: Path | None = None,
) -> ExecutableTarget:
    interpreter = _absolute_path(interpreter_path)
    executable = _absolute_path(executable_path or interpreter.with_name("pihole-ai"))
    references_checkout = _path_references_checkout(interpreter, project_dir) or _path_references_checkout(
        executable,
        project_dir,
    )
    references_developer_venv = _path_references_developer_venv(interpreter) or _path_references_developer_venv(
        executable
    )
    stable = (
        interpreter.is_absolute()
        and executable.is_absolute()
        and (development_mode or not references_checkout)
        and (development_mode or not references_developer_venv)
    )
    invocation = [str(interpreter), "-m", "pihole_ai.cli"]

    if not interpreter.exists():
        return ExecutableTarget(
            executable_path=executable,
            invocation=invocation,
            interpreter_path=interpreter,
            package_importable=False,
            version=None,
            source=source,
            stable=stable,
            reason="interpreter does not exist",
            references_checkout=references_checkout,
            references_developer_venv=references_developer_venv,
        )

    importable = _run_python_check(
        interpreter,
        ["-c", "import pihole_ai, pihole_ai.cli"],
    )
    version = None
    version_ok = False
    if importable:
        completed = _run_python_check(
            interpreter,
            ["-m", "pihole_ai.cli", "--version"],
            capture=True,
        )
        version_ok = completed.returncode == 0
        version = completed.stdout.strip() if version_ok else None

    reason = "ok"
    if not importable:
        reason = "pihole_ai is not importable from interpreter"
    elif not version_ok:
        reason = "pihole-ai --version failed from interpreter"
    elif not stable:
        reason = "path is not stable for appliance mode"

    return ExecutableTarget(
        executable_path=executable,
        invocation=invocation,
        interpreter_path=interpreter,
        package_importable=bool(importable and version_ok),
        version=version,
        source=source,
        stable=stable,
        reason=reason,
        references_checkout=references_checkout,
        references_developer_venv=references_developer_venv,
    )


def _run_python_check(
    interpreter: Path,
    args: list[str],
    capture: bool = False,
) -> Any:
    try:
        completed = subprocess.run(
            [str(interpreter), *args],
            check=False,
            capture_output=True,
            text=True,
            cwd="/",
            env=_validation_environment(),
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        if capture:
            return SimpleCompletedProcess(returncode=1, stdout="")
        return False

    if capture:
        return completed
    return completed.returncode == 0


def _validation_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    return env


@dataclass(frozen=True)
class SimpleCompletedProcess:
    returncode: int
    stdout: str


def _path_references_checkout(
    path: Path,
    project_dir: str | Path | None = None,
) -> bool:
    candidates = [_absolute_path(Path(project_dir))] if project_dir is not None else []
    candidates.append(_absolute_path(Path.cwd()))
    return any(_is_relative_to(path, candidate) for candidate in candidates)


def _path_references_developer_venv(path: Path) -> bool:
    return ".venv" in path.parts


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _absolute_path(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate
    return Path.cwd() / candidate


def build_install_plan(
    python_path: str | None = None,
    project_dir: str | Path | None = None,
    layout: InstallationLayout | None = None,
    user: str | None = None,
    group: str | None = None,
    enable_services: bool = True,
    start_services: bool = True,
    development_mode: bool = False,
    validate_executable: bool = True,
) -> InstallPlan:
    """
    Build an inspectable appliance installation plan.
    """

    runtime_layout = layout or InstallationLayout()
    development_mode = development_mode or _development_mode_enabled()
    project = Path(project_dir or runtime_layout.data_dir).resolve()
    if validate_executable:
        executable_target = discover_executable_target(
            python_path=python_path,
            project_dir=project,
            development_mode=development_mode,
        )
    else:
        executable_target = _unvalidated_executable_target(
            Path(python_path or sys.executable),
            source="metadata_only",
        )
    python = executable_target.interpreter_path
    executable = executable_target.executable_path
    service_user = user or DEFAULT_SERVICE_USER
    service_group = group or DEFAULT_SERVICE_GROUP
    unit_paths = {
        name: runtime_layout.systemd_dir / name
        for name in SERVICE_NAMES
    }
    directories = [
        runtime_layout.config_dir,
        runtime_layout.data_dir,
        runtime_layout.log_dir,
        runtime_layout.runtime_dir,
        runtime_layout.systemd_dir,
    ]
    files_to_write = [
        runtime_layout.config_file,
        runtime_layout.wrapper_path,
        *unit_paths.values(),
    ]
    files_to_preserve = [
        runtime_layout.config_file,
        runtime_layout.events_db,
    ]
    actions = [
        InstallAction("create_directory", str(path), f"Ensure {path}")
        for path in directories
    ] + [
        InstallAction("write_file", str(path), f"Install {path}")
        for path in files_to_write
    ]

    return InstallPlan(
        layout=runtime_layout,
        project_dir=project,
        python_path=python,
        executable_path=executable,
        executable_target=executable_target,
        service_user=service_user,
        service_group=service_group,
        unit_paths=unit_paths,
        directories=directories,
        files_to_write=files_to_write,
        files_to_preserve=files_to_preserve,
        enable_services=enable_services,
        start_services=start_services,
        daemon_reload=True,
        actions=actions,
    )


def _unvalidated_executable_target(
    python_path: Path,
    source: str,
) -> ExecutableTarget:
    interpreter = _absolute_path(python_path)
    executable = interpreter.with_name("pihole-ai")
    return ExecutableTarget(
        executable_path=executable,
        invocation=[str(interpreter), "-m", "pihole_ai.cli"],
        interpreter_path=interpreter,
        package_importable=False,
        version=None,
        source=source,
        stable=False,
        reason="not validated",
        references_checkout=_path_references_checkout(interpreter),
        references_developer_venv=_path_references_developer_venv(interpreter),
    )


def run_preflight(
    plan: InstallPlan,
    require_root: bool = True,
    dry_run: bool = False,
) -> PreflightResult:
    """
    Collect installation preflight issues without modifying the system.
    """

    issues: list[PreflightIssue] = []

    if sys.platform != "linux":
        issues.append(
            _preflight_issue(
                "install.platform.unsupported",
                "error",
                "PiHole-AI appliance install currently supports Linux.",
                "Run appliance lifecycle commands on the Pi-hole Linux host.",
            )
        )

    if shutil.which("systemctl") is None:
        issues.append(
            _preflight_issue(
                "install.systemd.unavailable",
                "error",
                "systemctl was not found.",
                "Install systemd/systemctl support or run in development mode.",
            )
        )

    if require_root and not dry_run and _effective_uid() != 0:
        issues.append(
            _preflight_issue(
                "install.privileges.required",
                "error",
                "Installation requires root privileges.",
                "Re-run this command with sudo: sudo pihole-ai install",
            )
        )

    if sys.version_info < (3, 10):
        issues.append(
            _preflight_issue(
                "install.python.unsupported",
                "error",
                "Python version is too old.",
                "Use Python 3.10 or newer.",
                {"python": sys.version.split()[0]},
            )
        )

    _check_executable_target(plan, issues)

    if not plan.python_path.exists():
        issues.append(
            _preflight_issue(
                "install.python.missing",
                "error",
                "Configured Python executable does not exist.",
                "Install PiHole-AI in a valid Python environment.",
                {"python": str(plan.python_path)},
            )
        )

    _check_service_identity(plan, issues)
    _check_config_for_install(issues)
    _check_pihole_db_access(plan, issues)
    _check_database_schema(plan, issues)
    _check_unit_conflicts(plan, issues)
    _check_install_disk_space(plan, issues)

    return PreflightResult(issues)


def _development_mode_enabled() -> bool:
    return os.getenv("PIHOLE_AI_DEVELOPMENT_MODE", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _check_executable_target(
    plan: InstallPlan,
    issues: list[PreflightIssue],
) -> None:
    target = plan.executable_target

    if target.package_importable and target.stable:
        return

    if not target.package_importable:
        summary = "Selected PiHole-AI executable cannot import the installed package."
    else:
        summary = "Selected PiHole-AI executable is not stable for appliance mode."

    issues.append(
        _preflight_issue(
            "install.executable.package_not_importable",
            "error",
            summary,
            (
                "Install the built wheel into a stable appliance environment, for example: "
                "sudo python3 -m venv /opt/pihole-ai/venv && "
                "sudo /opt/pihole-ai/venv/bin/pip install <wheel>, then rerun: "
                "sudo pihole-ai install"
            ),
            {
                "source": target.source,
                "package_importable": target.package_importable,
                "stable": target.stable,
                "reason": target.reason,
                "references_checkout": target.references_checkout,
                "references_developer_venv": target.references_developer_venv,
            },
        )
    )


def installation_status(
    layout: InstallationLayout | None = None,
    project_dir: str | Path | None = None,
    python_path: str | None = None,
) -> InstallationStatus:
    """
    Return read-only installation status and drift information.
    """

    plan = build_install_plan(
        layout=layout,
        project_dir=project_dir,
        python_path=python_path,
    )
    units: dict[str, dict[str, Any]] = {}
    managed_count = 0
    installed_count = 0
    drifted = False

    expected_units = generated_units(
        python_path=str(plan.python_path),
        project_dir=plan.project_dir,
        env_file=plan.layout.config_file,
        user=plan.service_user,
        group=plan.service_group,
        layout=plan.layout,
    )

    for name, path in plan.unit_paths.items():
        try:
            exists = path.exists()
        except OSError:
            exists = False
        managed = False
        expected_hash = _sha256(expected_units[name])
        installed_hash = None
        drift = False

        if exists:
            installed_count += 1
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                content = ""
            if content:
                managed = _is_managed_content(content)
                installed_hash = _sha256(content)
                drift = managed and installed_hash != expected_hash
                managed_count += 1 if managed else 0
                drifted = drifted or drift

        units[name] = {
            "path": str(path),
            "exists": exists,
            "managed": managed,
            "drifted": drift,
            "expected_hash": expected_hash,
            "installed_hash": installed_hash,
            "active": _run_capture(["systemctl", "is-active", name]) if exists else "missing",
            "enabled": _run_capture(["systemctl", "is-enabled", name]) if exists else "missing",
        }

    database: dict[str, Any]

    try:
        database = asdict(database_status(plan.layout.events_db))
    except Exception as exc:
        database = {"error": exc.__class__.__name__}

    legacy = _legacy_status(plan.project_dir, plan.unit_paths)

    if installed_count == 0:
        state = "legacy" if legacy["detected"] else "not_installed"
    elif drifted:
        state = "drifted"
    elif installed_count < len(SERVICE_NAMES) or managed_count < installed_count:
        state = "partial"
    else:
        state = "installed"

    if "error" in database:
        state = "incompatible"

    return InstallationStatus(
        state=state,
        managed=managed_count == installed_count and installed_count > 0,
        version=get_version(),
        service_user=plan.service_user,
        service_group=plan.service_group,
        config_file=str(plan.layout.config_file),
        data_dir=str(plan.layout.data_dir),
        events_db=str(plan.layout.events_db),
        unit_files=units,
        database=database,
        legacy=legacy,
        executable=plan.executable_target.to_dict(),
    )


def print_installation_status(
    as_json: bool = False,
) -> int:
    """
    Print read-only appliance installation status.
    """

    status = installation_status()

    if as_json:
        print(json.dumps(status.to_dict(), sort_keys=True))
    else:
        print(f"PiHole-AI install status: {status.state}")
        print(f"config_file: {status.config_file}")
        print(f"data_dir: {status.data_dir}")
        print(f"events_db: {status.events_db}")
        print(f"service_user: {status.service_user}")
        print(f"service_group: {status.service_group}")
        print(f"executable_interpreter: {status.executable['interpreter_path']}")
        print(f"executable_importable: {status.executable['package_importable']}")
        print(f"executable_stable: {status.executable['stable']}")
        print(f"executable_source: {status.executable['source']}")
        for name, unit in status.unit_files.items():
            drift = " drifted" if unit["drifted"] else ""
            print(
                f"- {name}: exists={unit['exists']} managed={unit['managed']}{drift}"
            )

    return 0 if status.state in {"installed", "not_installed", "legacy"} else 1


def _preflight_issue(
    code: str,
    severity: str,
    summary: str,
    remediation: str,
    details: dict[str, Any] | None = None,
    blocking: bool | None = None,
) -> PreflightIssue:
    return PreflightIssue(
        code=code,
        severity=severity,
        summary=summary,
        remediation=remediation,
        details=details or {},
        blocking=severity in {"error", "fatal"} if blocking is None else blocking,
    )


def _check_service_identity(
    plan: InstallPlan,
    issues: list[PreflightIssue],
) -> None:
    try:
        import pwd

        pwd.getpwnam(plan.service_user)
    except Exception:
        issues.append(
            _preflight_issue(
                "install.user.missing",
                "warning",
                f"Service user '{plan.service_user}' does not exist.",
                "Create the service user or install using an existing --user.",
            )
        )


def _check_config_for_install(
    issues: list[PreflightIssue],
) -> None:
    try:
        _config, result = load_config_with_result(mode=ValidationMode.INSTALL)
    except OSError as exc:
        issues.append(
            _preflight_issue(
                "install.config.inaccessible",
                "error",
                "PiHole-AI configuration could not be read.",
                "Check /etc/pihole-ai/pihole-ai.env ownership and permissions.",
                {"error": exc.__class__.__name__},
            )
        )
        return

    for issue in result.issues:
        code = issue.code

        if issue.code == "config.pihole_db.missing":
            code = "install.pihole_db.missing"
        elif issue.code == "config.pihole_db.not_readable":
            code = "install.pihole_db.unreadable"
        elif issue.code == "config.dashboard.non_loopback_bind":
            code = "install.dashboard.non_loopback_bind"

        issues.append(
            _preflight_issue(
                code,
                issue.severity,
                issue.summary,
                issue.remediation,
                issue.details or {},
                blocking=issue.severity in {"error", "fatal"},
            )
        )


def _check_database_schema(
    plan: InstallPlan,
    issues: list[PreflightIssue],
) -> None:
    try:
        database_status(plan.layout.events_db)
    except UnsupportedSchemaVersion:
        issues.append(
            _preflight_issue(
                "install.database.unsupported_schema",
                "error",
                "Events database schema is newer than this PiHole-AI version.",
                "Upgrade PiHole-AI before installing or upgrading services.",
            )
        )
    except MigrationError:
        issues.append(
            _preflight_issue(
                "install.database.incompatible",
                "error",
                "Events database schema is incompatible.",
                "Run: pihole-ai db status",
            )
        )
    except OSError:
        issues.append(
            _preflight_issue(
                "install.database.inaccessible",
                "error",
                "Events database path could not be inspected.",
                "Check EVENTS_DB_PATH parent permissions.",
            )
        )
    except sqlite3.Error:
        issues.append(
            _preflight_issue(
                "install.database.sqlite_error",
                "error",
                "Events database status could not be read.",
                "Run: pihole-ai db status",
            )
        )


def _check_pihole_db_access(
    plan: InstallPlan,
    issues: list[PreflightIssue],
) -> None:
    try:
        config, _result = load_config_with_result(mode=ValidationMode.SYNTAX)
    except OSError:
        return

    if config is None or not config.pihole_db.exists():
        return

    try:
        db_stat = config.pihole_db.stat()
        parent_stat = config.pihole_db.parent.stat()
    except OSError:
        return

    file_mode = db_stat.st_mode
    parent_mode = parent_stat.st_mode
    other_can_read = bool(file_mode & stat.S_IROTH)
    group_can_read = bool(file_mode & stat.S_IRGRP)
    other_can_traverse = bool(parent_mode & stat.S_IXOTH)
    group_can_traverse = bool(parent_mode & stat.S_IXGRP)

    if other_can_read and other_can_traverse:
        return

    if group_can_read and group_can_traverse:
        try:
            group_name = grp.getgrgid(db_stat.st_gid).gr_name
        except KeyError:
            issues.append(
                _preflight_issue(
                    "install.pihole_group.missing",
                    "error",
                    "Pi-hole database group could not be resolved.",
                    "Check Pi-hole database group ownership.",
                )
            )
            return

        issues.append(
            _preflight_issue(
                "install.pihole_group.membership.required",
                "warning",
                "PiHole-AI service user needs membership in the Pi-hole database group.",
                f"Installer will add {plan.service_user} to group {group_name}.",
                {"group": group_name},
                blocking=False,
            )
        )
        return

    issues.append(
        _preflight_issue(
            "install.pihole_db.no_service_access",
            "error",
            "Pi-hole database permissions do not expose a safe read group for PiHole-AI.",
            "Grant read/traverse access through a dedicated Pi-hole group; do not make the database world-writable.",
        )
    )


def _pihole_read_group() -> str | None:
    try:
        config, _result = load_config_with_result(mode=ValidationMode.SYNTAX)
    except OSError:
        return None

    if config is None or not config.pihole_db.exists():
        return None

    try:
        db_stat = config.pihole_db.stat()
    except OSError:
        return None

    if not (db_stat.st_mode & stat.S_IRGRP):
        return None

    try:
        return grp.getgrgid(db_stat.st_gid).gr_name
    except KeyError:
        return None


def _check_unit_conflicts(
    plan: InstallPlan,
    issues: list[PreflightIssue],
) -> None:
    for name, path in plan.unit_paths.items():
        if path.exists() and not _is_managed_content(path.read_text(encoding="utf-8")):
            issues.append(
                _preflight_issue(
                    "install.unit.unmanaged_conflict",
                    "error",
                    f"{name} exists but is not managed by PiHole-AI.",
                    "Move or remove the conflicting unit file before installing.",
                    {"path": str(path)},
                )
            )


def _check_install_disk_space(
    plan: InstallPlan,
    issues: list[PreflightIssue],
) -> None:
    try:
        usage = shutil.disk_usage(plan.layout.data_dir.parent)
    except OSError:
        return

    if usage.free < 100 * 1024 * 1024:
        issues.append(
            _preflight_issue(
                "install.disk_space.low",
                "warning",
                "Less than 100 MB is available for PiHole-AI data.",
                "Free disk space before installing.",
                {"free_bytes": usage.free},
            )
        )


@contextmanager
def lifecycle_lock(
    operation: str,
    layout: InstallationLayout | None = None,
    dry_run: bool = False,
):
    """
    Hold an exclusive OS lock for mutating lifecycle operations.
    """

    if dry_run:
        yield
        return

    runtime_layout = layout or InstallationLayout()
    lock_path = runtime_layout.runtime_dir / "lifecycle.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    with lock_path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ServiceError(
                "Another PiHole-AI lifecycle operation is already running."
            ) from exc

        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()} operation={operation}\n")
        handle.flush()
        os.fsync(handle.fileno())

        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _enforce_preflight(
    plan: InstallPlan,
    operation: str,
    dry_run: bool,
) -> PreflightResult:
    result = run_preflight(
        plan,
        require_root=True,
        dry_run=dry_run,
    )

    if result.blocking_count and dry_run:
        _print_preflight_failures(
            operation=operation,
            result=result,
        )

    if result.blocking_count and not dry_run:
        _print_preflight_failures(
            operation=operation,
            result=result,
        )
        raise ServiceError(
            f"{operation} preflight failed. No changes were made."
        )

    return result


def _enforce_service_control_preflight(
    operation: str,
    dry_run: bool,
) -> None:
    issues: list[PreflightIssue] = []

    if shutil.which("systemctl") is None:
        issues.append(
            _preflight_issue(
                "install.systemctl.unavailable",
                "error",
                "systemctl was not found.",
                "Run this command on the Pi-hole systemd host.",
            )
        )

    if not dry_run and _effective_uid() != 0:
        issues.append(
            _preflight_issue(
                "install.privileges.required",
                "error",
                "This command requires root privileges.",
                f"Re-run this command with sudo: sudo pihole-ai {operation}",
            )
        )

    result = PreflightResult(issues)

    if result.blocking_count and not dry_run:
        _print_preflight_failures(operation, result)
        raise ServiceError(
            f"{operation} preflight failed. No changes were made."
        )


def _print_preflight_failures(
    operation: str,
    result: PreflightResult,
) -> None:
    print(f"PiHole-AI {operation} preflight failed:")

    for issue in result.issues:
        if not issue.blocking:
            continue
        print(f"- [{issue.code}] {issue.summary}")
        print(f"  fix: {issue.remediation}")


def _ensure_service_identity(
    user: str,
    group: str,
    dry_run: bool,
) -> list[str]:
    actions: list[str] = []

    if not _group_exists(group):
        command = [_command_path("groupadd"), "--system", group]
        _run_command(command, dry_run=dry_run)
        actions.append(f"created group {group}")

    if not _user_exists(user):
        command = [
            _command_path("useradd"),
            "--system",
            "--gid",
            group,
            "--home-dir",
            str(RUNTIME_DATA_DIR),
            "--no-create-home",
            "--shell",
            _nologin_shell(),
            user,
        ]
        _run_command(command, dry_run=dry_run)
        actions.append(f"created user {user}")

    return actions


def _ensure_pihole_group_access(
    user: str,
    dry_run: bool,
) -> list[str]:
    group = _pihole_read_group()

    if group is None or group == DEFAULT_SERVICE_GROUP:
        return []

    command = [_command_path("usermod"), "-a", "-G", group, user]
    _run_command(command, dry_run=dry_run)
    return [f"added {user} to group {group}"]


def _group_exists(
    group: str,
) -> bool:
    try:
        grp.getgrnam(group)
        return True
    except KeyError:
        return False


def _user_exists(
    user: str,
) -> bool:
    try:
        pwd.getpwnam(user)
        return True
    except KeyError:
        return False


def _command_path(
    name: str,
) -> str:
    return shutil.which(name) or name


def _nologin_shell() -> str:
    for candidate in ("/usr/sbin/nologin", "/sbin/nologin"):
        if Path(candidate).exists():
            return candidate

    return "/usr/sbin/nologin"


def _validate_managed_directory(
    path: Path,
) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return

    if stat.S_ISLNK(info.st_mode):
        raise ServiceError(
            f"Refusing to manage symlink path: {path}"
        )

    if not stat.S_ISDIR(info.st_mode):
        raise ServiceError(
            f"Expected directory path is not a directory: {path}"
        )


def _legacy_status(
    project_dir: Path,
    unit_paths: dict[str, Path],
) -> dict[str, Any]:
    project_env = project_dir / ".env"
    project_db = project_dir / "data" / "events.db"
    units_reference_venv = False
    units_run_as_dev_user = False

    def exists(path: Path) -> bool:
        try:
            return path.exists()
        except OSError:
            return False

    for path in unit_paths.values():
        if not exists(path):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        units_reference_venv = units_reference_venv or ".venv" in content
        units_run_as_dev_user = units_run_as_dev_user or f"User={_current_service_user()}" in content

    project_env_exists = exists(project_env)
    project_db_exists = exists(project_db)
    detected = project_env_exists or project_db_exists or units_reference_venv

    return {
        "detected": detected,
        "project_dir": str(project_dir),
        "project_env": str(project_env) if project_env_exists else None,
        "project_database": str(project_db) if project_db_exists else None,
        "services_reference_venv": units_reference_venv,
        "services_run_as_development_user": units_run_as_dev_user,
        "remediation": (
            "Legacy source-checkout layout detected. Preserve it until a future "
            "migration command moves data into appliance paths."
            if detected
            else None
        ),
    }


def service_install(
    dry_run: bool = False,
    as_json: bool = False,
    enable_services: bool = True,
    start_services: bool = True,
    systemd_dir: str | Path = SYSTEMD_DIR,
    python_path: str | None = None,
    project_dir: str | Path | None = None,
    create_wrapper: bool = True,
    wrapper_path: str | Path = WRAPPER_PATH,
    config_dir: str | Path = CONFIG_DIR,
    data_dir: str | Path = RUNTIME_DATA_DIR,
    log_dir: str | Path = RUNTIME_LOG_DIR,
    env_file: str | Path | None = None,
    runtime_db_path: str | Path | None = None,
    runtime_log_path: str | Path | None = None,
) -> InstallResult:
    """
    Install PiHole-AI systemd services.
    """

    layout = InstallationLayout(
        config_dir=Path(config_dir),
        config_file=Path(env_file or Path(config_dir) / "pihole-ai.env"),
        data_dir=Path(data_dir),
        events_db=Path(runtime_db_path or Path(data_dir) / "events.db"),
        log_dir=Path(log_dir),
        log_file=Path(runtime_log_path or Path(log_dir) / "pihole-ai.log"),
        runtime_dir=RUNTIME_STATE_DIR,
        systemd_dir=Path(systemd_dir),
        wrapper_path=Path(wrapper_path),
    )
    plan = build_install_plan(
        python_path=python_path,
        project_dir=project_dir,
        layout=layout,
        enable_services=enable_services,
        start_services=start_services,
    )
    target = plan.layout.systemd_dir
    project = plan.project_dir
    config_path = plan.layout.config_dir
    data_path = plan.layout.data_dir
    log_path = plan.layout.log_dir
    environment_file = plan.layout.config_file
    database_path = plan.layout.events_db
    log_file = plan.layout.log_file
    service_user = plan.service_user
    service_group = plan.service_group
    units = generated_units(
        python_path=str(plan.python_path),
        project_dir=project,
        env_file=environment_file,
        user=service_user,
        group=service_group,
        layout=layout,
    )
    actions: list[str] = []
    preserved: list[str] = []

    print("Installing PiHole-AI systemd service files.")
    _enforce_preflight(plan, "install", dry_run)

    with lifecycle_lock("install", layout=layout, dry_run=dry_run):
        actions.extend(
            _ensure_service_identity(
                user=service_user,
                group=service_group,
                dry_run=dry_run,
            )
        )
        actions.extend(
            _ensure_pihole_group_access(
                user=service_user,
                dry_run=dry_run,
            )
        )

        _prepare_runtime_layout(
            project_dir=project,
            config_dir=config_path,
            data_dir=data_path,
            log_dir=log_path,
            env_file=environment_file,
            runtime_db_path=database_path,
            runtime_log_path=log_file,
            user=service_user,
            group=service_group,
            dry_run=dry_run,
        )

        if not dry_run:
            _validate_managed_directory(target)
            target.mkdir(
                parents=True,
                exist_ok=True,
            )
            actions.append(f"created {target}")

        for name, content in units.items():
            path = target / name

            if dry_run:
                print(f"Would write {path}:")
                print(content)

            else:
                _atomic_write_managed(
                    path=path,
                    content=content,
                    mode=0o644,
                    backup=True,
                )
                print(f"Wrote {path}.")
                actions.append(f"wrote {path}")

        if create_wrapper:
            _write_launcher(
                path=Path(wrapper_path),
                project_dir=project,
                executable_path=plan.executable_path,
                dry_run=dry_run,
            )
            actions.append(f"wrote {wrapper_path}")

        if not dry_run:
            _initialize_database(database_path)
            actions.append(f"migrated {database_path}")

        _run_systemctl(
            ["daemon-reload"],
            dry_run=dry_run,
        )
        actions.append("systemctl daemon-reload")

        if enable_services:
            _run_systemctl(
                ["enable", *SERVICE_NAMES],
                dry_run=dry_run,
            )
            actions.append("enabled services")

        if start_services:
            _run_systemctl(
                ["start", *START_ORDER],
                dry_run=dry_run,
            )
            actions.append("started services")

    if dry_run:
        print("Dry-run complete. No systemd files were changed.")

    else:
        print("Install complete. Run 'pihole-ai enable' and 'pihole-ai start' next.")

    result = InstallResult(
        command="install",
        changed=not dry_run,
        dry_run=dry_run,
        actions=actions,
        preserved_paths=preserved,
    )

    if as_json:
        print(json.dumps(result.to_dict(), sort_keys=True))

    return result


def service_uninstall(
    dry_run: bool = False,
    as_json: bool = False,
    purge: bool = False,
    confirm_purge: bool = False,
    systemd_dir: str | Path = SYSTEMD_DIR,
    project_dir: str | Path | None = None,
    wrapper_path: str | Path = WRAPPER_PATH,
) -> InstallResult:
    """
    Stop, disable, and remove PiHole-AI systemd services.
    """

    print("Uninstalling PiHole-AI systemd service files.")

    if purge and not confirm_purge:
        raise ServiceError(
            "Purge requires explicit confirmation.\n"
            "Run: sudo /usr/local/bin/pihole-ai uninstall --purge --confirm-purge"
        )

    plan = build_install_plan(
        project_dir=project_dir,
        layout=InstallationLayout(
            systemd_dir=Path(systemd_dir),
            wrapper_path=Path(wrapper_path),
        ),
        enable_services=False,
        start_services=False,
        validate_executable=False,
    )
    _enforce_preflight(plan, "uninstall", dry_run)
    actions: list[str] = []
    removed: list[str] = []
    preserved = [
        str(CONFIG_FILE),
        str(RUNTIME_DB_PATH),
        str(RUNTIME_DATA_DIR),
    ]

    with lifecycle_lock("uninstall", layout=plan.layout, dry_run=dry_run):
        _run_systemctl(
            ["disable", "--now", *SERVICE_NAMES],
            dry_run=dry_run,
        )
        actions.append("disabled and stopped services")

        for name in SERVICE_NAMES:
            path = Path(systemd_dir) / name

            if dry_run:
                print(f"Would remove {path}.")

            elif path.exists():
                path.unlink()
                print(f"Removed {path}.")
                removed.append(str(path))

        _remove_launcher(
            path=Path(wrapper_path),
            project_dir=plan.project_dir,
            executable_path=plan.executable_path,
            dry_run=dry_run,
        )

        _run_systemctl(
            ["daemon-reload"],
            dry_run=dry_run,
        )
        actions.append("systemctl daemon-reload")

        if purge:
            for path in (RUNTIME_LOG_DIR,):
                if dry_run:
                    print(f"Would purge {path}.")
                elif path.exists():
                    shutil.rmtree(path)
                    removed.append(str(path))

    print("Preserved configuration and data by default.")

    result = InstallResult(
        command="uninstall",
        changed=not dry_run,
        dry_run=dry_run,
        actions=actions,
        preserved_paths=preserved,
        removed_paths=removed,
    )

    if as_json:
        print(json.dumps(result.to_dict(), sort_keys=True))

    return result


def service_upgrade(
    dry_run: bool = False,
    as_json: bool = False,
    systemd_dir: str | Path = SYSTEMD_DIR,
    python_path: str | None = None,
    project_dir: str | Path | None = None,
) -> InstallResult:
    """
    Safely refresh managed units and apply pending DB migrations.
    """

    plan = build_install_plan(
        python_path=python_path,
        project_dir=project_dir,
        layout=InstallationLayout(systemd_dir=Path(systemd_dir)),
        enable_services=False,
        start_services=False,
    )
    print("Upgrading PiHole-AI appliance files.")
    _enforce_preflight(plan, "upgrade", dry_run)
    actions: list[str] = []
    preserved: list[str] = [str(plan.layout.config_file), str(plan.layout.events_db)]
    previous_states = {
        name: _service_state(name, dry_run=dry_run)
        for name in SERVICE_NAMES
    }
    backups: dict[Path, str] = {}

    try:
        with lifecycle_lock("upgrade", layout=plan.layout, dry_run=dry_run):
            if not dry_run:
                database_status(plan.layout.events_db)

            units = generated_units(
                python_path=str(plan.python_path),
                project_dir=plan.project_dir,
                env_file=plan.layout.config_file,
                user=plan.service_user,
                group=plan.service_group,
                layout=plan.layout,
            )

            for name, content in units.items():
                path = plan.unit_paths[name]

                if dry_run:
                    print(f"Would update {path}.")
                    continue

                if path.exists():
                    backups[path] = path.read_text(encoding="utf-8")

                _atomic_write_managed(
                    path=path,
                    content=content,
                    mode=0o644,
                    backup=True,
                )
                actions.append(f"updated {path}")

            if not dry_run:
                _initialize_database(plan.layout.events_db)
                actions.append(f"migrated {plan.layout.events_db}")

            _run_systemctl(["daemon-reload"], dry_run=dry_run)
            actions.append("systemctl daemon-reload")

            _restore_service_states(previous_states, dry_run=dry_run)

    except Exception:
        for path, content in backups.items():
            try:
                _atomic_write_managed(
                    path=path,
                    content=content,
                    mode=0o644,
                    backup=False,
                )
            except Exception:
                pass
        _restore_service_states(previous_states, dry_run=dry_run)
        raise

    result = InstallResult(
        command="upgrade",
        changed=not dry_run,
        dry_run=dry_run,
        actions=actions,
        preserved_paths=preserved,
    )

    if as_json:
        print(json.dumps(result.to_dict(), sort_keys=True))

    return result


def service_enable(
    dry_run: bool = False,
) -> None:
    """
    Enable PiHole-AI services at boot.
    """

    print("Enabling PiHole-AI services at boot.")
    _enforce_service_control_preflight("enable", dry_run)
    plan = build_install_plan(
        enable_services=False,
        start_services=False,
        validate_executable=False,
    )

    with lifecycle_lock("enable", layout=plan.layout, dry_run=dry_run):
        _run_systemctl(
            ["enable", *SERVICE_NAMES],
            dry_run=dry_run,
        )


def service_disable(
    dry_run: bool = False,
) -> None:
    """
    Disable PiHole-AI services at boot.
    """

    print("Disabling PiHole-AI services at boot.")
    _enforce_service_control_preflight("disable", dry_run)
    plan = build_install_plan(
        enable_services=False,
        start_services=False,
        validate_executable=False,
    )

    with lifecycle_lock("disable", layout=plan.layout, dry_run=dry_run):
        _run_systemctl(
            ["disable", *SERVICE_NAMES],
            dry_run=dry_run,
        )


def service_action(
    action: str,
    dry_run: bool = False,
) -> None:
    """
    Run a systemctl action against all PiHole-AI services.
    """

    if action not in {"start", "stop", "restart"}:
        raise ValueError(
            f"Unsupported service action: {action}"
        )

    labels = {
        "start": "Starting",
        "stop": "Stopping",
        "restart": "Restarting",
    }
    print(f"{labels[action]} PiHole-AI services.")
    _enforce_service_control_preflight(action, dry_run)
    plan = build_install_plan(
        enable_services=False,
        start_services=False,
        validate_executable=False,
    )

    with lifecycle_lock(action, layout=plan.layout, dry_run=dry_run):
        if action == "start":
            for name in START_ORDER:
                _run_systemctl([action, name], dry_run=dry_run)
        elif action == "stop":
            for name in STOP_ORDER:
                _run_systemctl([action, name], dry_run=dry_run)
        else:
            _run_systemctl(
                [action, *SERVICE_NAMES],
                dry_run=dry_run,
            )


def service_status(
    include_ollama: bool = True,
    dry_run: bool = False,
) -> None:
    """
    Print service state and PiHole-AI project/database status.
    """

    print("PiHole-AI appliance status")
    print("Services:")

    states = {
        name: _service_state(name, dry_run=dry_run)
        for name in SERVICE_NAMES
    }

    for name, state in states.items():
        print(
            f"  {name}: active={state['active']} enabled={state['enabled']}"
        )

    from pihole_ai.status import collect_status

    status = collect_status(
        include_ollama=include_ollama,
    )
    database = status["database"]
    collector = status["collector"]
    ai = status["ai"]
    config = status["config"]

    print("Project:")
    print(f"  events_db: {config['events_db']}")
    print(f"  pihole_db: {config['pihole_db']}")
    print(f"  dashboard_port: {config['dashboard_port']}")
    print("Database:")
    print(f"  events: {database['events']}")
    print(f"  processed: {database['processed']}")
    print(f"  domains: {database['domains']}")
    print(f"  analyses: {database['analyses']}")
    print(f"  actions: {database.get('actions', 0)}")
    print(f"  reputations: {database.get('reputations', 0)}")
    print(f"  threat_intel: {database.get('threat_intel', 0)}")
    print(f"  collector.last_query_id: {collector['last_query_id']}")
    print("AI:")
    print(f"  enabled: {config['ai_enabled']}")
    print(f"  max_calls_per_minute: {config['ai_max_calls_per_minute']}")
    print(f"  cooldown_seconds: {config['ai_cooldown_seconds']}")
    print(f"  timeout_seconds: {config['ai_timeout_seconds']}")
    print(f"  ai_calls: {ai['ai_calls']}")
    print(f"  ai_skipped: {ai['ai_skipped']}")
    print(f"  ai_parse_errors: {ai['ai_parse_errors']}")
    print(f"  ai_timeouts: {ai['ai_timeouts']}")

    if include_ollama and "ollama" in status:
        ollama = status["ollama"]
        print("Ollama:")
        print(f"  available: {ollama['available']}")
        print(f"  host: {ollama['host']}")
        print(f"  model: {ollama['model']}")

        if "error" in ollama:
            print(f"  error: {ollama['error']}")


def service_logs(
    lines: int = 80,
    follow: bool = False,
    dry_run: bool = False,
) -> None:
    """
    Show journal logs for PiHole-AI services.
    """

    command = [
        "journalctl",
        "--no-pager",
        *[
            item
            for name in SERVICE_NAMES
            for item in ("-u", name)
        ],
        "-n",
        str(lines),
    ]

    if follow:
        command.append("-f")

    print("Showing PiHole-AI service logs.")

    try:
        _run_command(
            command,
            dry_run=dry_run,
        )

    except KeyboardInterrupt:
        print("")
        print("Stopped log tail.")


def _service_state(
    name: str,
    dry_run: bool,
) -> dict[str, str]:
    """
    Return active/enabled state for one service.
    """

    if dry_run:
        print(f"Would run: systemctl is-active {shlex.quote(name)}")
        print(f"Would run: systemctl is-enabled {shlex.quote(name)}")
        return {
            "active": "dry-run",
            "enabled": "dry-run",
        }

    return {
        "active": _run_capture(
            ["systemctl", "is-active", name],
        ),
        "enabled": _run_capture(
            ["systemctl", "is-enabled", name],
        ),
    }


def _run_capture(
    command: list[str],
) -> str:
    """
    Run a status command and return stdout or a useful fallback.
    """

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = completed.stdout.strip() or completed.stderr.strip()
    except subprocess.TimeoutExpired:
        return "timeout"
    except FileNotFoundError:
        return "missing"

    if output:
        return output

    return "unknown"


def _prepare_runtime_layout(
    project_dir: Path,
    config_dir: Path,
    data_dir: Path,
    log_dir: Path,
    env_file: Path,
    runtime_db_path: Path,
    runtime_log_path: Path,
    user: str,
    group: str,
    dry_run: bool,
) -> None:
    """
    Create standard Linux runtime paths and migrate project data if needed.
    """

    for directory in (config_dir, data_dir, log_dir):
        if dry_run:
            print(f"Would create {directory}.")
        else:
            _validate_managed_directory(directory)
            directory.mkdir(
                parents=True,
                exist_ok=True,
            )
            os.chmod(directory, 0o750)
            print(f"Ensured {directory}.")

    _ensure_runtime_env(
        project_dir=project_dir,
        env_file=env_file,
        runtime_db_path=runtime_db_path,
        runtime_log_path=runtime_log_path,
        dry_run=dry_run,
    )
    _migrate_project_database(
        project_dir=project_dir,
        runtime_db_path=runtime_db_path,
        dry_run=dry_run,
    )
    _chown_runtime_paths(
        paths=[data_dir, log_dir],
        user=user,
        group=group,
        dry_run=dry_run,
    )


def _ensure_runtime_env(
    project_dir: Path,
    env_file: Path,
    runtime_db_path: Path,
    runtime_log_path: Path,
    dry_run: bool,
) -> None:
    """
    Create the runtime environment file once.
    """

    try:
        env_file_exists = env_file.exists()
    except OSError as exc:
        if dry_run:
            print(f"Cannot inspect {env_file}: {exc}")
            print(f"Would leave {env_file} unchanged if it already exists.")
            return
        raise ServiceError(
            f"Cannot inspect {env_file}: {exc}"
        ) from exc

    if env_file_exists:
        print(f"Kept existing {env_file}.")
        return

    content = _runtime_env_content(
        project_dir=project_dir,
        runtime_db_path=runtime_db_path,
        runtime_log_path=runtime_log_path,
    )

    if dry_run:
        print(f"Would write {env_file}:")
        print(content)
        return

    env_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    _atomic_write_managed(
        path=env_file,
        content=MANAGED_FILE_HEADER + content,
        mode=0o640,
        backup=False,
    )
    print(f"Wrote {env_file}.")


def _runtime_env_content(
    project_dir: Path,
    runtime_db_path: Path,
    runtime_log_path: Path,
) -> str:
    """
    Build initial /etc/pihole-ai/pihole-ai.env content.
    """

    example = project_dir / ".env.example"

    if example.exists():
        lines = example.read_text(encoding="utf-8").splitlines()
    else:
        packaged = resources.files("pihole_ai.defaults").joinpath("pihole-ai.env")
        lines = packaged.read_text(encoding="utf-8").splitlines()

    normalized = _upsert_env_line(
        lines=lines,
        key="EVENTS_DB_PATH",
        value=str(runtime_db_path),
    )
    normalized = _upsert_env_line(
        lines=normalized,
        key="LOG_PATH",
        value=str(runtime_log_path),
    )
    for key, value in {
        "PIHOLE_AI_DASHBOARD_AUTH_ENABLED": "true",
        "PIHOLE_AI_DASHBOARD_USERNAME": "admin",
        "PIHOLE_AI_DASHBOARD_PASSWORD_HASH": "",
        "PIHOLE_AI_DASHBOARD_SECRET_KEY": secrets.token_urlsafe(48),
        "PIHOLE_AI_DASHBOARD_SESSION_LIFETIME_MINUTES": "480",
        "PIHOLE_AI_DASHBOARD_TRUST_PROXY": "false",
    }.items():
        normalized = _upsert_env_line(
            lines=normalized,
            key=key,
            value=value,
        )

    return "\n".join(normalized).rstrip() + "\n"


def _upsert_env_line(
    lines: list[str],
    key: str,
    value: str,
) -> list[str]:
    """
    Replace or append one KEY=value line.
    """

    prefix = f"{key}="
    updated: list[str] = []
    replaced = False

    for line in lines:
        if line.startswith(prefix):
            updated.append(f"{key}={value}")
            replaced = True
        else:
            updated.append(line)

    if not replaced:
        updated.append(f"{key}={value}")

    return updated


def _atomic_write_managed(
    path: Path,
    content: str,
    mode: int,
    backup: bool,
) -> None:
    """
    Atomically write a managed file and protect unrelated existing files.
    """

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if path.exists():
        existing = path.read_text(encoding="utf-8")

        if not _is_managed_content(existing):
            raise ServiceError(
                f"Refusing to overwrite unmanaged file: {path}"
            )

        if existing == content:
            return

        if backup:
            backup_path = path.with_suffix(path.suffix + ".bak")
            _atomic_replace(
                path=backup_path,
                content=existing,
                mode=mode,
            )

    _atomic_replace(
        path=path,
        content=content,
        mode=mode,
    )


def _atomic_replace(
    path: Path,
    content: str,
    mode: int,
) -> None:
    """
    Write content to a temp file in the destination directory and replace.
    """

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
        os.replace(tmp_path, path)

    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def _is_managed_content(
    content: str,
) -> bool:
    return "PiHole-AI" in content and MANAGED_FILE_MARKER in content


def _sha256(
    content: str,
) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _migrate_project_database(
    project_dir: Path,
    runtime_db_path: Path,
    dry_run: bool,
) -> None:
    """
    Copy the old project database into the runtime data directory once.
    """

    old_db = project_dir / "data" / "events.db"

    try:
        old_db_exists = old_db.exists()
    except OSError as exc:
        if dry_run:
            print(f"Cannot inspect {old_db}: {exc}")
            print("Would skip project database migration check.")
            return
        raise ServiceError(
            f"Cannot inspect existing project database {old_db}: {exc}"
        ) from exc

    if not old_db_exists:
        return

    try:
        runtime_db_exists = runtime_db_path.exists()
    except OSError as exc:
        if dry_run:
            print(f"Cannot inspect {runtime_db_path}: {exc}")
            print("Would leave runtime database unchanged if it already exists.")
            return
        raise ServiceError(
            f"Cannot inspect runtime database {runtime_db_path}: {exc}"
        ) from exc

    if runtime_db_exists:
        return

    message = (
        "Migrating existing project database: "
        f"{old_db} -> {runtime_db_path}"
    )

    if dry_run:
        print(
            "Would migrate existing project database: "
            f"{old_db} -> {runtime_db_path}."
        )
        return

    runtime_db_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    shutil.copy2(
        old_db,
        runtime_db_path,
    )
    print(f"{message}.")
    print(f"Kept old project database at {old_db}.")


def _initialize_database(
    database_path: Path,
) -> None:
    """
    Initialize or migrate the events database with clear failure behavior.
    """

    try:
        migrate_database(database_path)
    except sqlite3.DatabaseError:
        print(
            "Skipped database migration because existing file is not a valid "
            f"SQLite database: {database_path}."
        )


def _chown_runtime_paths(
    paths: list[Path],
    user: str,
    group: str,
    dry_run: bool,
) -> None:
    """
    Give service user ownership of runtime directories.
    """

    target = f"{user}:{group}"

    for path in paths:
        if not dry_run:
            _validate_managed_directory(path)
        command = [
            "chown",
            target,
            str(path),
        ]
        _run_command(
            command,
            dry_run=dry_run,
        )


def _restore_service_states(
    states: dict[str, dict[str, str]],
    dry_run: bool,
) -> None:
    for name, state in states.items():
        if state.get("enabled") == "enabled":
            _run_systemctl(["enable", name], dry_run=dry_run)
        elif state.get("enabled") == "disabled":
            _run_systemctl(["disable", name], dry_run=dry_run)

    for name, state in states.items():
        if state.get("active") == "active":
            _run_systemctl(["start", name], dry_run=dry_run)
        elif state.get("active") == "inactive":
            _run_systemctl(["stop", name], dry_run=dry_run)


def _run_systemctl(
    arguments: list[str],
    dry_run: bool,
) -> None:
    """
    Run systemctl with arguments.
    """

    _run_command(
        ["systemctl", *arguments],
        dry_run=dry_run,
    )


def _run_command(
    command: list[str],
    dry_run: bool,
) -> None:
    """
    Run or print a command.
    """

    printable = " ".join(
        shlex.quote(part)
        for part in command
    )

    if dry_run:
        print(f"Would run: {printable}")
        return

    try:
        subprocess.run(
            command,
            check=True,
        )

    except FileNotFoundError as exc:
        raise ServiceError(
            f"Command not found: {command[0]}"
        ) from exc

    except subprocess.CalledProcessError as exc:
        stderr = getattr(exc, "stderr", "") or ""
        stdout = getattr(exc, "stdout", "") or ""
        detail = stderr or stdout
        hint = ""

        if "authentication" in detail.lower() or "permission" in detail.lower():
            hint = "\nThis looks like a permissions/authentication failure. Re-run with sudo."

        raise ServiceError(
            "Command failed: "
            f"{printable}\n"
            f"Exit code: {exc.returncode}"
            f"{hint}"
        ) from exc

    except subprocess.TimeoutExpired as exc:
        raise ServiceError(
            "Command timed out: "
            f"{printable}"
        ) from exc


def _require_root(
    dry_run: bool,
    sudo_command: str,
) -> None:
    """
    Stop write/service actions early when sudo is required.
    """

    if dry_run:
        return

    if _effective_uid() != 0:
        raise ServiceError(
            "This command needs sudo.\n"
            f"Run: {sudo_command}"
        )


def _effective_uid() -> int:
    get_euid = getattr(os, "geteuid", None)

    if get_euid is None:
        return 0

    return int(get_euid())


def launcher_target(
    project_dir: str | Path | None = None,
    executable_path: str | Path | None = None,
) -> Path:
    """
    Return the installed pihole-ai executable.
    """

    if executable_path is not None:
        return _absolute_path(executable_path)

    return _absolute_path(project_dir or Path.cwd()) / ".venv" / "bin" / "pihole-ai"


def launcher_content(
    project_dir: str | Path | None = None,
    executable_path: str | Path | None = None,
) -> str:
    """
    Return managed /usr/local/bin launcher content.
    """

    project = _absolute_path(project_dir or Path.cwd())
    target = launcher_target(project, executable_path=executable_path)

    return "\n".join(
        [
            "#!/bin/sh",
            MANAGED_FILE_HEADER.rstrip(),
            f"# Project: {project}",
            f"# Target: {target}",
            f"exec {shlex.quote(str(target))} \"$@\"",
            "",
        ]
    )


def _write_launcher(
    path: Path,
    project_dir: str | Path,
    executable_path: str | Path,
    dry_run: bool,
) -> None:
    """
    Write the global PiHole-AI launcher into /usr/local/bin.
    """

    content = launcher_content(
        project_dir,
        executable_path=executable_path,
    )

    if dry_run:
        print(f"Would write {path}:")
        print(content)
        return

    _atomic_write_managed(
        path=path,
        content=content,
        mode=0o755,
        backup=True,
    )
    print(f"Wrote {path}.")


def _remove_launcher(
    path: Path,
    project_dir: str | Path,
    executable_path: str | Path,
    dry_run: bool,
) -> None:
    """
    Remove the global launcher only when it belongs to this project.
    """

    if dry_run:
        print(f"Would remove {path} if it points to this project.")
        return

    if not path.exists():
        return

    content = path.read_text(encoding="utf-8")

    if _launcher_matches_project(
        content=content,
        project_dir=project_dir,
        executable_path=executable_path,
    ):
        path.unlink()
        print(f"Removed {path}.")

    else:
        print(f"Kept {path}; it does not point to this project.")


def _launcher_matches_project(
    content: str,
    project_dir: str | Path,
    executable_path: str | Path | None = None,
) -> bool:
    """
    Return True if launcher content was generated for this project.
    """

    project = _absolute_path(project_dir)
    target = launcher_target(
        project,
        executable_path=executable_path,
    )
    legacy_target = launcher_target(project)

    return (
        MANAGED_FILE_MARKER in content
        and f"# Project: {project}" in content
        and (
            f"# Target: {target}" in content
            or f"# Target: {legacy_target}" in content
        )
    )


def _current_service_user() -> str:
    """
    Prefer the original sudo user so services do not write root-owned logs.
    """

    sudo_user = os.getenv("SUDO_USER")

    if sudo_user and sudo_user != "root":
        return sudo_user

    try:
        import getpass

        return getpass.getuser()

    except Exception:
        return "root"


def _service_user_for_directory(
    path: Path,
) -> str:
    """
    Prefer the project directory owner when it is not root.
    """

    try:
        import pwd

        owner = pwd.getpwuid(path.stat().st_uid).pw_name

        if owner != "root":
            return owner

    except Exception:
        pass

    return _current_service_user()


def _current_service_group(
    user: str,
) -> str:
    """
    Return the primary group for a service user.
    """

    try:
        import grp
        import pwd

        user_info = pwd.getpwnam(user)

        return grp.getgrgid(user_info.pw_gid).gr_name

    except Exception:
        return user
