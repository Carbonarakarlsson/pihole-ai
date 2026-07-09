"""
Linux systemd service management for PiHole-AI.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
import os
from dataclasses import dataclass
from pathlib import Path


SYSTEMD_DIR = Path("/etc/systemd/system")
WRAPPER_PATH = Path("/usr/local/bin/pihole-ai")
CONFIG_DIR = Path("/etc/pihole-ai")
CONFIG_FILE = CONFIG_DIR / "pihole-ai.env"
RUNTIME_DATA_DIR = Path("/var/lib/pihole-ai")
RUNTIME_LOG_DIR = Path("/var/log/pihole-ai")
RUNTIME_DB_PATH = RUNTIME_DATA_DIR / "events.db"
RUNTIME_LOG_PATH = RUNTIME_LOG_DIR / "pihole-ai.log"

SERVICE_NAMES = [
    "pihole-ai-collector.service",
    "pihole-ai-engine.service",
    "pihole-ai-dashboard.service",
]


@dataclass(frozen=True)
class ServiceDefinition:
    """
    One generated systemd service.
    """

    name: str
    description: str
    command: list[str]
    after: str


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
) -> str:
    """
    Generate systemd unit content for one PiHole-AI service.
    """

    python = python_path or sys.executable
    working_directory = Path(project_dir or Path.cwd()).resolve()
    environment_file = Path(env_file)
    service_user = user or _service_user_for_directory(working_directory)
    service_group = group or _current_service_group(service_user)
    exec_start = " ".join(
        shlex.quote(part)
        for part in [
            python,
            "-m",
            "pihole_ai.cli",
            *service.command,
        ]
    )

    return "\n".join(
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
        )
        for service in SERVICE_DEFINITIONS
    }


def service_install(
    dry_run: bool = False,
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
) -> None:
    """
    Install PiHole-AI systemd services.
    """

    target = Path(systemd_dir)
    project = Path(project_dir or Path.cwd()).resolve()
    config_path = Path(config_dir)
    data_path = Path(data_dir)
    log_path = Path(log_dir)
    environment_file = Path(env_file or config_path / "pihole-ai.env")
    database_path = Path(runtime_db_path or data_path / "events.db")
    log_file = Path(runtime_log_path or log_path / "pihole-ai.log")
    service_user = _service_user_for_directory(project)
    service_group = _current_service_group(service_user)
    units = generated_units(
        python_path=python_path,
        project_dir=project,
        env_file=environment_file,
        user=service_user,
        group=service_group,
    )

    print("Installing PiHole-AI systemd service files.")
    _require_root(
        dry_run=dry_run,
        sudo_command=f"sudo {WRAPPER_PATH} install",
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
        target.mkdir(
            parents=True,
            exist_ok=True,
        )

    for name, content in units.items():
        path = target / name

        if dry_run:
            print(f"Would write {path}:")
            print(content)

        else:
            path.write_text(content, encoding="utf-8")
            print(f"Wrote {path}.")

    if create_wrapper:
        _write_launcher(
            path=Path(wrapper_path),
            project_dir=project,
            dry_run=dry_run,
        )

    _run_systemctl(
        ["daemon-reload"],
        dry_run=dry_run,
    )

    if dry_run:
        print("Dry-run complete. No systemd files were changed.")

    else:
        print("Install complete. Run 'pihole-ai enable' and 'pihole-ai start' next.")


def service_uninstall(
    dry_run: bool = False,
    systemd_dir: str | Path = SYSTEMD_DIR,
    project_dir: str | Path | None = None,
    wrapper_path: str | Path = WRAPPER_PATH,
) -> None:
    """
    Stop, disable, and remove PiHole-AI systemd services.
    """

    print("Uninstalling PiHole-AI systemd service files.")
    _require_root(
        dry_run=dry_run,
        sudo_command=f"sudo {WRAPPER_PATH} uninstall",
    )

    _run_systemctl(
        ["disable", "--now", *SERVICE_NAMES],
        dry_run=dry_run,
    )

    for name in SERVICE_NAMES:
        path = Path(systemd_dir) / name

        if dry_run:
            print(f"Would remove {path}.")

        elif path.exists():
            path.unlink()
            print(f"Removed {path}.")

    _remove_launcher(
        path=Path(wrapper_path),
        project_dir=project_dir or Path.cwd(),
        dry_run=dry_run,
    )

    _run_systemctl(
        ["daemon-reload"],
        dry_run=dry_run,
    )


def service_enable(
    dry_run: bool = False,
) -> None:
    """
    Enable PiHole-AI services at boot.
    """

    print("Enabling PiHole-AI services at boot.")
    _require_root(
        dry_run=dry_run,
        sudo_command=f"sudo {WRAPPER_PATH} enable",
    )

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
    _require_root(
        dry_run=dry_run,
        sudo_command=f"sudo {WRAPPER_PATH} disable",
    )

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
    _require_root(
        dry_run=dry_run,
        sudo_command=f"sudo {WRAPPER_PATH} {action}",
    )

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

    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    output = completed.stdout.strip() or completed.stderr.strip()

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
            directory.mkdir(
                parents=True,
                exist_ok=True,
            )
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

    if env_file.exists():
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
    env_file.write_text(
        content,
        encoding="utf-8",
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
        lines = [
            "PIHOLE_AI_COLLECT_BATCH_SIZE=200",
            "PIHOLE_AI_COLLECT_INTERVAL=2",
            "PIHOLE_AI_ENGINE_BATCH_SIZE=500",
            "PIHOLE_AI_ENGINE_INTERVAL=5",
            "PIHOLE_AI_ACTION_MODE=dry-run",
            "AI_ENABLED=true",
            "AI_MAX_CALLS_PER_MINUTE=2",
            "AI_COOLDOWN_SECONDS=60",
            "AI_TIMEOUT_SECONDS=20",
            "PIHOLE_AI_OLLAMA_URL=http://127.0.0.1:11434",
            "PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b",
            "PIHOLE_AI_DASHBOARD_PORT=8080",
            "LOG_LEVEL=INFO",
        ]

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


def _migrate_project_database(
    project_dir: Path,
    runtime_db_path: Path,
    dry_run: bool,
) -> None:
    """
    Copy the old project database into the runtime data directory once.
    """

    old_db = project_dir / "data" / "events.db"

    if not old_db.exists():
        return

    if runtime_db_path.exists():
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
        command = [
            "chown",
            "-R",
            target,
            str(path),
        ]
        _run_command(
            command,
            dry_run=dry_run,
        )


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
        raise ServiceError(
            "Command failed: "
            f"{printable}\n"
            f"Exit code: {exc.returncode}"
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

    get_euid = getattr(os, "geteuid", None)

    if get_euid is not None and get_euid() != 0:
        raise ServiceError(
            "This command needs sudo.\n"
            f"Run: {sudo_command}"
        )


def launcher_target(
    project_dir: str | Path | None = None,
) -> Path:
    """
    Return the venv pihole-ai executable for a project directory.
    """

    return Path(project_dir or Path.cwd()).resolve() / ".venv" / "bin" / "pihole-ai"


def launcher_content(
    project_dir: str | Path | None = None,
) -> str:
    """
    Return managed /usr/local/bin launcher content.
    """

    project = Path(project_dir or Path.cwd()).resolve()
    target = launcher_target(project)

    return "\n".join(
        [
            "#!/bin/sh",
            "# Managed by PiHole-AI",
            f"# Project: {project}",
            f"# Target: {target}",
            f"exec {shlex.quote(str(target))} \"$@\"",
            "",
        ]
    )


def _write_launcher(
    path: Path,
    project_dir: str | Path,
    dry_run: bool,
) -> None:
    """
    Write the global PiHole-AI launcher into /usr/local/bin.
    """

    content = launcher_content(project_dir)

    if dry_run:
        print(f"Would write {path}:")
        print(content)
        return

    path.write_text(
        content,
        encoding="utf-8",
    )
    path.chmod(0o755)
    print(f"Wrote {path}.")


def _remove_launcher(
    path: Path,
    project_dir: str | Path,
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
    ):
        path.unlink()
        print(f"Removed {path}.")

    else:
        print(f"Kept {path}; it does not point to this project.")


def _launcher_matches_project(
    content: str,
    project_dir: str | Path,
) -> bool:
    """
    Return True if launcher content was generated for this project.
    """

    project = Path(project_dir).resolve()
    target = launcher_target(project)

    return (
        "# Managed by PiHole-AI" in content
        and f"# Project: {project}" in content
        and f"# Target: {target}" in content
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
