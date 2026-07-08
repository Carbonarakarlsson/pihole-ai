"""
Linux systemd service management for PiHole-AI.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from pihole_ai.status import collect_status


SYSTEMD_DIR = Path("/etc/systemd/system")

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


def generate_unit_file(
    service: ServiceDefinition,
    python_path: str | None = None,
    project_dir: str | Path | None = None,
) -> str:
    """
    Generate systemd unit content for one PiHole-AI service.
    """

    python = python_path or sys.executable
    working_directory = Path(project_dir or Path.cwd()).resolve()
    env_file = working_directory / ".env"
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
            f"WorkingDirectory={working_directory}",
            f"EnvironmentFile=-{env_file}",
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
) -> dict[str, str]:
    """
    Return all generated unit file contents.
    """

    return {
        service.name: generate_unit_file(
            service=service,
            python_path=python_path,
            project_dir=project_dir,
        )
        for service in SERVICE_DEFINITIONS
    }


def service_install(
    dry_run: bool = False,
    systemd_dir: str | Path = SYSTEMD_DIR,
    python_path: str | None = None,
    project_dir: str | Path | None = None,
) -> None:
    """
    Install PiHole-AI systemd services.
    """

    target = Path(systemd_dir)
    units = generated_units(
        python_path=python_path,
        project_dir=project_dir,
    )

    print("Installing PiHole-AI systemd service files.")

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
) -> None:
    """
    Stop, disable, and remove PiHole-AI systemd services.
    """

    print("Uninstalling PiHole-AI systemd service files.")

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

    status = collect_status(
        include_ollama=include_ollama,
    )
    database = status["database"]
    collector = status["collector"]
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

    if include_ollama and "ollama" in status:
        ollama = status["ollama"]
        print("Ollama:")
        print(f"  available: {ollama['available']}")
        print(f"  host: {ollama['host']}")
        print(f"  model: {ollama['model']}")

        if "error" in ollama:
            print(f"  error: {ollama['error']}")


def service_logs(
    lines: int = 100,
    follow: bool = False,
    dry_run: bool = False,
) -> None:
    """
    Show journal logs for PiHole-AI services.
    """

    command = [
        "journalctl",
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

    _run_command(
        command,
        dry_run=dry_run,
    )


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

    subprocess.run(
        command,
        check=True,
    )
