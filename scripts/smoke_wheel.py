"""
Install a built wheel into a temporary venv and run RC smoke checks.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


COMMANDS = [
    (["pihole-ai", "--version"], {0}),
    (["pihole-ai", "--help"], {0}),
    (["pihole-ai", "config", "show", "--json"], {0}),
    (["pihole-ai", "config", "check", "--mode", "syntax", "--json"], {0, 1}),
    (["pihole-ai", "install", "--dry-run", "--json"], {0}),
    (["pihole-ai", "setup", "status", "--json", "--skip-ollama-check"], {0, 2}),
]

IMPORTS = [
    "core.config",
    "core.db",
    "core.migrations",
    "pihole_ai.cli",
    "pihole_ai.health",
    "pihole_ai.setup",
    "pihole_ai.service",
    "pihole_ai.dashboard_auth",
    "ui.dashboard",
]


def bin_path(venv_dir: Path, name: str) -> Path:
    return venv_dir / ("Scripts" if os.name == "nt" else "bin") / name


def run(
    command: list[str],
    env: dict[str, str],
    expected_codes: set[int] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, capture_output=True, text=True, env=env)
    if expected_codes is None:
        expected_codes = {0}
    if completed.returncode not in expected_codes:
        raise RuntimeError(
            "Smoke command failed:\n"
            f"  command: {' '.join(command)}\n"
            f"  returncode: {completed.returncode}\n"
            f"  stdout: {completed.stdout}\n"
            f"  stderr: {completed.stderr}"
        )
    return completed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Smoke-test a PiHole-AI wheel.")
    parser.add_argument("wheel", help="Path to built wheel.")
    args = parser.parse_args(argv)
    wheel = Path(args.wheel).resolve()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        venv_dir = tmp / "venv"
        venv.EnvBuilder(with_pip=True, system_site_packages=True).create(venv_dir)
        python = bin_path(venv_dir, "python")
        run([str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)], os.environ.copy())
        env = os.environ.copy()
        env.update(
            {
                "EVENTS_DB_PATH": str(tmp / "events.db"),
                "LOG_PATH": str(tmp / "pihole-ai.log"),
                "PIHOLE_AI_PIHOLE_DB": str(tmp / "pihole-FTL.db"),
                "PIHOLE_AI_DASHBOARD_HOST": "127.0.0.1",
                "PIHOLE_AI_DASHBOARD_AUTH_ENABLED": "false",
            }
        )
        (tmp / "pihole-FTL.db").write_text("", encoding="utf-8")
        cli = bin_path(venv_dir, "pihole-ai")
        for command, expected_codes in COMMANDS:
            completed = run([str(cli), *command[1:]], env, expected_codes)
            if "--json" in command:
                json.loads(completed.stdout)
        imports = "; ".join(f"import {name}" for name in IMPORTS)
        run([str(python), "-c", imports], env)
    print("wheel smoke test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
