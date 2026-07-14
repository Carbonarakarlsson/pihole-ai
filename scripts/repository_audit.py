"""
Run lightweight repository hygiene checks.

This is not a comprehensive secret scanner. It catches common PiHole-AI release
drift: tracked generated files, stale active wheel commands, machine-local paths,
and documentation/config mismatches covered by the checked-in docs.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path


GENERATED_PATTERNS = (
    re.compile(r"(^|/)(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache)(/|$)"),
    re.compile(r"(^|/)(build|dist|htmlcov|\.venv|venv)(/|$)"),
    re.compile(r"\.(pyc|pyo|db|sqlite|sqlite3|log)$"),
    re.compile(r"\.egg-info(/|$)"),
)

ALLOWED_GENERATED = {
    "deploy/systemd/pihole-ai-collector.service",
    "deploy/systemd/pihole-ai-dashboard.service",
    "deploy/systemd/pihole-ai-engine.service",
    "deploy/systemd/pihole-ai-maintenance.service",
    "deploy/systemd/pihole-ai-maintenance.timer",
}

ACTIVE_DOCS = [
    "README.md",
    "docs/OPERATIONS.md",
    "docs/DEVELOPMENT.md",
    "docs/CONFIGURATION.md",
    "docs/CLI_REFERENCE.md",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def tracked_files(root: Path) -> list[str]:
    output = subprocess.check_output(
        ["git", "ls-files"],
        cwd=root,
        text=True,
    )
    return output.splitlines()


def project_version(root: Path) -> str:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def audit(root: Path) -> list[str]:
    errors: list[str] = []
    tracked = tracked_files(root)
    for path in tracked:
        if path in ALLOWED_GENERATED:
            continue
        if any(pattern.search(path) for pattern in GENERATED_PATTERNS):
            errors.append(f"tracked generated artifact: {path}")
        if path.startswith("\"") or path.startswith(":"):
            errors.append(f"suspicious tracked path: {path}")

    version = project_version(root)
    stale_wheel = re.compile(r"pihole_ai-(?!\*)([0-9][A-Za-z0-9.+-]*)-py3-none-any\.whl")
    for doc in ACTIVE_DOCS:
        path = root / doc
        if not path.exists():
            continue
        for match in stale_wheel.finditer(read(path)):
            if match.group(1) != version:
                errors.append(
                    f"{doc}: stale wheel version {match.group(1)}; expected {version}"
                )

    for doc in ACTIVE_DOCS:
        path = root / doc
        if not path.exists():
            continue
        text = read(path)
        if re.search(r"/home/[A-Za-z0-9_.-]+/", text):
            errors.append(f"{doc}: contains developer home path")
        if re.search(r"\b192\.168\.\d+\.\d+\b", text):
            errors.append(f"{doc}: contains private LAN IP")

    config_doc = root / "docs/CONFIGURATION.md"
    if config_doc.exists():
        text = read(config_doc)
        for env_file in (root / ".env.example", root / "pihole_ai/defaults/pihole-ai.env"):
            for line in read(env_file).splitlines():
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key = line.split("=", 1)[0]
                if f"`{key}`" not in text:
                    errors.append(f"docs/CONFIGURATION.md missing {key}")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit repository hygiene.")
    parser.parse_args(argv)
    errors = audit(repo_root())
    if errors:
        print("repository audit failed")
        for error in errors:
            print(f"  {error}")
        return 1
    print("repository audit ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
