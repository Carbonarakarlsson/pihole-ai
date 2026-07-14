"""
Remove known repository-local generated artifacts.

The cleaner is intentionally conservative. It resolves the repository root and
refuses to delete anything outside that tree or any live appliance path.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


LIVE_APPLIANCE_PATHS = {
    Path("/etc/pihole-ai"),
    Path("/var/lib/pihole-ai"),
    Path("/var/log/pihole-ai"),
    Path("/run/pihole-ai"),
    Path("/opt/pihole-ai"),
}

GENERATED_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "build",
    "dist",
    "htmlcov",
}

GENERATED_SUFFIXES = {
    ".egg-info",
}

GENERATED_FILE_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".log",
}

GENERATED_FILE_NAMES = {
    ".coverage",
}

GENERATED_REPO_RELATIVE = {
    "dns_memory.db",
    "domains.db",
    "data/events.db",
    "data/alerts.log",
    "backup/events_old.db",
}


def find_repo_root(start: Path | None = None) -> Path:
    """
    Return the repository root containing .git.
    """

    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError("Could not find repository root")


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def assert_safe_path(path: Path, repo_root: Path) -> None:
    """
    Raise if path is outside the repository or points at a live appliance path.
    """

    resolved = path.resolve()
    if not _is_relative_to(resolved, repo_root):
        raise ValueError(f"Refusing to remove outside repository: {path}")
    for appliance_path in LIVE_APPLIANCE_PATHS:
        if resolved == appliance_path or _is_relative_to(resolved, appliance_path):
            raise ValueError(f"Refusing to remove appliance path: {path}")
    protected_names = {
        ".env.example",
        "pihole-ai.env",
    }
    if resolved.name in protected_names:
        raise ValueError(f"Refusing to remove protected file: {path}")


def cleanup_candidates(repo_root: Path) -> list[Path]:
    """
    Return generated paths that currently exist under repo_root.
    """

    candidates: set[Path] = set()
    ignored_roots = {
        repo_root / ".git",
        repo_root / ".venv",
        repo_root / "venv",
    }

    for relative in GENERATED_REPO_RELATIVE:
        path = repo_root / relative
        if path.exists():
            candidates.add(path)

    for path in repo_root.rglob("*"):
        if any(path == root or _is_relative_to(path, root) for root in ignored_roots):
            continue
        if path.name in GENERATED_DIR_NAMES and path.is_dir():
            candidates.add(path)
            continue
        if any(path.name.endswith(suffix) for suffix in GENERATED_SUFFIXES) and path.is_dir():
            candidates.add(path)
            continue
        if path.name in GENERATED_FILE_NAMES and path.is_file():
            candidates.add(path)
            continue
        if path.suffix in GENERATED_FILE_SUFFIXES and path.is_file():
            candidates.add(path)

    ordered = sorted(candidates, key=lambda item: (len(item.parts), str(item)))
    filtered: list[Path] = []
    for path in ordered:
        if any(_is_relative_to(path, selected) for selected in filtered if selected.is_dir()):
            continue
        filtered.append(path)
    return sorted(filtered, key=lambda item: str(item.relative_to(repo_root)))


def remove_path(path: Path) -> None:
    """
    Remove a generated path.
    """

    if not path.exists():
        return
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Remove known generated files from this repository.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print paths that would be removed without deleting them.",
    )
    args = parser.parse_args(argv)

    try:
        repo_root = find_repo_root()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    candidates = cleanup_candidates(repo_root)
    for path in candidates:
        try:
            assert_safe_path(path, repo_root)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(path.relative_to(repo_root))
        if not args.dry_run:
            remove_path(path)

    if not candidates:
        print("No generated artifacts found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
