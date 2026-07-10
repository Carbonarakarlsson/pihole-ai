"""
Inspect built PiHole-AI artifacts for required and forbidden files.
"""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path


WHEEL_REQUIRED_SUFFIXES = {
    ".dist-info/METADATA",
    "pihole_ai/defaults/pihole-ai.env",
}
SDIST_REQUIRED_SUFFIXES = {
    "README.md",
    "pihole_ai/defaults/pihole-ai.env",
}
FORBIDDEN_PARTS = {
    ".git",
    ".env",
    ".venv",
    "venv",
    "__pycache__",
}
FORBIDDEN_SUFFIXES = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".log",
    ".pyc",
}


def artifact_names(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    if path.suffixes[-2:] == [".tar", ".gz"]:
        with tarfile.open(path) as archive:
            return archive.getnames()
    raise ValueError(f"Unsupported artifact: {path}")


def audit(path: Path) -> list[str]:
    names = artifact_names(path)
    errors: list[str] = []
    required_suffixes = (
        WHEEL_REQUIRED_SUFFIXES
        if path.suffix == ".whl"
        else SDIST_REQUIRED_SUFFIXES
    )
    for required in required_suffixes:
        if not any(name.endswith(required) for name in names):
            errors.append(f"missing required file: {required}")
    for name in names:
        parts = set(Path(name).parts)
        if parts & FORBIDDEN_PARTS:
            errors.append(f"forbidden path: {name}")
        if Path(name).suffix in FORBIDDEN_SUFFIXES:
            errors.append(f"forbidden file type: {name}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit PiHole-AI package artifacts.")
    parser.add_argument("artifacts", nargs="+", help="Wheel or sdist paths.")
    args = parser.parse_args(argv)
    failed = False
    for raw_path in args.artifacts:
        path = Path(raw_path)
        errors = audit(path)
        if errors:
            failed = True
            print(f"{path}: failed")
            for error in errors:
                print(f"  {error}")
        else:
            print(f"{path}: ok")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
