"""
PiHole-AI version helpers.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import tomllib


PACKAGE_NAME = "pihole-ai"
DEVELOPMENT_VERSION = "0.4.0rc3"


def get_version() -> str:
    """
    Return installed package version with a development fallback.
    """

    local_version = _version_from_pyproject()
    if local_version is not None:
        return local_version

    try:
        return version(PACKAGE_NAME)

    except PackageNotFoundError:
        return DEVELOPMENT_VERSION


def _version_from_pyproject() -> str | None:
    """
    Return local pyproject version when running from an unpackaged checkout.
    """

    path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return None
    return str(data.get("project", {}).get("version") or "") or None
