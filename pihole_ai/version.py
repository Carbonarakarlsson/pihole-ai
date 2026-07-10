"""
PiHole-AI version helpers.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


PACKAGE_NAME = "pihole-ai"
DEVELOPMENT_VERSION = "0.4-dev"


def get_version() -> str:
    """
    Return installed package version with a development fallback.
    """

    try:
        return version(PACKAGE_NAME)

    except PackageNotFoundError:
        return DEVELOPMENT_VERSION
