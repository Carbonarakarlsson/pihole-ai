"""
Threat-intelligence import helpers.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from core.db import (
    list_threat_intel,
    save_threat_intel,
)


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9][a-z0-9.-]*[a-z0-9]$"
)
BLOCKLIST_IPS = {
    "0.0.0.0",
    "127.0.0.1",
    "::",
}


def normalize_domain(
    value: str,
) -> str | None:
    """
    Normalize and validate a domain from a feed line.
    """

    domain = value.strip().lower().rstrip(".")

    if not domain:
        return None

    if domain in {"localhost", "localhost.localdomain"}:
        return None

    if "/" in domain or ":" in domain:
        return None

    if "." not in domain:
        return None

    if not DOMAIN_PATTERN.match(domain):
        return None

    return domain


def parse_hosts_domains(
    lines: Iterable[str],
) -> list[str]:
    """
    Parse domains from hosts-style or plain-domain feed lines.
    """

    domains: list[str] = []
    seen: set[str] = set()

    for line in lines:
        content = line.split("#", 1)[0].strip()

        if not content:
            continue

        parts = content.split()

        if not parts:
            continue

        candidates = parts

        if parts[0] in BLOCKLIST_IPS:
            candidates = parts[1:]

        for candidate in candidates:
            domain = normalize_domain(
                candidate,
            )

            if domain is None or domain in seen:
                continue

            seen.add(
                domain,
            )
            domains.append(
                domain,
            )

    return domains


def import_hosts_file(
    path: str,
    source: str,
    category: str = "malware",
    confidence: int = 90,
) -> int:
    """
    Import a local hosts-style threat-intel file.
    """

    lines = Path(path).read_text(
        encoding="utf-8",
    ).splitlines()
    domains = parse_hosts_domains(
        lines,
    )

    for domain in domains:
        save_threat_intel(
            domain=domain,
            source=source,
            category=category,
            confidence=confidence,
        )

    return len(domains)


def get_intel_rows(
    limit: int = 100,
    search: str = "",
    source: str = "",
    category: str = "",
) -> list[dict[str, Any]]:
    """
    Return threat-intel rows as dictionaries.
    """

    return [
        dict(row)
        for row in list_threat_intel(
            limit=limit,
            search=search,
            source=source,
            category=category,
        )
    ]


def print_intel(
    limit: int = 100,
    search: str = "",
    source: str = "",
    category: str = "",
) -> int:
    """
    Print threat-intel rows and return the number printed.
    """

    rows = get_intel_rows(
        limit=limit,
        search=search,
        source=source,
        category=category,
    )

    if not rows:
        print("No threat-intel rows found.")
        return 0

    for row in rows:
        print(
            f"{row['domain']} source={row['source']} "
            f"category={row['category']} confidence={row['confidence']}"
        )

    return len(rows)
