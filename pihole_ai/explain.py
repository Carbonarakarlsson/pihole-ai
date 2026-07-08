"""
Domain explanation helpers.
"""

from __future__ import annotations

import json
from typing import Any

from core.db import (
    get_analysis,
    get_domain_metadata,
    get_domain_reputation,
    get_domain_rule,
    get_recent_actions,
    get_threat_intel,
)


def normalize_domain(
    domain: str,
) -> str:
    """
    Normalize a domain for lookup.
    """

    return domain.strip().lower().rstrip(".")


def row_to_dict(
    row: Any,
) -> dict[str, Any] | None:
    """
    Convert a database row to a dictionary.
    """

    if row is None:
        return None

    return dict(row)


def parse_signals(
    value: str | None,
) -> list[str]:
    """
    Parse JSON-encoded signal lists.
    """

    try:
        parsed = json.loads(value or "[]")

    except json.JSONDecodeError:
        return []

    if not isinstance(parsed, list):
        return []

    return [
        str(item)
        for item in parsed
        if str(item)
    ]


def explain_domain(
    domain: str,
    action_limit: int = 10,
) -> dict[str, Any]:
    """
    Collect all known evidence for a domain.
    """

    normalized = normalize_domain(
        domain,
    )
    reputation = row_to_dict(
        get_domain_reputation(normalized),
    )

    if reputation is not None:
        reputation["signals"] = parse_signals(
            reputation.get("signals"),
        )

    actions = [
        dict(row)
        for row in get_recent_actions(
            limit=action_limit,
            search=normalized,
        )
        if row["domain"] == normalized
    ]

    explanation = {
        "domain": normalized,
        "rule": row_to_dict(
            get_domain_rule(normalized),
        ),
        "threat_intel": row_to_dict(
            get_threat_intel(normalized),
        ),
        "reputation": reputation,
        "analysis": row_to_dict(
            get_analysis(normalized),
        ),
        "metadata": get_domain_metadata(
            normalized,
        ),
        "actions": actions,
    }
    explanation["summary"] = summarize_explanation(
        explanation,
    )

    return explanation


def summarize_explanation(
    explanation: dict[str, Any],
) -> str:
    """
    Return the strongest currently known signal.
    """

    rule = explanation["rule"]

    if rule is not None:
        return f"manual {rule['decision']} rule"

    threat = explanation["threat_intel"]

    if threat is not None:
        return (
            f"threat-intel match from {threat['source']} "
            f"as {threat['category']}"
        )

    reputation = explanation["reputation"]

    if reputation is not None and reputation["score"] >= 70:
        return f"high learned reputation score {reputation['score']}"

    analysis = explanation["analysis"]

    if analysis is not None:
        return (
            f"cached analysis risk {analysis['risk']} "
            f"category {analysis['category']}"
        )

    metadata = explanation["metadata"]

    if metadata["query_count"] > 0:
        return "observed locally without a strong classification"

    return "no local evidence found"


def print_explanation(
    domain: str,
    as_json: bool = False,
) -> dict[str, Any]:
    """
    Print an explanation and return the collected data.
    """

    explanation = explain_domain(
        domain,
    )

    if as_json:
        print(
            json.dumps(
                explanation,
                indent=2,
            )
        )
        return explanation

    print(f"PiHole-AI explanation for {explanation['domain']}")
    print(f"  summary: {explanation['summary']}")

    _print_section(
        "rule",
        explanation["rule"],
    )
    _print_section(
        "threat_intel",
        explanation["threat_intel"],
    )
    _print_section(
        "reputation",
        explanation["reputation"],
    )
    _print_section(
        "analysis",
        explanation["analysis"],
    )
    _print_section(
        "metadata",
        explanation["metadata"],
    )

    actions = explanation["actions"]
    print("  actions:")

    if not actions:
        print("    none")

    for action in actions:
        print(
            "    "
            f"{action['action']} status={action['status']} "
            f"risk={action['risk']} source={action['source']} "
            f"reason={action['reason']}"
        )

    return explanation


def _print_section(
    name: str,
    values: dict[str, Any] | None,
) -> None:
    """
    Print one explanation section.
    """

    print(f"  {name}:")

    if values is None:
        print("    none")
        return

    for key, value in values.items():
        print(f"    {key}: {value}")
