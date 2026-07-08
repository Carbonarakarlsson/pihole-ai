"""
Domain rule management helpers.
"""

from __future__ import annotations

from typing import Any

from core.db import (
    delete_domain_rule,
    list_domain_rules,
    record_action,
    save_domain_rule,
)


def add_rule(
    domain: str,
    decision: str,
    reason: str = "",
    apply_block: bool = False,
) -> None:
    """
    Add or update a domain allow/block rule.
    """

    save_domain_rule(
        domain=domain,
        decision=decision,
        source="cli",
        reason=reason,
    )

    record_action(
        domain=domain,
        action=decision,
        source="pihole_ai.rules",
        status="rule_saved",
        reason=reason,
    )

    if decision == "block" and apply_block:
        from actions.blocklist import block

        block(domain)


def remove_rule(
    domain: str,
) -> bool:
    """
    Remove a domain rule and audit the change.
    """

    removed = delete_domain_rule(
        domain,
    )

    if removed:
        record_action(
            domain=domain,
            action="remove_rule",
            source="pihole_ai.rules",
            status="removed",
            reason="Removed domain rule.",
        )

    return removed


def get_rules(
    limit: int = 100,
    search: str = "",
    decision: str = "",
) -> list[dict[str, Any]]:
    """
    Return active domain rules as dictionaries.
    """

    return [
        dict(row)
        for row in list_domain_rules(
            limit=limit,
            search=search,
            decision=decision,
            enabled=True,
        )
    ]


def print_rules(
    limit: int = 100,
    search: str = "",
    decision: str = "",
) -> int:
    """
    Print active rules and return the number printed.
    """

    rows = get_rules(
        limit=limit,
        search=search,
        decision=decision,
    )

    if not rows:
        print("No active domain rules.")
        return 0

    for row in rows:
        reason = row["reason"] or "-"
        print(
            f"{row['decision']:5} {row['domain']} "
            f"source={row['source']} reason={reason}"
        )

    return len(rows)
