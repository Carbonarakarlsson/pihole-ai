"""
Action policy for analysis results.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from core.config import settings
from core.db import get_domain_rule, record_action
from core.logger import get_logger


logger = get_logger(__name__)


class AnalysisLike(Protocol):
    domain: str
    risk: int
    confidence: int
    category: str
    reason: str


@dataclass(frozen=True)
class PolicyDecision:
    """
    Action decision produced for an analysis result.
    """

    action: str
    status: str
    reason: str


def decide_action(
    result: AnalysisLike,
    mode: str | None = None,
    alert_threshold: int | None = None,
    block_threshold: int | None = None,
) -> PolicyDecision | None:
    """
    Decide which action should be audited for an analysis result.
    """

    if mode is None:
        mode = settings.action_mode

    if alert_threshold is None:
        alert_threshold = settings.alert_threshold

    if block_threshold is None:
        block_threshold = settings.high_risk_threshold

    if mode == "off":
        return None

    rule = get_domain_rule(
        result.domain,
    )

    if rule is not None:
        decision = rule["decision"]

        if decision == "allow":
            return PolicyDecision(
                action="allow",
                status="rule_match",
                reason="Domain matches an active allow rule.",
            )

        if decision == "block":
            return PolicyDecision(
                action="block",
                status="rule_match",
                reason="Domain matches an active block rule.",
            )

    if result.confidence <= 0:
        return PolicyDecision(
            action="review",
            status="low_confidence",
            reason="Analysis confidence is zero; manual review recommended.",
        )

    if result.risk >= block_threshold:
        if mode == "block":
            return PolicyDecision(
                action="block",
                status="pending",
                reason=(
                    f"Risk {result.risk} is at or above block "
                    f"threshold {block_threshold}."
                ),
            )

        return PolicyDecision(
            action="suggest_block",
            status="dry_run",
            reason=(
                f"Risk {result.risk} is at or above block "
                f"threshold {block_threshold}."
            ),
        )

    if result.risk >= alert_threshold:
        return PolicyDecision(
            action="alert",
            status="logged",
            reason=(
                f"Risk {result.risk} is at or above alert "
                f"threshold {alert_threshold}."
            ),
        )

    return None


def apply_action_policy(
    result: AnalysisLike,
    mode: str | None = None,
) -> PolicyDecision | None:
    """
    Apply the configured action policy and record the result.
    """

    decision = decide_action(
        result,
        mode=mode,
    )

    if decision is None:
        return None

    if mode is None:
        mode = settings.action_mode

    if decision.action == "block" and mode == "block":
        try:
            from actions.blocklist import block

            block(result.domain)

        except Exception as exc:
            record_action(
                domain=result.domain,
                action="block",
                source="actions.policy",
                status="failed",
                reason=str(exc),
                risk=result.risk,
            )
            logger.exception(
                "Failed applying block action for %s.",
                result.domain,
            )
            return PolicyDecision(
                action="block",
                status="failed",
                reason=str(exc),
            )

        return PolicyDecision(
            action="block",
            status="written",
            reason=decision.reason,
        )

    record_action(
        domain=result.domain,
        action=decision.action,
        source="actions.policy",
        status=decision.status,
        reason=decision.reason,
        risk=result.risk,
    )

    return decision
