"""
Feedback helpers for PiHole-AI.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.db import record_action
from pihole_ai.rules import add_rule


FEEDBACK_VERDICTS = {
    "safe",
    "bad",
    "false-positive",
    "false-negative",
    "noisy",
}


@dataclass(frozen=True)
class FeedbackResult:
    """
    Result of recording feedback.
    """

    domain: str
    verdict: str
    promoted: str | None = None


def record_feedback(
    domain: str,
    verdict: str,
    reason: str = "",
    promote: bool = False,
    apply_block: bool = False,
) -> FeedbackResult:
    """
    Record human feedback for a domain.
    """

    normalized = domain.strip().lower().rstrip(".")

    if verdict not in FEEDBACK_VERDICTS:
        raise ValueError(
            f"Unknown feedback verdict: {verdict}"
        )

    promoted: str | None = None

    if promote:
        promoted = _promote_feedback(
            domain=normalized,
            verdict=verdict,
            reason=reason,
            apply_block=apply_block,
        )

    record_action(
        domain=normalized,
        action="feedback",
        source="pihole_ai.feedback",
        status=verdict,
        reason=reason,
    )

    return FeedbackResult(
        domain=normalized,
        verdict=verdict,
        promoted=promoted,
    )


def _promote_feedback(
    domain: str,
    verdict: str,
    reason: str,
    apply_block: bool,
) -> str | None:
    """
    Promote feedback into a manual rule when appropriate.
    """

    if verdict in {"safe", "false-positive"}:
        add_rule(
            domain=domain,
            decision="allow",
            reason=reason or f"Feedback: {verdict}",
        )
        return "allow"

    if verdict in {"bad", "false-negative"}:
        add_rule(
            domain=domain,
            decision="block",
            reason=reason or f"Feedback: {verdict}",
            apply_block=apply_block,
        )
        return "block"

    return None


def print_feedback(
    domain: str,
    verdict: str,
    reason: str = "",
    promote: bool = False,
    apply_block: bool = False,
) -> FeedbackResult:
    """
    Record feedback and print a short confirmation.
    """

    result = record_feedback(
        domain=domain,
        verdict=verdict,
        reason=reason,
        promote=promote,
        apply_block=apply_block,
    )

    if result.promoted:
        print(
            f"Recorded {result.verdict} feedback for {result.domain} "
            f"and promoted {result.promoted} rule."
        )
    else:
        print(
            f"Recorded {result.verdict} feedback for {result.domain}."
        )

    return result
