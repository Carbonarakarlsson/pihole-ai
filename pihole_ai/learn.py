"""
Local reputation learning for PiHole-AI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.db import (
    get_reputation_candidates,
    list_domain_reputations,
    record_action,
    save_domain_reputation,
)
from engine.models import AnalysisResult
from engine.classifiers.heuristics import SUSPICIOUS_TLDS, HeuristicsEngine


@dataclass(frozen=True)
class ReputationResult:
    """
    Learned reputation score for a domain.
    """

    domain: str
    score: int
    confidence: int
    signals: list[str]


def _as_int(
    value: Any,
) -> int:
    """
    Convert database values to integers.
    """

    return int(value or 0)


def score_candidate(
    row: Any,
) -> ReputationResult:
    """
    Score one domain using local history.
    """

    domain = str(row["domain"]).lower()

    score = 0
    signals: list[str] = []

    query_count = _as_int(row["query_count"])
    device_count = _as_int(row["device_count"])
    recent_queries = _as_int(row["recent_queries"])
    analysis_risk = _as_int(row["analysis_risk"])
    analysis_confidence = _as_int(row["analysis_confidence"])
    suggest_block_count = _as_int(row["suggest_block_count"])
    alert_count = _as_int(row["alert_count"])
    review_count = _as_int(row["review_count"])

    if query_count >= 500:
        score += 15
        signals.append("high total query count")

    if recent_queries >= 100:
        score += 20
        signals.append("recent query spike")

    if device_count >= 3:
        score += 15
        signals.append("seen across multiple devices")

    if analysis_risk >= 70 and analysis_confidence > 0:
        score += 30
        signals.append("previous high-risk analysis")

    elif analysis_risk >= 40 and analysis_confidence > 0:
        score += 15
        signals.append("previous medium-risk analysis")

    if analysis_confidence == 0 and analysis_risk > 0:
        score += 10
        signals.append("previous low-confidence analysis")

    if suggest_block_count:
        score += min(30, 15 + suggest_block_count * 5)
        signals.append("previous suggest-block audit")

    if alert_count:
        score += min(20, 10 + alert_count * 3)
        signals.append("previous alert audit")

    if review_count:
        score += min(15, 5 + review_count * 3)
        signals.append("previous review audit")

    if HeuristicsEngine._entropy(domain) > 3.8:
        score += 15
        signals.append("high entropy domain")

    tld = domain.rsplit(".", 1)[-1]

    if tld in SUSPICIOUS_TLDS:
        score += 10
        signals.append(f"suspicious tld {tld}")

    if not signals:
        signals.append("no suspicious local signals")

    score = max(
        0,
        min(score, 100),
    )
    confidence = 80 if score >= 40 else 60

    return ReputationResult(
        domain=domain,
        score=score,
        confidence=confidence,
        signals=signals,
    )


def learn(
    limit: int = 500,
    min_score: int = 50,
    audit: bool = True,
) -> list[ReputationResult]:
    """
    Update local reputation scores from observed DNS history.
    """

    results = [
        score_candidate(row)
        for row in get_reputation_candidates(
            limit=limit,
        )
    ]

    for result in results:
        save_domain_reputation(
            domain=result.domain,
            score=result.score,
            confidence=result.confidence,
            signals=result.signals,
        )

        if audit and result.score >= min_score:
            action = "suggest_block" if result.score >= 70 else "alert"
            record_action(
                domain=result.domain,
                action=action,
                source="pihole_ai.learn",
                status="learned",
                reason=", ".join(result.signals),
                risk=result.score,
            )

    return [
        result
        for result in results
        if result.score >= min_score
    ]


def update_reputation_from_analysis(
    result: AnalysisResult,
) -> ReputationResult | None:
    """
    Incrementally update reputation from completed classifier evidence.
    """

    if result.model in {
        "manual-rule",
        "local-reputation",
    }:
        return None

    if result.confidence <= 0:
        return None

    signals = [
        f"{result.model} classification",
        f"category {result.category}",
    ]

    score = max(
        0,
        min(result.risk, 100),
    )
    confidence = max(
        0,
        min(result.confidence, 100),
    )
    reputation = ReputationResult(
        domain=result.domain.lower(),
        score=score,
        confidence=confidence,
        signals=signals,
    )

    save_domain_reputation(
        domain=reputation.domain,
        score=reputation.score,
        confidence=reputation.confidence,
        signals=reputation.signals,
    )

    return reputation


def get_reputations(
    limit: int = 100,
    search: str = "",
    min_score: int = 0,
) -> list[dict[str, Any]]:
    """
    Return learned reputation rows as dictionaries.
    """

    return [
        dict(row)
        for row in list_domain_reputations(
            limit=limit,
            search=search,
            min_score=min_score,
        )
    ]


def print_learned(
    limit: int = 500,
    min_score: int = 50,
    audit: bool = True,
) -> int:
    """
    Run learning and print suspicious results.
    """

    results = learn(
        limit=limit,
        min_score=min_score,
        audit=audit,
    )

    if not results:
        print("No learned reputation results met the threshold.")
        return 0

    for result in results:
        print(
            f"{result.score:3} {result.domain} "
            f"confidence={result.confidence} "
            f"signals={'; '.join(result.signals)}"
        )

    return len(results)
