"""
Threat-intelligence classifier.

Uses imported known-bad domain feeds before heuristic or AI analysis.
"""

from __future__ import annotations

import time

from core.db import get_threat_intel
from engine.evidence import EvidenceItem, EvidencePolarity
from engine.classifiers.base import BaseClassifier
from engine.models import (
    AnalysisRequest,
    AnalysisResult,
    DomainCategory,
)


INTEL_CATEGORY_MAP = {
    DomainCategory.MALWARE.value: DomainCategory.MALWARE.value,
    DomainCategory.PHISHING.value: DomainCategory.PHISHING.value,
    DomainCategory.COMMAND_AND_CONTROL.value: (
        DomainCategory.COMMAND_AND_CONTROL.value
    ),
    "c2": DomainCategory.COMMAND_AND_CONTROL.value,
    "suspicious": DomainCategory.SUSPICIOUS.value,
}


class ThreatIntelClassifier(BaseClassifier):
    """
    Classify domains found in imported threat-intel feeds.
    """

    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult | None:
        domain = request.domain.lower()
        hit = get_threat_intel(
            domain,
        )

        if hit is None:
            return None

        category = INTEL_CATEGORY_MAP.get(
            str(hit["category"]).lower(),
            DomainCategory.SUSPICIOUS.value,
        )
        confidence = int(hit["confidence"] or 0)
        risk = max(
            70,
            min(100, confidence),
        )

        return AnalysisResult(
            domain=domain,
            risk=risk,
            confidence=confidence,
            category=category,
            reason=(
                f"Matched threat-intel feed '{hit['source']}' "
                f"as {hit['category']}."
            ),
            model="threat-intel",
            analyzed_at=time.time(),
            cached=False,
        )

    def collect_evidence(
        self,
        request: AnalysisRequest,
    ) -> list[EvidenceItem]:
        domain = request.domain.lower()
        hit = get_threat_intel(domain)
        if hit is None:
            return []

        category = INTEL_CATEGORY_MAP.get(
            str(hit["category"]).lower(),
            DomainCategory.SUSPICIOUS.value,
        )
        confidence = int(hit["confidence"] or 0)
        decisive = confidence >= 70
        return [
            EvidenceItem(
                evidence_id=f"threat-intel:{domain}:{hit['source']}",
                classifier="threat-intel",
                evidence_type="feed_hit",
                polarity=EvidencePolarity.RISK,
                score=max(70, min(100, confidence)),
                confidence=confidence / 100.0,
                summary=(
                    f"Matched threat-intel feed '{hit['source']}' "
                    f"as {hit['category']}."
                ),
                metadata={
                    "decisive": decisive,
                    "precedence": 30,
                    "policy_reason": "high-confidence threat-intelligence hit",
                    "source": "threat-intel",
                    "feed_source": hit["source"],
                    "feed_category": hit["category"],
                    "feed_confidence": confidence,
                    "category": category,
                },
            )
        ]
