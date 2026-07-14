"""
PiHole-AI Rule Engine

Fast deterministic classifications that do not require AI.

These rules classify well-known infrastructure domains,
local network names, and reverse DNS lookups.

If no rule matches, None is returned and the next
classifier in the pipeline is used.
"""

from __future__ import annotations

import time

from engine.evidence import EvidenceItem, EvidencePolarity
from engine.models import (
    AnalysisRequest,
    AnalysisResult,
    DomainCategory,
)
from engine.classifiers.base import BaseClassifier


class RuleEngine(BaseClassifier):
    """
    Fast deterministic domain classifier.
    """

    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult | None:
        """
        Return an AnalysisResult if a rule matches.

        Otherwise return None.
        """

        domain = request.domain.lower()

        #
        # Reverse DNS
        #

        if domain.endswith(".in-addr.arpa"):

            return self._safe(
                domain,
                "Reverse DNS lookup.",
            )

        if domain.endswith(".ip6.arpa"):

            return self._safe(
                domain,
                "IPv6 reverse DNS lookup.",
            )

        #
        # Local network
        #

        if domain.endswith(".local"):

            return self._safe(
                domain,
                "Local network hostname.",
            )

        if domain == "localhost":

            return self._safe(
                domain,
                "Localhost.",
            )

        #
        # Broadcast / multicast
        #

        if domain.endswith(".home.arpa"):

            return self._safe(
                domain,
                "Home network domain.",
            )

        #
        # No match
        #

        return None

    def collect_evidence(
        self,
        request: AnalysisRequest,
    ) -> list[EvidenceItem]:
        result = self.classify(request)
        if result is None:
            return []
        return [
            EvidenceItem(
                evidence_id=f"rule-engine:{result.domain}:infrastructure",
                classifier="rule-engine",
                evidence_type="local_infrastructure",
                polarity=EvidencePolarity.SAFETY,
                score=-90,
                confidence=0.98,
                summary=result.reason,
                metadata={
                    "decisive": True,
                    "precedence": 40,
                    "source": "rule-engine",
                    "category": result.category,
                },
            )
        ]

    # ------------------------------------------------------------------

    def _safe(
        self,
        domain: str,
        reason: str,
    ) -> AnalysisResult:

        return AnalysisResult(
            domain=domain,
            risk=0,
            confidence=100,
            category=DomainCategory.INFRASTRUCTURE.value,
            reason=reason,
            model="rule-engine",
            analyzed_at=time.time(),
            cached=False,
        )
