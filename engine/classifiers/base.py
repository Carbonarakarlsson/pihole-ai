"""
Base classifier interface for PiHole-AI.

Compatibility contract:
classifiers may still implement classify(request) -> AnalysisResult | None.

Evidence contract:
classifiers should contribute structured EvidenceItem values through
collect_evidence(request). The central DecisionEngine is responsible for
ordinary final decisions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from engine.evidence import EvidenceItem, EvidencePolarity
from engine.models import AnalysisRequest, AnalysisResult


class BaseClassifier(ABC):
    """
    Common interface for domain classifiers.
    """

    @abstractmethod
    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult | None:
        """
        Classify a domain or return None to let the next classifier try.
        """

    def collect_evidence(
        self,
        request: AnalysisRequest,
    ) -> list[EvidenceItem]:
        """
        Return structured evidence for the central decision engine.
        """

        result = self.classify(request)
        if result is None:
            return []

        if result.risk > 50:
            polarity = EvidencePolarity.RISK
            score = result.risk
        elif result.risk < 50:
            polarity = EvidencePolarity.SAFETY
            score = -100 + result.risk
        else:
            polarity = EvidencePolarity.NEUTRAL
            score = 0

        return [
            EvidenceItem(
                evidence_id=f"{result.model}:{request.domain}:legacy",
                classifier=result.model,
                evidence_type="legacy_result",
                polarity=polarity,
                score=score,
                confidence=result.confidence / 100.0,
                summary=result.reason,
                metadata={
                    "category": result.category,
                    "legacy_model": result.model,
                },
            )
        ]
