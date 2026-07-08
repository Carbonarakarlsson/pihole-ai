"""
Local reputation classifier.

Uses learned domain reputation before the request reaches Ollama.
"""

from __future__ import annotations

import json
import time
from typing import Any

from core.config import settings
from core.db import get_domain_reputation, get_domain_rule
from engine.classifiers.base import BaseClassifier
from engine.models import (
    AnalysisRequest,
    AnalysisResult,
    DomainCategory,
)


class ReputationClassifier(BaseClassifier):
    """
    Classify domains using manual rules and learned reputation.
    """

    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult | None:
        domain = request.domain.lower()
        rule = get_domain_rule(
            domain,
        )

        if rule is not None:
            return self._classify_rule(
                domain,
                rule,
            )

        reputation = get_domain_reputation(
            domain,
        )

        if reputation is None:
            return None

        score = int(reputation["score"] or 0)
        confidence = int(reputation["confidence"] or 0)

        if score < settings.high_risk_threshold:
            return None

        signals = self._parse_signals(
            reputation["signals"],
        )

        return AnalysisResult(
            domain=domain,
            risk=score,
            confidence=confidence,
            category=DomainCategory.SUSPICIOUS.value,
            reason="Learned local reputation: " + ", ".join(signals),
            model="local-reputation",
            analyzed_at=time.time(),
            cached=False,
        )

    @staticmethod
    def _classify_rule(
        domain: str,
        rule: Any,
    ) -> AnalysisResult:
        """
        Convert a manual domain rule into an analysis result.
        """

        decision = rule["decision"]
        reason = rule["reason"] or f"Manual {decision} rule."

        if decision == "allow":
            return AnalysisResult(
                domain=domain,
                risk=0,
                confidence=95,
                category=DomainCategory.BENIGN.value,
                reason=f"Manual allow rule: {reason}",
                model="manual-rule",
                analyzed_at=time.time(),
                cached=False,
            )

        return AnalysisResult(
            domain=domain,
            risk=100,
            confidence=95,
            category=DomainCategory.SUSPICIOUS.value,
            reason=f"Manual block rule: {reason}",
            model="manual-rule",
            analyzed_at=time.time(),
            cached=False,
        )

    @staticmethod
    def _parse_signals(
        raw: str,
    ) -> list[str]:
        """
        Parse reputation signal JSON from the database.
        """

        try:
            values = json.loads(raw or "[]")

        except json.JSONDecodeError:
            return ["unparsed reputation signals"]

        if not isinstance(values, list):
            return ["unparsed reputation signals"]

        signals = [
            str(value)
            for value in values
            if str(value)
        ]

        if not signals:
            return ["learned suspicious behavior"]

        return signals
