"""
PiHole-AI Heuristics Engine

Fast heuristic-based domain analysis.

Unlike the rule engine, heuristics are probabilistic.
They assign a risk score based on suspicious patterns.
"""

from __future__ import annotations

import math
import re
import time

from engine.evidence import EvidenceItem, EvidencePolarity
from engine.models import (
    AnalysisRequest,
    AnalysisResult,
    DomainCategory,
)
from engine.classifiers.base import BaseClassifier


SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "monster",
    "zip",
    "review",
    "country",
    "gq",
    "tk",
    "cf",
    "ml",
}

PHISHING_WORDS = {
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "password",
    "wallet",
    "bank",
    "paypal",
    "microsoft",
    "apple",
    "amazon",
}


class HeuristicsEngine(BaseClassifier):

    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult | None:

        domain = request.domain.lower()
        score, reasons, _ = self._score_domain(request)

        if score < 40:
            return None

        return AnalysisResult(
            domain=domain,
            risk=min(score, 100),
            confidence=75,
            category=DomainCategory.SUSPICIOUS.value,
            reason=", ".join(reasons),
            model="heuristics",
            analyzed_at=time.time(),
            cached=False,
        )

    def collect_evidence(
        self,
        request: AnalysisRequest,
    ) -> list[EvidenceItem]:
        _, _, evidence = self._score_domain(request)
        return evidence

    # -------------------------------------------------------------

    def _score_domain(
        self,
        request: AnalysisRequest,
    ) -> tuple[int, list[str], list[EvidenceItem]]:
        domain = request.domain.lower()
        score = 0
        reasons: list[str] = []
        evidence: list[EvidenceItem] = []

        def add_signal(
            evidence_type: str,
            points: int,
            summary: str,
            *,
            confidence: float = 0.70,
            metadata: dict | None = None,
        ) -> None:
            nonlocal score
            score += points
            reasons.append(summary)
            evidence.append(
                EvidenceItem(
                    evidence_id=f"heuristics:{domain}:{evidence_type}",
                    classifier="heuristics",
                    evidence_type=evidence_type,
                    polarity=EvidencePolarity.RISK,
                    score=points,
                    confidence=confidence,
                    summary=summary,
                    metadata={
                        "category": DomainCategory.SUSPICIOUS.value,
                        **(metadata or {}),
                    },
                )
            )

        #
        # Punycode
        #

        if "xn--" in domain:
            add_signal("punycode", 40, "Punycode domain", confidence=0.85)

        #
        # Long domain
        #

        if len(domain) > 40:
            add_signal(
                "long_domain",
                15,
                "Very long domain",
                metadata={"length": len(domain)},
            )

        #
        # Deep subdomain structure
        #

        if domain.count(".") > 3:
            add_signal(
                "deep_subdomain",
                15,
                "Deep subdomain structure",
                metadata={"dot_count": domain.count(".")},
            )

        #
        # Many digits
        #

        digits = sum(
            c.isdigit()
            for c in domain
        )

        if digits >= 6:
            add_signal(
                "many_digits",
                20,
                "Many numeric characters",
                metadata={"digit_count": digits},
            )

        #
        # High entropy
        #

        entropy = self._entropy(domain)

        if entropy > 3.8:
            add_signal(
                "high_entropy",
                25,
                "High entropy",
                metadata={"entropy": round(entropy, 3)},
            )

        #
        # Suspicious TLD
        #

        tld = domain.split(".")[-1]

        if tld in SUSPICIOUS_TLDS:
            add_signal(
                "suspicious_tld",
                20,
                f"TLD '{tld}'",
                metadata={"tld": tld},
            )

        #
        # Phishing keywords
        #

        for word in PHISHING_WORDS:

            if word in domain:
                add_signal(
                    f"phishing_word_{word}",
                    15,
                    word,
                    metadata={"word": word},
                )

        #
        # Repeated hyphens
        #

        if domain.count("-") >= 3:
            add_signal(
                "many_hyphens",
                15,
                "Many hyphens",
                metadata={"hyphen_count": domain.count("-")},
            )

        #
        # Random-looking label
        #

        if re.search(
            r"[a-z]{8,}[0-9]{3,}",
            domain,
        ):
            add_signal(
                "random_label",
                20,
                "Random-looking hostname",
            )

        #
        # High query frequency
        #

        if (
            request.metadata is not None
            and request.metadata.query_count > 500
        ):
            add_signal(
                "high_query_frequency",
                15,
                "High query frequency",
                metadata={"query_count": request.metadata.query_count},
            )

        return score, reasons, evidence

    # -------------------------------------------------------------

    @staticmethod
    def _entropy(
        text: str,
    ) -> float:

        probability = [
            float(text.count(c)) / len(text)
            for c in dict.fromkeys(text)
        ]

        return -sum(
            p * math.log2(p)
            for p in probability
        )
