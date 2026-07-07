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

from engine.models import (
    AnalysisRequest,
    AnalysisResult,
)


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


class HeuristicsEngine:

    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult | None:

        domain = request.domain.lower()

        score = 0
        reasons = []

        #
        # Punycode
        #

        if "xn--" in domain:
            score += 40
            reasons.append("Punycode domain")

        #
        # Long domain
        #

        if len(domain) > 40:
            score += 15
            reasons.append("Very long domain")

        #
        # Many digits
        #

        digits = sum(
            c.isdigit()
            for c in domain
        )

        if digits >= 6:
            score += 20
            reasons.append("Many numeric characters")

        #
        # High entropy
        #

        entropy = self._entropy(domain)

        if entropy > 3.8:
            score += 25
            reasons.append("High entropy")

        #
        # Suspicious TLD
        #

        tld = domain.split(".")[-1]

        if tld in SUSPICIOUS_TLDS:
            score += 20
            reasons.append(f"TLD '{tld}'")

        #
        # Phishing keywords
        #

        for word in PHISHING_WORDS:

            if word in domain:
                score += 15
                reasons.append(word)

        #
        # Repeated hyphens
        #

        if domain.count("-") >= 3:
            score += 15
            reasons.append("Many hyphens")

        #
        # Random-looking label
        #

        if re.search(
            r"[a-z]{8,}[0-9]{3,}",
            domain,
        ):
            score += 20
            reasons.append("Random-looking hostname")

        if score < 40:
            return None

        return AnalysisResult(
            domain=domain,
            risk=min(score, 100),
            confidence=75,
            category="Suspicious",
            reason=", ".join(reasons),
            model="heuristics",
            analyzed_at=time.time(),
            cached=False,
        )

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
