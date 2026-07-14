"""
Central evidence aggregation policy for PiHole-AI.
"""

from __future__ import annotations

from collections import defaultdict

from engine.evidence import (
    DecisionResult,
    EVIDENCE_POLICY_VERSION,
    EvidenceCollection,
    EvidenceItem,
    EvidencePolarity,
)
from engine.models import AnalysisResult, DomainCategory
from pihole_ai.version import get_version


LOW_RISK_MAX = 29
MEDIUM_RISK_MAX = 59
HIGH_RISK_MAX = 79
AI_CONFIDENCE_CEILING = 0.75
SUFFICIENT_DETERMINISTIC_CONFIDENCE = 0.80


class DecisionEngine:
    """
    Convert structured evidence into one final decision.
    """

    def decide(
        self,
        collection: EvidenceCollection,
        classifier_trace: list[dict] | None = None,
    ) -> DecisionResult:
        trace = tuple(classifier_trace or [])
        decisive = sorted(
            [item for item in collection.items if item.decisive],
            key=lambda item: (item.precedence, item.created_at, item.evidence_id),
        )

        if decisive:
            return self._decisive_decision(collection, decisive, trace)

        return self._aggregate_decision(collection, trace)

    def should_skip_ai(
        self,
        collection: EvidenceCollection,
    ) -> tuple[bool, str]:
        decisive = [item for item in collection.items if item.decisive]
        if decisive:
            strongest = sorted(decisive, key=lambda item: item.precedence)[0]
            return True, f"decisive evidence from {strongest.classifier}"

        non_ai = [
            item
            for item in collection.items
            if item.classifier != "ai"
        ]
        if not non_ai:
            return False, ""

        interim = self._aggregate_decision(collection, ())
        if (
            interim.confidence >= SUFFICIENT_DETERMINISTIC_CONFIDENCE
            and (interim.risk_score <= LOW_RISK_MAX or interim.risk_score > MEDIUM_RISK_MAX)
        ):
            return True, "deterministic evidence was sufficient"

        return False, ""

    def to_analysis_result(
        self,
        decision: DecisionResult,
    ) -> AnalysisResult:
        return AnalysisResult(
            domain=decision.domain,
            risk=decision.risk_score,
            confidence=int(round(decision.confidence * 100)),
            category=decision.category,
            reason=decision.explanation,
            model=decision.source,
            analyzed_at=decision.created_at,
            cached=False,
            decision=decision,
        )

    def _decisive_decision(
        self,
        collection: EvidenceCollection,
        decisive: list[EvidenceItem],
        trace: tuple[dict, ...],
    ) -> DecisionResult:
        item = decisive[0]
        risk = 100 if item.polarity == EvidencePolarity.RISK else 0
        category = str(item.metadata.get("category") or self._category_for_risk(risk))
        verdict = self._verdict_for_risk(risk, category)
        explanation = item.summary
        if len(decisive) > 1:
            explanation += " Conflicting decisive evidence was resolved by documented precedence."

        return DecisionResult(
            domain=collection.domain,
            verdict=verdict,
            risk_score=risk,
            confidence=max(0.0, min(1.0, item.confidence)),
            category=category,
            source=str(item.metadata.get("source") or item.classifier),
            explanation=explanation,
            evidence=collection,
            decisive_evidence_ids=tuple(evidence.evidence_id for evidence in decisive),
            classifier_trace=trace,
            conflicts=tuple(self._conflicts(collection.items)),
            policy_version=EVIDENCE_POLICY_VERSION,
            application_version=get_version(),
        )

    def _aggregate_decision(
        self,
        collection: EvidenceCollection,
        trace: tuple[dict, ...],
    ) -> DecisionResult:
        if not collection.items:
            return DecisionResult(
                domain=collection.domain,
                verdict="unknown",
                risk_score=50,
                confidence=0.0,
                category=DomainCategory.UNKNOWN.value,
                source="decision-engine",
                explanation="No evidence was available.",
                evidence=collection,
                classifier_trace=trace,
            )

        influence = 0.0
        confidence_values: list[float] = []
        grouped: dict[tuple[str, str], list[EvidenceItem]] = defaultdict(list)
        for item in collection.items:
            grouped[(item.classifier, item.evidence_type)].append(item)

        for group_items in grouped.values():
            ordered = sorted(group_items, key=lambda item: abs(item.score) * item.confidence, reverse=True)
            for index, item in enumerate(ordered[:3]):
                diminishing = 1.0 / (index + 1)
                influence += item.score * item.confidence * diminishing
                confidence_values.append(item.confidence * diminishing)

        risk = max(0, min(100, int(round(50 + influence * 0.5))))
        confidence = min(0.95, sum(confidence_values) / max(1, len(confidence_values)) + 0.15)
        if collection.items and all(item.classifier == "ai" for item in collection.items):
            confidence = min(confidence, AI_CONFIDENCE_CEILING)

        category = self._category_from_evidence(collection.items, risk)
        verdict = self._verdict_for_risk(risk, category)
        explanation = self._explanation(collection.items, risk, confidence)

        return DecisionResult(
            domain=collection.domain,
            verdict=verdict,
            risk_score=risk,
            confidence=round(confidence, 3),
            category=category,
            source="decision-engine",
            explanation=explanation,
            evidence=collection,
            classifier_trace=trace,
            conflicts=tuple(self._conflicts(collection.items)),
            policy_version=EVIDENCE_POLICY_VERSION,
            application_version=get_version(),
        )

    def _category_from_evidence(
        self,
        items: tuple[EvidenceItem, ...],
        risk: int,
    ) -> str:
        risk_items = [
            item
            for item in items
            if item.polarity == EvidencePolarity.RISK
        ]
        if risk_items:
            strongest = max(risk_items, key=lambda item: item.score * item.confidence)
            category = strongest.metadata.get("category")
            if category:
                return str(category)
        return self._category_for_risk(risk)

    def _category_for_risk(
        self,
        risk: int,
    ) -> str:
        if risk <= LOW_RISK_MAX:
            return DomainCategory.BENIGN.value
        if risk <= MEDIUM_RISK_MAX:
            return DomainCategory.UNKNOWN.value
        return DomainCategory.SUSPICIOUS.value

    def _verdict_for_risk(
        self,
        risk: int,
        category: str,
    ) -> str:
        if risk >= 80 or category in {
            DomainCategory.MALWARE.value,
            DomainCategory.PHISHING.value,
            DomainCategory.COMMAND_AND_CONTROL.value,
        }:
            return "malicious"
        if risk >= 60:
            return "suspicious"
        if risk <= LOW_RISK_MAX:
            return "safe"
        return "unknown"

    def _explanation(
        self,
        items: tuple[EvidenceItem, ...],
        risk: int,
        confidence: float,
    ) -> str:
        risk_count = sum(1 for item in items if item.polarity == EvidencePolarity.RISK)
        safety_count = sum(1 for item in items if item.polarity == EvidencePolarity.SAFETY)
        if risk_count and safety_count:
            prefix = "Contradictory risk and safety evidence was balanced."
        elif risk_count:
            prefix = "Risk evidence increased the score."
        elif safety_count:
            prefix = "Safety evidence reduced the score."
        else:
            prefix = "Only neutral evidence was available."
        return f"{prefix} Final risk {risk}/100 with confidence {confidence:.2f}."

    def _conflicts(
        self,
        items: tuple[EvidenceItem, ...],
    ) -> list[str]:
        risk_count = sum(1 for item in items if item.polarity == EvidencePolarity.RISK)
        safety_count = sum(1 for item in items if item.polarity == EvidencePolarity.SAFETY)
        if risk_count and safety_count:
            return ["Risk evidence conflicts with safety evidence."]
        return []
