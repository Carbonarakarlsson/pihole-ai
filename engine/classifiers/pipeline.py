"""
PiHole-AI Classifier Pipeline

Collects classifier evidence and asks the central decision engine for a result.
"""

from __future__ import annotations

import time

from core.logger import get_logger

from engine.decision_engine import DecisionEngine
from engine.evidence import EvidenceCollection, EvidenceItem
from engine.models import (
    AnalysisRequest,
    AnalysisResult,
)

from engine.classifiers.rule_engine import RuleEngine
from engine.classifiers.reputation import ReputationClassifier
from engine.classifiers.threat_intel import ThreatIntelClassifier
from engine.classifiers.heuristics import HeuristicsEngine
from engine.classifiers.ai_classifier import AIClassifier
from engine.classifiers.base import BaseClassifier


class ClassifierPipeline:
    """
    Executes classifiers in order and aggregates their evidence.
    """

    def __init__(self) -> None:

        self.logger = get_logger(__name__)

        self.classifiers: list[BaseClassifier] = [

            RuleEngine(),

            ReputationClassifier(),

            ThreatIntelClassifier(),

            HeuristicsEngine(),

            AIClassifier(),

        ]

        self.decision_engine = DecisionEngine()

        self.logger.debug(
            "Initialized classifier pipeline (%d classifiers).",
            len(self.classifiers),
        )

    # ------------------------------------------------------------------

    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult:
        """
        Collect evidence and return one final decision-compatible analysis.
        """

        domain = request.domain.lower()
        evidence: list[EvidenceItem] = []
        consulted: list[str] = []
        skipped: list[dict] = []
        trace: list[dict] = []
        collection = EvidenceCollection(domain=domain)

        for index, classifier in enumerate(self.classifiers):
            classifier_name = self._classifier_name(classifier)
            interim_collection = EvidenceCollection(
                domain=domain,
                items=tuple(evidence),
                started_at=collection.started_at,
                classifiers_consulted=tuple(consulted),
                classifiers_skipped=tuple(skipped),
            )

            if isinstance(classifier, AIClassifier):
                skip_ai, reason = self.decision_engine.should_skip_ai(
                    interim_collection,
                )
                if skip_ai:
                    self._record_skipped(
                        classifier_name,
                        reason,
                        trace,
                        skipped,
                    )
                    continue

            started = time.monotonic()
            try:
                items = classifier.collect_evidence(request)
            except Exception as exc:
                self.logger.exception(
                    "%s failed while collecting evidence for '%s'",
                    classifier_name,
                    domain,
                )
                trace.append(
                    {
                        "classifier": classifier_name,
                        "status": "failed",
                        "evidence_count": 0,
                        "latency_ms": self._elapsed_ms(started),
                        "reason": str(exc),
                    }
                )
                continue

            consulted.append(classifier_name)
            evidence.extend(items)
            trace.append(
                {
                    "classifier": classifier_name,
                    "status": "consulted",
                    "evidence_count": len(items),
                    "latency_ms": self._elapsed_ms(started),
                }
            )

            decisive = [item for item in items if item.decisive]
            if decisive:
                reason = f"decisive evidence from {classifier_name}"
                for remaining in self.classifiers[index + 1 :]:
                    remaining_name = self._classifier_name(remaining)
                    self._record_skipped(
                        remaining_name,
                        reason,
                        trace,
                        skipped,
                    )
                break

        completed = collection.completed(
            items=evidence,
            consulted=consulted,
            skipped=skipped,
        )
        decision = self.decision_engine.decide(
            completed,
            classifier_trace=trace,
        )

        self.logger.debug(
            "Decision for '%s': risk=%d category=%s source=%s",
            domain,
            decision.risk_score,
            decision.category,
            decision.source,
        )

        return self.decision_engine.to_analysis_result(decision)

    def _record_skipped(
        self,
        classifier_name: str,
        reason: str,
        trace: list[dict],
        skipped: list[dict],
    ) -> None:
        entry = {
            "classifier": classifier_name,
            "reason": reason,
        }
        skipped.append(entry)
        trace.append(
            {
                "classifier": classifier_name,
                "status": "skipped",
                "evidence_count": 0,
                "latency_ms": 0,
                "reason": reason,
            }
        )

    @staticmethod
    def _classifier_name(
        classifier: BaseClassifier,
    ) -> str:
        return classifier.__class__.__name__

    @staticmethod
    def _elapsed_ms(
        started: float,
    ) -> int:
        return int(round((time.monotonic() - started) * 1000))
