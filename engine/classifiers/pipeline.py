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
from engine.prompts import PROMPT_VERSION
from engine.telemetry import (
    ClassifierTelemetry,
    PipelineTelemetry,
    confidence_band,
    new_telemetry_id,
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
        telemetry = PipelineTelemetry.start(domain)

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
                        telemetry,
                        index + 1,
                    )
                    continue

            stage_started_at = time.time()
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
                telemetry.stages.append(
                    ClassifierTelemetry(
                        stage_id=new_telemetry_id("pts"),
                        run_id=telemetry.run_id,
                        classifier_name=classifier_name,
                        execution_order=index + 1,
                        started_at=stage_started_at,
                        duration_ms=self._elapsed_ms(started),
                        classifier_result="failed",
                        skipped=False,
                        stop_reason=None,
                        retry_count=0,
                        timeout=False,
                    )
                )
                continue

            elapsed_ms = self._elapsed_ms(started)
            consulted.append(classifier_name)
            evidence.extend(items)
            trace.append(
                {
                    "classifier": classifier_name,
                    "status": "consulted",
                    "evidence_count": len(items),
                    "latency_ms": elapsed_ms,
                }
            )
            telemetry.stages.append(
                self._stage_telemetry(
                    telemetry=telemetry,
                    classifier_name=classifier_name,
                    execution_order=index + 1,
                    started_at=stage_started_at,
                    duration_ms=elapsed_ms,
                    items=items,
                )
            )

            decisive = [item for item in items if item.decisive]
            if decisive:
                reason = f"decisive evidence from {classifier_name}"
                telemetry.stop_reason = reason
                for remaining in self.classifiers[index + 1 :]:
                    remaining_name = self._classifier_name(remaining)
                    self._record_skipped(
                        remaining_name,
                        reason,
                        trace,
                        skipped,
                        telemetry,
                        self.classifiers.index(remaining) + 1,
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
        telemetry.finish(
            stop_reason=telemetry.stop_reason or "pipeline_exhausted",
        )

        self.logger.debug(
            "Decision for '%s': risk=%d category=%s source=%s",
            domain,
            decision.risk_score,
            decision.category,
            decision.source,
        )

        result = self.decision_engine.to_analysis_result(decision)
        result.telemetry = telemetry
        return result

    def _record_skipped(
        self,
        classifier_name: str,
        reason: str,
        trace: list[dict],
        skipped: list[dict],
        telemetry: PipelineTelemetry,
        execution_order: int,
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
        if classifier_name == "AIClassifier":
            telemetry.stop_reason = reason
        telemetry.stages.append(
            ClassifierTelemetry(
                stage_id=new_telemetry_id("pts"),
                run_id=telemetry.run_id,
                classifier_name=classifier_name,
                execution_order=execution_order,
                skipped=True,
                skip_reason=reason,
                stop_reason=reason,
                cache_hit=False,
                ai_invoked=False if classifier_name == "AIClassifier" else None,
                ai_invocation_reason=reason if classifier_name == "AIClassifier" else None,
                prompt_version=None,
                ai_considered=True if classifier_name == "AIClassifier" else None,
                request_attempt_count=0 if classifier_name == "AIClassifier" else None,
                parse_attempt_count=0 if classifier_name == "AIClassifier" else None,
                retry_count=0,
                timeout=False,
                parse_failure=False if classifier_name == "AIClassifier" else None,
            )
        )

    def _stage_telemetry(
        self,
        *,
        telemetry: PipelineTelemetry,
        classifier_name: str,
        execution_order: int,
        started_at: float,
        duration_ms: int,
        items: list[EvidenceItem],
    ) -> ClassifierTelemetry:
        confidence = self._raw_confidence(items)
        category = self._category(items)
        result = category or ("no_evidence" if not items else None)
        ai_invoked = None
        ai_considered = None
        ai_invocation_reason = None
        configured_ai_model = None
        ai_model = None
        prompt_version = None
        timeout = False
        parse_failure = None
        rate_limit_skip = None
        cooldown_skip = None
        request_attempt_count = None
        parse_attempt_count = None
        inference_duration_ms = None
        final_ai_category = None
        final_ai_confidence = None
        fallback_reason = None
        retry_count = 0
        skip_reason = None

        if classifier_name == "AIClassifier":
            prompt_version = PROMPT_VERSION
            ai_item = items[0] if items else None
            if ai_item is not None:
                metadata = ai_item.metadata
                ai_considered = bool(metadata.get("ai_considered", True))
                ai_invocation_reason = str(metadata.get("ai_invocation_reason") or "") or None
                configured_ai_model = str(metadata.get("configured_ai_model") or "") or None
                ai_model = (
                    str(metadata.get("actual_ai_model") or metadata.get("model") or "")
                    or None
                )
                prompt_version = (
                    str(metadata.get("template_version") or "") or PROMPT_VERSION
                )
                skip_reason = str(metadata.get("skip_reason") or "") or None
                timeout = skip_reason == "ai_timeout"
                if "ai_invoked" in metadata:
                    ai_invoked = bool(metadata.get("ai_invoked"))
                else:
                    ai_invoked = skip_reason not in {
                        "ai_disabled",
                        "ai_rate_limited",
                        "ai_cooldown",
                    }
                request_attempt_count = self._int_or_none(metadata.get("request_attempt_count"))
                parse_attempt_count = self._int_or_none(metadata.get("parse_attempt_count"))
                retry_count = self._int_or_none(metadata.get("retry_count")) or 0
                timeout = bool(metadata.get("timeout", timeout))
                parse_failure = bool(metadata.get("parse_failure", False))
                rate_limit_skip = bool(metadata.get("rate_limit_skip", False))
                cooldown_skip = bool(metadata.get("cooldown_skip", False))
                inference_duration_ms = self._int_or_none(metadata.get("inference_duration_ms"))
                final_ai_category = str(metadata.get("final_ai_category") or "") or category
                final_ai_confidence = self._int_or_none(metadata.get("final_ai_confidence"))
                fallback_reason = str(metadata.get("fallback_reason") or "") or None
            else:
                ai_considered = True
                ai_invoked = False

        return ClassifierTelemetry(
            stage_id=new_telemetry_id("pts"),
            run_id=telemetry.run_id,
            classifier_name=classifier_name,
            execution_order=execution_order,
            started_at=started_at,
            duration_ms=duration_ms,
            classifier_result=result,
            confidence_raw=confidence,
            confidence_band=confidence_band(confidence),
            skipped=False,
            skip_reason=skip_reason,
            cache_hit=False,
            ai_considered=ai_considered,
            ai_invoked=ai_invoked,
            ai_invocation_reason=ai_invocation_reason,
            configured_ai_model=configured_ai_model,
            ai_model=ai_model,
            prompt_version=prompt_version,
            request_attempt_count=request_attempt_count,
            parse_attempt_count=parse_attempt_count,
            retry_count=retry_count,
            timeout=timeout,
            parse_failure=parse_failure,
            rate_limit_skip=rate_limit_skip,
            cooldown_skip=cooldown_skip,
            inference_duration_ms=inference_duration_ms,
            final_ai_category=final_ai_category,
            final_ai_confidence=final_ai_confidence,
            fallback_reason=fallback_reason,
        )

    @staticmethod
    def _raw_confidence(
        items: list[EvidenceItem],
    ) -> int | None:
        if not items:
            return None
        return int(round(max(item.confidence for item in items) * 100))

    @staticmethod
    def _category(
        items: list[EvidenceItem],
    ) -> str | None:
        for item in items:
            category = item.metadata.get("category")
            if category:
                return str(category)
        return None

    @staticmethod
    def _int_or_none(
        value,
    ) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

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
