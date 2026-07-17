"""
PiHole-AI AI Classifier

Uses a local Ollama model to classify domains that cannot be
classified by deterministic rules or heuristics.
"""

from __future__ import annotations

import json
import time

from core.config import settings
from core.db import (
    get_int_state,
    increment_state_counter,
    set_state,
)
from core.logger import get_logger

from engine.evidence import EvidenceItem, EvidencePolarity
from engine.models import (
    AnalysisRequest,
    AnalysisResult,
    DomainCategory,
    analysis_from_json,
    validate_ai_response,
)
from engine.classifiers.base import BaseClassifier
from engine.ollama_client import OllamaClient
from engine.prompts import (
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    build_domain_prompt,
)


class AIClassifier(BaseClassifier):
    """
    AI-powered classifier backed by a local Ollama model.
    """

    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self.client = OllamaClient()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult | None:
        """
        Classify a domain using the configured Ollama model.
        """

        if not settings.ai_enabled:
            increment_state_counter("ai.disabled_skips.total")
            return self._with_ai_telemetry(
                self._safe_unknown(
                    request,
                    "ai_disabled",
                ),
                request,
                ai_invoked=False,
                ai_invocation_reason="ai_disabled",
                skip_reason="ai_disabled",
                request_attempt_count=0,
                parse_attempt_count=0,
                fallback_reason="ai_disabled",
            )

        now = time.time()

        if self._in_cooldown(now):
            increment_state_counter("ai.cooldown_skips.total")
            return self._with_ai_telemetry(
                self._safe_unknown(
                    request,
                    "ai_cooldown",
                ),
                request,
                ai_invoked=False,
                ai_invocation_reason="ai_cooldown",
                skip_reason="ai_cooldown",
                request_attempt_count=0,
                parse_attempt_count=0,
                cooldown_skip=True,
                fallback_reason="ai_cooldown",
            )

        if not self._reserve_call(now):
            increment_state_counter("ai.rate_limit_skips.total")
            return self._with_ai_telemetry(
                self._safe_unknown(
                    request,
                    "ai_rate_limited",
                ),
                request,
                ai_invoked=False,
                ai_invocation_reason="ai_rate_limited",
                skip_reason="ai_rate_limited",
                request_attempt_count=0,
                parse_attempt_count=0,
                rate_limit_skip=True,
                fallback_reason="ai_rate_limited",
            )

        self.logger.debug(
            "Falling back to AI for '%s'",
            request.domain,
        )

        prompt = build_domain_prompt(
            domain=request.domain,
            metadata=request.metadata,
        )

        try:
            started_at = time.monotonic()
            response = self.client.generate(
                system=SYSTEM_PROMPT,
                prompt=prompt,
            )
            elapsed = time.monotonic() - started_at

        except Exception as exc:
            self.logger.warning(
                "AI backend failed for '%s': %s",
                request.domain,
                exc,
            )
            self._start_cooldown(time.time())

            if self._is_timeout_exception(exc):
                increment_state_counter("ai.timeouts.total")
                return self._with_ai_telemetry(
                    self._safe_unknown(
                        request,
                        "ai_timeout",
                    ),
                    request,
                    ai_invoked=True,
                    ai_invocation_reason="fallback_needed",
                    skip_reason="ai_timeout",
                    request_attempt_count=1,
                    parse_attempt_count=0,
                    timeout=True,
                    inference_duration_ms=self._elapsed_ms(started_at),
                    fallback_reason="ai_timeout",
                )

            return self._with_ai_telemetry(
                self._fallback(
                    request,
                    "AI backend unavailable.",
                ),
                request,
                ai_invoked=True,
                ai_invocation_reason="fallback_needed",
                request_attempt_count=1,
                parse_attempt_count=0,
                inference_duration_ms=self._elapsed_ms(started_at),
                fallback_reason="AI backend unavailable.",
            )

        result = self._parse_response(
            request,
            response,
        )

        if result.reason == "AI returned invalid response":
            increment_state_counter("ai.parse_errors.total")
            self._start_cooldown(time.time())

        elif self._is_slow_response(elapsed):
            increment_state_counter("ai.slow_responses.total")
            self._start_cooldown(time.time())

        return self._with_ai_telemetry(
            result,
            request,
            ai_invoked=True,
            ai_invocation_reason="fallback_needed",
            request_attempt_count=1,
            parse_attempt_count=1,
            parse_failure=result.reason == "AI returned invalid response",
            inference_duration_ms=int(round(elapsed * 1000)),
            final_ai_category=result.category,
            final_ai_confidence=result.confidence,
            fallback_reason=(
                result.reason
                if result.reason == "AI returned invalid response"
                else None
            ),
        )

    def collect_evidence(
        self,
        request: AnalysisRequest,
    ) -> list[EvidenceItem]:
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

        evidence_type = "ai_result"
        if result.reason in {
            "ai_disabled",
            "ai_rate_limited",
            "ai_cooldown",
            "ai_timeout",
            "AI returned invalid response",
        }:
            evidence_type = "ai_skipped"

        ai_telemetry = (
            dict(result.telemetry)
            if isinstance(result.telemetry, dict)
            else {}
        )
        metadata = {
            "category": result.category,
            "model": result.model,
            "skip_reason": (
                result.reason if evidence_type == "ai_skipped" else ""
            ),
        }
        metadata.update(ai_telemetry)

        return [
            EvidenceItem(
                evidence_id=f"ai:{request.domain.lower()}:{evidence_type}",
                classifier="ai",
                evidence_type=evidence_type,
                polarity=polarity,
                score=score,
                confidence=result.confidence / 100.0,
                summary=result.reason,
                metadata=metadata,
            )
        ]

    # ------------------------------------------------------------------
    # Rate Limiting
    # ------------------------------------------------------------------

    def _in_cooldown(
        self,
        now: float,
    ) -> bool:
        """
        Return True when AI calls should be skipped temporarily.
        """

        return int(now) < get_int_state("ai.cooldown_until", 0)

    def _start_cooldown(
        self,
        now: float,
    ) -> None:
        """
        Persist the next time at which AI calls are allowed.
        """

        if settings.ai_cooldown_seconds <= 0:
            return

        set_state(
            "ai.cooldown_until",
            str(int(now + settings.ai_cooldown_seconds)),
        )

    def _reserve_call(
        self,
        now: float,
    ) -> bool:
        """
        Reserve one Ollama call in the current one-minute window.
        """

        max_calls = settings.ai_max_calls_per_minute

        if max_calls <= 0:
            return False

        window_started_at = get_int_state("ai.window_started_at", 0)
        window_calls = get_int_state("ai.window_calls", 0)

        if int(now) - window_started_at >= 60:
            window_started_at = int(now)
            window_calls = 0
            set_state("ai.window_started_at", str(window_started_at))
            set_state("ai.window_calls", "0")

        if window_calls >= max_calls:
            return False

        set_state("ai.window_calls", str(window_calls + 1))
        increment_state_counter("ai.calls.total")

        return True

    def _is_slow_response(
        self,
        elapsed: float,
    ) -> bool:
        """
        Treat responses slower than the timeout budget as unhealthy.
        """

        return (
            settings.ai_timeout_seconds > 0
            and elapsed >= settings.ai_timeout_seconds
        )

    def _is_timeout_exception(
        self,
        exc: Exception,
    ) -> bool:
        """
        Return True for common timeout exceptions without importing clients.
        """

        class_name = exc.__class__.__name__.lower()
        return isinstance(exc, TimeoutError) or "timeout" in class_name

    def _with_ai_telemetry(
        self,
        result: AnalysisResult,
        request: AnalysisRequest,
        **values,
    ) -> AnalysisResult:
        """
        Attach safe observational AI metadata to one classifier result.
        """

        actual_model = values.pop("actual_ai_model", None)
        if actual_model is None and values.get("ai_invoked"):
            actual_model = result.model if result.model != "ai" else self._current_model_safe()

        result.telemetry = {
            "ai_considered": True,
            "ai_invoked": values.get("ai_invoked"),
            "ai_invocation_reason": values.get("ai_invocation_reason"),
            "configured_ai_model": self._configured_model(),
            "actual_ai_model": actual_model,
            "template_version": PROMPT_VERSION,
            "request_attempt_count": values.get("request_attempt_count"),
            "parse_attempt_count": values.get("parse_attempt_count"),
            "retry_count": 0,
            "timeout": bool(values.get("timeout", False)),
            "parse_failure": bool(values.get("parse_failure", False)),
            "rate_limit_skip": bool(values.get("rate_limit_skip", False)),
            "cooldown_skip": bool(values.get("cooldown_skip", False)),
            "inference_duration_ms": values.get("inference_duration_ms"),
            "final_ai_category": values.get("final_ai_category", result.category),
            "final_ai_confidence": values.get("final_ai_confidence", result.confidence),
            "fallback_reason": values.get("fallback_reason"),
            "skip_reason": values.get("skip_reason"),
        }
        return result

    def _configured_model(self) -> str | None:
        return str(getattr(settings, "ollama_model", "") or "") or None

    def _current_model_safe(self) -> str | None:
        try:
            return self.client.current_model()
        except Exception:
            return None

    @staticmethod
    def _elapsed_ms(
        started_at: float,
    ) -> int:
        return int(round((time.monotonic() - started_at) * 1000))

    # ------------------------------------------------------------------
    # Response Parsing
    # ------------------------------------------------------------------

    def _parse_response(
        self,
        request: AnalysisRequest,
        response: str,
    ) -> AnalysisResult:
        """
        Parse and validate the JSON returned by the LLM.
        """

        try:
            data = json.loads(response)

        except json.JSONDecodeError:

            self.logger.warning(
                "Model returned invalid JSON for '%s'.",
                request.domain,
            )

            return self._parse_error(
                request,
            )

        if not validate_ai_response(data):

            self.logger.warning(
                "Model returned an invalid response for '%s'.",
                request.domain,
            )

            return self._parse_error(
                request,
            )

        return analysis_from_json(
            domain=request.domain,
            model=self.client.current_model(),
            response=data,
        )

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------

    def _fallback(
        self,
        request: AnalysisRequest,
        reason: str,
    ) -> AnalysisResult:
        """
        Return a safe fallback result if the AI response
        cannot be parsed or validated.
        """

        return AnalysisResult(
            domain=request.domain,
            risk=50,
            confidence=0,
            category=DomainCategory.UNKNOWN.value,
            reason=reason,
            model=self.client.current_model(),
        )

    def _safe_unknown(
        self,
        request: AnalysisRequest,
        reason: str,
    ) -> AnalysisResult:
        """
        Return a safe unknown result without contacting Ollama.
        """

        return AnalysisResult(
            domain=request.domain,
            risk=0,
            confidence=0,
            category=DomainCategory.UNKNOWN.value,
            reason=reason,
            model="ai",
        )

    def _parse_error(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult:
        """
        Return a safe parse-error result for invalid model output.
        """

        return AnalysisResult(
            domain=request.domain,
            risk=0,
            confidence=0,
            category=DomainCategory.UNKNOWN.value,
            reason="AI returned invalid response",
            model="ai",
        )
