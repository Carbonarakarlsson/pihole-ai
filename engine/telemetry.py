"""
Observational pipeline telemetry models.

Telemetry is sidecar data. It must never influence classifier ordering,
evidence, or final decisions.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any


PROMPT_VERSION_UNKNOWN = "unknown"


def new_telemetry_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def confidence_band(confidence: int | float | None) -> str | None:
    if confidence is None:
        return None

    value = float(confidence)
    if value > 1:
        value = value / 100.0

    if value < 0.20:
        return "very_low"
    if value < 0.40:
        return "low"
    if value < 0.70:
        return "medium"
    if value < 0.90:
        return "high"
    return "very_high"


@dataclass(slots=True)
class ClassifierTelemetry:
    stage_id: str
    run_id: str
    classifier_name: str
    execution_order: int
    started_at: float | None = None
    duration_ms: int | None = None
    classifier_result: str | None = None
    confidence_raw: int | None = None
    confidence_band: str | None = None
    skipped: bool = False
    skip_reason: str | None = None
    stop_reason: str | None = None
    cache_hit: bool | None = None
    ai_considered: bool | None = None
    ai_invoked: bool | None = None
    ai_invocation_reason: str | None = None
    configured_ai_model: str | None = None
    ai_model: str | None = None
    prompt_version: str | None = None
    request_attempt_count: int | None = None
    parse_attempt_count: int | None = None
    retry_count: int | None = None
    timeout: bool | None = None
    parse_failure: bool | None = None
    rate_limit_skip: bool | None = None
    cooldown_skip: bool | None = None
    inference_duration_ms: int | None = None
    final_ai_category: str | None = None
    final_ai_confidence: int | None = None
    fallback_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PipelineTelemetry:
    run_id: str
    domain: str
    started_at: float
    completed_at: float | None = None
    duration_ms: int | None = None
    cache_hit: bool | None = None
    stop_reason: str | None = None
    ai_considered: bool | None = None
    ai_invoked: bool | None = None
    ai_invocation_reason: str | None = None
    configured_ai_model: str | None = None
    ai_model: str | None = None
    prompt_version: str | None = None
    request_attempt_count: int | None = None
    parse_attempt_count: int | None = None
    retry_count: int | None = None
    timeout: bool | None = None
    parse_failure: bool | None = None
    rate_limit_skip: bool | None = None
    cooldown_skip: bool | None = None
    inference_duration_ms: int | None = None
    final_ai_category: str | None = None
    final_ai_confidence: int | None = None
    fallback_reason: str | None = None
    final_decision_id: str | None = None
    stages: list[ClassifierTelemetry] = field(default_factory=list)

    @classmethod
    def start(
        cls,
        domain: str,
    ) -> "PipelineTelemetry":
        return cls(
            run_id=new_telemetry_id("ptr"),
            domain=domain.lower(),
            started_at=time.time(),
        )

    @classmethod
    def cache_hit_run(
        cls,
        domain: str,
    ) -> "PipelineTelemetry":
        now = time.time()
        return cls(
            run_id=new_telemetry_id("ptr"),
            domain=domain.lower(),
            started_at=now,
            completed_at=now,
            duration_ms=0,
            cache_hit=True,
            stop_reason="cache_hit",
            ai_considered=False,
            ai_invoked=False,
            retry_count=0,
            timeout=False,
        )

    def finish(
        self,
        *,
        stop_reason: str | None = None,
    ) -> None:
        self.completed_at = time.time()
        self.duration_ms = int(round((self.completed_at - self.started_at) * 1000))
        if stop_reason is not None:
            self.stop_reason = stop_reason
        ai_stages = [stage for stage in self.stages if stage.classifier_name == "AIClassifier"]
        if ai_stages:
            latest = ai_stages[-1]
            self.ai_considered = latest.ai_considered
            self.ai_invoked = latest.ai_invoked
            self.ai_invocation_reason = latest.ai_invocation_reason
            self.configured_ai_model = latest.configured_ai_model
            self.ai_model = latest.ai_model
            self.prompt_version = latest.prompt_version
            self.request_attempt_count = latest.request_attempt_count
            self.parse_attempt_count = latest.parse_attempt_count
            self.retry_count = latest.retry_count
            self.timeout = latest.timeout
            self.parse_failure = latest.parse_failure
            self.rate_limit_skip = latest.rate_limit_skip
            self.cooldown_skip = latest.cooldown_skip
            self.inference_duration_ms = latest.inference_duration_ms
            self.final_ai_category = latest.final_ai_category
            self.final_ai_confidence = latest.final_ai_confidence
            self.fallback_reason = latest.fallback_reason
        elif self.ai_invoked is None:
            self.ai_invoked = False
