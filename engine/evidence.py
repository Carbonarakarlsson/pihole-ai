"""
Structured evidence and decision models for PiHole-AI.

Evidence scores use a signed -100..100 scale:
- positive scores increase risk
- negative scores decrease risk
- zero is neutral

Final decisions use the existing 0..100 risk scale.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


EVIDENCE_POLICY_VERSION = "evidence-policy-v1"
MAX_EVIDENCE_ITEMS = 50
MAX_CLASSIFIER_TRACE_ITEMS = 30
MAX_SUMMARY_LENGTH = 240
MAX_DETAILS_LENGTH = 1000
MAX_METADATA_BYTES = 2048
SECRET_METADATA_MARKERS = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "csrf",
    "password",
    "prompt",
    "raw_model",
    "raw_payload",
    "secret",
    "session",
    "token",
}


class EvidencePolarity(str, Enum):
    RISK = "risk"
    SAFETY = "safety"
    NEUTRAL = "neutral"


class EvidenceStrength(str, Enum):
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    DECISIVE = "decisive"


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        if isinstance(value, dict):
            return {str(key): _json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [_json_safe(item) for item in value]
        return str(value)


def sanitize_metadata(
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Return JSON-safe metadata with secrets and oversize values removed.
    """

    sanitized: dict[str, Any] = {}
    for key, value in dict(metadata or {}).items():
        normalized = str(key).lower()
        if any(marker in normalized for marker in SECRET_METADATA_MARKERS):
            sanitized[str(key)] = "[redacted]"
            continue
        sanitized[str(key)] = _json_safe(value)

    encoded = json.dumps(sanitized, sort_keys=True)
    if len(encoded.encode("utf-8")) <= MAX_METADATA_BYTES:
        return sanitized

    compact: dict[str, Any] = {
        "_truncated": True,
    }
    size = len(json.dumps(compact).encode("utf-8"))
    for key in sorted(sanitized):
        candidate = {**compact, key: sanitized[key]}
        encoded_candidate = json.dumps(candidate, sort_keys=True)
        candidate_size = len(encoded_candidate.encode("utf-8"))
        if candidate_size > MAX_METADATA_BYTES:
            continue
        compact[key] = sanitized[key]
        size = candidate_size
        if size >= MAX_METADATA_BYTES:
            break
    return compact


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    evidence_id: str
    classifier: str
    evidence_type: str
    polarity: EvidencePolarity | str
    score: float
    confidence: float
    summary: str
    details: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        polarity = EvidencePolarity(self.polarity)
        object.__setattr__(self, "polarity", polarity)
        object.__setattr__(self, "score", max(-100.0, min(100.0, float(self.score))))
        object.__setattr__(self, "confidence", max(0.0, min(1.0, float(self.confidence))))
        object.__setattr__(self, "summary", str(self.summary)[:MAX_SUMMARY_LENGTH])
        object.__setattr__(self, "details", str(self.details)[:MAX_DETAILS_LENGTH])
        object.__setattr__(self, "metadata", sanitize_metadata(self.metadata))

    @property
    def decisive(self) -> bool:
        return bool(self.metadata.get("decisive", False))

    @property
    def precedence(self) -> int:
        return int(self.metadata.get("precedence", 1000))

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "classifier": self.classifier,
            "evidence_type": self.evidence_type,
            "polarity": self.polarity.value,
            "score": self.score,
            "confidence": self.confidence,
            "summary": self.summary,
            "details": self.details,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "decisive": self.decisive,
        }


@dataclass(frozen=True, slots=True)
class EvidenceCollection:
    domain: str
    items: tuple[EvidenceItem, ...] = ()
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    classifiers_consulted: tuple[str, ...] = ()
    classifiers_skipped: tuple[dict[str, Any], ...] = ()

    def completed(
        self,
        *,
        items: list[EvidenceItem],
        consulted: list[str],
        skipped: list[dict[str, Any]],
    ) -> "EvidenceCollection":
        return EvidenceCollection(
            domain=self.domain,
            items=tuple(items),
            started_at=self.started_at,
            completed_at=time.time(),
            classifiers_consulted=tuple(consulted),
            classifiers_skipped=tuple(skipped),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "items": [item.to_dict() for item in self.items],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "classifiers_consulted": list(self.classifiers_consulted),
            "classifiers_skipped": list(self.classifiers_skipped),
        }


@dataclass(frozen=True, slots=True)
class DecisionResult:
    domain: str
    verdict: str
    risk_score: int
    confidence: float
    category: str
    source: str
    explanation: str
    evidence: EvidenceCollection
    decisive_evidence_ids: tuple[str, ...] = ()
    classifier_trace: tuple[dict[str, Any], ...] = ()
    conflicts: tuple[str, ...] = ()
    policy_version: str = EVIDENCE_POLICY_VERSION
    application_version: str = ""
    schema_version: int | None = None
    evidence_truncated: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return serialize_decision(self)


def evidence_sort_key(
    item: dict[str, Any],
) -> tuple[int, float, float, str, str]:
    return (
        0 if item.get("decisive") else 1,
        -abs(float(item.get("score", 0) or 0)),
        -float(item.get("confidence", 0) or 0),
        str(item.get("classifier", "")),
        str(item.get("evidence_id", "")),
    )


def serialize_evidence_item(
    item: EvidenceItem | dict[str, Any],
) -> dict[str, Any]:
    if isinstance(item, EvidenceItem):
        payload = item.to_dict()
    else:
        payload = dict(item)
        payload["metadata"] = sanitize_metadata(payload.get("metadata"))

    polarity = payload.get("polarity", EvidencePolarity.NEUTRAL.value)
    if isinstance(polarity, EvidencePolarity):
        polarity = polarity.value
    if polarity not in {item.value for item in EvidencePolarity}:
        polarity = EvidencePolarity.NEUTRAL.value

    return {
        "evidence_id": str(payload.get("evidence_id", "")),
        "classifier": str(payload.get("classifier", "unknown")),
        "evidence_type": str(payload.get("evidence_type", "unknown")),
        "polarity": polarity,
        "score": max(-100.0, min(100.0, float(payload.get("score", 0) or 0))),
        "confidence": max(0.0, min(1.0, float(payload.get("confidence", 0) or 0))),
        "summary": str(payload.get("summary", ""))[:MAX_SUMMARY_LENGTH],
        "details": str(payload.get("details", ""))[:MAX_DETAILS_LENGTH],
        "metadata": sanitize_metadata(payload.get("metadata")),
        "decisive": bool(payload.get("decisive", False)),
        "created_at": float(payload.get("created_at", time.time()) or 0),
    }


def serialize_classifier_trace(
    trace: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    allowed_statuses = {"consulted", "skipped", "failed", "decisive"}
    serialized = []
    for entry in list(trace or [])[:MAX_CLASSIFIER_TRACE_ITEMS]:
        status = str(entry.get("status", "consulted"))
        if status not in allowed_statuses:
            status = "failed"
        serialized.append(
            {
                "classifier": str(entry.get("classifier", "unknown")),
                "status": status,
                "evidence_count": int(entry.get("evidence_count", 0) or 0),
                "latency_ms": int(entry.get("latency_ms", 0) or 0),
                "reason": str(entry.get("reason", ""))[:MAX_SUMMARY_LENGTH],
            }
        )
    return serialized


def detect_conflicts(
    evidence: list[dict[str, Any]],
) -> list[str]:
    risk = [item for item in evidence if item["polarity"] == EvidencePolarity.RISK.value]
    safety = [item for item in evidence if item["polarity"] == EvidencePolarity.SAFETY.value]
    conflicts = []
    if risk and safety:
        conflicts.append("Risk evidence conflicts with safety evidence.")
    if any(item["classifier"] == "ai" for item in risk) and any(
        item["classifier"] != "ai" for item in safety
    ):
        conflicts.append("AI risk evidence conflicts with deterministic safety evidence.")
    if any(item["classifier"] == "ai" for item in safety) and any(
        item["classifier"] != "ai" for item in risk
    ):
        conflicts.append("AI safety evidence conflicts with deterministic risk evidence.")
    return conflicts


def serialize_decision(
    decision: DecisionResult,
    *,
    legacy: bool = False,
) -> dict[str, Any]:
    evidence = [
        serialize_evidence_item(item)
        for item in decision.evidence.items
    ]
    evidence = sorted(evidence, key=evidence_sort_key)
    truncated = decision.evidence_truncated or len(evidence) > MAX_EVIDENCE_ITEMS
    evidence = evidence[:MAX_EVIDENCE_ITEMS]
    conflicts = list(decision.conflicts) or detect_conflicts(evidence)

    return {
        "domain": decision.domain,
        "verdict": decision.verdict,
        "risk_score": int(decision.risk_score),
        "confidence": float(decision.confidence),
        "category": decision.category,
        "source": decision.source,
        "explanation": decision.explanation,
        "decisive_evidence_ids": list(decision.decisive_evidence_ids),
        "evidence": evidence,
        "classifier_trace": serialize_classifier_trace(decision.classifier_trace),
        "conflicts": conflicts,
        "legacy": legacy,
        "policy_version": decision.policy_version,
        "application_version": decision.application_version,
        "schema_version": decision.schema_version,
        "evidence_truncated": truncated,
        "created_at": float(decision.created_at),
    }
