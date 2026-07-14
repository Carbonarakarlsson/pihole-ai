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
        object.__setattr__(self, "summary", str(self.summary)[:240])
        object.__setattr__(self, "details", str(self.details)[:1000])
        object.__setattr__(self, "metadata", _json_safe(dict(self.metadata or {})))

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
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "category": self.category,
            "source": self.source,
            "explanation": self.explanation,
            "evidence": self.evidence.to_dict(),
            "decisive_evidence_ids": list(self.decisive_evidence_ids),
            "classifier_trace": list(self.classifier_trace),
            "created_at": self.created_at,
        }
