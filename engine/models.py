"""
Data models used by the AI engine.

These dataclasses define the structured objects exchanged between
the analyzer, Ollama client, database layer, and future dashboard.

Using dataclasses instead of dictionaries provides:

- Better type safety
- IDE autocompletion
- Easier testing
- Clearer interfaces
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from time import time
from typing import Any


# ============================================================================
# Domain Categories
# ============================================================================

class DomainCategory(str, Enum):
    """
    Canonical domain analysis categories.
    """

    BENIGN = "benign"
    INFRASTRUCTURE = "infrastructure"
    ADVERTISING = "advertising"
    ANALYTICS = "analytics"
    TRACKING = "tracking"
    SUSPICIOUS = "suspicious"
    MALWARE = "malware"
    PHISHING = "phishing"
    COMMAND_AND_CONTROL = "command-and-control"
    UNKNOWN = "unknown"


ALLOWED_CATEGORIES = {
    category.value
    for category in DomainCategory
}


# ============================================================================
# Domain Analysis Result
# ============================================================================

@dataclass(slots=True)
class AnalysisResult:
    """
    Result returned by the AI analyzer.
    """

    domain: str

    risk: int

    confidence: int

    category: str

    reason: str

    model: str

    analyzed_at: float = field(default_factory=time)

    cached: bool = False


# ============================================================================
# Domain Metadata
# ============================================================================

@dataclass(slots=True)
class DomainMetadata:
    """
    Context gathered from the database before analysis.
    """

    domain: str

    query_count: int = 0

    first_seen: float = 0.0

    last_seen: float = 0.0

    device_count: int = 0

    recent_queries: int = 0

    tags: list[str] = field(default_factory=list)


# ============================================================================
# AI Request
# ============================================================================

@dataclass(slots=True)
class AnalysisRequest:
    """
    Request sent to the analyzer.
    """

    domain: str

    metadata: DomainMetadata | None = None

    force_refresh: bool = False


# ============================================================================
# Health Check Result
# ============================================================================

@dataclass(slots=True)
class HealthStatus:
    """
    Health information for the AI subsystem.
    """

    available: bool

    model: str

    latency_ms: float

    message: str = ""


# ============================================================================
# JSON Validation
# ============================================================================

REQUIRED_FIELDS = {
    "risk",
    "confidence",
    "category",
    "reason",
}


def validate_ai_response(response: dict[str, Any]) -> bool:
    """
    Validate that an AI response contains the expected fields.
    """

    if not REQUIRED_FIELDS.issubset(response.keys()):
        return False

    if not isinstance(response["risk"], int):
        return False

    if not isinstance(response["confidence"], int):
        return False

    if not isinstance(response["category"], str):
        return False

    if not isinstance(response["reason"], str):
        return False

    if not (0 <= response["risk"] <= 100):
        return False

    if not (0 <= response["confidence"] <= 100):
        return False

    if response["category"] not in ALLOWED_CATEGORIES:
        return False

    return True


# ============================================================================
# Factory
# ============================================================================

def analysis_from_json(
    domain: str,
    model: str,
    response: dict[str, Any],
) -> AnalysisResult:
    """
    Convert validated JSON into an AnalysisResult.
    """

    return AnalysisResult(
        domain=domain,
        risk=response["risk"],
        confidence=response["confidence"],
        category=response["category"],
        reason=response["reason"],
        model=model,
    )
