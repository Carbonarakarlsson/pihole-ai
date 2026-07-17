"""
Prompt builders for PiHole-AI.

All prompts sent to the LLM should be defined here.

Keeping prompts centralized makes it easy to:
- Improve prompt engineering
- Switch models
- Test prompt quality
- Keep analyzer logic clean
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
import json
from typing import Any, Mapping

from engine.models import ALLOWED_CATEGORIES


CATEGORY_LIST = "\n".join(
    f"- {category}"
    for category in sorted(ALLOWED_CATEGORIES)
)
PROMPT_VERSION = "domain-classification-v1"

# ============================================================================
# System Prompt
# ============================================================================

SYSTEM_PROMPT = f"""
You are an expert cybersecurity analyst specializing in DNS traffic analysis.

Your job is to determine whether a domain appears benign, suspicious,
tracking-related, advertising-related, or malicious.

Return ONLY valid JSON.

Never include markdown.

Never explain outside the JSON.

Use this schema exactly:

{{
    "risk": 0,
    "confidence": 0,
    "category": "",
    "reason": ""
}}

Field definitions:

risk:
Integer from 0-100

confidence:
Integer from 0-100

category:
One of:

{CATEGORY_LIST}

reason:
Short explanation (1-3 sentences).
"""

# ============================================================================
# Prompt Builder
# ============================================================================


def build_domain_prompt(
    domain: str,
    metadata: Mapping[str, Any] | Any | None = None,
) -> str:
    """
    Build a prompt for analyzing a single domain.

    Parameters
    ----------
    domain:
        Domain name to analyze.

    metadata:
        Optional contextual information gathered from Pi-hole.

    Returns
    -------
    str
        Prompt sent to the language model.
    """

    metadata_dict = metadata_to_dict(metadata)

    prompt = {
        "task": "Analyze this DNS domain.",
        "domain": domain,
        "metadata": metadata_dict,
        "instructions": [
            "Assess the likelihood that this domain is malicious.",
            "Consider whether it appears to be advertising, tracking, analytics, malware, phishing, or command-and-control.",
            "Use the metadata when available.",
            "Return ONLY valid JSON matching the required schema.",
        ],
    }

    return json.dumps(prompt, indent=2)


def metadata_to_dict(
    metadata: Mapping[str, Any] | Any | None,
) -> dict[str, Any]:
    """
    Convert metadata into a JSON-safe plain dictionary.
    """

    if metadata is None:
        return {}

    if isinstance(metadata, dict):
        return metadata

    if is_dataclass(metadata):
        return asdict(metadata)

    return dict(metadata)


# ============================================================================
# Helper Prompt
# ============================================================================


def build_health_check_prompt() -> str:
    """
    Simple prompt used to verify the LLM is responding correctly.
    """

    return (
        'Return ONLY this JSON: '
        '{"risk":0,"confidence":100,"category":"benign","reason":"health check"}'
    )
