"""
PiHole-AI AI Classifier

Uses a local Ollama model to classify domains that cannot be
classified by deterministic rules or heuristics.
"""

from __future__ import annotations

import json

from core.logger import get_logger

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

        self.logger.info(
            "Falling back to AI for '%s'",
            request.domain,
        )

        prompt = build_domain_prompt(
            domain=request.domain,
            metadata=request.metadata,
        )

        try:
            response = self.client.generate(
                system=SYSTEM_PROMPT,
                prompt=prompt,
            )

        except Exception as exc:
            self.logger.warning(
                "AI backend failed for '%s': %s",
                request.domain,
                exc,
            )

            return self._fallback(
                request,
                "AI backend unavailable.",
            )

        return self._parse_response(
            request,
            response,
        )

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

            return self._fallback(
                request,
                "Model returned invalid JSON.",
            )

        if not validate_ai_response(data):

            self.logger.warning(
                "Model returned an invalid response for '%s'.",
                request.domain,
            )

            return self._fallback(
                request,
                "Model returned an invalid response.",
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
