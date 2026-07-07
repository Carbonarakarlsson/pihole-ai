"""
PiHole-AI Analyzer

Coordinates domain analysis using:

Database
    ↓
Prompt Builder
    ↓
Ollama Client
    ↓
JSON Validation
    ↓
AnalysisResult
"""

from __future__ import annotations

import json

from core.logger import get_logger

from engine.models import (
    AnalysisRequest,
    AnalysisResult,
    analysis_from_json,
    validate_ai_response,
)

from engine.ollama_client import OllamaClient
from engine.prompts import (
    SYSTEM_PROMPT,
    build_domain_prompt,
)

logger = get_logger(__name__)


class Analyzer:
    """
    High-level AI analyzer.

    This class coordinates prompt generation,
    model execution,
    validation,
    and conversion into strongly typed objects.
    """

    def __init__(
        self,
        client: OllamaClient | None = None,
    ) -> None:

        self.client = client or OllamaClient()

    # ------------------------------------------------------------------

    def analyze(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult:
        """
        Analyze a domain.

        Parameters
        ----------
        request
            Analysis request.

        Returns
        -------
        AnalysisResult
        """

        logger.info("Analyzing %s", request.domain)

        prompt = build_domain_prompt(
            request.domain,
            request.metadata.__dict__
            if request.metadata
            else {},
        )

        response = self.client.generate(
            system=SYSTEM_PROMPT,
            prompt=prompt,
        )

        if isinstance(response, str):
            data = json.loads(response)
        else:
            data = response

        if not validate_ai_response(data):
            raise ValueError("Invalid AI response.")

        result = analysis_from_json(
            domain=request.domain,
            model=self.client.model,
            response=data,
        )

        logger.info(
            "Analysis complete (%s → risk=%s)",
            result.domain,
            result.risk,
        )

        return result

    # ------------------------------------------------------------------

    def health(self) -> bool:
        """
        Verify the AI backend is available.
        """

        return self.client.validate()
