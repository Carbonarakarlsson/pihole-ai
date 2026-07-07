"""
PiHole-AI Analyzer

High-level coordinator for domain analysis.
"""

from __future__ import annotations

from engine.models import (
    AnalysisRequest,
    AnalysisResult,
)

from engine.classifiers.pipeline import (
    ClassifierPipeline,
)


class Analyzer:
    """
    High-level analysis coordinator.
    """

    def __init__(self) -> None:

        self.pipeline = ClassifierPipeline()

    # ------------------------------------------------------------------

    def analyze(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult:
        """
        Analyze a domain.
        """

        return self.pipeline.classify(
            request,
        )