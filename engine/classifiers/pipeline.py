"""
PiHole-AI Classifier Pipeline

Executes classifiers in order until one returns a result.
"""

from __future__ import annotations

from core.logger import get_logger

from engine.models import (
    AnalysisRequest,
    AnalysisResult,
)

from engine.classifiers.rule_engine import RuleEngine
from engine.classifiers.reputation import ReputationClassifier
from engine.classifiers.heuristics import HeuristicsEngine
from engine.classifiers.ai_classifier import AIClassifier
from engine.classifiers.base import BaseClassifier


class ClassifierPipeline:
    """
    Executes classifiers in order.
    """

    def __init__(self) -> None:

        self.logger = get_logger(__name__)

        self.classifiers: list[BaseClassifier] = [

            RuleEngine(),

            ReputationClassifier(),

            HeuristicsEngine(),

            AIClassifier(),

        ]

        self.logger.info(
            "Initialized classifier pipeline (%d classifiers).",
            len(self.classifiers),
        )

    # ------------------------------------------------------------------

    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult:
        """
        Run every classifier until one returns a result.
        """

        for classifier in self.classifiers:

            result = classifier.classify(
                request,
            )

            if result is not None:

                self.logger.debug(
                    "%s handled '%s'",
                    classifier.__class__.__name__,
                    request.domain,
                )

                return result

        #
        # Should never happen.
        #

        raise RuntimeError(
            "Classifier pipeline returned no result."
        )
