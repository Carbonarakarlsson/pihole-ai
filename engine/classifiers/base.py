"""
Base classifier interface for PiHole-AI.

All classifiers in the pipeline implement this contract:
return an AnalysisResult when they can classify the domain, otherwise None.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from engine.models import AnalysisRequest, AnalysisResult


class BaseClassifier(ABC):
    """
    Common interface for domain classifiers.
    """

    @abstractmethod
    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult | None:
        """
        Classify a domain or return None to let the next classifier try.
        """
