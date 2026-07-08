__all__ = [
    "BaseClassifier",
    "ClassifierPipeline",
    "RuleEngine",
    "ReputationClassifier",
    "HeuristicsEngine",
    "AIClassifier",
]


def __getattr__(name: str):
    """
    Lazily expose classifiers without importing Ollama for every package import.
    """

    if name == "BaseClassifier":
        from .base import BaseClassifier

        return BaseClassifier

    if name == "ClassifierPipeline":
        from .pipeline import ClassifierPipeline

        return ClassifierPipeline

    if name == "RuleEngine":
        from .rule_engine import RuleEngine

        return RuleEngine

    if name == "ReputationClassifier":
        from .reputation import ReputationClassifier

        return ReputationClassifier

    if name == "HeuristicsEngine":
        from .heuristics import HeuristicsEngine

        return HeuristicsEngine

    if name == "AIClassifier":
        from .ai_classifier import AIClassifier

        return AIClassifier

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )
