import sys
import types
import unittest

sys.modules.setdefault(
    "ollama",
    types.SimpleNamespace(
        Client=lambda *args, **kwargs: None,
    ),
)

from engine.classifiers.ai_classifier import AIClassifier
from engine.classifiers.base import BaseClassifier
from engine.classifiers.heuristics import HeuristicsEngine
from engine.classifiers.pipeline import ClassifierPipeline
from engine.classifiers.rule_engine import RuleEngine
from engine.models import (
    AnalysisRequest,
    AnalysisResult,
    DomainCategory,
    validate_ai_response,
)


class DummyLogger:
    def debug(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


class FakeClient:
    def current_model(self) -> str:
        return "fake-model"


class FakeClassifier(BaseClassifier):
    def __init__(self, result: AnalysisResult | None) -> None:
        self.result = result
        self.calls = 0

    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult | None:
        self.calls += 1
        return self.result


class RuleEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RuleEngine()

    def test_classifies_local_infrastructure_domains(self) -> None:
        domains = [
            "localhost",
            "printer.local",
            "1.168.192.in-addr.arpa",
            "b.a.9.8.ip6.arpa",
            "router.home.arpa",
        ]

        for domain in domains:
            with self.subTest(domain=domain):
                result = self.engine.classify(AnalysisRequest(domain=domain))

                self.assertIsNotNone(result)
                self.assertEqual(
                    result.category,
                    DomainCategory.INFRASTRUCTURE.value,
                )
                self.assertEqual(result.risk, 0)

    def test_returns_none_for_unknown_domain(self) -> None:
        result = self.engine.classify(
            AnalysisRequest(domain="example.com"),
        )

        self.assertIsNone(result)


class HeuristicsEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = HeuristicsEngine()

    def test_returns_none_for_ordinary_domain(self) -> None:
        result = self.engine.classify(
            AnalysisRequest(domain="example.com"),
        )

        self.assertIsNone(result)

    def test_classifies_obvious_suspicious_domain(self) -> None:
        result = self.engine.classify(
            AnalysisRequest(
                domain="login-secure-wallet-verify-123456789.xyz",
            ),
        )

        self.assertIsNotNone(result)
        self.assertEqual(
            result.category,
            DomainCategory.SUSPICIOUS.value,
        )
        self.assertGreaterEqual(result.risk, 40)


class AIResponseValidationTests(unittest.TestCase):
    def test_accepts_valid_category(self) -> None:
        self.assertTrue(
            validate_ai_response(
                {
                    "risk": 10,
                    "confidence": 90,
                    "category": DomainCategory.SUSPICIOUS.value,
                    "reason": "Looks unusual.",
                }
            )
        )

    def test_rejects_unknown_category(self) -> None:
        self.assertFalse(
            validate_ai_response(
                {
                    "risk": 10,
                    "confidence": 90,
                    "category": "other",
                    "reason": "Not canonical.",
                }
            )
        )

    def test_rejects_wrong_category_casing(self) -> None:
        self.assertFalse(
            validate_ai_response(
                {
                    "risk": 10,
                    "confidence": 90,
                    "category": "Suspicious",
                    "reason": "Wrong casing.",
                }
            )
        )


class ClassifierPipelineTests(unittest.TestCase):
    def test_stops_at_first_classifier_with_result(self) -> None:
        first = FakeClassifier(None)
        expected = AnalysisResult(
            domain="example.com",
            risk=5,
            confidence=80,
            category=DomainCategory.BENIGN.value,
            reason="Known safe test result.",
            model="fake",
        )
        second = FakeClassifier(expected)
        third = FakeClassifier(
            AnalysisResult(
                domain="example.com",
                risk=90,
                confidence=90,
                category=DomainCategory.MALWARE.value,
                reason="Should not be reached.",
                model="fake",
            )
        )

        pipeline = ClassifierPipeline.__new__(ClassifierPipeline)
        pipeline.logger = DummyLogger()
        pipeline.classifiers = [first, second, third]

        result = pipeline.classify(
            AnalysisRequest(domain="example.com"),
        )

        self.assertIs(result, expected)
        self.assertEqual(first.calls, 1)
        self.assertEqual(second.calls, 1)
        self.assertEqual(third.calls, 0)


class AIClassifierParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.classifier = AIClassifier.__new__(AIClassifier)
        self.classifier.logger = DummyLogger()
        self.classifier.client = FakeClient()
        self.request = AnalysisRequest(domain="example.com")

    def test_parse_valid_json_response(self) -> None:
        result = self.classifier._parse_response(
            self.request,
            (
                '{"risk": 25, "confidence": 88, '
                '"category": "tracking", "reason": "Telemetry domain."}'
            ),
        )

        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.risk, 25)
        self.assertEqual(result.confidence, 88)
        self.assertEqual(result.category, DomainCategory.TRACKING.value)
        self.assertEqual(result.model, "fake-model")

    def test_invalid_json_falls_back_to_unknown(self) -> None:
        result = self.classifier._parse_response(
            self.request,
            "not json",
        )

        self.assertEqual(result.category, DomainCategory.UNKNOWN.value)
        self.assertEqual(result.risk, 50)
        self.assertEqual(result.confidence, 0)

    def test_invalid_schema_falls_back_to_unknown(self) -> None:
        result = self.classifier._parse_response(
            self.request,
            '{"risk": 25, "confidence": 88, "category": "Other"}',
        )

        self.assertEqual(result.category, DomainCategory.UNKNOWN.value)
        self.assertEqual(result.risk, 50)
        self.assertEqual(result.confidence, 0)


if __name__ == "__main__":
    unittest.main()
