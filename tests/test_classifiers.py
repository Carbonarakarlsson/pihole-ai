import sys
import types
import unittest
from unittest.mock import patch

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
from engine.classifiers.reputation import ReputationClassifier
from engine.classifiers.rule_engine import RuleEngine
from engine.classifiers.threat_intel import ThreatIntelClassifier
from engine.models import (
    AnalysisRequest,
    AnalysisResult,
    DomainMetadata,
    DomainCategory,
    validate_ai_response,
)


class DummyLogger:
    def info(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


class FakeClient:
    def current_model(self) -> str:
        return "fake-model"


class FailingClient:
    def generate(self, *args, **kwargs):
        raise RuntimeError("ollama unavailable")

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

    def test_deep_subdomain_contributes_to_suspicious_score(self) -> None:
        result = self.engine.classify(
            AnalysisRequest(
                domain="login.verify.secure.account.example.com",
            ),
        )

        self.assertIsNotNone(result)
        self.assertIn(
            "Deep subdomain structure",
            result.reason,
        )

    def test_high_query_frequency_uses_metadata(self) -> None:
        result = self.engine.classify(
            AnalysisRequest(
                domain="login-secure.example.com",
                metadata=DomainMetadata(
                    domain="login-secure.example.com",
                    query_count=501,
                ),
            ),
        )

        self.assertIsNotNone(result)
        self.assertIn(
            "High query frequency",
            result.reason,
        )


class ReputationClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.classifier = ReputationClassifier()

    def test_manual_allow_rule_returns_benign_result(self) -> None:
        with patch(
            "engine.classifiers.reputation.get_domain_rule",
            return_value={
                "decision": "allow",
                "reason": "Known safe.",
            },
        ), patch(
            "engine.classifiers.reputation.get_domain_reputation",
        ) as get_domain_reputation:
            result = self.classifier.classify(
                AnalysisRequest(domain="Example.COM"),
            )

        self.assertIsNotNone(result)
        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.risk, 0)
        self.assertEqual(result.category, DomainCategory.BENIGN.value)
        self.assertEqual(result.model, "manual-rule")
        get_domain_reputation.assert_not_called()

    def test_manual_block_rule_returns_high_risk_result(self) -> None:
        with patch(
            "engine.classifiers.reputation.get_domain_rule",
            return_value={
                "decision": "block",
                "reason": "Confirmed unwanted.",
            },
        ):
            result = self.classifier.classify(
                AnalysisRequest(domain="bad.example"),
            )

        self.assertIsNotNone(result)
        self.assertEqual(result.risk, 100)
        self.assertEqual(result.category, DomainCategory.SUSPICIOUS.value)
        self.assertEqual(result.model, "manual-rule")

    def test_high_reputation_score_returns_suspicious_result(self) -> None:
        with patch(
            "engine.classifiers.reputation.get_domain_rule",
            return_value=None,
        ), patch(
            "engine.classifiers.reputation.get_domain_reputation",
            return_value={
                "score": 85,
                "confidence": 80,
                "signals": '["recent query spike", "previous alert audit"]',
            },
        ):
            result = self.classifier.classify(
                AnalysisRequest(domain="bad.example"),
            )

        self.assertIsNotNone(result)
        self.assertEqual(result.risk, 85)
        self.assertEqual(result.confidence, 80)
        self.assertEqual(result.category, DomainCategory.SUSPICIOUS.value)
        self.assertIn("recent query spike", result.reason)
        self.assertEqual(result.model, "local-reputation")

    def test_low_reputation_score_returns_none(self) -> None:
        with patch(
            "engine.classifiers.reputation.get_domain_rule",
            return_value=None,
        ), patch(
            "engine.classifiers.reputation.get_domain_reputation",
            return_value={
                "score": 40,
                "confidence": 60,
                "signals": "[]",
            },
        ):
            result = self.classifier.classify(
                AnalysisRequest(domain="quiet.example"),
            )

        self.assertIsNone(result)


class ThreatIntelClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.classifier = ThreatIntelClassifier()

    def test_returns_none_when_domain_is_not_in_feed(self) -> None:
        with patch(
            "engine.classifiers.threat_intel.get_threat_intel",
            return_value=None,
        ):
            result = self.classifier.classify(
                AnalysisRequest(domain="example.com"),
            )

        self.assertIsNone(result)

    def test_classifies_known_bad_domain_from_feed(self) -> None:
        with patch(
            "engine.classifiers.threat_intel.get_threat_intel",
            return_value={
                "domain": "bad.example",
                "source": "test-feed",
                "category": DomainCategory.MALWARE.value,
                "confidence": 95,
            },
        ):
            result = self.classifier.classify(
                AnalysisRequest(domain="Bad.Example"),
            )

        self.assertIsNotNone(result)
        self.assertEqual(result.domain, "bad.example")
        self.assertEqual(result.risk, 95)
        self.assertEqual(result.confidence, 95)
        self.assertEqual(result.category, DomainCategory.MALWARE.value)
        self.assertIn("test-feed", result.reason)
        self.assertEqual(result.model, "threat-intel")

    def test_unknown_feed_category_falls_back_to_suspicious(self) -> None:
        with patch(
            "engine.classifiers.threat_intel.get_threat_intel",
            return_value={
                "domain": "bad.example",
                "source": "test-feed",
                "category": "unknown-feed-category",
                "confidence": 60,
            },
        ):
            result = self.classifier.classify(
                AnalysisRequest(domain="bad.example"),
            )

        self.assertIsNotNone(result)
        self.assertEqual(result.risk, 70)
        self.assertEqual(result.category, DomainCategory.SUSPICIOUS.value)


class DomainMetadataTests(unittest.TestCase):
    def test_builds_from_mapping_with_defaults(self) -> None:
        metadata = DomainMetadata.from_mapping(
            {
                "domain": "example.com",
                "query_count": None,
                "first_seen": None,
                "last_seen": 20,
                "device_count": 2,
                "recent_queries": 7,
            }
        )

        self.assertEqual(metadata.domain, "example.com")
        self.assertEqual(metadata.query_count, 0)
        self.assertEqual(metadata.first_seen, 0.0)
        self.assertEqual(metadata.last_seen, 20.0)
        self.assertEqual(metadata.device_count, 2)
        self.assertEqual(metadata.recent_queries, 7)
        self.assertEqual(metadata.tags, [])


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
    def test_default_pipeline_includes_reputation_before_heuristics(self) -> None:
        with patch(
            "engine.classifiers.ai_classifier.OllamaClient",
        ):
            pipeline = ClassifierPipeline()

        self.assertIsInstance(pipeline.classifiers[0], RuleEngine)
        self.assertIsInstance(pipeline.classifiers[1], ReputationClassifier)
        self.assertIsInstance(pipeline.classifiers[2], ThreatIntelClassifier)
        self.assertIsInstance(pipeline.classifiers[3], HeuristicsEngine)
        self.assertIsInstance(pipeline.classifiers[4], AIClassifier)

    def test_threat_intel_beats_low_learned_reputation(self) -> None:
        with patch(
            "engine.classifiers.ai_classifier.OllamaClient",
        ), patch(
            "engine.classifiers.reputation.get_domain_rule",
            return_value=None,
        ), patch(
            "engine.classifiers.reputation.get_domain_reputation",
            return_value={
                "score": 0,
                "confidence": 95,
                "signals": '["manual allow rule"]',
            },
        ), patch(
            "engine.classifiers.threat_intel.get_threat_intel",
            return_value={
                "domain": "bad.example",
                "source": "test-feed",
                "category": DomainCategory.MALWARE.value,
                "confidence": 95,
            },
        ):
            pipeline = ClassifierPipeline()
            result = pipeline.classify(
                AnalysisRequest(domain="bad.example"),
            )

        self.assertEqual(result.model, "threat-intel")
        self.assertEqual(result.category, DomainCategory.MALWARE.value)
        self.assertEqual(result.risk, 95)

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

    def test_generate_exception_falls_back_to_unknown(self) -> None:
        classifier = AIClassifier.__new__(AIClassifier)
        classifier.logger = DummyLogger()
        classifier.client = FailingClient()

        result = classifier.classify(
            AnalysisRequest(domain="example.com"),
        )

        self.assertEqual(result.category, DomainCategory.UNKNOWN.value)
        self.assertEqual(result.risk, 50)
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.reason, "AI backend unavailable.")
        self.assertEqual(result.model, "fake-model")


if __name__ == "__main__":
    unittest.main()
