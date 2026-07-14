import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.modules.setdefault(
    "ollama",
    types.SimpleNamespace(
        Client=lambda *args, **kwargs: None,
    ),
)

from core import db
from engine.classifiers.ai_classifier import AIClassifier
from engine.classifiers.base import BaseClassifier
from engine.classifiers.heuristics import HeuristicsEngine
from engine.classifiers.pipeline import ClassifierPipeline
from engine.classifiers.reputation import ReputationClassifier
from engine.classifiers.rule_engine import RuleEngine
from engine.classifiers.threat_intel import ThreatIntelClassifier
from engine.evidence import EvidenceItem, EvidencePolarity
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


class RecordingClient:
    def __init__(self) -> None:
        self.prompt = ""
        self.calls = 0

    def generate(self, *args, **kwargs):
        self.calls += 1
        self.prompt = kwargs["prompt"]
        return (
            '{"risk": 10, "confidence": 90, '
            '"category": "benign", "reason": "Looks safe."}'
        )

    def current_model(self) -> str:
        return "recording-model"


class FailingClient:
    def generate(self, *args, **kwargs):
        raise RuntimeError("ollama unavailable")

    def current_model(self) -> str:
        return "fake-model"


class InvalidJSONClient:
    def __init__(self) -> None:
        self.calls = 0

    def generate(self, *args, **kwargs):
        self.calls += 1
        return "not json"

    def current_model(self) -> str:
        return "invalid-json-model"


class TimeoutClient:
    def __init__(self) -> None:
        self.calls = 0

    def generate(self, *args, **kwargs):
        self.calls += 1
        raise TimeoutError("ollama timed out")

    def current_model(self) -> str:
        return "timeout-model"


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


class EvidenceClassifier(BaseClassifier):
    def __init__(self, evidence: list[EvidenceItem]) -> None:
        self.evidence = evidence
        self.calls = 0

    def classify(
        self,
        request: AnalysisRequest,
    ) -> AnalysisResult | None:
        return None

    def collect_evidence(
        self,
        request: AnalysisRequest,
    ) -> list[EvidenceItem]:
        self.calls += 1
        return self.evidence


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

    def test_collect_evidence_returns_individual_signals(self) -> None:
        evidence = self.engine.collect_evidence(
            AnalysisRequest(
                domain="login-secure-wallet-verify-123456789.xyz",
            ),
        )

        evidence_types = {item.evidence_type for item in evidence}
        self.assertIn("suspicious_tld", evidence_types)
        self.assertIn("many_digits", evidence_types)
        self.assertTrue(
            all(item.classifier == "heuristics" for item in evidence)
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

    def test_low_reputation_score_returns_safety_evidence(self) -> None:
        with patch(
            "engine.classifiers.reputation.get_domain_rule",
            return_value=None,
        ), patch(
            "engine.classifiers.reputation.get_domain_reputation",
            return_value={
                "score": 10,
                "confidence": 90,
                "signals": '["quiet locally"]',
            },
        ):
            evidence = self.classifier.collect_evidence(
                AnalysisRequest(domain="quiet.example"),
            )

        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].classifier, "local-reputation")
        self.assertEqual(evidence[0].polarity, EvidencePolarity.SAFETY)
        self.assertLess(evidence[0].score, 0)

    def test_manual_block_returns_decisive_evidence(self) -> None:
        with patch(
            "engine.classifiers.reputation.get_domain_rule",
            return_value={
                "decision": "block",
                "reason": "Confirmed unwanted.",
            },
        ):
            evidence = self.classifier.collect_evidence(
                AnalysisRequest(domain="bad.example"),
            )

        self.assertEqual(len(evidence), 1)
        self.assertTrue(evidence[0].decisive)
        self.assertEqual(evidence[0].classifier, "manual-rule")


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

    def test_high_confidence_feed_hit_is_decisive_evidence(self) -> None:
        with patch(
            "engine.classifiers.threat_intel.get_threat_intel",
            return_value={
                "domain": "bad.example",
                "source": "test-feed",
                "category": DomainCategory.MALWARE.value,
                "confidence": 95,
            },
        ):
            evidence = self.classifier.collect_evidence(
                AnalysisRequest(domain="bad.example"),
            )

        self.assertEqual(len(evidence), 1)
        self.assertTrue(evidence[0].decisive)
        self.assertEqual(evidence[0].metadata["precedence"], 30)


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
        self.assertEqual(result.risk, 100)

    def test_collects_evidence_before_deciding(self) -> None:
        first = EvidenceClassifier(
            [
                EvidenceItem(
                    evidence_id="test:safety",
                    classifier="test-safety",
                    evidence_type="known_safe",
                    polarity=EvidencePolarity.SAFETY,
                    score=-80,
                    confidence=0.9,
                    summary="Known safe.",
                )
            ]
        )
        second = EvidenceClassifier(
            [
                EvidenceItem(
                    evidence_id="test:risk",
                    classifier="test-risk",
                    evidence_type="suspicious",
                    polarity=EvidencePolarity.RISK,
                    score=70,
                    confidence=0.8,
                    summary="Suspicious.",
                )
            ]
        )

        pipeline = ClassifierPipeline.__new__(ClassifierPipeline)
        pipeline.logger = DummyLogger()
        pipeline.classifiers = [first, second]
        from engine.decision_engine import DecisionEngine

        pipeline.decision_engine = DecisionEngine()

        result = pipeline.classify(
            AnalysisRequest(domain="example.com"),
        )

        self.assertEqual(first.calls, 1)
        self.assertEqual(second.calls, 1)
        self.assertIsNotNone(result.decision)
        self.assertEqual(len(result.decision.evidence.items), 2)

    def test_decisive_evidence_skips_remaining_classifiers(self) -> None:
        decisive = EvidenceClassifier(
            [
                EvidenceItem(
                    evidence_id="test:block",
                    classifier="manual-rule",
                    evidence_type="manual_block",
                    polarity=EvidencePolarity.RISK,
                    score=100,
                    confidence=0.95,
                    summary="Manual block.",
                    metadata={
                        "decisive": True,
                        "precedence": 10,
                        "category": DomainCategory.SUSPICIOUS.value,
                    },
                )
            ]
        )
        later = EvidenceClassifier([])

        pipeline = ClassifierPipeline.__new__(ClassifierPipeline)
        pipeline.logger = DummyLogger()
        pipeline.classifiers = [decisive, later]
        from engine.decision_engine import DecisionEngine

        pipeline.decision_engine = DecisionEngine()

        result = pipeline.classify(
            AnalysisRequest(domain="example.com"),
        )

        self.assertEqual(result.risk, 100)
        self.assertEqual(decisive.calls, 1)
        self.assertEqual(later.calls, 0)
        self.assertEqual(
            result.decision.classifier_trace[-1]["status"],
            "skipped",
        )


class AIClassifierParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.tmpdir.name) / "events.db"
        self.path_patch = patch.object(
            db,
            "DATABASE_PATH",
            self.database_path,
        )
        self.path_patch.start()
        db.init_db()
        self.classifier = AIClassifier.__new__(AIClassifier)
        self.classifier.logger = DummyLogger()
        self.classifier.client = FakeClient()
        self.request = AnalysisRequest(domain="example.com")

    def tearDown(self) -> None:
        self.path_patch.stop()
        self.tmpdir.cleanup()

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
        self.assertEqual(result.risk, 0)
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.reason, "AI returned invalid response")
        self.assertEqual(result.model, "ai")

    def test_invalid_schema_falls_back_to_unknown(self) -> None:
        result = self.classifier._parse_response(
            self.request,
            '{"risk": 25, "confidence": 88, "category": "Other"}',
        )

        self.assertEqual(result.category, DomainCategory.UNKNOWN.value)
        self.assertEqual(result.risk, 0)
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.reason, "AI returned invalid response")
        self.assertEqual(result.model, "ai")

    def test_generate_exception_falls_back_to_unknown(self) -> None:
        classifier = AIClassifier.__new__(AIClassifier)
        classifier.logger = DummyLogger()
        classifier.client = FailingClient()
        patched_settings = types.SimpleNamespace(
            ai_enabled=True,
            ai_max_calls_per_minute=2,
            ai_cooldown_seconds=60,
            ai_timeout_seconds=20,
        )

        with patch(
            "engine.classifiers.ai_classifier.settings",
            patched_settings,
        ):
            result = classifier.classify(
                AnalysisRequest(domain="example.com"),
            )

        self.assertEqual(result.category, DomainCategory.UNKNOWN.value)
        self.assertEqual(result.risk, 50)
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.reason, "AI backend unavailable.")
        self.assertEqual(result.model, "fake-model")

    def test_classify_accepts_domain_metadata_dataclass(self) -> None:
        classifier = AIClassifier.__new__(AIClassifier)
        classifier.logger = DummyLogger()
        classifier.client = RecordingClient()
        patched_settings = types.SimpleNamespace(
            ai_enabled=True,
            ai_max_calls_per_minute=2,
            ai_cooldown_seconds=60,
            ai_timeout_seconds=20,
        )

        with patch(
            "engine.classifiers.ai_classifier.settings",
            patched_settings,
        ):
            result = classifier.classify(
                AnalysisRequest(
                    domain="it",
                    metadata=DomainMetadata(
                        domain="it",
                        query_count=5,
                        device_count=2,
                    ),
                )
            )

        self.assertEqual(result.category, DomainCategory.BENIGN.value)
        self.assertEqual(result.model, "recording-model")
        self.assertIn('"query_count": 5', classifier.client.prompt)
        self.assertIn('"device_count": 2', classifier.client.prompt)

    def test_disabled_ai_returns_safe_unknown_without_calling_client(self) -> None:
        classifier = AIClassifier.__new__(AIClassifier)
        classifier.logger = DummyLogger()
        classifier.client = RecordingClient()
        patched_settings = types.SimpleNamespace(
            ai_enabled=False,
            ai_max_calls_per_minute=2,
            ai_cooldown_seconds=60,
            ai_timeout_seconds=20,
        )

        with patch(
            "engine.classifiers.ai_classifier.settings",
            patched_settings,
        ):
            result = classifier.classify(
                AnalysisRequest(domain="example.com"),
            )

        self.assertEqual(result.risk, 0)
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.category, DomainCategory.UNKNOWN.value)
        self.assertEqual(result.reason, "ai_disabled")
        self.assertEqual(result.model, "ai")
        self.assertEqual(classifier.client.calls, 0)
        self.assertEqual(db.ai_metrics()["disabled_skips"], 1)
        self.assertEqual(db.ai_metrics()["ai_skipped"], 1)

    def test_rate_limit_returns_safe_unknown_without_calling_client(self) -> None:
        classifier = AIClassifier.__new__(AIClassifier)
        classifier.logger = DummyLogger()
        classifier.client = RecordingClient()
        patched_settings = types.SimpleNamespace(
            ai_enabled=True,
            ai_max_calls_per_minute=1,
            ai_cooldown_seconds=0,
            ai_timeout_seconds=20,
        )

        with patch(
            "engine.classifiers.ai_classifier.settings",
            patched_settings,
        ):
            first = classifier.classify(
                AnalysisRequest(domain="one.example"),
            )
            second = classifier.classify(
                AnalysisRequest(domain="two.example"),
            )

        self.assertEqual(first.model, "recording-model")
        self.assertEqual(second.risk, 0)
        self.assertEqual(second.reason, "ai_rate_limited")
        self.assertEqual(classifier.client.calls, 1)
        metrics = db.ai_metrics()
        self.assertEqual(metrics["ai_calls"], 1)
        self.assertEqual(metrics["rate_limit_skips"], 1)
        self.assertEqual(metrics["ai_skipped"], 1)

    def test_timeout_returns_safe_unknown_and_tracks_timeout(self) -> None:
        classifier = AIClassifier.__new__(AIClassifier)
        classifier.logger = DummyLogger()
        classifier.client = TimeoutClient()
        patched_settings = types.SimpleNamespace(
            ai_enabled=True,
            ai_max_calls_per_minute=2,
            ai_cooldown_seconds=60,
            ai_timeout_seconds=20,
        )

        with patch(
            "engine.classifiers.ai_classifier.settings",
            patched_settings,
        ), patch(
            "engine.classifiers.ai_classifier.time.time",
            return_value=100,
        ):
            result = classifier.classify(
                AnalysisRequest(domain="timeout.example"),
            )

        self.assertEqual(result.risk, 0)
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.category, DomainCategory.UNKNOWN.value)
        self.assertEqual(result.reason, "ai_timeout")
        self.assertEqual(result.model, "ai")
        self.assertEqual(classifier.client.calls, 1)
        metrics = db.ai_metrics()
        self.assertEqual(metrics["ai_calls"], 1)
        self.assertEqual(metrics["ai_timeouts"], 1)
        self.assertEqual(metrics["ai_skipped"], 1)
        self.assertEqual(metrics["cooldown_until"], 160)

    def test_invalid_response_starts_cooldown_for_later_calls(self) -> None:
        classifier = AIClassifier.__new__(AIClassifier)
        classifier.logger = DummyLogger()
        classifier.client = InvalidJSONClient()
        patched_settings = types.SimpleNamespace(
            ai_enabled=True,
            ai_max_calls_per_minute=5,
            ai_cooldown_seconds=60,
            ai_timeout_seconds=20,
        )

        with patch(
            "engine.classifiers.ai_classifier.settings",
            patched_settings,
        ), patch(
            "engine.classifiers.ai_classifier.time.time",
            return_value=100,
        ):
            first = classifier.classify(
                AnalysisRequest(domain="one.example"),
            )
            second = classifier.classify(
                AnalysisRequest(domain="two.example"),
            )

        self.assertEqual(first.reason, "AI returned invalid response")
        self.assertEqual(second.reason, "ai_cooldown")
        self.assertEqual(classifier.client.calls, 1)
        metrics = db.ai_metrics()
        self.assertEqual(metrics["ai_parse_errors"], 1)
        self.assertEqual(metrics["cooldown_skips"], 1)
        self.assertEqual(metrics["ai_skipped"], 1)
        self.assertEqual(metrics["cooldown_until"], 160)

    def test_slow_response_starts_cooldown_for_later_calls(self) -> None:
        classifier = AIClassifier.__new__(AIClassifier)
        classifier.logger = DummyLogger()
        classifier.client = RecordingClient()
        patched_settings = types.SimpleNamespace(
            ai_enabled=True,
            ai_max_calls_per_minute=5,
            ai_cooldown_seconds=60,
            ai_timeout_seconds=20,
        )

        with patch(
            "engine.classifiers.ai_classifier.settings",
            patched_settings,
        ), patch(
            "engine.classifiers.ai_classifier.time.time",
            return_value=100,
        ), patch(
            "engine.classifiers.ai_classifier.time.monotonic",
            side_effect=[0, 21],
        ):
            first = classifier.classify(
                AnalysisRequest(domain="one.example"),
            )
            second = classifier.classify(
                AnalysisRequest(domain="two.example"),
            )

        self.assertEqual(first.model, "recording-model")
        self.assertEqual(second.reason, "ai_cooldown")
        self.assertEqual(classifier.client.calls, 1)
        metrics = db.ai_metrics()
        self.assertEqual(metrics["slow_responses"], 1)
        self.assertEqual(metrics["cooldown_skips"], 1)
        self.assertEqual(metrics["ai_skipped"], 1)
        self.assertEqual(metrics["cooldown_until"], 160)


class ReputationClassifierIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.tmpdir.name) / "events.db"
        self.path_patch = patch.object(
            db,
            "DATABASE_PATH",
            self.database_path,
        )
        self.path_patch.start()
        db.init_db()

    def tearDown(self) -> None:
        self.path_patch.stop()
        self.tmpdir.cleanup()

    def test_reputation_classifier_uses_learned_database_rows(self) -> None:
        db.save_domain_reputation(
            domain="learned.example",
            score=85,
            confidence=90,
            signals=[
                "heuristics classification",
            ],
        )

        result = ReputationClassifier().classify(
            AnalysisRequest(domain="learned.example"),
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.model, "local-reputation")
        self.assertEqual(result.risk, 85)
        self.assertEqual(result.category, DomainCategory.SUSPICIOUS.value)


if __name__ == "__main__":
    unittest.main()
