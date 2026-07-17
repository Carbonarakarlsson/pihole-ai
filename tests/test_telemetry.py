import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
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
from engine.classifiers.pipeline import ClassifierPipeline
from engine.decision_engine import DecisionEngine
from engine.engine import AnalysisEngine, _persist_pipeline_telemetry
from engine.evidence import EvidenceItem, EvidencePolarity
from engine.models import AnalysisRequest, AnalysisResult, DomainCategory
from pihole_ai import cli


class DummyLogger:
    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def exception(self, *args, **kwargs):
        pass


class EvidenceClassifier(BaseClassifier):
    def __init__(self, evidence: list[EvidenceItem]) -> None:
        self.evidence = evidence

    def classify(self, request: AnalysisRequest) -> AnalysisResult | None:
        return None

    def collect_evidence(self, request: AnalysisRequest) -> list[EvidenceItem]:
        return self.evidence


class FakeAIClient:
    def generate(self, *args, **kwargs) -> str:
        return (
            '{"risk": 12, "confidence": 88, '
            '"category": "benign", "reason": "Looks safe."}'
        )

    def current_model(self) -> str:
        return "fake-ai-model"


class TimeoutAIClient:
    def generate(self, *args, **kwargs) -> str:
        raise TimeoutError("timed out")

    def current_model(self) -> str:
        return "timeout-model"


class InvalidAIClient:
    def generate(self, *args, **kwargs) -> str:
        return "not-json"

    def current_model(self) -> str:
        return "invalid-model"


class TelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.tmpdir.name) / "events.db"
        self.path_patch = patch.object(db, "DATABASE_PATH", self.database_path)
        self.path_patch.start()
        db.init_db()

    def tearDown(self) -> None:
        self.path_patch.stop()
        self.tmpdir.cleanup()

    def _pipeline(self, classifiers: list[BaseClassifier]) -> ClassifierPipeline:
        pipeline = ClassifierPipeline.__new__(ClassifierPipeline)
        pipeline.logger = DummyLogger()
        pipeline.classifiers = classifiers
        pipeline.decision_engine = DecisionEngine()
        return pipeline

    def test_pipeline_telemetry_records_classifier_result_and_decision_id(self) -> None:
        classifier = EvidenceClassifier(
            [
                EvidenceItem(
                    evidence_id="test:safe",
                    classifier="test-safety",
                    evidence_type="known_safe",
                    polarity=EvidencePolarity.SAFETY,
                    score=-80,
                    confidence=0.9,
                    summary="Known safe.",
                    metadata={"category": DomainCategory.BENIGN.value},
                )
            ]
        )

        result = self._pipeline([classifier]).classify(
            AnalysisRequest(domain="Example.COM"),
        )
        decision_id = db.save_analysis_with_decision(
            domain=result.domain,
            risk=result.risk,
            confidence=result.confidence,
            category=result.category,
            reason=result.reason,
            model=result.model,
            analyzed_at=result.analyzed_at,
            decision=result.decision,
            trigger="test",
        )
        db.save_pipeline_telemetry(result.telemetry, final_decision_id=decision_id)

        run = db.query_one(
            "SELECT domain, final_decision_id, cache_hit FROM pipeline_telemetry_runs"
        )
        stage = db.query_one(
            """
            SELECT classifier_name, execution_order, classifier_result,
                   confidence_raw, confidence_band, skipped, final_decision_id
            FROM pipeline_telemetry_stages
            """
        )

        self.assertEqual(result.category, DomainCategory.BENIGN.value)
        self.assertEqual(run["domain"], "example.com")
        self.assertEqual(run["final_decision_id"], decision_id)
        self.assertIsNone(run["cache_hit"])
        self.assertEqual(stage["classifier_name"], "EvidenceClassifier")
        self.assertEqual(stage["execution_order"], 1)
        self.assertEqual(stage["classifier_result"], DomainCategory.BENIGN.value)
        self.assertEqual(stage["confidence_raw"], 90)
        self.assertEqual(stage["confidence_band"], "very_high")
        self.assertEqual(stage["skipped"], 0)
        self.assertEqual(stage["final_decision_id"], decision_id)

        by_decision = db.get_pipeline_telemetry_by_decision_id(
            decision_id,
            database_path=self.database_path,
        )
        by_analysis = db.get_pipeline_telemetry_by_analysis_id(
            result.telemetry.run_id,
            database_path=self.database_path,
        )
        self.assertEqual(by_decision["run_id"], result.telemetry.run_id)
        self.assertEqual(by_analysis["final_decision_id"], decision_id)

    def test_skipped_classifier_telemetry_is_recorded(self) -> None:
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
                        "category": DomainCategory.MALWARE.value,
                    },
                )
            ]
        )
        later = EvidenceClassifier([])

        result = self._pipeline([decisive, later]).classify(
            AnalysisRequest(domain="bad.example"),
        )
        db.save_pipeline_telemetry(result.telemetry, final_decision_id=None)

        skipped = db.query_one(
            """
            SELECT classifier_name, skipped, skip_reason, stop_reason
            FROM pipeline_telemetry_stages
            WHERE execution_order = 2
            """
        )

        self.assertEqual(result.risk, 100)
        self.assertEqual(skipped["classifier_name"], "EvidenceClassifier")
        self.assertEqual(skipped["skipped"], 1)
        self.assertIn("decisive evidence", skipped["skip_reason"])
        self.assertIn("decisive evidence", skipped["stop_reason"])

    def test_cache_hit_telemetry_is_recorded(self) -> None:
        db.record_cache_hit_telemetry("Cached.Example")

        stats = db.telemetry_stats_readonly(self.database_path)
        run = db.query_one(
            "SELECT domain, cache_hit, stop_reason, ai_invoked FROM pipeline_telemetry_runs"
        )

        self.assertEqual(run["domain"], "cached.example")
        self.assertEqual(run["cache_hit"], 1)
        self.assertEqual(run["stop_reason"], "cache_hit")
        self.assertEqual(run["ai_invoked"], 0)
        self.assertEqual(stats["analyses_recorded"], 1)
        self.assertEqual(stats["cache_hit_rate"], 1.0)

    def test_engine_records_cache_hit_without_invoking_analyzer(self) -> None:
        db.insert_event("device-a", "cached-engine.example", 100.0)
        db.save_analysis(
            domain="cached-engine.example",
            risk=10,
            confidence=80,
            category=DomainCategory.BENIGN.value,
            reason="Cached.",
            model="test",
            analyzed_at=100.0,
        )
        engine = AnalysisEngine.__new__(AnalysisEngine)
        engine.analyzer = object()

        with patch("engine.engine.logger", DummyLogger()), patch(
            "engine.engine.settings",
            SimpleNamespace(cache_ttl=0, engine_batch_size=500),
        ):
            processed = engine.process_once()

        stats = db.telemetry_stats_readonly(self.database_path)
        self.assertEqual(processed, 1)
        self.assertEqual(stats["analyses_recorded"], 1)
        self.assertEqual(stats["cache_hit_rate"], 1.0)

    def test_ai_invocation_telemetry_records_model_and_prompt_version(self) -> None:
        ai = AIClassifier.__new__(AIClassifier)
        ai.logger = DummyLogger()
        ai.client = FakeAIClient()

        with patch(
            "engine.classifiers.ai_classifier.settings",
            SimpleNamespace(
                ai_enabled=True,
                ai_max_calls_per_minute=10,
                ai_cooldown_seconds=0,
                ai_timeout_seconds=20,
            ),
        ):
            result = self._pipeline([ai]).classify(
                AnalysisRequest(domain="example.com"),
            )
        db.save_pipeline_telemetry(result.telemetry, final_decision_id=None)

        stage = db.query_one(
            """
            SELECT ai_considered, ai_invoked, ai_invocation_reason,
                   configured_ai_model, ai_model, prompt_version,
                   request_attempt_count, parse_attempt_count, retry_count,
                   timeout, parse_failure, inference_duration_ms,
                   final_ai_category, final_ai_confidence
            FROM pipeline_telemetry_stages
            WHERE classifier_name = 'AIClassifier'
            """
        )

        self.assertEqual(stage["ai_considered"], 1)
        self.assertEqual(stage["ai_invoked"], 1)
        self.assertEqual(stage["ai_invocation_reason"], "fallback_needed")
        self.assertIsNone(stage["configured_ai_model"])
        self.assertEqual(stage["ai_model"], "fake-ai-model")
        self.assertEqual(stage["prompt_version"], "domain-classification-v1")
        self.assertEqual(stage["request_attempt_count"], 1)
        self.assertEqual(stage["parse_attempt_count"], 1)
        self.assertEqual(stage["retry_count"], 0)
        self.assertEqual(stage["timeout"], 0)
        self.assertEqual(stage["parse_failure"], 0)
        self.assertIsNotNone(stage["inference_duration_ms"])
        self.assertEqual(stage["final_ai_category"], DomainCategory.BENIGN.value)
        self.assertEqual(stage["final_ai_confidence"], 88)

    def test_ai_disabled_skip_records_skip_metadata(self) -> None:
        ai = AIClassifier.__new__(AIClassifier)
        ai.logger = DummyLogger()
        ai.client = FakeAIClient()

        with patch(
            "engine.classifiers.ai_classifier.settings",
            SimpleNamespace(
                ai_enabled=False,
                ai_max_calls_per_minute=10,
                ai_cooldown_seconds=0,
                ai_timeout_seconds=20,
            ),
        ):
            result = self._pipeline([ai]).classify(
                AnalysisRequest(domain="disabled.example"),
            )
        db.save_pipeline_telemetry(result.telemetry, final_decision_id=None)

        stage = db.query_one(
            """
            SELECT ai_considered, ai_invoked, ai_invocation_reason,
                   skip_reason, request_attempt_count, parse_attempt_count,
                   fallback_reason
            FROM pipeline_telemetry_stages
            WHERE classifier_name = 'AIClassifier'
            """
        )

        self.assertEqual(stage["ai_considered"], 1)
        self.assertEqual(stage["ai_invoked"], 0)
        self.assertEqual(stage["ai_invocation_reason"], "ai_disabled")
        self.assertEqual(stage["skip_reason"], "ai_disabled")
        self.assertEqual(stage["request_attempt_count"], 0)
        self.assertEqual(stage["parse_attempt_count"], 0)
        self.assertEqual(stage["fallback_reason"], "ai_disabled")

    def test_ai_timeout_records_timeout_metadata(self) -> None:
        ai = AIClassifier.__new__(AIClassifier)
        ai.logger = DummyLogger()
        ai.client = TimeoutAIClient()

        with patch(
            "engine.classifiers.ai_classifier.settings",
            SimpleNamespace(
                ai_enabled=True,
                ai_max_calls_per_minute=10,
                ai_cooldown_seconds=0,
                ai_timeout_seconds=20,
            ),
        ):
            result = self._pipeline([ai]).classify(
                AnalysisRequest(domain="timeout.example"),
            )
        db.save_pipeline_telemetry(result.telemetry, final_decision_id=None)

        stage = db.query_one(
            """
            SELECT ai_invoked, timeout, parse_failure, request_attempt_count,
                   parse_attempt_count, fallback_reason
            FROM pipeline_telemetry_stages
            WHERE classifier_name = 'AIClassifier'
            """
        )

        self.assertEqual(stage["ai_invoked"], 1)
        self.assertEqual(stage["timeout"], 1)
        self.assertEqual(stage["parse_failure"], 0)
        self.assertEqual(stage["request_attempt_count"], 1)
        self.assertEqual(stage["parse_attempt_count"], 0)
        self.assertEqual(stage["fallback_reason"], "ai_timeout")

    def test_ai_parse_failure_records_parse_metadata(self) -> None:
        ai = AIClassifier.__new__(AIClassifier)
        ai.logger = DummyLogger()
        ai.client = InvalidAIClient()

        with patch(
            "engine.classifiers.ai_classifier.settings",
            SimpleNamespace(
                ai_enabled=True,
                ai_max_calls_per_minute=10,
                ai_cooldown_seconds=0,
                ai_timeout_seconds=20,
            ),
        ):
            result = self._pipeline([ai]).classify(
                AnalysisRequest(domain="parse.example"),
            )
        db.save_pipeline_telemetry(result.telemetry, final_decision_id=None)

        stage = db.query_one(
            """
            SELECT ai_invoked, timeout, parse_failure, request_attempt_count,
                   parse_attempt_count, fallback_reason
            FROM pipeline_telemetry_stages
            WHERE classifier_name = 'AIClassifier'
            """
        )

        self.assertEqual(stage["ai_invoked"], 1)
        self.assertEqual(stage["timeout"], 0)
        self.assertEqual(stage["parse_failure"], 1)
        self.assertEqual(stage["request_attempt_count"], 1)
        self.assertEqual(stage["parse_attempt_count"], 1)
        self.assertEqual(stage["fallback_reason"], "AI returned invalid response")

    def test_unavailable_values_are_persisted_as_null(self) -> None:
        result = self._pipeline([EvidenceClassifier([])]).classify(
            AnalysisRequest(domain="unknown.example"),
        )
        db.save_pipeline_telemetry(result.telemetry, final_decision_id=None)

        stage = db.query_one(
            """
            SELECT confidence_raw, confidence_band, ai_model, prompt_version
            FROM pipeline_telemetry_stages
            """
        )

        self.assertIsNone(stage["confidence_raw"])
        self.assertIsNone(stage["confidence_band"])
        self.assertIsNone(stage["ai_model"])
        self.assertIsNone(stage["prompt_version"])

    def test_partial_run_telemetry_remains_serializable(self) -> None:
        with db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO pipeline_telemetry_runs
                (
                    run_id,
                    domain,
                    started_at,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                ("ptr_partial", "partial.example", 1.0, 1.0),
            )

        telemetry = db.get_pipeline_telemetry_by_analysis_id(
            "ptr_partial",
            database_path=self.database_path,
        )

        self.assertEqual(telemetry["run_id"], "ptr_partial")
        self.assertTrue(telemetry["available"])
        self.assertEqual(telemetry["pipeline_timeline"], [])

    def test_telemetry_write_failure_does_not_fail_analysis_pipeline(self) -> None:
        result = AnalysisResult(
            domain="example.com",
            risk=10,
            confidence=90,
            category=DomainCategory.BENIGN.value,
            reason="Safe.",
            model="test",
            telemetry=object(),
        )

        with patch("engine.engine.logger", DummyLogger()), patch(
            "engine.engine.save_pipeline_telemetry",
            side_effect=RuntimeError("boom"),
        ):
            _persist_pipeline_telemetry(result, decision_id="dec_test")

    def test_telemetry_stats_cli_outputs_json(self) -> None:
        db.record_cache_hit_telemetry("cli.example")

        with patch("sys.stdout", io.StringIO()) as stdout:
            exit_code = cli.main(["telemetry", "stats", "--json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["analyses_recorded"], 1)
        self.assertEqual(payload["telemetry_rows"], 0)
        self.assertEqual(payload["cache_hit_rate"], 1.0)
        self.assertEqual(payload["classifier_counts"], {})


if __name__ == "__main__":
    unittest.main()
