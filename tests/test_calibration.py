import io
import json
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

from core import db, migrations
from pihole_ai import cli
from pihole_ai.benchmark import save_benchmark_run
from pihole_ai.calibration import (
    activate_calibration_profile,
    build_calibration_profile_from_benchmark,
    build_calibration_profile_from_feedback,
    calibration_for_confidence,
    deactivate_calibration_profile,
    get_calibration_profile,
    list_calibration_profiles,
    reliability_metrics,
    reporting_confidence_band,
)
from pihole_ai.explain import explain_domain


class CalibrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.tmpdir.name) / "events.db"
        self.previous_path = db.DATABASE_PATH
        db.DATABASE_PATH = self.database_path
        db.init_db()

    def tearDown(self) -> None:
        db.DATABASE_PATH = self.previous_path
        self.tmpdir.cleanup()

    def _run_payload(
        self,
        run_id: str = "bench_a",
        *,
        status: str = "completed",
        source: str = "heuristics",
        results: list[dict] | None = None,
    ) -> dict:
        now = 1000.0
        rows = results if results is not None else [
            self._result("one", confidence=90, correct=True, source=source),
            self._result("two", confidence=80, correct=True, source=source),
            self._result("three", confidence=20, correct=False, source=source),
            self._result("four", confidence=None, correct=False, source=source),
        ]
        return {
            "run_id": run_id,
            "name": "baseline",
            "fixture_identifier": "fixture.json",
            "fixture_digest": "digest",
            "started_at": now,
            "completed_at": now + 1,
            "status": status,
            "pihole_ai_version": "test",
            "git_commit": None,
            "model_name": None,
            "prompt_version": None,
            "classifier_config_id": "default",
            "threshold_config": {},
            "risk_tolerance": 15,
            "sample_count": len(rows),
            "notes": "",
            "duration_ms": 1,
            "error_summary": None,
            "metrics": {
                "sample_count": len(rows),
                "accuracy": 0.75,
                "precision": 1.0,
                "recall": 1.0,
                "f1": 1.0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
                "abstention_rate": 0.0,
                "error_rate": 0.0,
                "average_latency_ms": 1.0,
                "p50_latency_ms": 1,
                "p95_latency_ms": 1,
                "ai_invocation_rate": 0.0,
                "cache_hit_rate": None,
                "category_metrics": {},
                "classifier_source_counts": {source: len(rows)},
            },
            "results": rows,
        }

    def _result(
        self,
        sample_id: str,
        *,
        confidence: int | None,
        correct: bool,
        source: str = "heuristics",
    ) -> dict:
        return {
            "result_id": f"bres_{sample_id}",
            "sample_id": sample_id,
            "domain": f"{sample_id}.example",
            "expected_category": "benign",
            "expected_action": "allow",
            "predicted_category": "benign" if correct else "malware",
            "predicted_action": "allow" if correct else "block",
            "confidence": confidence,
            "confidence_band": reporting_confidence_band(confidence),
            "classifier_source": source,
            "correct": correct,
            "false_positive": not correct,
            "false_negative": False,
            "abstained": False,
            "duration_ms": 1,
            "error_summary": None,
            "telemetry_run_id": None,
        }

    def test_profile_creation_from_completed_benchmark(self) -> None:
        save_benchmark_run(self._run_payload())

        profile = build_calibration_profile_from_benchmark("bench_a", name="Cal", bins=5)

        self.assertEqual(profile["name"], "Cal")
        self.assertEqual(profile["source_type"], "benchmark")
        self.assertEqual(profile["source_id"], "bench_a")
        self.assertEqual(profile["sample_count"], 3)
        self.assertEqual(len(profile["bins"]), 5)
        self.assertGreaterEqual(profile["expected_calibration_error"], 0)
        self.assertGreaterEqual(profile["maximum_calibration_error"], 0)
        self.assertGreaterEqual(profile["brier_score"], 0)
        self.assertIsNotNone(get_calibration_profile(profile["profile_id"]))

    def test_incomplete_benchmark_is_rejected(self) -> None:
        save_benchmark_run(self._run_payload(status="failed", results=[]))

        with self.assertRaisesRegex(ValueError, "not completed"):
            build_calibration_profile_from_benchmark("bench_a")

    def test_missing_benchmark_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "not found"):
            build_calibration_profile_from_benchmark("missing")

    def test_null_confidence_samples_are_ignored(self) -> None:
        save_benchmark_run(
            self._run_payload(
                results=[
                    self._result("one", confidence=None, correct=True),
                    self._result("two", confidence=50, correct=True),
                ]
            )
        )

        profile = build_calibration_profile_from_benchmark("bench_a")

        self.assertEqual(profile["sample_count"], 1)

    def test_classifier_specific_profile_filters_samples(self) -> None:
        save_benchmark_run(
            self._run_payload(
                results=[
                    self._result("one", confidence=90, correct=True, source="heuristics"),
                    self._result("two", confidence=90, correct=False, source="ai"),
                ]
            )
        )

        profile = build_calibration_profile_from_benchmark(
            "bench_a",
            classifier_source="ai",
        )

        self.assertEqual(profile["classifier_source"], "ai")
        self.assertEqual(profile["sample_count"], 1)

    def test_activation_and_deactivation_are_reporting_only(self) -> None:
        save_benchmark_run(self._run_payload())
        profile = build_calibration_profile_from_benchmark("bench_a")

        active = activate_calibration_profile(profile["profile_id"])
        calibrated = calibration_for_confidence(90, classifier_source="heuristics")
        inactive = deactivate_calibration_profile(profile["profile_id"])
        uncalibrated = calibration_for_confidence(90, classifier_source="heuristics")

        self.assertTrue(active["active"])
        self.assertTrue(calibrated["observational"])
        self.assertIsNotNone(calibrated["calibrated_confidence"])
        self.assertFalse(inactive["active"])
        self.assertIsNone(uncalibrated["calibrated_confidence"])

    def test_feedback_calibration_is_rejected_until_labels_are_linked(self) -> None:
        with self.assertRaisesRegex(ValueError, "feedback-based calibration"):
            build_calibration_profile_from_feedback()

    def test_reliability_metrics_empty_database(self) -> None:
        metrics = reliability_metrics()

        self.assertEqual(metrics["summary"]["benchmark_runs"], 0)
        self.assertEqual(metrics["summary"]["active_calibration_profiles"], 0)
        self.assertEqual(metrics["confidence"]["raw_distribution"], {})
        self.assertEqual(metrics["errors"]["false_positive_count"], 0)

    def test_reliability_metrics_with_benchmark_and_profile(self) -> None:
        save_benchmark_run(self._run_payload())
        profile = build_calibration_profile_from_benchmark("bench_a")
        activate_calibration_profile(profile["profile_id"])

        metrics = reliability_metrics()

        self.assertEqual(metrics["summary"]["benchmark_runs"], 1)
        self.assertEqual(metrics["summary"]["active_calibration_profiles"], 1)
        self.assertGreater(metrics["errors"]["false_positive_count"], 0)
        self.assertIn("very_high", metrics["confidence"]["raw_distribution"])

    def test_cli_build_list_show_and_activate_json(self) -> None:
        save_benchmark_run(self._run_payload())
        with patch("sys.stdout", io.StringIO()) as stdout:
            exit_code = cli.main(["calibration", "build", "--benchmark", "bench_a", "--json"])
        payload = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        with patch("sys.stdout", io.StringIO()) as stdout:
            list_code = cli.main(["calibration", "list", "--json"])
        self.assertEqual(list_code, 0)
        self.assertEqual(len(json.loads(stdout.getvalue())), 1)

        with patch("sys.stdout", io.StringIO()) as stdout:
            show_code = cli.main(["calibration", "show", payload["profile_id"], "--json"])
        self.assertEqual(show_code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["profile_id"], payload["profile_id"])

        with patch("sys.stdout", io.StringIO()) as stdout:
            activate_code = cli.main(["calibration", "activate", payload["profile_id"], "--json"])
        self.assertEqual(activate_code, 0)
        self.assertTrue(json.loads(stdout.getvalue())["active"])

    def test_cli_feedback_build_fails_cleanly(self) -> None:
        with patch("sys.stdout", io.StringIO()) as stdout:
            exit_code = cli.main(["calibration", "build", "--feedback"])

        self.assertEqual(exit_code, 1)
        self.assertIn("feedback-based calibration", stdout.getvalue())

    def test_explain_includes_calibration_when_profile_matches(self) -> None:
        save_benchmark_run(self._run_payload())
        profile = build_calibration_profile_from_benchmark("bench_a")
        activate_calibration_profile(profile["profile_id"])

        with patch("pihole_ai.explain.get_domain_rule", return_value=None), \
             patch("pihole_ai.explain.get_threat_intel", return_value=None), \
             patch("pihole_ai.explain.get_domain_reputation", return_value=None), \
             patch("pihole_ai.explain.get_analysis", return_value={"risk": 10, "confidence": 90, "category": "benign", "model": "heuristics", "reason": "ok"}), \
             patch("pihole_ai.explain.get_decision_evidence", return_value=[]), \
             patch("pihole_ai.explain.get_decision_record", return_value=None), \
             patch("pihole_ai.explain.get_domain_metadata", return_value={"query_count": 1}), \
             patch("pihole_ai.explain.get_recent_actions", return_value=[]), \
             patch("pihole_ai.explain.get_pipeline_telemetry_for_domain", return_value=None):
            explanation = explain_domain("good.example")

        self.assertTrue(explanation["calibration"]["available"])
        self.assertEqual(explanation["calibration"]["profile_id"], profile["profile_id"])
        self.assertTrue(explanation["calibration"]["observational"])

    def test_explain_without_calibration_remains_available(self) -> None:
        with patch("pihole_ai.explain.get_domain_rule", return_value=None), \
             patch("pihole_ai.explain.get_threat_intel", return_value=None), \
             patch("pihole_ai.explain.get_domain_reputation", return_value=None), \
             patch("pihole_ai.explain.get_analysis", return_value={"risk": 10, "confidence": 90, "category": "benign", "model": "heuristics", "reason": "ok"}), \
             patch("pihole_ai.explain.get_decision_evidence", return_value=[]), \
             patch("pihole_ai.explain.get_decision_record", return_value=None), \
             patch("pihole_ai.explain.get_domain_metadata", return_value={"query_count": 1}), \
             patch("pihole_ai.explain.get_recent_actions", return_value=[]), \
             patch("pihole_ai.explain.get_pipeline_telemetry_for_domain", return_value=None):
            explanation = explain_domain("good.example")

        self.assertFalse(explanation["calibration"]["available"])
        self.assertEqual(explanation["calibration"]["raw_confidence_band"], "very_high")


if __name__ == "__main__":
    unittest.main()
