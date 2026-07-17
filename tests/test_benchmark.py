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
from pihole_ai.benchmark import (
    compare_benchmark_runs,
    fixture_digest,
    get_benchmark_run,
    list_benchmark_runs,
    run_benchmark_command,
    save_benchmark_run,
)


class BenchmarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.tmpdir.name) / "events.db"
        self.path_patch = patch.object(db, "DATABASE_PATH", self.database_path)
        self.path_patch.start()
        db.init_db()

    def tearDown(self) -> None:
        self.path_patch.stop()
        self.tmpdir.cleanup()

    def _fixture(self, rows: list[dict]) -> Path:
        path = Path(self.tmpdir.name) / f"fixture-{len(rows)}.json"
        path.write_text(json.dumps(rows), encoding="utf-8")
        return path

    def _run_payload(
        self,
        run_id: str,
        *,
        digest: str = "digest-a",
        accuracy: float | None = 1.0,
        f1: float | None = 1.0,
        false_positive_rate: float | None = 0.0,
        false_negative_rate: float | None = 0.0,
        abstention_rate: float | None = 0.0,
        average_latency_ms: float | None = 10.0,
        results: list[dict] | None = None,
        status: str = "completed",
    ) -> dict:
        rows = results or [
            {
                "result_id": f"bres_{run_id}",
                "sample_id": "one",
                "domain": "one.example",
                "expected_category": "benign",
                "expected_action": "allow",
                "predicted_category": "benign",
                "predicted_action": "allow",
                "confidence": 90,
                "confidence_band": "very_high",
                "classifier_source": "rule-engine",
                "correct": True,
                "false_positive": False,
                "false_negative": False,
                "abstained": False,
                "duration_ms": 10,
                "error_summary": None,
                "telemetry_run_id": None,
            }
        ]
        return {
            "run_id": run_id,
            "name": run_id,
            "fixture_identifier": "fixture.json",
            "fixture_digest": digest,
            "started_at": 1.0,
            "completed_at": 2.0,
            "status": status,
            "pihole_ai_version": "test",
            "git_commit": "abc123",
            "model_name": None,
            "prompt_version": None,
            "classifier_config_id": "test",
            "threshold_config": {},
            "risk_tolerance": 15,
            "sample_count": len(rows),
            "notes": "",
            "duration_ms": 1,
            "error_summary": None if status == "completed" else "failed",
            "metrics": {
                "sample_count": len(rows),
                "accuracy": accuracy,
                "precision": None,
                "recall": None,
                "f1": f1,
                "false_positive_rate": false_positive_rate,
                "false_negative_rate": false_negative_rate,
                "abstention_rate": abstention_rate,
                "error_rate": 0.0,
                "average_latency_ms": average_latency_ms,
                "p50_latency_ms": average_latency_ms,
                "p95_latency_ms": average_latency_ms,
                "ai_invocation_rate": 0.0,
                "cache_hit_rate": None,
                "category_metrics": {},
                "classifier_source_counts": {},
            },
            "results": rows,
        }

    def test_successful_persisted_benchmark_run_is_isolated_from_runtime_tables(self) -> None:
        fixture = self._fixture(
            [
                {
                    "domain": "localhost",
                    "category": "infrastructure",
                    "risk": 0,
                    "sample_id": "local",
                }
            ]
        )

        run = run_benchmark_command(fixture, name="smoke")
        persisted = get_benchmark_run(run["run_id"])
        stats = db.database_stats()

        self.assertEqual(run["status"], "completed")
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted["sample_count"], 1)
        self.assertEqual(len(persisted["results"]), 1)
        self.assertEqual(stats["analyses"], 0)
        self.assertEqual(stats["actions"], 0)
        self.assertEqual(stats["reputations"], 0)

    def test_failed_benchmark_run_is_persisted_with_error_summary(self) -> None:
        fixture = Path(self.tmpdir.name) / "bad.json"
        fixture.write_text("{}", encoding="utf-8")

        run = run_benchmark_command(fixture)
        persisted = get_benchmark_run(run["run_id"])

        self.assertEqual(run["status"], "failed")
        self.assertIn("list of cases", persisted["error_summary"])
        self.assertEqual(persisted["results"], [])

    def test_no_persist_leaves_no_benchmark_rows(self) -> None:
        fixture = self._fixture(
            [{"domain": "localhost", "category": "infrastructure", "risk": 0}]
        )

        run = run_benchmark_command(fixture, persist=False)

        self.assertEqual(run["status"], "completed")
        self.assertEqual(list_benchmark_runs(), [])

    def test_fixture_digest_is_stable_for_content(self) -> None:
        first = self._fixture(
            [{"domain": "localhost", "category": "infrastructure", "risk": 0}]
        )
        second = Path(self.tmpdir.name) / "copy.json"
        second.write_bytes(first.read_bytes())

        self.assertEqual(fixture_digest(first), fixture_digest(second))

    def test_compare_refuses_different_fixture_digest_by_default(self) -> None:
        save_benchmark_run(self._run_payload("bench_a", digest="a"))
        save_benchmark_run(self._run_payload("bench_b", digest="b"))

        comparison = compare_benchmark_runs("bench_a", "bench_b")

        self.assertEqual(comparison["verdict"], "invalid")
        self.assertIn("fixture_digest_mismatch", comparison["reasons"])

    def test_identical_runs_compare_cleanly(self) -> None:
        save_benchmark_run(self._run_payload("bench_a"))
        save_benchmark_run(self._run_payload("bench_b"))

        comparison = compare_benchmark_runs("bench_a", "bench_b")

        self.assertTrue(comparison["passed"])
        self.assertEqual(comparison["verdict"], "pass")

    def test_accuracy_regression_is_detected(self) -> None:
        save_benchmark_run(self._run_payload("bench_a", accuracy=1.0))
        save_benchmark_run(self._run_payload("bench_b", accuracy=0.9))

        comparison = compare_benchmark_runs("bench_a", "bench_b")

        self.assertFalse(comparison["passed"])
        self.assertIn("accuracy_drop", comparison["reasons"])

    def test_false_positive_and_false_negative_regressions_are_detected(self) -> None:
        save_benchmark_run(self._run_payload("bench_a"))
        save_benchmark_run(
            self._run_payload(
                "bench_b",
                false_positive_rate=0.1,
                false_negative_rate=0.1,
            )
        )

        comparison = compare_benchmark_runs("bench_a", "bench_b")

        self.assertIn("false_positive_rate_increase", comparison["reasons"])
        self.assertIn("false_negative_rate_increase", comparison["reasons"])

    def test_latency_and_abstention_regressions_are_detected(self) -> None:
        save_benchmark_run(self._run_payload("bench_a", average_latency_ms=10, abstention_rate=0.0))
        save_benchmark_run(self._run_payload("bench_b", average_latency_ms=20, abstention_rate=0.2))

        comparison = compare_benchmark_runs("bench_a", "bench_b")

        self.assertIn("latency_increase", comparison["reasons"])
        self.assertIn("abstention_rate_increase", comparison["reasons"])

    def test_tolerance_boundary_passes(self) -> None:
        save_benchmark_run(self._run_payload("bench_a", accuracy=1.0))
        save_benchmark_run(self._run_payload("bench_b", accuracy=0.98))

        comparison = compare_benchmark_runs("bench_a", "bench_b")

        self.assertTrue(comparison["passed"])

    def test_null_and_zero_division_metrics_remain_serializable(self) -> None:
        save_benchmark_run(
            self._run_payload(
                "bench_empty",
                accuracy=None,
                f1=None,
                false_positive_rate=None,
                false_negative_rate=None,
                average_latency_ms=None,
                results=[],
            )
        )

        run = get_benchmark_run("bench_empty")

        self.assertIsNone(run["metrics"]["accuracy"])
        json.dumps(run)

    def test_partial_incomplete_run_is_invalid_for_comparison(self) -> None:
        save_benchmark_run(self._run_payload("bench_a"))
        save_benchmark_run(self._run_payload("bench_failed", status="failed", results=[]))

        comparison = compare_benchmark_runs("bench_a", "bench_failed")

        self.assertEqual(comparison["verdict"], "invalid")
        self.assertIn("run_incomplete", comparison["reasons"])

    def test_cli_benchmark_run_json_and_show(self) -> None:
        fixture = self._fixture(
            [{"domain": "localhost", "category": "infrastructure", "risk": 0}]
        )

        with patch("sys.stdout", io.StringIO()) as stdout:
            exit_code = cli.main(["benchmark", "run", str(fixture), "--json"])
        payload = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "completed")

        with patch("sys.stdout", io.StringIO()) as stdout:
            show_code = cli.main(["benchmark", "show", payload["run_id"], "--json"])

        self.assertEqual(show_code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["run_id"], payload["run_id"])

    def test_cli_compare_exit_code_reflects_regression(self) -> None:
        save_benchmark_run(self._run_payload("bench_a", accuracy=1.0))
        save_benchmark_run(self._run_payload("bench_b", accuracy=0.5))

        with patch("sys.stdout", io.StringIO()):
            exit_code = cli.main(["benchmark", "compare", "bench_a", "bench_b", "--json"])

        self.assertEqual(exit_code, 1)

    def test_cli_list_json(self) -> None:
        save_benchmark_run(self._run_payload("bench_a"))

        with patch("sys.stdout", io.StringIO()) as stdout:
            exit_code = cli.main(["benchmark", "list", "--json"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(stdout.getvalue())[0]["run_id"], "bench_a")

    def test_migration_12_is_registered(self) -> None:
        registry = {migration.version: migration.name for migration in migrations.MIGRATIONS}
        self.assertEqual(registry[12], "ai_benchmark_history")


if __name__ == "__main__":
    unittest.main()
