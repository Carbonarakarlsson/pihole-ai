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

from pihole_ai.evaluate import (
    BenchmarkCase,
    load_benchmark_cases,
    print_benchmark,
    run_benchmark,
)


class EvaluateTests(unittest.TestCase):
    def test_loads_json_benchmark_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cases.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "domain": "Example.COM.",
                            "category": "unknown",
                            "risk": 50,
                            "query_count": 10,
                            "device_count": 2,
                            "recent_queries": 3,
                        }
                    ]
                ),
                encoding="utf-8",
            )

            cases = load_benchmark_cases(path)

        self.assertEqual(
            cases,
            [
                BenchmarkCase(
                    domain="example.com",
                    category="unknown",
                    risk=50,
                    query_count=10,
                    device_count=2,
                    recent_queries=3,
                )
            ],
        )

    def test_loads_csv_benchmark_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cases.csv"
            path.write_text(
                "domain,category,risk\nlocalhost,infrastructure,0\n",
                encoding="utf-8",
            )

            cases = load_benchmark_cases(path)

        self.assertEqual(
            cases,
            [
                BenchmarkCase(
                    domain="localhost",
                    category="infrastructure",
                    risk=0,
                )
            ],
        )

    def test_run_benchmark_scores_category_and_risk_matches(self) -> None:
        cases = [
            BenchmarkCase(
                domain="localhost",
                category="infrastructure",
                risk=0,
            ),
            BenchmarkCase(
                domain="login-secure-wallet-verify-123456789.xyz",
                category="suspicious",
                risk=70,
            ),
            BenchmarkCase(
                domain="example.com",
                category="unknown",
                risk=50,
            ),
        ]

        with patch(
            "engine.classifiers.ai_classifier.OllamaClient",
        ), patch(
            "engine.classifiers.reputation.get_domain_rule",
            return_value=None,
        ), patch(
            "engine.classifiers.reputation.get_domain_reputation",
            return_value=None,
        ), patch(
            "engine.classifiers.threat_intel.get_active_threat_intel",
            return_value=None,
        ):
            result = run_benchmark(
                cases=cases,
                risk_tolerance=30,
            )

        self.assertEqual(result.total, 3)
        self.assertEqual(result.category_matches, 3)
        self.assertEqual(result.risk_matches, 3)
        self.assertEqual(result.rows[2].model, "benchmark-fallback")

    def test_print_benchmark_can_output_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "cases.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "domain": "localhost",
                            "category": "infrastructure",
                            "risk": 0,
                        }
                    ]
                ),
                encoding="utf-8",
            )

            with patch(
                "engine.classifiers.ai_classifier.OllamaClient",
            ), patch(
                "sys.stdout",
                io.StringIO(),
            ) as stdout:
                result = print_benchmark(
                    path=path,
                    as_json=True,
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(result.total, 1)
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["rows"][0]["domain"], "localhost")


if __name__ == "__main__":
    unittest.main()
