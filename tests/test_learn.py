import io
import unittest
from unittest.mock import patch

from pihole_ai.learn import (
    ReputationResult,
    learn,
    print_learned,
    score_candidate,
)


class LearningTests(unittest.TestCase):
    def test_score_candidate_respects_allow_rule(self) -> None:
        result = score_candidate(
            {
                "domain": "example.com",
                "rule_decision": "allow",
            }
        )

        self.assertEqual(
            result,
            ReputationResult(
                domain="example.com",
                score=0,
                confidence=95,
                signals=[
                    "manual allow rule",
                ],
            ),
        )

    def test_score_candidate_combines_local_signals(self) -> None:
        result = score_candidate(
            {
                "domain": "login-verify-1234567890.xyz",
                "rule_decision": None,
                "query_count": 600,
                "device_count": 4,
                "recent_queries": 120,
                "analysis_risk": 75,
                "analysis_confidence": 80,
                "suggest_block_count": 1,
                "alert_count": 1,
                "review_count": 0,
            }
        )

        self.assertGreaterEqual(result.score, 70)
        self.assertIn("high total query count", result.signals)
        self.assertIn("previous high-risk analysis", result.signals)
        self.assertIn("previous suggest-block audit", result.signals)

    def test_learn_saves_reputation_and_audits_threshold_hits(self) -> None:
        rows = [
            {
                "domain": "bad.example",
                "rule_decision": None,
                "query_count": 600,
                "device_count": 4,
                "recent_queries": 120,
                "analysis_risk": 75,
                "analysis_confidence": 80,
                "suggest_block_count": 0,
                "alert_count": 0,
                "review_count": 0,
            },
            {
                "domain": "quiet.example",
                "rule_decision": None,
                "query_count": 1,
                "device_count": 1,
                "recent_queries": 1,
                "analysis_risk": 0,
                "analysis_confidence": 0,
                "suggest_block_count": 0,
                "alert_count": 0,
                "review_count": 0,
            },
        ]

        with patch(
            "pihole_ai.learn.get_reputation_candidates",
            return_value=rows,
        ), patch(
            "pihole_ai.learn.save_domain_reputation",
        ) as save_domain_reputation, patch(
            "pihole_ai.learn.record_action",
        ) as record_action:
            results = learn(
                limit=10,
                min_score=50,
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].domain, "bad.example")
        self.assertEqual(save_domain_reputation.call_count, 2)
        record_action.assert_called_once()
        self.assertEqual(
            record_action.call_args.kwargs["domain"],
            "bad.example",
        )

    def test_print_learned_prints_results(self) -> None:
        with patch(
            "pihole_ai.learn.learn",
            return_value=[
                ReputationResult(
                    domain="bad.example",
                    score=80,
                    confidence=80,
                    signals=[
                        "test signal",
                    ],
                )
            ],
        ), patch("sys.stdout", io.StringIO()) as stdout:
            count = print_learned()

        self.assertEqual(count, 1)
        self.assertIn("bad.example", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
