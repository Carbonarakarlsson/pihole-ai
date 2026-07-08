import unittest
from types import SimpleNamespace
from unittest.mock import patch

from actions.policy import (
    PolicyDecision,
    apply_action_policy,
    decide_action,
)


def result(
    risk: int,
    confidence: int = 80,
) -> SimpleNamespace:
    return SimpleNamespace(
        domain="example.com",
        risk=risk,
        confidence=confidence,
        category="unknown",
        reason="Test result.",
    )


class ActionPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rule_patch = patch(
            "actions.policy.get_domain_rule",
            return_value=None,
        )
        self.rule_patch.start()

    def tearDown(self) -> None:
        self.rule_patch.stop()

    def test_decide_action_returns_none_when_mode_is_off(self) -> None:
        self.assertIsNone(
            decide_action(
                result(100),
                mode="off",
            )
        )

    def test_decide_action_reviews_zero_confidence_results(self) -> None:
        decision = decide_action(
            result(50, confidence=0),
            mode="dry-run",
        )

        self.assertEqual(
            decision,
            PolicyDecision(
                action="review",
                status="low_confidence",
                reason=(
                    "Analysis confidence is zero; manual review "
                    "recommended."
                ),
            ),
        )

    def test_decide_action_alerts_medium_risk_results(self) -> None:
        decision = decide_action(
            result(55),
            mode="dry-run",
            alert_threshold=50,
            block_threshold=70,
        )

        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "alert")
        self.assertEqual(decision.status, "logged")

    def test_decide_action_suggests_block_in_dry_run_mode(self) -> None:
        decision = decide_action(
            result(90),
            mode="dry-run",
            block_threshold=70,
        )

        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "suggest_block")
        self.assertEqual(decision.status, "dry_run")

    def test_decide_action_respects_allow_rule_before_thresholds(self) -> None:
        with patch(
            "actions.policy.get_domain_rule",
            return_value={
                "decision": "allow",
            },
        ):
            decision = decide_action(
                result(100),
                mode="dry-run",
            )

        self.assertEqual(
            decision,
            PolicyDecision(
                action="allow",
                status="rule_match",
                reason="Domain matches an active allow rule.",
            ),
        )

    def test_decide_action_respects_block_rule_before_thresholds(self) -> None:
        with patch(
            "actions.policy.get_domain_rule",
            return_value={
                "decision": "block",
            },
        ):
            decision = decide_action(
                result(5),
                mode="dry-run",
            )

        self.assertEqual(
            decision,
            PolicyDecision(
                action="block",
                status="rule_match",
                reason="Domain matches an active block rule.",
            ),
        )

    def test_apply_action_policy_records_dry_run_decision(self) -> None:
        with patch("actions.policy.record_action") as record_action:
            decision = apply_action_policy(
                result(90),
                mode="dry-run",
            )

        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "suggest_block")
        record_action.assert_called_once()
        self.assertEqual(
            record_action.call_args.kwargs["domain"],
            "example.com",
        )
        self.assertEqual(
            record_action.call_args.kwargs["action"],
            "suggest_block",
        )

    def test_apply_action_policy_calls_block_in_block_mode(self) -> None:
        with patch("actions.blocklist.block") as block:
            decision = apply_action_policy(
                result(90),
                mode="block",
            )

        self.assertEqual(
            decision,
            PolicyDecision(
                action="block",
                status="written",
                reason="Risk 90 is at or above block threshold 70.",
            ),
        )
        block.assert_called_once_with("example.com")


if __name__ == "__main__":
    unittest.main()
