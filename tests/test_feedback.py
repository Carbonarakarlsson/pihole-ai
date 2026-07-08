import io
import unittest
from unittest.mock import patch

from pihole_ai.feedback import (
    FeedbackResult,
    print_feedback,
    record_feedback,
)


class FeedbackTests(unittest.TestCase):
    def test_record_feedback_audits_verdict(self) -> None:
        with patch("pihole_ai.feedback.record_action") as record_action:
            result = record_feedback(
                domain="Example.COM",
                verdict="noisy",
                reason="Too chatty.",
            )

        self.assertEqual(
            result,
            FeedbackResult(
                domain="example.com",
                verdict="noisy",
                promoted=None,
            ),
        )
        record_action.assert_called_once_with(
            domain="example.com",
            action="feedback",
            source="pihole_ai.feedback",
            status="noisy",
            reason="Too chatty.",
        )

    def test_safe_feedback_can_promote_allow_rule(self) -> None:
        with patch("pihole_ai.feedback.add_rule") as add_rule, \
             patch("pihole_ai.feedback.record_action"):
            result = record_feedback(
                domain="safe.example",
                verdict="false-positive",
                reason="Business app.",
                promote=True,
            )

        self.assertEqual(result.promoted, "allow")
        add_rule.assert_called_once_with(
            domain="safe.example",
            decision="allow",
            reason="Business app.",
        )

    def test_bad_feedback_can_promote_block_rule(self) -> None:
        with patch("pihole_ai.feedback.add_rule") as add_rule, \
             patch("pihole_ai.feedback.record_action"):
            result = record_feedback(
                domain="bad.example",
                verdict="false-negative",
                reason="Confirmed bad.",
                promote=True,
                apply_block=True,
            )

        self.assertEqual(result.promoted, "block")
        add_rule.assert_called_once_with(
            domain="bad.example",
            decision="block",
            reason="Confirmed bad.",
            apply_block=True,
        )

    def test_print_feedback_outputs_confirmation(self) -> None:
        with patch(
            "pihole_ai.feedback.record_feedback",
            return_value=FeedbackResult(
                domain="example.com",
                verdict="safe",
                promoted="allow",
            ),
        ), patch("sys.stdout", io.StringIO()) as stdout:
            result = print_feedback(
                domain="example.com",
                verdict="safe",
            )

        self.assertEqual(result.promoted, "allow")
        self.assertIn(
            "promoted allow rule",
            stdout.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
