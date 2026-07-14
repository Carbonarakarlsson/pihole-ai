import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db
from engine.decision_engine import DecisionEngine
from engine.evidence import EvidenceCollection, EvidenceItem, EvidencePolarity
from pihole_ai.feedback import (
    FeedbackResult,
    print_feedback,
    record_feedback,
)


class FeedbackTests(unittest.TestCase):
    def test_record_feedback_audits_verdict(self) -> None:
        with patch("pihole_ai.feedback.record_action") as record_action, patch(
            "pihole_ai.feedback.get_decision_record",
            return_value={
                "created_at": 123.0,
            },
        ):
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
            decision_ref="decision:example.com:123.0",
        )

    def test_safe_feedback_can_promote_allow_rule(self) -> None:
        with patch("pihole_ai.feedback.add_rule") as add_rule, \
             patch("pihole_ai.feedback.record_action"), \
             patch("pihole_ai.feedback.get_decision_record", return_value=None):
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
             patch("pihole_ai.feedback.record_action"), \
             patch("pihole_ai.feedback.get_decision_record", return_value=None):
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

    def test_feedback_links_to_stored_decision_without_rewriting_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"
            with patch.object(db, "DATABASE_PATH", database_path):
                db.init_db()
                decision = DecisionEngine().decide(
                    EvidenceCollection(
                        domain="bad.example",
                        items=(
                            EvidenceItem(
                                evidence_id="risk",
                                classifier="test",
                                evidence_type="signal",
                                polarity=EvidencePolarity.RISK,
                                score=90,
                                confidence=0.9,
                                summary="Risk.",
                            ),
                        ),
                    )
                )
                db.save_decision_evidence("bad.example", decision)
                before = db.get_decision_evidence("bad.example")

                result = record_feedback(
                    domain="bad.example",
                    verdict="bad",
                    reason="Confirmed.",
                )

                after = db.get_decision_evidence("bad.example")
                actions = db.get_recent_actions(search="bad.example")

        self.assertEqual(result.domain, "bad.example")
        self.assertEqual(before, after)
        self.assertEqual(actions[0]["decision_ref"], "decision:bad.example:" + str(decision.created_at))


if __name__ == "__main__":
    unittest.main()
