import io
import unittest
from unittest.mock import patch

from pihole_ai.rules import add_rule, print_rules, remove_rule


class RuleManagementTests(unittest.TestCase):
    def test_add_rule_saves_and_audits_manual_rule(self) -> None:
        with patch("pihole_ai.rules.save_domain_rule") as save_domain_rule, \
             patch("pihole_ai.rules.record_action") as record_action:
            add_rule(
                domain="example.com",
                decision="allow",
                reason="Known safe.",
            )

        save_domain_rule.assert_called_once_with(
            domain="example.com",
            decision="allow",
            source="cli",
            reason="Known safe.",
        )
        record_action.assert_called_once_with(
            domain="example.com",
            action="allow",
            source="pihole_ai.rules",
            status="rule_saved",
            reason="Known safe.",
        )

    def test_add_block_rule_can_apply_blocklist_helper(self) -> None:
        with patch("pihole_ai.rules.save_domain_rule"), \
             patch("pihole_ai.rules.record_action"), \
             patch("actions.blocklist.block") as block:
            add_rule(
                domain="bad.example",
                decision="block",
                apply_block=True,
            )

        block.assert_called_once_with("bad.example")

    def test_remove_rule_audits_removed_rule(self) -> None:
        with patch(
            "pihole_ai.rules.delete_domain_rule",
            return_value=True,
        ) as delete_domain_rule, patch(
            "pihole_ai.rules.record_action",
        ) as record_action:
            removed = remove_rule("example.com")

        self.assertTrue(removed)
        delete_domain_rule.assert_called_once_with("example.com")
        record_action.assert_called_once_with(
            domain="example.com",
            action="remove_rule",
            source="pihole_ai.rules",
            status="removed",
            reason="Removed domain rule.",
        )

    def test_print_rules_prints_active_rules(self) -> None:
        rows = [
            {
                "domain": "example.com",
                "decision": "allow",
                "source": "cli",
                "reason": "Known safe.",
            }
        ]

        with patch("pihole_ai.rules.get_rules", return_value=rows), \
             patch("sys.stdout", io.StringIO()) as stdout:
            count = print_rules()

        self.assertEqual(count, 1)
        self.assertIn("allow example.com", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
