import io
import sys
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault(
    "ollama",
    types.SimpleNamespace(
        Client=lambda *args, **kwargs: None,
    ),
)

from pihole_ai import cli


class CLITests(unittest.TestCase):
    def test_engine_once_dispatches_to_single_cycle_runner(self) -> None:
        with patch("engine.run_engine.run") as run_engine_once:
            exit_code = cli.main(["engine-once"])

        self.assertEqual(exit_code, 0)
        run_engine_once.assert_called_once_with()

    def test_engine_dispatches_to_continuous_worker(self) -> None:
        with patch("engine.engine.AnalysisEngine") as analysis_engine:
            exit_code = cli.main(["engine"])

        self.assertEqual(exit_code, 0)
        analysis_engine.assert_called_once_with()
        analysis_engine.return_value.run_loop.assert_called_once_with()

    def test_collector_dispatches_to_collector_main(self) -> None:
        with patch("collector.scan.main") as collector_main:
            exit_code = cli.main(["collector"])

        self.assertEqual(exit_code, 0)
        collector_main.assert_called_once_with()

    def test_dashboard_dispatches_to_dashboard_main(self) -> None:
        with patch("ui.dashboard.main") as dashboard_main:
            exit_code = cli.main(["dashboard"])

        self.assertEqual(exit_code, 0)
        dashboard_main.assert_called_once_with()

    def test_status_dispatches_to_status_printer(self) -> None:
        with patch("pihole_ai.status.print_status") as print_status:
            exit_code = cli.main(["status", "--no-ollama"])

        self.assertEqual(exit_code, 0)
        print_status.assert_called_once_with(
            include_ollama=False,
        )

    def test_export_dispatches_with_options(self) -> None:
        with patch("pihole_ai.export.export_rows", return_value=3) as export_rows, \
             patch("sys.stdout", io.StringIO()):
            exit_code = cli.main(
                [
                    "export",
                    "analysis",
                    "--format",
                    "csv",
                    "--output",
                    "out.csv",
                    "--limit",
                    "10",
                    "--q",
                    "example",
                    "--min-risk",
                    "40",
                    "--category",
                    "benign",
                ]
            )

        self.assertEqual(exit_code, 0)
        export_rows.assert_called_once_with(
            dataset="analysis",
            export_format="csv",
            path="out.csv",
            limit=10,
            search="example",
            min_risk=40,
            category="benign",
        )

    def test_maintenance_dispatches_with_options(self) -> None:
        with patch("core.maintenance.run_maintenance") as run_maintenance, \
             patch("sys.stdout", io.StringIO()):
            run_maintenance.return_value.deleted_events = 2
            run_maintenance.return_value.before = {"events": 5}
            run_maintenance.return_value.after = {"events": 3}
            run_maintenance.return_value.vacuumed = True

            exit_code = cli.main(
                [
                    "maintenance",
                    "--keep-latest",
                    "3",
                    "--vacuum",
                ]
            )

        self.assertEqual(exit_code, 0)
        run_maintenance.assert_called_once_with(
            keep_latest=3,
            vacuum_db=True,
        )

    def test_learn_dispatches_with_options(self) -> None:
        with patch("pihole_ai.learn.print_learned", return_value=2) as print_learned, \
             patch("sys.stdout", io.StringIO()):
            exit_code = cli.main(
                [
                    "learn",
                    "--limit",
                    "10",
                    "--min-score",
                    "60",
                    "--no-audit",
                ]
            )

        self.assertEqual(exit_code, 0)
        print_learned.assert_called_once_with(
            limit=10,
            min_score=60,
            audit=False,
        )

    def test_rules_list_dispatches_with_options(self) -> None:
        with patch("pihole_ai.rules.print_rules", return_value=1) as print_rules, \
             patch("sys.stdout", io.StringIO()):
            exit_code = cli.main(
                [
                    "rules",
                    "list",
                    "--limit",
                    "10",
                    "--q",
                    "example",
                    "--decision",
                    "allow",
                ]
            )

        self.assertEqual(exit_code, 0)
        print_rules.assert_called_once_with(
            limit=10,
            search="example",
            decision="allow",
        )

    def test_rules_allow_dispatches_to_add_rule(self) -> None:
        with patch("pihole_ai.rules.add_rule") as add_rule, \
             patch("sys.stdout", io.StringIO()):
            exit_code = cli.main(
                [
                    "rules",
                    "allow",
                    "example.com",
                    "--reason",
                    "Known safe.",
                ]
            )

        self.assertEqual(exit_code, 0)
        add_rule.assert_called_once_with(
            domain="example.com",
            decision="allow",
            reason="Known safe.",
            apply_block=False,
        )

    def test_rules_block_can_apply_blocklist_helper(self) -> None:
        with patch("pihole_ai.rules.add_rule") as add_rule, \
             patch("sys.stdout", io.StringIO()):
            exit_code = cli.main(
                [
                    "rules",
                    "block",
                    "bad.example",
                    "--reason",
                    "Manual block.",
                    "--apply",
                ]
            )

        self.assertEqual(exit_code, 0)
        add_rule.assert_called_once_with(
            domain="bad.example",
            decision="block",
            reason="Manual block.",
            apply_block=True,
        )

    def test_rules_remove_dispatches_to_remove_rule(self) -> None:
        with patch("pihole_ai.rules.remove_rule", return_value=True) as remove_rule, \
             patch("sys.stdout", io.StringIO()):
            exit_code = cli.main(
                [
                    "rules",
                    "remove",
                    "example.com",
                ]
            )

        self.assertEqual(exit_code, 0)
        remove_rule.assert_called_once_with("example.com")


if __name__ == "__main__":
    unittest.main()
