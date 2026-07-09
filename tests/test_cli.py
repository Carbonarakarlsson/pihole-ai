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

    def test_collect_dispatches_to_collector_main(self) -> None:
        with patch("collector.scan.main") as collector_main:
            exit_code = cli.main(["collect"])

        self.assertEqual(exit_code, 0)
        collector_main.assert_called_once_with()

    def test_run_engine_dispatches_to_continuous_worker(self) -> None:
        with patch("engine.engine.AnalysisEngine") as analysis_engine:
            exit_code = cli.main(["run-engine"])

        self.assertEqual(exit_code, 0)
        analysis_engine.assert_called_once_with()
        analysis_engine.return_value.run_loop.assert_called_once_with()

    def test_path_commands_print_runtime_paths(self) -> None:
        from core.config import settings

        expected = {
            "config-path": str(settings.config_file),
            "data-path": str(settings.events_db),
            "log-path": str(settings.log_file),
        }

        for command, path in expected.items():
            with self.subTest(command=command), patch(
                "sys.stdout",
                io.StringIO(),
            ) as stdout:
                exit_code = cli.main([command])

            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue().strip(), path)

    def test_dashboard_dispatches_to_dashboard_main(self) -> None:
        with patch("ui.dashboard.main") as dashboard_main:
            exit_code = cli.main(
                [
                    "dashboard",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "9000",
                ]
            )

        self.assertEqual(exit_code, 0)
        dashboard_main.assert_called_once_with(
            host="127.0.0.1",
            port=9000,
        )

    def test_status_dispatches_to_status_printer(self) -> None:
        with patch("pihole_ai.service.service_status") as service_status:
            exit_code = cli.main(["status", "--dry-run"])

        self.assertEqual(exit_code, 0)
        service_status.assert_called_once_with(
            include_ollama=False,
            dry_run=True,
        )

    def test_status_can_include_ollama_when_requested(self) -> None:
        with patch("pihole_ai.service.service_status") as service_status:
            exit_code = cli.main(["status", "--ollama"])

        self.assertEqual(exit_code, 0)
        service_status.assert_called_once_with(
            include_ollama=True,
            dry_run=False,
        )

    def test_explain_dispatches_to_explanation_printer(self) -> None:
        with patch("pihole_ai.explain.print_explanation") as print_explanation:
            exit_code = cli.main(
                [
                    "explain",
                    "Example.COM",
                    "--json",
                ]
            )

        self.assertEqual(exit_code, 0)
        print_explanation.assert_called_once_with(
            domain="Example.COM",
            as_json=True,
        )

    def test_feedback_dispatches_with_options(self) -> None:
        with patch("pihole_ai.feedback.print_feedback") as print_feedback:
            exit_code = cli.main(
                [
                    "feedback",
                    "Example.COM",
                    "false-negative",
                    "--reason",
                    "Confirmed bad.",
                    "--promote",
                    "--apply",
                ]
            )

        self.assertEqual(exit_code, 0)
        print_feedback.assert_called_once_with(
            domain="Example.COM",
            verdict="false-negative",
            reason="Confirmed bad.",
            promote=True,
            apply_block=True,
        )

    def test_evaluate_dispatches_with_options(self) -> None:
        with patch("pihole_ai.evaluate.print_benchmark") as print_benchmark:
            exit_code = cli.main(
                [
                    "evaluate",
                    "fixtures/domains.json",
                    "--risk-tolerance",
                    "20",
                    "--include-ai",
                    "--json",
                ]
            )

        self.assertEqual(exit_code, 0)
        print_benchmark.assert_called_once_with(
            path="fixtures/domains.json",
            risk_tolerance=20,
            include_ai=True,
            as_json=True,
        )

    def test_service_install_dispatches_with_dry_run(self) -> None:
        with patch("pihole_ai.service.service_install") as service_install:
            exit_code = cli.main(
                [
                    "service",
                    "install",
                    "--dry-run",
                ]
            )

        self.assertEqual(exit_code, 0)
        service_install.assert_called_once_with(
            dry_run=True,
        )

    def test_install_dispatches_with_dry_run(self) -> None:
        with patch("pihole_ai.service.service_install") as service_install:
            exit_code = cli.main(
                [
                    "install",
                    "--dry-run",
                ]
            )

        self.assertEqual(exit_code, 0)
        service_install.assert_called_once_with(
            dry_run=True,
        )

    def test_service_uninstall_dispatches_with_dry_run(self) -> None:
        with patch("pihole_ai.service.service_uninstall") as service_uninstall:
            exit_code = cli.main(
                [
                    "service",
                    "uninstall",
                    "--dry-run",
                ]
            )

        self.assertEqual(exit_code, 0)
        service_uninstall.assert_called_once_with(
            dry_run=True,
        )

    def test_uninstall_dispatches_with_dry_run(self) -> None:
        with patch("pihole_ai.service.service_uninstall") as service_uninstall:
            exit_code = cli.main(
                [
                    "uninstall",
                    "--dry-run",
                ]
            )

        self.assertEqual(exit_code, 0)
        service_uninstall.assert_called_once_with(
            dry_run=True,
        )

    def test_enable_disable_dispatch_with_dry_run(self) -> None:
        cases = [
            ("enable", "pihole_ai.service.service_enable"),
            ("disable", "pihole_ai.service.service_disable"),
        ]

        for command, target in cases:
            with self.subTest(command=command), patch(target) as handler:
                exit_code = cli.main(
                    [
                        command,
                        "--dry-run",
                    ]
                )

            self.assertEqual(exit_code, 0)
            handler.assert_called_once_with(
                dry_run=True,
            )

    def test_start_stop_restart_dispatch_to_service_action(self) -> None:
        for command in ("start", "stop", "restart"):
            with self.subTest(command=command), patch(
                "pihole_ai.service.service_action",
            ) as service_action:
                exit_code = cli.main(
                    [
                        command,
                        "--dry-run",
                    ]
                )

            self.assertEqual(exit_code, 0)
            service_action.assert_called_once_with(
                action=command,
                dry_run=True,
            )

    def test_service_errors_are_printed_without_traceback(self) -> None:
        from pihole_ai.service import ServiceError

        with patch(
            "pihole_ai.service.service_action",
            side_effect=ServiceError("Command failed cleanly."),
        ), patch("sys.stdout", io.StringIO()) as stdout:
            exit_code = cli.main(["start"])

        self.assertEqual(exit_code, 1)
        self.assertIn("Command failed cleanly.", stdout.getvalue())
        self.assertNotIn("Traceback", stdout.getvalue())

    def test_logs_dispatches_with_options(self) -> None:
        with patch("pihole_ai.service.service_logs") as service_logs:
            exit_code = cli.main(
                [
                    "logs",
                    "--lines",
                    "25",
                    "-f",
                    "--dry-run",
                ]
            )

        self.assertEqual(exit_code, 0)
        service_logs.assert_called_once_with(
            lines=25,
            follow=True,
            dry_run=True,
        )

    def test_logs_defaults_to_last_80_lines_without_follow(self) -> None:
        with patch("pihole_ai.service.service_logs") as service_logs:
            exit_code = cli.main(["logs"])

        self.assertEqual(exit_code, 0)
        service_logs.assert_called_once_with(
            lines=80,
            follow=False,
            dry_run=False,
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

    def test_intel_import_hosts_dispatches_with_options(self) -> None:
        with patch("pihole_ai.intel.import_hosts_file", return_value=2) as import_hosts_file, \
             patch("sys.stdout", io.StringIO()):
            exit_code = cli.main(
                [
                    "intel",
                    "import-hosts",
                    "feeds/hosts.txt",
                    "--source",
                    "test-feed",
                    "--category",
                    "phishing",
                    "--confidence",
                    "85",
                ]
            )

        self.assertEqual(exit_code, 0)
        import_hosts_file.assert_called_once_with(
            path="feeds/hosts.txt",
            source="test-feed",
            category="phishing",
            confidence=85,
        )

    def test_intel_list_dispatches_with_options(self) -> None:
        with patch("pihole_ai.intel.print_intel", return_value=1) as print_intel, \
             patch("sys.stdout", io.StringIO()):
            exit_code = cli.main(
                [
                    "intel",
                    "list",
                    "--limit",
                    "10",
                    "--q",
                    "bad",
                    "--source",
                    "test-feed",
                    "--category",
                    "malware",
                ]
            )

        self.assertEqual(exit_code, 0)
        print_intel.assert_called_once_with(
            limit=10,
            search="bad",
            source="test-feed",
            category="malware",
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
