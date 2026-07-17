import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.service_control import ServiceRestartResult
from core.service_control import ordered_services
from core.service_control import restart_services
from pihole_ai import cli
import subprocess


class ConfigCLIRestartTests(unittest.TestCase):
    def run_config(
        self,
        argv: list[str],
        *,
        config_text: str = "",
        import_text: str | None = None,
    ):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        config_file = root / "pihole-ai.env"
        project_root = root / "project"
        project_root.mkdir()
        config_file.write_text(config_text, encoding="utf-8")
        if import_text is not None:
            import_file = root / "import.env"
            import_file.write_text(import_text, encoding="utf-8")
            argv = [
                item if item != "{import}" else str(import_file)
                for item in argv
            ]
        with patch("core.config_manager.runtime_config.PROJECT_ROOT", project_root), \
             patch("pihole_ai.config_cli.runtime_config.PROJECT_ROOT", project_root), \
             patch.dict(os.environ, {}, clear=True), \
             patch("sys.stdout", io.StringIO()) as stdout, \
             patch("sys.stderr", io.StringIO()) as stderr, \
             patch("sys.stdin", io.StringIO()):
            exit_code = cli.main(["config", *argv, "--config-file", str(config_file)])
        return exit_code, stdout.getvalue(), stderr.getvalue(), config_file

    def test_restart_planning_order_and_deduplication(self) -> None:
        self.assertEqual(
            ordered_services(
                [
                    "pihole-ai-dashboard.service",
                    "pihole-ai-engine.service",
                    "pihole-ai-engine.service",
                    "pihole-ai-collector.service",
                ]
            ),
            [
                "pihole-ai-collector.service",
                "pihole-ai-engine.service",
                "pihole-ai-dashboard.service",
            ],
        )

    def test_arbitrary_service_injection_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ordered_services(["ssh.service"])

    def test_set_with_restart_restarts_only_affected_service_after_write(self) -> None:
        calls: list[str] = []

        def restart_services(services):
            calls.append("restart")
            self.assertEqual(services, ["pihole-ai-engine.service"])
            return [
                ServiceRestartResult(
                    service="pihole-ai-engine.service",
                    attempted=True,
                    success=True,
                    exit_code=0,
                )
            ]

        with patch("pihole_ai.config_cli.service_control.restart_services", side_effect=restart_services):
            exit_code, stdout, _, path = self.run_config(
                ["set", "ollama_model", "new", "--yes", "--restart"],
                config_text="PIHOLE_AI_OLLAMA_MODEL=old\n",
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(calls, ["restart"])
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=new", path.read_text(encoding="utf-8"))
        self.assertIn("Restart completed.", stdout)

    def test_unset_with_restart_restarts_affected_service(self) -> None:
        with patch("pihole_ai.config_cli.service_control.restart_services") as restart_services:
            restart_services.return_value = [
                ServiceRestartResult("pihole-ai-engine.service", True, True, 0)
            ]
            exit_code, _, _, _ = self.run_config(
                ["unset", "ollama_model", "--yes", "--restart"],
                config_text="PIHOLE_AI_OLLAMA_MODEL=old\n",
            )

        self.assertEqual(exit_code, 0)
        restart_services.assert_called_once_with(["pihole-ai-engine.service"])

    def test_import_with_restart_restarts_multiple_services_in_order(self) -> None:
        with patch("pihole_ai.config_cli.service_control.restart_services") as restart_services:
            restart_services.return_value = [
                ServiceRestartResult("pihole-ai-engine.service", True, True, 0),
                ServiceRestartResult("pihole-ai-dashboard.service", True, True, 0),
            ]
            exit_code, stdout, _, _ = self.run_config(
                ["import", "{import}", "--yes", "--restart"],
                config_text="PIHOLE_AI_OLLAMA_MODEL=old\nPIHOLE_AI_DASHBOARD_PORT=8080\n",
                import_text="PIHOLE_AI_OLLAMA_MODEL=new\nPIHOLE_AI_DASHBOARD_PORT=8081\n",
            )

        self.assertEqual(exit_code, 0)
        restart_services.assert_called_once_with(
            ["pihole-ai-engine.service", "pihole-ai-dashboard.service"]
        )
        self.assertIn("Restart completed.", stdout)

    def test_dry_run_restart_shows_plan_without_write_or_subprocess(self) -> None:
        with patch("pihole_ai.config_cli.service_control.restart_services") as restart_services:
            exit_code, stdout, _, path = self.run_config(
                ["set", "ollama_model", "new", "--restart", "--dry-run", "--json"],
                config_text="PIHOLE_AI_OLLAMA_MODEL=old\n",
            )

        self.assertEqual(exit_code, 0)
        restart_services.assert_not_called()
        payload = json.loads(stdout)
        self.assertTrue(payload["restart_requested"])
        self.assertFalse(payload["restart_attempted"])
        self.assertEqual(payload["affected_services"], ["pihole-ai-engine.service"])
        self.assertIn("old", path.read_text(encoding="utf-8"))
        self.assertFalse(path.with_suffix(".env.bak").exists())

    def test_no_impact_change_with_restart_does_not_call_service_manager(self) -> None:
        with patch("pihole_ai.config_cli.service_control.restart_services") as restart_services:
            exit_code, stdout, _, _ = self.run_config(
                ["set", "keep_latest_events", "200000", "--yes", "--restart"],
                config_text="PIHOLE_AI_KEEP_LATEST_EVENTS=100000\n",
            )

        self.assertEqual(exit_code, 0)
        restart_services.assert_not_called()
        self.assertIn("No service restart is required.", stdout)

    def test_semantic_noop_with_restart_does_not_write_or_restart(self) -> None:
        with patch("pihole_ai.config_cli.service_control.restart_services") as restart_services:
            exit_code, stdout, _, path = self.run_config(
                ["set", "ollama_model", "old", "--yes", "--restart"],
                config_text="PIHOLE_AI_OLLAMA_MODEL=old\n",
            )

        self.assertEqual(exit_code, 0)
        restart_services.assert_not_called()
        self.assertIn("No configuration change is required.", stdout)
        self.assertFalse(path.with_suffix(".env.bak").exists())

    def test_persistence_failure_prevents_restart(self) -> None:
        with patch("core.config_manager.os.replace", side_effect=OSError("boom")), \
             patch("pihole_ai.config_cli.service_control.restart_services") as restart_services:
            exit_code, _, stderr, path = self.run_config(
                ["set", "ollama_model", "new", "--yes", "--restart"],
                config_text="PIHOLE_AI_OLLAMA_MODEL=old\n",
            )

        self.assertEqual(exit_code, 1)
        restart_services.assert_not_called()
        self.assertIn("could not be written", stderr)
        self.assertEqual(path.read_text(encoding="utf-8"), "PIHOLE_AI_OLLAMA_MODEL=old\n")

    def test_restart_failure_preserves_written_configuration_and_reports_recovery(self) -> None:
        with patch("pihole_ai.config_cli.service_control.restart_services") as restart_services:
            restart_services.return_value = [
                ServiceRestartResult(
                    service="pihole-ai-engine.service",
                    attempted=True,
                    success=False,
                    exit_code=1,
                    error_code="authorization_required",
                    message="Restart authorization was denied.",
                )
            ]
            exit_code, stdout, _, path = self.run_config(
                ["set", "ollama_model", "new", "--yes", "--restart"],
                config_text="PIHOLE_AI_OLLAMA_MODEL=old\n",
            )

        self.assertEqual(exit_code, 1)
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=new", path.read_text(encoding="utf-8"))
        self.assertIn("Restart failed", stdout)
        self.assertIn("sudo systemctl restart pihole-ai-engine.service", stdout)
        self.assertTrue(path.with_suffix(".env.bak").exists())

    def test_json_restart_failure_contract(self) -> None:
        with patch("pihole_ai.config_cli.service_control.restart_services") as restart_services:
            restart_services.return_value = [
                ServiceRestartResult(
                    service="pihole-ai-engine.service",
                    attempted=True,
                    success=False,
                    exit_code=1,
                    error_code="service_not_found",
                    message="Service unit was not found.",
                )
            ]
            exit_code, stdout, _, _ = self.run_config(
                ["set", "ollama_model", "new", "--yes", "--restart", "--json"],
                config_text="PIHOLE_AI_OLLAMA_MODEL=old\n",
            )

        self.assertEqual(exit_code, 1)
        payload = json.loads(stdout)
        self.assertTrue(payload["written"])
        self.assertTrue(payload["restart_attempted"])
        self.assertFalse(payload["restart_success"])
        self.assertEqual(payload["service_results"][0]["error_code"], "service_not_found")
        self.assertEqual(
            payload["recovery_commands"],
            ["sudo systemctl restart pihole-ai-engine.service"],
        )

    def test_service_control_invokes_systemctl_without_shell_or_sudo(self) -> None:
        completed = subprocess.CompletedProcess(
            ["systemctl"],
            0,
            stdout="",
            stderr="",
        )
        with patch("core.service_control.subprocess.run", return_value=completed) as run:
            results = restart_services(["pihole-ai-engine.service"])

        self.assertTrue(results[0].success)
        run.assert_called_once()
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["systemctl", "restart", "pihole-ai-engine.service"])
        self.assertNotIn("sudo", args[0])
        self.assertNotIn("shell", kwargs)
        self.assertTrue(kwargs["capture_output"])

    def test_service_control_classifies_common_failures_safely(self) -> None:
        cases = [
            ("Access denied", "authorization_required"),
            ("Unit pihole-ai-engine.service not found", "service_not_found"),
            ("System has not been booted with systemd", "systemd_unavailable"),
        ]
        for stderr, code in cases:
            with self.subTest(code=code), patch(
                "core.service_control.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    ["systemctl"],
                    1,
                    stdout="",
                    stderr=stderr,
                ),
            ):
                result = restart_services(["pihole-ai-engine.service"])[0]
            self.assertFalse(result.success)
            self.assertEqual(result.error_code, code)

    def test_service_control_handles_missing_systemctl_and_timeout(self) -> None:
        with patch("core.service_control.subprocess.run", side_effect=FileNotFoundError):
            missing = restart_services(["pihole-ai-engine.service"])[0]
        self.assertEqual(missing.error_code, "systemctl_unavailable")

        with patch(
            "core.service_control.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["systemctl"], 30),
        ):
            timeout = restart_services(["pihole-ai-engine.service"])[0]
        self.assertEqual(timeout.error_code, "timeout")


if __name__ == "__main__":
    unittest.main()
