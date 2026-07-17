import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.config import ConfigurationIssue
from core.config import ConfigurationValidationResult
from core.config import Settings
from core.config import ValidationSeverity
from pihole_ai import cli


class ConfigCLITests(unittest.TestCase):
    def isolated_config_paths(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        config_file = root / "etc.env"
        project_root = root / "project"
        project_root.mkdir()
        return tmp, config_file, project_root

    def run_config(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        config_text: str = "",
        project_text: str = "",
    ):
        tmp, config_file, project_root = self.isolated_config_paths()
        self.addCleanup(tmp.cleanup)
        if config_text:
            config_file.write_text(config_text, encoding="utf-8")
        if project_text:
            (project_root / ".env").write_text(project_text, encoding="utf-8")
        with patch("core.config_manager.runtime_config.CONFIG_FILE", config_file), \
             patch("core.config_manager.runtime_config.PROJECT_ROOT", project_root), \
             patch.dict(os.environ, env or {}, clear=True), \
             patch("sys.stdout", io.StringIO()) as stdout, \
             patch("sys.stderr", io.StringIO()) as stderr:
            exit_code = cli.main(["config", *argv])
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_show_human_output_is_schema_ordered_and_safe(self) -> None:
        exit_code, stdout, _ = self.run_config(
            ["show"],
            env={
                "PIHOLE_AI_DASHBOARD_PASSWORD_HASH": "scrypt:secret",
            },
        )

        self.assertEqual(exit_code, 0)
        self.assertLess(stdout.index("project_root:"), stdout.index("data_dir:"))
        self.assertIn("source=environment", stdout)
        self.assertIn("category=Authentication", stdout)
        self.assertIn("restart=pihole-ai-dashboard.service", stdout)
        self.assertNotIn("scrypt:secret", stdout)

    def test_show_json_output_is_deterministic_and_masks_secrets(self) -> None:
        exit_code, stdout, _ = self.run_config(
            ["show", "--json"],
            env={
                "PIHOLE_AI_DASHBOARD_SECRET_KEY": "secret-key",
            },
        )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout)
        keys = [item["key"] for item in payload["settings"]]
        self.assertEqual(keys, sorted(keys, key=keys.index))
        secret = next(
            item
            for item in payload["settings"]
            if item["key"] == "dashboard_secret_key"
        )
        self.assertTrue(secret["configured"])
        self.assertTrue(secret["masked"])
        self.assertIsNone(secret["value"])

    def test_show_category_filter_is_case_insensitive(self) -> None:
        exit_code, stdout, _ = self.run_config(["show", "--category", "dashboard"])

        self.assertEqual(exit_code, 0)
        self.assertIn("dashboard_port:", stdout)
        self.assertNotIn("ollama_model:", stdout)

    def test_show_source_filter_supports_source_kind(self) -> None:
        exit_code, stdout, _ = self.run_config(
            ["show", "--source", "env_file"],
            config_text="PIHOLE_AI_OLLAMA_MODEL=from-file\n",
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("ollama_model:", stdout)
        self.assertNotIn("dashboard_port:", stdout)

    def test_show_invalid_filter_returns_usage_error(self) -> None:
        exit_code, _, stderr = self.run_config(["show", "--category", "missing"])

        self.assertEqual(exit_code, 2)
        self.assertIn("Unknown configuration category", stderr)

    def test_get_accepts_canonical_key_env_name_and_alias(self) -> None:
        for key in ("ollama_model", "PIHOLE_AI_OLLAMA_MODEL", "LOG_LEVEL"):
            with self.subTest(key=key):
                exit_code, stdout, _ = self.run_config(
                    ["get", key],
                    env={
                        "PIHOLE_AI_OLLAMA_MODEL": "model-a",
                        "LOG_LEVEL": "DEBUG",
                    },
                )
                self.assertEqual(exit_code, 0)
                self.assertTrue(stdout.strip())

    def test_get_details_and_json_are_stable(self) -> None:
        exit_code, stdout, _ = self.run_config(
            ["get", "PIHOLE_AI_DASHBOARD_PORT", "--json", "--details"],
            env={"PIHOLE_AI_DASHBOARD_PORT": "8081"},
        )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["key"], "dashboard_port")
        self.assertEqual(payload["value"], "8081")
        self.assertEqual(payload["source"], "environment")
        self.assertEqual(payload["restart"], ["pihole-ai-dashboard.service"])

    def test_get_unknown_key_fails_cleanly(self) -> None:
        exit_code, _, stderr = self.run_config(["get", "missing.key"])

        self.assertEqual(exit_code, 2)
        self.assertIn("Unknown configuration key", stderr)

    def test_get_invalid_value_returns_validation_exit_without_secret_leak(self) -> None:
        exit_code, stdout, _ = self.run_config(
            ["get", "dashboard_secret_key", "--json", "--details"],
            env={
                "PIHOLE_AI_DASHBOARD_SECRET_KEY": "secret-value",
            },
        )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout)
        self.assertTrue(payload["masked"])
        self.assertIsNone(payload["value"])
        self.assertNotIn("secret-value", stdout)

    def test_validate_success_uses_new_message(self) -> None:
        with patch(
            "pihole_ai.config_cli.load_config_with_result",
            return_value=(
                Settings(env={}),
                ConfigurationValidationResult(mode="runtime", issues=[]),
            ),
        ):
            exit_code, stdout, _ = self.run_config(["validate"])

        self.assertEqual(exit_code, 0)
        self.assertIn("Configuration is valid.", stdout)

    def test_validate_failure_returns_dedicated_exit_code_and_json(self) -> None:
        issue = ConfigurationIssue(
            code="config.dashboard.invalid_port",
            severity=ValidationSeverity.ERROR.value,
            setting="PIHOLE_AI_DASHBOARD_PORT",
            summary="Dashboard port must be between 1 and 65535.",
            remediation="Set a valid port.",
        )
        with patch(
            "pihole_ai.config_cli.load_config_with_result",
            return_value=(
                None,
                ConfigurationValidationResult(mode="runtime", issues=[issue]),
            ),
        ):
            exit_code, stdout, _ = self.run_config(
                ["validate", "--json"],
                env={"PIHOLE_AI_DASHBOARD_PORT": "70000"},
            )

        self.assertEqual(exit_code, 3)
        payload = json.loads(stdout)
        self.assertFalse(payload["valid"])
        self.assertEqual(payload["errors"][0]["severity"], "error")

    def test_config_commands_do_not_write_env_files(self) -> None:
        tmp, config_file, project_root = self.isolated_config_paths()
        self.addCleanup(tmp.cleanup)
        config_file.write_text("AI_ENABLED=true\n", encoding="utf-8")
        before = config_file.read_text(encoding="utf-8")

        with patch("core.config_manager.runtime_config.CONFIG_FILE", config_file), \
             patch("core.config_manager.runtime_config.PROJECT_ROOT", project_root), \
             patch.dict(os.environ, {}, clear=True), \
             patch("sys.stdout", io.StringIO()):
            self.assertEqual(cli.main(["config", "show"]), 0)
            self.assertEqual(cli.main(["config", "get", "AI_ENABLED"]), 0)
            self.assertEqual(cli.main(["config", "impact", "AI_ENABLED"]), 0)

        self.assertEqual(config_file.read_text(encoding="utf-8"), before)

    def test_impact_deduplicates_keys_and_does_not_call_systemctl(self) -> None:
        with patch("subprocess.run") as subprocess_run:
            exit_code, stdout, _ = self.run_config(
                ["impact", "PIHOLE_AI_OLLAMA_URL", "ollama_url", "--json"]
            )

        self.assertEqual(exit_code, 0)
        subprocess_run.assert_not_called()
        payload = json.loads(stdout)
        self.assertEqual(payload["changed_keys"], ["ollama_url"])
        self.assertEqual(payload["services"], ["pihole-ai-engine.service"])

    def test_impact_no_restart_required(self) -> None:
        exit_code, stdout, _ = self.run_config(["impact", "keep_latest_events"])

        self.assertEqual(exit_code, 0)
        self.assertIn("No service restart is required.", stdout)

    def test_impact_unknown_key_fails_before_partial_result(self) -> None:
        exit_code, stdout, stderr = self.run_config(
            ["impact", "ollama_url", "missing.key"]
        )

        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("Unknown configuration key", stderr)

    def test_help_output_includes_read_only_config_family(self) -> None:
        parser = cli.build_parser()
        with patch("sys.stdout", io.StringIO()) as stdout:
            with self.assertRaises(SystemExit):
                parser.parse_args(["config", "--help"])

        help_text = stdout.getvalue()
        self.assertIn("show", help_text)
        self.assertIn("get", help_text)
        self.assertIn("validate", help_text)
        self.assertIn("impact", help_text)


if __name__ == "__main__":
    unittest.main()
