import json
import io
import os
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from core.config import (
    CONFIG_FILE,
    ConfigurationIssue,
    ConfigurationValidationResult,
    ProtectedConfigurationAccessError,
    Settings,
    ValidationMode,
    ValidationSeverity,
    load_env_file,
    load_config_with_result,
    validate_config,
)
from pihole_ai import cli


class ConfigTests(unittest.TestCase):
    def valid_env(self, tmpdir: str) -> dict[str, str]:
        root = Path(tmpdir)
        pihole_db = root / "pihole-FTL.db"
        pihole_db.write_text("", encoding="utf-8")
        data_dir = root / "data"
        log_dir = root / "logs"
        data_dir.mkdir()
        log_dir.mkdir()

        return {
            "PIHOLE_AI_PIHOLE_DB": str(pihole_db),
            "EVENTS_DB_PATH": str(data_dir / "events.db"),
            "LOG_PATH": str(log_dir / "pihole-ai.log"),
            "PIHOLE_AI_DASHBOARD_HOST": "127.0.0.1",
            "PIHOLE_AI_DASHBOARD_PASSWORD_HASH": "scrypt:32768:8:1$salt$hash",
            "PIHOLE_AI_DASHBOARD_SECRET_KEY": "x" * 48,
        }

    def test_load_env_file_sets_log_level_without_overriding_existing_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / ".env"
            path.write_text(
                "LOG_LEVEL=DEBUG\nPIHOLE_AI_LOG_LEVEL=WARNING\n",
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                {
                    "PIHOLE_AI_LOG_LEVEL": "ERROR",
                },
                clear=True,
            ):
                load_env_file(path)

                self.assertEqual(os.environ["LOG_LEVEL"], "DEBUG")
                self.assertEqual(os.environ["PIHOLE_AI_LOG_LEVEL"], "ERROR")

    def test_settings_respects_log_level_from_environment(self) -> None:
        with patch.dict(
            os.environ,
            {
                "LOG_LEVEL": "debug",
            },
            clear=True,
        ):
            self.assertEqual(Settings().log_level, "DEBUG")

    def test_default_alert_log_uses_appliance_log_directory(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                Settings().alert_log,
                Path("/var/log/pihole-ai/alerts.log"),
            )

    def test_specific_pihole_log_level_overrides_generic_log_level(self) -> None:
        with patch.dict(
            os.environ,
            {
                "LOG_LEVEL": "debug",
                "PIHOLE_AI_LOG_LEVEL": "warning",
            },
            clear=True,
        ):
            self.assertEqual(Settings().log_level, "WARNING")

    def test_valid_test_configuration_has_no_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Settings(
                env=self.valid_env(tmpdir),
            )
            result = validate_config(
                config,
                mode=ValidationMode.RUNTIME,
            )

        self.assertEqual(result.error_count, 0)
        self.assertEqual(result.warning_count, 0)

    def test_invalid_integer_parsing_is_structured(self) -> None:
        with self.assertRaises(Exception) as raised:
            Settings(
                env={
                    "PIHOLE_AI_COLLECT_BATCH_SIZE": "many",
                },
            )

        self.assertEqual(
            raised.exception.issues[0].code,
            "config.collect_batch_size.invalid_integer",
        )

    def test_invalid_boolean_parsing_is_structured(self) -> None:
        with self.assertRaises(Exception) as raised:
            Settings(
                env={
                    "AI_ENABLED": "maybe",
                },
            )

        self.assertEqual(
            raised.exception.issues[0].code,
            "config.ai_enabled.invalid_boolean",
        )

    def test_invalid_dashboard_port_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.valid_env(tmpdir) | {
                "PIHOLE_AI_DASHBOARD_PORT": "70000",
            }
            result = validate_config(
                Settings(env=env),
                mode=ValidationMode.RUNTIME,
            )

        self.assertIn(
            "config.dashboard.invalid_port",
            {issue.code for issue in result.issues},
        )

    def test_non_loopback_dashboard_warning_remediation_mentions_auth_and_firewall(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.valid_env(tmpdir) | {
                "PIHOLE_AI_DASHBOARD_HOST": "0.0.0.0",
            }
            result = validate_config(
                Settings(env=env),
                mode=ValidationMode.RUNTIME,
            )

        issue = next(
            item
            for item in result.issues
            if item.code == "config.dashboard.non_loopback_bind"
        )
        self.assertEqual(issue.severity, ValidationSeverity.WARNING.value)
        self.assertIn("authentication", issue.remediation)
        self.assertIn("firewall", issue.remediation)

    def test_missing_pihole_database_allowed_in_syntax_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.valid_env(tmpdir) | {
                "PIHOLE_AI_PIHOLE_DB": str(Path(tmpdir) / "missing.db"),
            }
            result = validate_config(
                Settings(env=env),
                mode=ValidationMode.SYNTAX,
            )

        self.assertNotIn(
            "config.pihole_db.missing",
            {issue.code for issue in result.issues},
        )

    def test_missing_pihole_database_is_runtime_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.valid_env(tmpdir) | {
                "PIHOLE_AI_PIHOLE_DB": str(Path(tmpdir) / "missing.db"),
            }
            result = validate_config(
                Settings(env=env),
                mode=ValidationMode.RUNTIME,
            )

        self.assertIn(
            "config.pihole_db.missing",
            {issue.code for issue in result.issues},
        )

    def test_unreadable_pihole_database_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "core.config.os.access",
            return_value=False,
        ):
            result = validate_config(
                Settings(env=self.valid_env(tmpdir)),
                mode=ValidationMode.RUNTIME,
            )

        self.assertIn(
            "config.pihole_db.not_readable",
            {issue.code for issue in result.issues},
        )

    def test_unwritable_events_database_parent_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.valid_env(tmpdir)

            def fake_access(path: Path, mode: int) -> bool:
                return not str(path).endswith("/data")

            with patch("core.config.os.access", side_effect=fake_access):
                result = validate_config(
                    Settings(env=env),
                    mode=ValidationMode.RUNTIME,
                )

        self.assertIn(
            "config.events_db.parent_not_writable",
            {issue.code for issue in result.issues},
        )

    def test_database_paths_conflict_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.valid_env(tmpdir)
            env["EVENTS_DB_PATH"] = env["PIHOLE_AI_PIHOLE_DB"]
            result = validate_config(
                Settings(env=env),
                mode=ValidationMode.RUNTIME,
            )

        self.assertIn(
            "config.database_paths.conflict",
            {issue.code for issue in result.issues},
        )

    def test_events_database_path_directory_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.valid_env(tmpdir)
            env["EVENTS_DB_PATH"] = str(Path(tmpdir) / "data")
            result = validate_config(
                Settings(env=env),
                mode=ValidationMode.RUNTIME,
            )

        self.assertIn(
            "config.events_db.is_directory",
            {issue.code for issue in result.issues},
        )

    def test_malformed_ollama_url_is_error(self) -> None:
        config = Settings(
            env={
                "PIHOLE_AI_OLLAMA_URL": "ftp://example.com",
            },
        )
        result = validate_config(
            config,
            mode=ValidationMode.SYNTAX,
        )

        self.assertIn(
            "config.ollama.invalid_url",
            {issue.code for issue in result.issues},
        )

    def test_ollama_url_credentials_are_rejected_and_redacted(self) -> None:
        config = Settings(
            env={
                "PIHOLE_AI_OLLAMA_URL": "http://user:secret@example.com:11434",
            },
        )
        result = validate_config(
            config,
            mode=ValidationMode.SYNTAX,
        )
        encoded = json.dumps(result.to_dict()) + json.dumps(config.to_safe_dict())

        self.assertIn(
            "config.ollama.credentials_in_url",
            {issue.code for issue in result.issues},
        )
        self.assertNotIn("user:secret", encoded)

    def test_empty_ollama_model_when_ai_enabled_is_error(self) -> None:
        result = validate_config(
            Settings(
                env={
                    "AI_ENABLED": "true",
                    "PIHOLE_AI_OLLAMA_MODEL": "",
                },
            ),
            mode=ValidationMode.SYNTAX,
        )

        self.assertIn(
            "config.ollama.empty_model",
            {issue.code for issue in result.issues},
        )

    def test_non_loopback_dashboard_binding_warns(self) -> None:
        result = validate_config(
            Settings(
                env={
                    "PIHOLE_AI_DASHBOARD_HOST": "0.0.0.0",
                    "PIHOLE_AI_DASHBOARD_PASSWORD_HASH": "scrypt:32768:8:1$salt$hash",
                    "PIHOLE_AI_DASHBOARD_SECRET_KEY": "x" * 48,
                },
            ),
            mode=ValidationMode.SYNTAX,
        )

        self.assertIn(
            "config.dashboard.non_loopback_bind",
            {issue.code for issue in result.issues},
        )

    def test_dashboard_auth_defaults_require_credentials(self) -> None:
        result = validate_config(
            Settings(
                env={
                    "PIHOLE_AI_DASHBOARD_HOST": "127.0.0.1",
                },
            ),
            mode=ValidationMode.RUNTIME,
        )
        codes = {issue.code for issue in result.issues}

        self.assertIn("config.dashboard.password_hash_missing", codes)
        self.assertIn("config.dashboard.secret_key_missing", codes)

    def test_auth_disabled_exposed_is_error(self) -> None:
        result = validate_config(
            Settings(
                env={
                    "PIHOLE_AI_DASHBOARD_HOST": "0.0.0.0",
                    "PIHOLE_AI_DASHBOARD_AUTH_ENABLED": "false",
                },
            ),
            mode=ValidationMode.SYNTAX,
        )

        self.assertIn(
            "config.dashboard.auth_disabled_exposed",
            {issue.code for issue in result.issues},
        )

    def test_auth_disabled_loopback_is_warning(self) -> None:
        result = validate_config(
            Settings(
                env={
                    "PIHOLE_AI_DASHBOARD_HOST": "127.0.0.1",
                    "PIHOLE_AI_DASHBOARD_AUTH_ENABLED": "false",
                },
            ),
            mode=ValidationMode.SYNTAX,
        )

        self.assertIn(
            "config.dashboard.auth_disabled_loopback",
            {issue.code for issue in result.issues},
        )
        self.assertEqual(result.error_count, 0)

    def test_invalid_session_lifetime_is_error(self) -> None:
        result = validate_config(
            Settings(
                env={
                    "PIHOLE_AI_DASHBOARD_SESSION_LIFETIME_MINUTES": "0",
                },
            ),
            mode=ValidationMode.SYNTAX,
        )

        self.assertIn(
            "config.dashboard.session_lifetime_invalid",
            {issue.code for issue in result.issues},
        )

    def test_safe_config_omits_dashboard_secrets(self) -> None:
        config = Settings(
            env={
                "PIHOLE_AI_DASHBOARD_PASSWORD_HASH": "scrypt:32768:8:1$salt$hash",
                "PIHOLE_AI_DASHBOARD_SECRET_KEY": "super-secret-value-that-is-long-enough",
            }
        )
        encoded = json.dumps(config.to_safe_dict())

        self.assertNotIn("super-secret", encoded)
        self.assertNotIn("scrypt:", encoded)
        self.assertTrue(config.to_safe_dict()["dashboard"]["credentials_configured"])

    def test_all_validation_issues_are_collected(self) -> None:
        result = validate_config(
            Settings(
                env={
                    "PIHOLE_AI_DASHBOARD_PORT": "0",
                    "PIHOLE_AI_OLLAMA_URL": "invalid",
                    "PIHOLE_AI_OLLAMA_MODEL": "",
                },
            ),
            mode=ValidationMode.SYNTAX,
        )
        codes = {issue.code for issue in result.issues}

        self.assertIn("config.dashboard.invalid_port", codes)
        self.assertIn("config.ollama.invalid_url", codes)
        self.assertIn("config.ollama.empty_model", codes)

    def test_config_check_text_output(self) -> None:
        result = ConfigurationValidationResult(
            mode="runtime",
            issues=[],
        )

        with patch(
            "pihole_ai.config_cli.load_config_with_result",
            return_value=(Settings(env={}), result),
        ), patch("sys.stdout") as stdout:
            exit_code = cli.main(["config", "check"])

        self.assertEqual(exit_code, 0)
        stdout.write.assert_any_call("PiHole-AI configuration check (runtime)")

    def test_config_check_json_output_and_exit_code(self) -> None:
        result = ConfigurationValidationResult(
            mode="runtime",
            issues=[
                ConfigurationIssue(
                    code="config.test.warning",
                    severity=ValidationSeverity.WARNING.value,
                    setting="TEST",
                    summary="warning",
                    remediation="fix",
                )
            ],
        )

        with patch(
            "pihole_ai.config_cli.load_config_with_result",
            return_value=(Settings(env={}), result),
        ), patch("sys.stdout") as stdout:
            exit_code = cli.main(["config", "check", "--json"])

        self.assertEqual(exit_code, 1)
        self.assertTrue(stdout.write.called)

    def test_config_show_json_output(self) -> None:
        with patch(
            "pihole_ai.config_cli.load_config",
            return_value=Settings(env={}),
        ), patch("sys.stdout") as stdout:
            exit_code = cli.main(["config", "show", "--json"])

        self.assertEqual(exit_code, 0)
        self.assertTrue(stdout.write.called)

    def test_protected_config_permission_denied_is_distinct_issue(self) -> None:
        original_exists = Path.exists

        def exists(path):
            if path == CONFIG_FILE:
                raise PermissionError("permission denied")
            return original_exists(path)

        with patch("pathlib.Path.exists", exists):
            config, result = load_config_with_result(
                env_files=[CONFIG_FILE],
                mode=ValidationMode.RUNTIME,
            )

        self.assertIsNone(config)
        self.assertIn(
            "config.appliance.permission_denied",
            {issue.code for issue in result.issues},
        )

    def test_protected_config_show_prints_sudo_guidance(self) -> None:
        with patch(
            "pihole_ai.config_cli.load_config",
            side_effect=ProtectedConfigurationAccessError(
                CONFIG_FILE,
                PermissionError("permission denied"),
            ),
        ), patch("sys.stdout", io.StringIO()) as stdout:
            exit_code = cli.main(["config", "show"])

        self.assertEqual(exit_code, 3)
        self.assertIn("sudo pihole-ai config show", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
