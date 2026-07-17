import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pihole_ai import cli


class ConfigCLIWriteTests(unittest.TestCase):
    def run_config(
        self,
        argv: list[str],
        *,
        config_text: str | None = "",
        env: dict[str, str] | None = None,
        stdin: io.StringIO | None = None,
    ):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        config_file = root / "pihole-ai.env"
        project_root = root / "project"
        project_root.mkdir()
        if config_text is not None:
            config_file.write_text(config_text, encoding="utf-8")
        stream = stdin or io.StringIO()
        with patch("core.config_manager.runtime_config.PROJECT_ROOT", project_root), \
             patch("pihole_ai.config_cli.runtime_config.PROJECT_ROOT", project_root), \
             patch.dict(os.environ, env or {}, clear=True), \
             patch("sys.stdout", io.StringIO()) as stdout, \
             patch("sys.stderr", io.StringIO()) as stderr, \
             patch("sys.stdin", stream):
            exit_code = cli.main(["config", *argv, "--config-file", str(config_file)])
        return exit_code, stdout.getvalue(), stderr.getvalue(), config_file

    def test_set_updates_existing_key_in_place_and_creates_backup(self) -> None:
        exit_code, stdout, _, path = self.run_config(
            ["set", "PIHOLE_AI_OLLAMA_MODEL", "llama3.2:3b", "--yes"],
            config_text="# keep\nPIHOLE_AI_OLLAMA_MODEL=llama3.2:1b\nUNKNOWN=value\n",
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("Configuration written.", stdout)
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=llama3.2:3b", path.read_text(encoding="utf-8"))
        self.assertIn("UNKNOWN=value", path.read_text(encoding="utf-8"))
        self.assertEqual(
            path.with_suffix(".env.bak").read_text(encoding="utf-8"),
            "# keep\nPIHOLE_AI_OLLAMA_MODEL=llama3.2:1b\nUNKNOWN=value\n",
        )

    def test_set_accepts_canonical_key_and_appends_new_key(self) -> None:
        exit_code, _, _, path = self.run_config(
            ["set", "ollama_model", "llama3.2:1b", "--yes"],
            config_text="# keep\n",
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            path.read_text(encoding="utf-8"),
            "# keep\nPIHOLE_AI_OLLAMA_MODEL=llama3.2:1b\n",
        )

    def test_set_accepts_ollama_model_alias_and_writes_canonical_key(self) -> None:
        exit_code, _, _, path = self.run_config(
            ["set", "OLLAMA_MODEL", "llama3.2:1b", "--yes"],
            config_text="",
        )

        self.assertEqual(exit_code, 0)
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b", lines)
        self.assertNotIn("OLLAMA_MODEL=llama3.2:1b", lines)

    def test_set_accepts_alias_and_normalizes_boolean(self) -> None:
        exit_code, _, _, path = self.run_config(
            ["set", "AI_ENABLED", "no", "--yes"],
            config_text="",
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("PIHOLE_AI_ENABLED=false", path.read_text(encoding="utf-8"))

    def test_set_rejects_parse_failure_without_writing(self) -> None:
        exit_code, stdout, _, path = self.run_config(
            ["set", "dashboard_port", "70000", "--yes"],
            config_text="PIHOLE_AI_DASHBOARD_PORT=8080\n",
        )

        self.assertEqual(exit_code, 3)
        self.assertIn("Configuration change rejected.", stdout)
        self.assertEqual(path.read_text(encoding="utf-8"), "PIHOLE_AI_DASHBOARD_PORT=8080\n")
        self.assertFalse(path.with_suffix(".env.bak").exists())

    def test_set_rejects_cross_setting_failure(self) -> None:
        exit_code, stdout, _, path = self.run_config(
            ["set", "PIHOLE_AI_DASHBOARD_AUTH_ENABLED", "false", "--yes"],
            config_text="PIHOLE_AI_DASHBOARD_HOST=0.0.0.0\n",
        )

        self.assertEqual(exit_code, 3)
        self.assertIn("config.dashboard.auth_disabled_exposed", stdout)
        self.assertNotIn("PIHOLE_AI_DASHBOARD_AUTH_ENABLED=false", path.read_text(encoding="utf-8"))

    def test_set_dry_run_does_not_create_file_or_backup(self) -> None:
        exit_code, stdout, _, path = self.run_config(
            ["set", "ollama_model", "llama3.2:1b", "--dry-run"],
            config_text=None,
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("Dry run: no file was written.", stdout)
        self.assertFalse(path.exists())
        self.assertFalse(path.with_suffix(".env.bak").exists())

    def test_set_json_requires_yes_or_dry_run(self) -> None:
        exit_code, _, stderr, path = self.run_config(
            ["set", "ollama_model", "llama3.2:1b", "--json"],
            config_text="",
        )

        self.assertEqual(exit_code, 2)
        self.assertIn("requires --dry-run or --yes", stderr)
        self.assertEqual(path.read_text(encoding="utf-8"), "")

    def test_set_json_masks_secret(self) -> None:
        secret = "x" * 48
        exit_code, stdout, _, path = self.run_config(
            ["set", "dashboard_secret_key", secret, "--dry-run", "--json"],
            config_text="",
        )

        self.assertEqual(exit_code, 0)
        self.assertFalse(path.with_suffix(".env.bak").exists())
        self.assertNotIn(secret, stdout)
        payload = json.loads(stdout)
        self.assertTrue(payload["proposed"]["masked"])
        self.assertIsNone(payload["proposed"]["value"])

    def test_set_confirmation_declined_does_not_write(self) -> None:
        stdin = io.StringIO("n\n")
        stdin.isatty = lambda: True
        exit_code, stdout, _, path = self.run_config(
            ["set", "ollama_model", "llama3.2:3b"],
            config_text="PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b\n",
            stdin=stdin,
        )

        self.assertEqual(exit_code, 1)
        self.assertIn("Change declined", stdout)
        self.assertEqual(path.read_text(encoding="utf-8"), "PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b\n")

    def test_set_confirmation_accepted_writes(self) -> None:
        stdin = io.StringIO("y\n")
        stdin.isatty = lambda: True
        exit_code, _, _, path = self.run_config(
            ["set", "ollama_model", "llama3.2:3b"],
            config_text="PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b\n",
            stdin=stdin,
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("llama3.2:3b", path.read_text(encoding="utf-8"))

    def test_set_noninteractive_without_yes_fails_safely(self) -> None:
        exit_code, _, stderr, path = self.run_config(
            ["set", "ollama_model", "llama3.2:3b"],
            config_text="PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b\n",
        )

        self.assertEqual(exit_code, 1)
        self.assertIn("Confirmation required", stderr)
        self.assertIn("llama3.2:1b", path.read_text(encoding="utf-8"))

    def test_set_noop_does_not_rewrite_or_backup(self) -> None:
        exit_code, stdout, _, path = self.run_config(
            ["set", "ollama_model", "llama3.2:1b", "--yes"],
            config_text="PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b\n",
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("No configuration change is required.", stdout)
        self.assertFalse(path.with_suffix(".env.bak").exists())

    def test_process_environment_override_warning(self) -> None:
        exit_code, stdout, _, _ = self.run_config(
            ["set", "ollama_model", "persisted-model", "--dry-run"],
            config_text="PIHOLE_AI_OLLAMA_MODEL=old-model\n",
            env={"PIHOLE_AI_OLLAMA_MODEL": "env-model"},
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("controlled by process environment", stdout)
        self.assertIn("source: environment", stdout)

    def test_unset_removes_key_and_reports_default_fallback(self) -> None:
        exit_code, stdout, _, path = self.run_config(
            ["unset", "PIHOLE_AI_OLLAMA_MODEL", "--yes"],
            config_text="# keep\nPIHOLE_AI_OLLAMA_MODEL=custom\nUNKNOWN=value\n",
        )

        self.assertEqual(exit_code, 0)
        content = path.read_text(encoding="utf-8")
        self.assertNotIn("PIHOLE_AI_OLLAMA_MODEL=", content)
        self.assertIn("UNKNOWN=value", content)
        self.assertIn("source: default", stdout)

    def test_unset_absent_key_is_idempotent_noop(self) -> None:
        exit_code, stdout, _, path = self.run_config(
            ["unset", "ollama_model", "--yes"],
            config_text="UNKNOWN=value\n",
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("No configuration change is required.", stdout)
        self.assertEqual(path.read_text(encoding="utf-8"), "UNKNOWN=value\n")
        self.assertFalse(path.with_suffix(".env.bak").exists())

    def test_unset_effective_fallback_to_process_environment(self) -> None:
        exit_code, stdout, _, _ = self.run_config(
            ["unset", "ollama_model", "--dry-run"],
            config_text="PIHOLE_AI_OLLAMA_MODEL=custom\n",
            env={"PIHOLE_AI_OLLAMA_MODEL": "env-model"},
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("source: environment", stdout)

    def test_duplicate_key_ambiguity_fails_without_writing(self) -> None:
        content = "PIHOLE_AI_OLLAMA_MODEL=a\nPIHOLE_AI_OLLAMA_MODEL=b\n"
        exit_code, _, stderr, path = self.run_config(
            ["set", "ollama_model", "c", "--yes"],
            config_text=content,
        )

        self.assertEqual(exit_code, 1)
        self.assertIn("duplicate persisted aliases", stderr)
        self.assertEqual(path.read_text(encoding="utf-8"), content)

    def test_atomic_write_failure_preserves_original(self) -> None:
        with patch("core.config_manager.os.replace", side_effect=OSError("boom")):
            exit_code, _, stderr, path = self.run_config(
                ["set", "ollama_model", "new", "--yes"],
                config_text="PIHOLE_AI_OLLAMA_MODEL=old\n",
            )

        self.assertEqual(exit_code, 1)
        self.assertIn("could not be written", stderr)
        self.assertEqual(path.read_text(encoding="utf-8"), "PIHOLE_AI_OLLAMA_MODEL=old\n")

    def test_no_service_operation_is_invoked(self) -> None:
        with patch("subprocess.run") as subprocess_run:
            exit_code, _, _, _ = self.run_config(
                ["set", "ollama_model", "new", "--yes"],
                config_text="",
            )

        self.assertEqual(exit_code, 0)
        subprocess_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
