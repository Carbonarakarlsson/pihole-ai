import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pihole_ai import cli


class ConfigCLIMigrateTests(unittest.TestCase):
    def run_config(
        self,
        argv: list[str],
        *,
        config_text: str,
        stdin: io.StringIO | None = None,
    ):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "pihole-ai.env"
        path.write_text(config_text, encoding="utf-8")
        stream = stdin or io.StringIO()
        with patch("sys.stdout", io.StringIO()) as stdout, \
             patch("sys.stderr", io.StringIO()) as stderr, \
             patch("sys.stdin", stream), \
             patch("pihole_ai.config_cli.service_control.restart_services") as restart:
            exit_code = cli.main(["config", "migrate", *argv, "--config-file", str(path)])
        return exit_code, stdout.getvalue(), stderr.getvalue(), path, restart

    def test_dry_run_human_preview_does_not_write_or_backup(self) -> None:
        exit_code, stdout, stderr, path, restart = self.run_config(
            ["--dry-run"],
            config_text="OLLAMA_MODEL=llama3.2:1b\n",
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Configuration migration preview", stdout)
        self.assertIn("legacy / unversioned", stdout)
        self.assertIn("config-v0-to-v1", stdout)
        self.assertIn("OLLAMA_MODEL -> PIHOLE_AI_OLLAMA_MODEL", stdout)
        self.assertIn("Would write configuration: yes", stdout)
        self.assertIn("Would restart services: no", stdout)
        self.assertEqual(path.read_text(encoding="utf-8"), "OLLAMA_MODEL=llama3.2:1b\n")
        self.assertFalse(list(path.parent.glob("*.bak*")))
        restart.assert_not_called()

    def test_json_dry_run_is_secret_safe(self) -> None:
        secret = "secret-value-that-must-not-print"
        exit_code, stdout, _, _, _ = self.run_config(
            ["--dry-run", "--json"],
            config_text=f"OLLAMA_MODEL=llama3.2:1b\nPIHOLE_AI_DASHBOARD_SECRET_KEY={secret}\n",
        )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["source_version"], 0)
        self.assertEqual(payload["target_version"], 1)
        self.assertTrue(payload["changed"])
        self.assertFalse(payload["written"])
        self.assertNotIn(secret, stdout)

    def test_yes_writes_and_creates_migration_backup(self) -> None:
        exit_code, stdout, _, path, restart = self.run_config(
            ["--yes"],
            config_text="OLLAMA_MODEL=llama3.2:1b\n",
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("Configuration migration completed successfully.", stdout)
        self.assertIn("Backup:", stdout)
        self.assertIn("PIHOLE_AI_CONFIG_SCHEMA_VERSION=1", path.read_text(encoding="utf-8"))
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b", path.read_text(encoding="utf-8"))
        self.assertTrue(list(path.parent.glob("pihole-ai.env.migration-v0-to-v1.bak*")))
        restart.assert_not_called()

    def test_confirmation_declined_leaves_file_unchanged(self) -> None:
        stdin = io.StringIO("n\n")
        stdin.isatty = lambda: True
        exit_code, stdout, _, path, _ = self.run_config(
            [],
            config_text="OLLAMA_MODEL=llama3.2:1b\n",
            stdin=stdin,
        )

        self.assertEqual(exit_code, 1)
        self.assertIn("Migration cancelled by user.", stdout)
        self.assertEqual(path.read_text(encoding="utf-8"), "OLLAMA_MODEL=llama3.2:1b\n")
        self.assertFalse(list(path.parent.glob("*.bak*")))

    def test_json_real_write_requires_yes_or_dry_run(self) -> None:
        exit_code, _, stderr, path, _ = self.run_config(
            ["--json"],
            config_text="OLLAMA_MODEL=llama3.2:1b\n",
        )

        self.assertEqual(exit_code, 2)
        self.assertIn("requires --dry-run or --yes", stderr)
        self.assertEqual(path.read_text(encoding="utf-8"), "OLLAMA_MODEL=llama3.2:1b\n")

    def test_current_version_is_successful_noop(self) -> None:
        exit_code, stdout, _, path, _ = self.run_config(
            ["--yes"],
            config_text="PIHOLE_AI_CONFIG_SCHEMA_VERSION=1\nPIHOLE_AI_OLLAMA_MODEL=model\n",
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("No configuration migration is required.", stdout)
        self.assertFalse(list(path.parent.glob("*.bak*")))

    def test_target_version_validation_future_and_downgrade(self) -> None:
        exit_code, _, stderr, _, _ = self.run_config(
            ["--dry-run", "--target-version", "banana"],
            config_text="OLLAMA_MODEL=model\n",
        )
        self.assertEqual(exit_code, 2)
        self.assertIn("Target version must be an integer", stderr)

        exit_code, stdout, _, _, _ = self.run_config(
            ["--dry-run", "--target-version", "2", "--json"],
            config_text="OLLAMA_MODEL=model\n",
        )
        self.assertEqual(exit_code, 2)
        self.assertEqual(json.loads(stdout)["error"]["code"], "config.migration.unsupported_target")

        exit_code, stdout, _, _, _ = self.run_config(
            ["--dry-run", "--target-version", "0", "--json"],
            config_text="PIHOLE_AI_CONFIG_SCHEMA_VERSION=1\n",
        )
        self.assertEqual(exit_code, 2)
        self.assertEqual(json.loads(stdout)["error"]["code"], "config.migration.downgrade_rejected")

    def test_conflict_and_invalid_value_are_rejected_without_values(self) -> None:
        exit_code, stdout, _, path, _ = self.run_config(
            ["--dry-run", "--json"],
            config_text="OLLAMA_MODEL=secret-a\nPIHOLE_AI_OLLAMA_MODEL=secret-b\n",
        )

        self.assertEqual(exit_code, 3)
        self.assertEqual(json.loads(stdout)["error"]["code"], "config.migration.conflict")
        self.assertNotIn("secret-a", stdout)
        self.assertNotIn("secret-b", stdout)
        self.assertIn("OLLAMA_MODEL=secret-a", path.read_text(encoding="utf-8"))

        exit_code, stdout, _, path, _ = self.run_config(
            ["--dry-run", "--json"],
            config_text="PIHOLE_AI_DASHBOARD_PORT=bad\n",
        )
        self.assertEqual(exit_code, 3)
        self.assertEqual(json.loads(stdout)["error"]["code"], "config.migration.validation_failed")
        self.assertIn("PIHOLE_AI_DASHBOARD_PORT=bad", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
