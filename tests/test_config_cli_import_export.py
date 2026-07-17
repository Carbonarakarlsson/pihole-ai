import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pihole_ai import cli


class ConfigCLIImportExportTests(unittest.TestCase):
    def make_paths(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        config_file = root / "pihole-ai.env"
        project_root = root / "project"
        project_root.mkdir()
        return root, config_file, project_root

    def run_config(
        self,
        argv: list[str],
        *,
        config_file: Path | None = None,
        project_root: Path | None = None,
        env: dict[str, str] | None = None,
        stdin: io.StringIO | None = None,
    ):
        stream = stdin or io.StringIO()
        default_config = config_file or (project_root or Path("/tmp")) / "pihole-ai.env"
        with patch("core.config_manager.runtime_config.PROJECT_ROOT", project_root or Path("/tmp/no-project")), \
             patch("pihole_ai.config_cli.runtime_config.PROJECT_ROOT", project_root or Path("/tmp/no-project")), \
             patch("core.config_manager.runtime_config.CONFIG_FILE", default_config), \
             patch("pihole_ai.config_cli.runtime_config.CONFIG_FILE", default_config), \
             patch.dict(os.environ, env or {}, clear=True), \
             patch("sys.stdout", io.StringIO()) as stdout, \
             patch("sys.stderr", io.StringIO()) as stderr, \
             patch("sys.stdin", stream):
            full_argv = ["config", *argv]
            if config_file is not None and argv[0] == "import":
                full_argv.extend(["--config-file", str(config_file)])
            exit_code = cli.main(full_argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_export_json_stdout_masks_sensitive_and_has_metadata(self) -> None:
        root, _, project_root = self.make_paths()
        output = root / "unused"
        exit_code, stdout, stderr = self.run_config(
            ["export"],
            project_root=project_root,
            env={
                "PIHOLE_AI_OLLAMA_URL": "http://127.0.0.1:11434",
                "PIHOLE_AI_DASHBOARD_SECRET_KEY": "x" * 48,
            },
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["schema_version"], 1)
        self.assertIn("pihole_ai_version", payload)
        self.assertFalse(payload["secure"])
        keys = [setting["key"] for setting in payload["settings"]]
        self.assertEqual(keys, sorted(keys, key=keys.index))
        self.assertNotIn("dashboard_secret_key", keys)
        ollama = next(item for item in payload["settings"] if item["key"] == "ollama_url")
        self.assertTrue(ollama["masked"])

    def test_export_env_stdout_uses_canonical_environment_names(self) -> None:
        _, _, project_root = self.make_paths()
        exit_code, stdout, _ = self.run_config(
            ["export", "--format", "env"],
            project_root=project_root,
            env={"OLLAMA_MODEL": "alias-model"},
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("# Generated PiHole-AI configuration export", stdout)
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=alias-model", stdout)
        self.assertNotIn("OLLAMA_MODEL=alias-model", stdout.splitlines())

    def test_export_output_file_and_secure_export_include_secrets(self) -> None:
        root, _, project_root = self.make_paths()
        output = root / "backup.json"
        secret = "x" * 48

        exit_code, stdout, stderr = self.run_config(
            ["export", "--secure", "--output", str(output)],
            project_root=project_root,
            env={"PIHOLE_AI_DASHBOARD_SECRET_KEY": secret},
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout, "")
        self.assertIn("secure configuration export", stderr)
        payload = json.loads(output.read_text(encoding="utf-8"))
        secret_row = next(item for item in payload["settings"] if item["key"] == "dashboard_secret_key")
        self.assertEqual(secret_row["value"], secret)

    def test_import_json_dry_run_reports_restart_impact_without_writing(self) -> None:
        root, config_file, project_root = self.make_paths()
        config_file.write_text("PIHOLE_AI_OLLAMA_MODEL=old\n", encoding="utf-8")
        import_file = root / "config.json"
        import_file.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "settings": [
                        {"key": "OLLAMA_MODEL", "value": "new-model"},
                    ],
                }
            ),
            encoding="utf-8",
        )

        exit_code, stdout, _ = self.run_config(
            ["import", str(import_file), "--dry-run", "--json"],
            config_file=config_file,
            project_root=project_root,
        )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout)
        self.assertTrue(payload["changed"])
        self.assertFalse(payload["written"])
        self.assertEqual(payload["affected_services"], ["pihole-ai-engine.service"])
        self.assertEqual(config_file.read_text(encoding="utf-8"), "PIHOLE_AI_OLLAMA_MODEL=old\n")
        self.assertFalse(config_file.with_suffix(".env.bak").exists())

    def test_import_json_yes_writes_and_creates_backup(self) -> None:
        root, config_file, project_root = self.make_paths()
        config_file.write_text("# keep\nPIHOLE_AI_OLLAMA_MODEL=old\n", encoding="utf-8")
        import_file = root / "config.json"
        import_file.write_text(
            json.dumps({"schema_version": 1, "settings": {"ollama_model": "new"}}),
            encoding="utf-8",
        )

        exit_code, stdout, _ = self.run_config(
            ["import", str(import_file), "--yes"],
            config_file=config_file,
            project_root=project_root,
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("Configuration import written.", stdout)
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=new", config_file.read_text(encoding="utf-8"))
        self.assertEqual(
            config_file.with_suffix(".env.bak").read_text(encoding="utf-8"),
            "# keep\nPIHOLE_AI_OLLAMA_MODEL=old\n",
        )

    def test_import_env_resolves_aliases_and_preserves_unknown_target_lines(self) -> None:
        root, config_file, project_root = self.make_paths()
        config_file.write_text("# keep\nUNKNOWN_TARGET=value\n", encoding="utf-8")
        import_file = root / "config.env"
        import_file.write_text("OLLAMA_MODEL=from-env\n", encoding="utf-8")

        exit_code, _, _ = self.run_config(
            ["import", str(import_file), "--yes"],
            config_file=config_file,
            project_root=project_root,
        )

        self.assertEqual(exit_code, 0)
        content = config_file.read_text(encoding="utf-8")
        self.assertIn("# keep", content)
        self.assertIn("UNKNOWN_TARGET=value", content)
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=from-env", content)

    def test_import_unknown_key_warns_by_default_and_strict_rejects(self) -> None:
        root, config_file, project_root = self.make_paths()
        config_file.write_text("", encoding="utf-8")
        import_file = root / "config.env"
        import_file.write_text("UNKNOWN_IMPORT=value\nPIHOLE_AI_OLLAMA_MODEL=model\n", encoding="utf-8")

        exit_code, stdout, _ = self.run_config(
            ["import", str(import_file), "--dry-run", "--json"],
            config_file=config_file,
            project_root=project_root,
        )
        self.assertEqual(exit_code, 0)
        self.assertIn("Unknown import setting ignored", json.loads(stdout)["warnings"][0])

        exit_code, _, stderr = self.run_config(
            ["import", str(import_file), "--strict", "--dry-run"],
            config_file=config_file,
            project_root=project_root,
        )
        self.assertEqual(exit_code, 2)
        self.assertIn("Unknown import setting", stderr)

    def test_import_rejects_schema_mismatch_and_malformed_inputs(self) -> None:
        root, config_file, project_root = self.make_paths()
        config_file.write_text("", encoding="utf-8")
        newer = root / "newer.json"
        newer.write_text(json.dumps({"schema_version": 999, "settings": []}), encoding="utf-8")
        bad_json = root / "bad.json"
        bad_json.write_text("{", encoding="utf-8")
        bad_env = root / "bad.env"
        bad_env.write_text("not-an-env-line\n", encoding="utf-8")

        exit_code, _, stderr = self.run_config(["import", str(newer), "--dry-run"], config_file=config_file, project_root=project_root)
        self.assertEqual(exit_code, 3)
        self.assertIn("Unsupported schema version", stderr)
        exit_code, _, stderr = self.run_config(["import", str(bad_json), "--dry-run"], config_file=config_file, project_root=project_root)
        self.assertEqual(exit_code, 3)
        self.assertIn("Malformed JSON", stderr)
        exit_code, _, stderr = self.run_config(["import", str(bad_env), "--dry-run"], config_file=config_file, project_root=project_root)
        self.assertEqual(exit_code, 3)
        self.assertIn("Malformed ENV", stderr)

    def test_import_duplicate_keys_and_rollback_on_write_failure(self) -> None:
        root, config_file, project_root = self.make_paths()
        original = "PIHOLE_AI_OLLAMA_MODEL=old\n"
        config_file.write_text(original, encoding="utf-8")
        duplicate = root / "duplicate.env"
        duplicate.write_text("PIHOLE_AI_OLLAMA_MODEL=a\nPIHOLE_AI_OLLAMA_MODEL=b\n", encoding="utf-8")
        exit_code, _, stderr = self.run_config(["import", str(duplicate), "--dry-run"], config_file=config_file, project_root=project_root)
        self.assertEqual(exit_code, 3)
        self.assertIn("Duplicate ENV import key", stderr)

        import_file = root / "config.env"
        import_file.write_text("PIHOLE_AI_OLLAMA_MODEL=new\n", encoding="utf-8")
        with patch("core.config_manager.os.replace", side_effect=OSError("boom")):
            exit_code, _, stderr = self.run_config(["import", str(import_file), "--yes"], config_file=config_file, project_root=project_root)
        self.assertEqual(exit_code, 1)
        self.assertIn("could not be written", stderr)
        self.assertEqual(config_file.read_text(encoding="utf-8"), original)

    def test_export_import_round_trip_is_semantic_noop(self) -> None:
        root, config_file, project_root = self.make_paths()
        config_file.write_text("PIHOLE_AI_OLLAMA_MODEL=roundtrip\n", encoding="utf-8")
        export_file = root / "backup.json"

        exit_code, _, _ = self.run_config(
            ["export", "--output", str(export_file)],
            project_root=project_root,
            env={"PIHOLE_AI_OLLAMA_MODEL": "roundtrip"},
        )
        self.assertEqual(exit_code, 0)
        exit_code, stdout, _ = self.run_config(
            ["import", str(export_file), "--dry-run", "--json"],
            config_file=config_file,
            project_root=project_root,
        )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout)
        self.assertFalse(payload["written"])

    def test_import_does_not_call_services(self) -> None:
        root, config_file, project_root = self.make_paths()
        config_file.write_text("", encoding="utf-8")
        import_file = root / "config.env"
        import_file.write_text("PIHOLE_AI_OLLAMA_MODEL=new\n", encoding="utf-8")
        with patch("subprocess.run") as subprocess_run:
            exit_code, _, _ = self.run_config(
                ["import", str(import_file), "--yes"],
                config_file=config_file,
                project_root=project_root,
            )

        self.assertEqual(exit_code, 0)
        subprocess_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
