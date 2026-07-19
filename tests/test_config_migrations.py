import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.config_migrations import ConfigMigrationError
from core.config_migrations import MigrationStep
from core.config_migrations import detect_config_version
from core.config_migrations import migrate_configuration
from core.config_migrations import plan_migrations
from core.config_migrations import validate_registry
from core.config_schema import CONFIG_SCHEMA_ENV


class ConfigMigrationTests(unittest.TestCase):
    def make_file(self, content: str | bytes | None) -> tuple[tempfile.TemporaryDirectory, Path]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "pihole-ai.env"
        if isinstance(content, bytes):
            path.write_bytes(content)
        elif content is not None:
            path.write_text(content, encoding="utf-8")
        return tmp, path

    def test_detects_missing_empty_legacy_current_and_future_versions(self) -> None:
        _, missing = self.make_file(None)
        self.assertEqual(detect_config_version(missing).label, "missing")

        _, empty = self.make_file("")
        empty_state = detect_config_version(empty)
        self.assertEqual(empty_state.version, 0)
        self.assertTrue(empty_state.empty)

        _, legacy = self.make_file("OLLAMA_MODEL=llama3.2:1b\n")
        legacy_state = detect_config_version(legacy)
        self.assertEqual(legacy_state.version, 0)
        self.assertEqual(legacy_state.label, "legacy / unversioned")

        _, current = self.make_file(f"{CONFIG_SCHEMA_ENV}=1\nPIHOLE_AI_OLLAMA_MODEL=model\n")
        self.assertEqual(detect_config_version(current).version, 1)

        _, future = self.make_file(f"{CONFIG_SCHEMA_ENV}=3\n")
        with self.assertRaisesRegex(ConfigMigrationError, "supports up to version 1"):
            detect_config_version(future)

    def test_detects_malformed_duplicate_and_invalid_encoding(self) -> None:
        _, malformed = self.make_file(f"{CONFIG_SCHEMA_ENV}=banana\n")
        with self.assertRaisesRegex(ConfigMigrationError, "Malformed"):
            detect_config_version(malformed)

        _, duplicate = self.make_file(f"{CONFIG_SCHEMA_ENV}=1\n{CONFIG_SCHEMA_ENV}=1\n")
        with self.assertRaisesRegex(ConfigMigrationError, "Duplicate"):
            detect_config_version(duplicate)

        _, invalid = self.make_file(b"\xff\xfe\x00")
        with self.assertRaisesRegex(ConfigMigrationError, "UTF-8"):
            detect_config_version(invalid)

    def test_registry_plans_direct_chain_noop_missing_and_rejects_bad_paths(self) -> None:
        direct = plan_migrations(0, 1)
        self.assertEqual([step.migration_id for step in direct.steps], ["config-v0-to-v1"])

        noop = plan_migrations(1, 1)
        self.assertFalse(noop.changed)
        self.assertEqual(noop.steps, [])

        missing = plan_migrations(None, 1)
        self.assertFalse(missing.changed)

        with self.assertRaisesRegex(ConfigMigrationError, "Target schema version 2"):
            plan_migrations(0, 2)
        with self.assertRaisesRegex(ConfigMigrationError, "downgrades"):
            plan_migrations(1, 0)

        step = MigrationStep("dup-a", 0, 1, "one", lambda doc, plan: doc)
        duplicate = MigrationStep("dup-b", 0, 1, "two", lambda doc, plan: doc)
        with self.assertRaisesRegex(ConfigMigrationError, "Duplicate"):
            validate_registry([step, duplicate])

    def test_migration_adds_marker_canonicalizes_aliases_and_preserves_content(self) -> None:
        _, path = self.make_file(
            "# keep me\n"
            "\n"
            "OLLAMA_HOST=http://127.0.0.1:11434\n"
            "OLLAMA_MODEL=llama3.2:1b\n"
            "PIHOLE_AI_DASHBOARD_SECRET_KEY=secret-value\n"
            "UNKNOWN=value\n"
        )

        result = migrate_configuration(path, dry_run=True)

        self.assertTrue(result.plan.changed)
        self.assertFalse(result.written)
        self.assertEqual(
            result.plan.renamed_keys,
            [
                {"from": "OLLAMA_HOST", "to": "PIHOLE_AI_OLLAMA_URL"},
                {"from": "OLLAMA_MODEL", "to": "PIHOLE_AI_OLLAMA_MODEL"},
            ],
        )
        written = migrate_configuration(path)
        self.assertTrue(written.written)
        content = path.read_text(encoding="utf-8")
        self.assertIn("# keep me", content)
        self.assertIn("\n\n", content)
        self.assertIn(f"{CONFIG_SCHEMA_ENV}=1", content)
        self.assertIn("PIHOLE_AI_OLLAMA_URL=http://127.0.0.1:11434", content)
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b", content)
        self.assertIn("PIHOLE_AI_DASHBOARD_SECRET_KEY=secret-value", content)
        self.assertIn("UNKNOWN=value", content)
        self.assertTrue(Path(written.backup_path or "").exists())
        self.assertIn("OLLAMA_HOST=", Path(written.backup_path or "").read_text(encoding="utf-8"))

    def test_current_config_is_noop_and_creates_no_backup(self) -> None:
        _, path = self.make_file(f"{CONFIG_SCHEMA_ENV}=1\nPIHOLE_AI_OLLAMA_MODEL=model\n")

        result = migrate_configuration(path)

        self.assertFalse(result.plan.changed)
        self.assertFalse(result.written)
        self.assertFalse(list(path.parent.glob("*.bak*")))

    def test_alias_conflict_duplicate_alias_and_deprecated_warning_are_safe(self) -> None:
        _, conflict = self.make_file("OLLAMA_MODEL=alias\nPIHOLE_AI_OLLAMA_MODEL=canonical\n")
        with self.assertRaises(ConfigMigrationError) as raised:
            migrate_configuration(conflict, dry_run=True)
        self.assertEqual(raised.exception.code, "config.migration.conflict")
        self.assertNotIn("alias\n", json.dumps(raised.exception.details))

        _, duplicate = self.make_file("OLLAMA_MODEL=a\nOLLAMA_MODEL=b\n")
        with self.assertRaises(ConfigMigrationError):
            migrate_configuration(duplicate, dry_run=True)

        _, deprecated = self.make_file("PIHOLE_AI_OLD_OPTION=value\n")
        result = migrate_configuration(deprecated, dry_run=True)
        self.assertIn("preserved unchanged", result.plan.warnings[0])
        self.assertNotIn("value", json.dumps(result.to_dict()))

    def test_invalid_known_value_blocks_without_writing(self) -> None:
        _, path = self.make_file("PIHOLE_AI_DASHBOARD_PORT=banana\n")
        original = path.read_text(encoding="utf-8")

        with self.assertRaises(ConfigMigrationError) as raised:
            migrate_configuration(path)

        self.assertEqual(raised.exception.code, "config.migration.validation_failed")
        self.assertEqual(path.read_text(encoding="utf-8"), original)
        self.assertFalse(list(path.parent.glob("*.bak*")))

    def test_write_failure_keeps_original_and_temp_files_are_cleaned(self) -> None:
        _, path = self.make_file("OLLAMA_MODEL=model\n")
        original = path.read_text(encoding="utf-8")

        with patch("core.config_migrations.os.replace", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                migrate_configuration(path)

        self.assertEqual(path.read_text(encoding="utf-8"), original)
        self.assertFalse(list(path.parent.glob(f".{path.name}.*")))

    def test_backup_name_is_collision_safe(self) -> None:
        _, path = self.make_file("OLLAMA_MODEL=model\n")
        existing = path.with_name("pihole-ai.env.migration-v0-to-v1.bak")
        existing.write_text("existing\n", encoding="utf-8")

        result = migrate_configuration(path)

        self.assertTrue(str(result.backup_path).endswith(".bak.1"))
        self.assertEqual(existing.read_text(encoding="utf-8"), "existing\n")


if __name__ == "__main__":
    unittest.main()
