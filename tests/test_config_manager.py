import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.config_manager import ConfigurationManager
from core.config_manager import EnvDocument
from core.config_manager import changed_key_impact
from core.config_manager import mask_value
from core.config_manager import write_env_file_atomic
from core.config_schema import CONFIG_SCHEMA
from core.config_schema import ConfigItem
from core.config_schema import ConfigValueType
from core.config_schema import DASHBOARD_SERVICE
from core.config_schema import ENGINE_SERVICE
from core.config_schema import RestartImpact
from core.config_schema import get_item
from core.config_schema import validate_schema
from core.config_validation import validate_boolean
from core.config_validation import validate_enum
from core.config_validation import validate_float
from core.config_validation import validate_hostname_or_ip
from core.config_validation import validate_integer
from core.config_validation import validate_numeric_range
from core.config_validation import validate_ollama_model
from core.config_validation import validate_path
from core.config_validation import validate_port
from core.config_validation import validate_url


class ConfigSchemaTests(unittest.TestCase):
    def test_schema_has_unique_keys_and_environment_names(self) -> None:
        validate_schema()

        keys = {item.key for item in CONFIG_SCHEMA}
        self.assertIn("events_db", keys)
        self.assertIn("dashboard_secret_key", keys)

    def test_duplicate_schema_key_is_rejected(self) -> None:
        item = get_item("events_db")

        with self.assertRaisesRegex(ValueError, "Duplicate configuration key"):
            validate_schema((item, item))

    def test_duplicate_schema_environment_name_is_rejected(self) -> None:
        first = get_item("events_db")
        duplicate = ConfigItem(
            key="different",
            env_names=(first.env_var,),
            default="x",
            value_type=ConfigValueType.STRING,
            description="duplicate env",
            category="test",
            validator=first.validator,
            restart_impact=RestartImpact.NONE,
            sensitivity=first.sensitivity,
            export_policy=first.export_policy,
        )

        with self.assertRaisesRegex(ValueError, "Duplicate configuration environment name"):
            validate_schema((first, duplicate))

    def test_restart_impact_is_deterministic_and_deduplicated(self) -> None:
        self.assertEqual(
            changed_key_impact(["ollama_url", "dashboard_port", "ollama_model"]),
            {
                "restart_required": True,
                "services": [ENGINE_SERVICE, DASHBOARD_SERVICE],
            },
        )


class ConfigValidationPrimitiveTests(unittest.TestCase):
    def test_reusable_validators_accept_supported_values(self) -> None:
        self.assertTrue(validate_boolean("x", "yes").value)
        self.assertEqual(validate_integer("x", "12").value, 12)
        self.assertEqual(validate_float("x", "1.5").value, 1.5)
        self.assertEqual(validate_port("x", "8080").value, 8080)
        self.assertEqual(validate_url("x", "https://example.com").value, "https://example.com")
        self.assertEqual(validate_hostname_or_ip("x", "127.0.0.1").value, "127.0.0.1")
        self.assertEqual(validate_path("x", "/tmp/example").value, Path("/tmp/example"))
        self.assertEqual(validate_enum("x", "INFO", allowed=("INFO", "DEBUG")).value, "INFO")
        self.assertEqual(validate_ollama_model("x", "llama3.2:1b").value, "llama3.2:1b")
        self.assertEqual(
            validate_numeric_range("x", "50", minimum=0, maximum=100).value,
            50,
        )

    def test_validation_errors_are_structured_and_do_not_include_secret_value(self) -> None:
        secret = "super-secret-token"
        result = validate_url("dashboard_secret_key", secret)

        self.assertFalse(result.is_valid)
        self.assertEqual(result.errors[0].key, "dashboard_secret_key")
        self.assertNotIn(secret, result.errors[0].message)
        self.assertNotIn(secret, result.errors[0].code)


class EnvDocumentTests(unittest.TestCase):
    def test_env_document_round_trips_comments_blanks_unknowns_and_quotes(self) -> None:
        content = (
            "# comment\n"
            "\n"
            "UNKNOWN_KEY='quoted value'\n"
            "AI_ENABLED=true\n"
        )
        document = EnvDocument.parse(content)

        self.assertEqual(document.values()["UNKNOWN_KEY"], "quoted value")
        self.assertEqual(document.to_text(), content)

    def test_env_document_updates_preserve_unknown_lines(self) -> None:
        document = EnvDocument.parse("# comment\nUNKNOWN=value\nAI_ENABLED=true\n")
        document.set("AI_ENABLED", "false")
        document.set("PIHOLE_AI_OLLAMA_MODEL", "llama3.2:1b")

        text = document.to_text()
        self.assertIn("# comment\n", text)
        self.assertIn("UNKNOWN=value\n", text)
        self.assertIn("AI_ENABLED=false\n", text)
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b\n", text)


class ConfigurationManagerTests(unittest.TestCase):
    def test_manager_preserves_current_runtime_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            appliance_env = root / "appliance.env"
            project_env = root / ".env"
            appliance_env.write_text("PIHOLE_AI_OLLAMA_MODEL=from-appliance\n", encoding="utf-8")
            project_env.write_text("PIHOLE_AI_OLLAMA_MODEL=from-project\n", encoding="utf-8")

            manager = ConfigurationManager(
                env={"PIHOLE_AI_OLLAMA_MODEL": "from-process"},
                env_files=[appliance_env, project_env],
            )

            self.assertEqual(manager.get("ollama_model"), "from-process")
            self.assertEqual(manager.source_of("ollama_model"), "environment")

    def test_manager_uses_project_env_over_appliance_env_when_no_process_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            appliance_env = root / "appliance.env"
            project_env = root / ".env"
            appliance_env.write_text("AI_ENABLED=false\n", encoding="utf-8")
            project_env.write_text("AI_ENABLED=true\n", encoding="utf-8")

            manager = ConfigurationManager(
                env={},
                env_files=[appliance_env, project_env],
            )

            self.assertTrue(manager.get("ai_enabled"))
            self.assertEqual(manager.source_of("ai_enabled"), f"env_file:{project_env}")

    def test_manager_validates_resolved_values(self) -> None:
        manager = ConfigurationManager(
            env={"PIHOLE_AI_DASHBOARD_PORT": "70000"},
            env_files=[],
        )

        result = manager.validate()

        self.assertFalse(result.is_valid)
        self.assertEqual(result.errors[0].key, "dashboard_port")

    def test_export_excludes_secrets_by_default_and_can_include_secure_values(self) -> None:
        manager = ConfigurationManager(
            env={
                "PIHOLE_AI_DASHBOARD_PASSWORD_HASH": "scrypt:secret",
                "PIHOLE_AI_DASHBOARD_SECRET_KEY": "secret-key",
                "PIHOLE_AI_OLLAMA_MODEL": "llama3.2:1b",
            },
            env_files=[],
        )

        normal = manager.export()
        secure = manager.export(include_secrets=True)

        self.assertEqual(normal["schema_version"], 1)
        self.assertIn("ollama_model", normal["settings"])
        self.assertNotIn("dashboard_password_hash", normal["settings"])
        self.assertEqual(
            secure["settings"]["dashboard_password_hash"],
            "scrypt:secret",
        )

    def test_masking_distinguishes_unset_configured_sensitive_and_secret(self) -> None:
        self.assertEqual(
            mask_value("dashboard_secret_key", None),
            {"configured": False, "masked": False, "value": None},
        )
        self.assertEqual(
            mask_value("dashboard_secret_key", "abcdef"),
            {"configured": True, "masked": True, "value": None},
        )
        self.assertEqual(
            mask_value("dashboard_username", "administrator"),
            {"configured": True, "masked": True, "value": "adm****tor"},
        )
        self.assertEqual(
            mask_value("ollama_model", "llama3.2:1b"),
            {"configured": True, "masked": False, "value": "llama3.2:1b"},
        )

    def test_atomic_write_creates_backup_and_preserves_unknown_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pihole-ai.env"
            path.write_text("# existing\nUNKNOWN=value\nAI_ENABLED=true\n", encoding="utf-8")

            backup = write_env_file_atomic(
                path,
                {
                    "AI_ENABLED": "false",
                    "PIHOLE_AI_OLLAMA_MODEL": "llama3.2:1b",
                },
            )

            self.assertIsNotNone(backup)
            self.assertTrue(backup.exists())
            text = path.read_text(encoding="utf-8")
            self.assertIn("# existing\n", text)
            self.assertIn("UNKNOWN=value\n", text)
            self.assertIn("AI_ENABLED=false\n", text)
            self.assertIn("PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b\n", text)

    def test_atomic_write_cleans_temporary_file_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pihole-ai.env"
            path.write_text("AI_ENABLED=true\n", encoding="utf-8")

            with patch("core.config_manager.os.replace", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    write_env_file_atomic(path, {"AI_ENABLED": "false"})

            leftovers = [
                item
                for item in Path(tmpdir).iterdir()
                if item.name.startswith(".pihole-ai.env.")
            ]
            self.assertEqual(leftovers, [])
            self.assertEqual(path.read_text(encoding="utf-8"), "AI_ENABLED=true\n")


if __name__ == "__main__":
    unittest.main()
