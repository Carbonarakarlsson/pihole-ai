import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.config_schema import CONFIG_SCHEMA_ENV
from pihole_ai import status


class StatusTests(unittest.TestCase):
    def test_collect_status_without_ollama(self) -> None:
        with patch(
            "pihole_ai.status.database_stats",
            return_value={
                "events": 1,
                "processed": 1,
                "domains": 1,
                "analyses": 1,
            },
        ), patch(
            "pihole_ai.status.ai_metrics",
            return_value={
                "ai_calls": 2,
                "ai_skipped": 1,
                "ai_parse_errors": 0,
                "ai_timeouts": 0,
                "calls": 2,
                "rate_limit_skips": 1,
                "disabled_skips": 0,
                "cooldown_skips": 0,
                "parse_errors": 0,
                "timeouts": 0,
                "slow_responses": 0,
                "cooldown_until": 0,
            },
        ), patch(
            "pihole_ai.status.get_state",
            return_value="42",
        ):
            result = status.collect_status(
                include_ollama=False,
            )

        self.assertEqual(
            result["database"],
            {
                "events": 1,
                "processed": 1,
                "domains": 1,
                "analyses": 1,
            },
        )
        self.assertEqual(
            result["collector"]["last_query_id"],
            "42",
        )
        self.assertEqual(result["ai"]["ai_calls"], 2)
        self.assertEqual(result["ai"]["ai_skipped"], 1)
        self.assertIn("configuration", result["config"])
        self.assertNotIn("ollama", result)

    def test_configuration_status_reports_current_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "pihole-ai.env"
            config_file.write_text(
                f"{CONFIG_SCHEMA_ENV}=1\nPIHOLE_AI_DASHBOARD_PORT=8080\n",
                encoding="utf-8",
            )

            result = status.configuration_status(str(config_file))

        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["schema_status"], "current")
        self.assertFalse(result["migration_required"])

    def test_configuration_status_reports_migration_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "pihole-ai.env"
            config_file.write_text("PIHOLE_AI_DASHBOARD_PORT=8080\n", encoding="utf-8")

            result = status.configuration_status(str(config_file))

        self.assertEqual(result["schema_status"], "legacy")
        self.assertTrue(result["migration_required"])
        self.assertEqual(result["last_validation_status"], "migration_required")

    def test_get_ollama_health_handles_import_or_client_failure(self) -> None:
        with patch.dict(
            "sys.modules",
            {
                "engine.ollama_client": None,
            },
        ):
            result = status.get_ollama_health()

        self.assertFalse(result["available"])
        self.assertIn("error", result)
        self.assertIn("host", result)
        self.assertIn("model", result)

    def test_print_status_outputs_summary(self) -> None:
        with patch(
            "pihole_ai.status.collect_status",
            return_value={
                "database": {
                    "events": 1,
                    "processed": 1,
                    "domains": 1,
                    "analyses": 1,
                },
                "collector": {
                    "last_query_id": "42",
                },
                "ai": {
                    "ai_calls": 2,
                    "ai_skipped": 1,
                    "ai_parse_errors": 0,
                    "ai_timeouts": 0,
                    "calls": 2,
                    "rate_limit_skips": 1,
                    "disabled_skips": 0,
                    "cooldown_skips": 0,
                    "parse_errors": 0,
                    "timeouts": 0,
                    "slow_responses": 0,
                    "cooldown_until": 0,
                },
                "config": {
                    "events_db": "events.db",
                    "pihole_db": "pihole-FTL.db",
                    "config_file": "/etc/pihole-ai/pihole-ai.env",
                    "configuration": {
                        "config_file": "/etc/pihole-ai/pihole-ai.env",
                        "schema_version": 1,
                        "schema_status": "current",
                        "valid": True,
                        "migration_required": False,
                        "last_validation_status": "valid",
                        "warnings": [],
                        "errors": [],
                    },
                    "ollama_url": "http://127.0.0.1:11434",
                    "ollama_model": "llama3.2:1b",
                    "ai_enabled": True,
                    "ai_max_calls_per_minute": 2,
                    "ai_cooldown_seconds": 60,
                    "ai_timeout_seconds": 20,
                    "dashboard_port": 8080,
                    "cache_ttl": 86400,
                },
            },
        ), patch(
            "sys.stdout",
            io.StringIO(),
        ) as stdout:
            status.print_status(
                include_ollama=False,
            )

        output = stdout.getvalue()

        self.assertIn("PiHole-AI status", output)
        self.assertIn("Configuration:", output)
        self.assertIn("schema_status: current", output)
        self.assertIn("events: 1", output)
        self.assertIn("ai_skipped: 1", output)
        self.assertIn("collector.last_query_id: 42", output)


if __name__ == "__main__":
    unittest.main()
