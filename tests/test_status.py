import io
import unittest
from unittest.mock import patch

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
        self.assertNotIn("ollama", result)

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
                "config": {
                    "events_db": "events.db",
                    "pihole_db": "pihole-FTL.db",
                    "ollama_url": "http://127.0.0.1:11434",
                    "ollama_model": "llama3.2:1b",
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
        self.assertIn("events: 1", output)
        self.assertIn("collector.last_query_id: 42", output)


if __name__ == "__main__":
    unittest.main()
