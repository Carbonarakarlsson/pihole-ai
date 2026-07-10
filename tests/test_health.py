import io
import json
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.modules.setdefault(
    "ollama",
    types.SimpleNamespace(
        Client=lambda *args, **kwargs: None,
    ),
)

from core import migrations
from pihole_ai import cli
from pihole_ai.health import (
    DISK_DEGRADED_BYTES,
    DISK_UNHEALTHY_BYTES,
    HealthCheck,
    HealthReport,
    HealthStatus,
    check_disk_space,
    check_events_database,
    check_ollama,
    check_pihole_ftl_database,
    exit_code_for_status,
    report_to_dict,
    run_health_checks,
)
from ui.dashboard import create_app


class FakeSettings:
    def __init__(
        self,
        events_db: str,
        pihole_db: str,
        ollama_url: str = "http://127.0.0.1:11434",
    ) -> None:
        self.events_db = Path(events_db)
        self.pihole_db = Path(pihole_db)
        self.ollama_url = ollama_url
        self.ollama_model = "llama3.2:1b"

    def validate(self) -> None:
        return None


def health_check(
    name: str,
    status: str = HealthStatus.HEALTHY.value,
) -> HealthCheck:
    return HealthCheck(
        name=name,
        status=status,
        summary=f"{name} {status}",
        details={},
        latency_ms=1.0,
        checked_at=1.0,
    )


def health_report(
    status: str,
) -> HealthReport:
    return HealthReport(
        overall_status=status,
        checks=[
            health_check("configuration", status),
        ],
        version="0.4",
        checked_at=1.0,
    )


class HealthTests(unittest.TestCase):
    def test_all_checks_healthy(self) -> None:
        with patch("pihole_ai.health.check_configuration", return_value=health_check("configuration")), \
             patch("pihole_ai.health.check_events_database", return_value=health_check("events_database")), \
             patch("pihole_ai.health.check_pihole_ftl_database", return_value=health_check("pihole_ftl_database")), \
             patch("pihole_ai.health.check_ollama", return_value=health_check("ollama")), \
             patch("pihole_ai.health.check_collector_progress", return_value=health_check("collector_progress")), \
             patch("pihole_ai.health.check_disk_space", return_value=health_check("disk_space")):
            report = run_health_checks()

        self.assertEqual(report.overall_status, HealthStatus.HEALTHY.value)
        self.assertEqual(len(report.checks), 6)

    def test_health_report_uses_package_version_metadata(self) -> None:
        with patch("pihole_ai.health.check_configuration", return_value=health_check("configuration")), \
             patch("pihole_ai.health.check_events_database", return_value=health_check("events_database")), \
             patch("pihole_ai.health.check_pihole_ftl_database", return_value=health_check("pihole_ftl_database")), \
             patch("pihole_ai.health.check_ollama", return_value=health_check("ollama")), \
             patch("pihole_ai.health.check_collector_progress", return_value=health_check("collector_progress")), \
             patch("pihole_ai.health.check_disk_space", return_value=health_check("disk_space")), \
             patch("pihole_ai.health.get_version", return_value="9.9-test"):
            report = run_health_checks()

        self.assertEqual(report.version, "9.9-test")

    def test_ollama_unavailable_is_degraded(self) -> None:
        class FakeClient:
            def health(self):
                return {
                    "available": False,
                    "host": "http://127.0.0.1:11434",
                    "model": "llama3.2:1b",
                    "latency_ms": 1,
                }

        with patch("engine.ollama_client.OllamaClient", return_value=FakeClient()):
            check = check_ollama()

        self.assertEqual(check.status, HealthStatus.DEGRADED.value)

    def test_events_database_unavailable_is_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.health.settings",
            FakeSettings(
                events_db=str(Path(tmpdir) / "missing.db"),
                pihole_db=str(Path(tmpdir) / "pihole.db"),
            ),
        ):
            check = check_events_database()

        self.assertEqual(check.status, HealthStatus.UNHEALTHY.value)
        self.assertNotIn("error", check.details)

    def test_events_database_reports_current_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"
            migrations.migrate_database(database_path)

            with patch(
                "pihole_ai.health.settings",
                FakeSettings(
                    events_db=str(database_path),
                    pihole_db=str(Path(tmpdir) / "pihole.db"),
                ),
            ):
                check = check_events_database()

        self.assertEqual(check.status, HealthStatus.HEALTHY.value)
        self.assertEqual(check.details["current_schema_version"], 1)
        self.assertEqual(check.details["pending_migration_count"], 0)

    def test_events_database_with_pending_migration_is_degraded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"
            database_path.touch()

            with patch(
                "pihole_ai.health.settings",
                FakeSettings(
                    events_db=str(database_path),
                    pihole_db=str(Path(tmpdir) / "pihole.db"),
                ),
            ):
                check = check_events_database()

        self.assertEqual(check.status, HealthStatus.DEGRADED.value)
        self.assertGreater(check.details["pending_migration_count"], 0)

    def test_events_database_future_schema_is_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"

            with sqlite3.connect(database_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE schema_migrations (
                        version INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        applied_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO schema_migrations (version, name, applied_at)
                    VALUES (999, 'future', 'now')
                    """
                )

            with patch(
                "pihole_ai.health.settings",
                FakeSettings(
                    events_db=str(database_path),
                    pihole_db=str(Path(tmpdir) / "pihole.db"),
                ),
            ):
                check = check_events_database()

        self.assertEqual(check.status, HealthStatus.UNHEALTHY.value)
        self.assertEqual(check.details["error"], "UnsupportedSchemaVersion")

    def test_pihole_database_missing_is_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing.db"
            patched_settings = FakeSettings(
                events_db=str(Path(tmpdir) / "events.db"),
                pihole_db=str(missing),
            )

            with patch("pihole_ai.health.settings", patched_settings):
                check = check_pihole_ftl_database()

        self.assertEqual(check.status, HealthStatus.UNHEALTHY.value)

    def test_low_disk_space_is_degraded(self) -> None:
        usage = SimpleNamespace(
            total=10,
            used=9,
            free=DISK_DEGRADED_BYTES - 1,
        )

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.health.settings",
            FakeSettings(
                events_db=str(Path(tmpdir) / "events.db"),
                pihole_db=str(Path(tmpdir) / "pihole.db"),
            ),
        ), patch("pihole_ai.health.shutil.disk_usage", return_value=usage):
            check = check_disk_space()

        self.assertEqual(check.status, HealthStatus.DEGRADED.value)

    def test_critically_low_disk_space_is_unhealthy(self) -> None:
        usage = SimpleNamespace(
            total=10,
            used=9,
            free=DISK_UNHEALTHY_BYTES - 1,
        )

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.health.settings",
            FakeSettings(
                events_db=str(Path(tmpdir) / "events.db"),
                pihole_db=str(Path(tmpdir) / "pihole.db"),
            ),
        ), patch("pihole_ai.health.shutil.disk_usage", return_value=usage):
            check = check_disk_space()

        self.assertEqual(check.status, HealthStatus.UNHEALTHY.value)

    def test_one_check_exception_does_not_stop_remaining_checks(self) -> None:
        with patch("pihole_ai.health.check_configuration", side_effect=RuntimeError("boom")), \
             patch("pihole_ai.health.check_events_database", return_value=health_check("events_database")), \
             patch("pihole_ai.health.check_pihole_ftl_database", return_value=health_check("pihole_ftl_database")), \
             patch("pihole_ai.health.check_ollama", return_value=health_check("ollama")), \
             patch("pihole_ai.health.check_collector_progress", return_value=health_check("collector_progress")), \
             patch("pihole_ai.health.check_disk_space", return_value=health_check("disk_space")):
            report = run_health_checks()

        self.assertEqual(report.overall_status, HealthStatus.UNHEALTHY.value)
        self.assertEqual(len(report.checks), 6)

    def test_cli_text_output_and_exit_code(self) -> None:
        with patch(
            "pihole_ai.health.run_health_checks",
            return_value=health_report(HealthStatus.DEGRADED.value),
        ), patch("sys.stdout", io.StringIO()) as stdout:
            exit_code = cli.main(["health"])

        self.assertEqual(exit_code, 1)
        self.assertIn("PiHole-AI health: degraded", stdout.getvalue())

    def test_cli_json_output(self) -> None:
        with patch(
            "pihole_ai.health.run_health_checks",
            return_value=health_report(HealthStatus.HEALTHY.value),
        ), patch("sys.stdout", io.StringIO()) as stdout:
            exit_code = cli.main(["health", "--json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["overall_status"], HealthStatus.HEALTHY.value)

    def test_cli_exit_codes(self) -> None:
        self.assertEqual(exit_code_for_status(HealthStatus.HEALTHY.value), 0)
        self.assertEqual(exit_code_for_status(HealthStatus.DEGRADED.value), 1)
        self.assertEqual(exit_code_for_status(HealthStatus.UNHEALTHY.value), 2)
        self.assertEqual(exit_code_for_status(HealthStatus.UNKNOWN.value), 3)

    def test_dashboard_health_endpoint_status_codes(self) -> None:
        app = create_app()
        app.config.update(TESTING=True)
        client = app.test_client()

        with patch(
            "pihole_ai.health.run_health_checks",
            return_value=health_report(HealthStatus.UNHEALTHY.value),
        ):
            response = client.get("/api/health")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.get_json()["overall_status"],
            HealthStatus.UNHEALTHY.value,
        )

    def test_health_output_does_not_expose_configured_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.health.settings",
            FakeSettings(
                events_db=str(Path(tmpdir) / "events.db"),
                pihole_db=str(Path(tmpdir) / "pihole.db"),
                ollama_url="http://user:secret@example.com:11434",
            ),
        ):
            from pihole_ai.health import check_configuration

            payload = report_to_dict(
                HealthReport(
                    overall_status=HealthStatus.HEALTHY.value,
                    checks=[check_configuration()],
                    version="0.4",
                    checked_at=1.0,
                )
            )

        encoded = json.dumps(payload)
        self.assertNotIn("secret", encoded)
        self.assertIn("http://example.com:11434", encoded)


if __name__ == "__main__":
    unittest.main()
