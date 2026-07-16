import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core import migrations
from pihole_ai import cli


class MigrationTests(unittest.TestCase):
    def test_empty_database_migrates_to_latest_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"

            result = migrations.migrate_database(database_path)

            with closing(sqlite3.connect(database_path)) as conn:
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                history = conn.execute(
                    "SELECT version, name FROM schema_migrations"
                ).fetchall()
                audit_columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info(threat_intel_update_audit)")
                }

        self.assertTrue(result.changed)
        self.assertEqual(result.version_before, 0)
        self.assertEqual(result.version_after, migrations.LATEST_SUPPORTED_SCHEMA_VERSION)
        self.assertIn("events", tables)
        self.assertIn("analysis", tables)
        self.assertIn("operation", audit_columns)
        self.assertIn("reused_generation", audit_columns)
        self.assertIn("created_generation", audit_columns)
        self.assertIn("content_unchanged", audit_columns)
        self.assertEqual(
            history,
            [(migration.version, migration.name) for migration in migrations.MIGRATIONS],
        )

    def test_repeated_migration_is_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"
            migrations.migrate_database(database_path)

            result = migrations.migrate_database(database_path)

        self.assertFalse(result.changed)
        self.assertEqual(result.version_before, migrations.LATEST_SUPPORTED_SCHEMA_VERSION)
        self.assertEqual(result.version_after, migrations.LATEST_SUPPORTED_SCHEMA_VERSION)
        self.assertEqual(result.applied_migrations, [])

    def test_existing_unversioned_baseline_is_adopted_without_data_loss(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"

            with closing(sqlite3.connect(database_path)) as conn:
                with conn:
                    for statement in migrations.BASELINE_SCHEMA_SQL:
                        conn.execute(statement)
                    conn.execute(
                        """
                        INSERT INTO events (device, domain, timestamp, processed)
                        VALUES (?, ?, ?, ?)
                        """,
                        ("device-a", "example.com", 1.0, 0),
                    )

            result = migrations.migrate_database(database_path)

            with closing(sqlite3.connect(database_path)) as conn:
                event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                migration_count = conn.execute(
                    "SELECT COUNT(*) FROM schema_migrations WHERE version = 1"
                ).fetchone()[0]

        self.assertTrue(result.changed)
        self.assertEqual(event_count, 1)
        self.assertEqual(migration_count, 1)

    def test_malformed_legacy_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"

            with closing(sqlite3.connect(database_path)) as conn:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE analysis (
                            domain TEXT PRIMARY KEY,
                            risk INTEGER
                        )
                        """
                    )

            with self.assertRaises(migrations.IncompatibleSchema):
                migrations.migrate_database(database_path)

            with closing(sqlite3.connect(database_path)) as conn:
                rows = conn.execute(
                    "SELECT COUNT(*) FROM schema_migrations"
                ).fetchone()[0]

        self.assertEqual(rows, 0)

    def test_pending_migrations_apply_in_order(self) -> None:
        order: list[str] = []

        def migration_one(conn: sqlite3.Connection) -> None:
            order.append("one")
            conn.execute("CREATE TABLE one (id INTEGER)")

        def migration_two(conn: sqlite3.Connection) -> None:
            order.append("two")
            conn.execute("CREATE TABLE two (id INTEGER)")

        fake_migrations = [
            migrations.Migration(1, "one", migration_one),
            migrations.Migration(2, "two", migration_two),
        ]

        with tempfile.TemporaryDirectory() as tmpdir, patch.object(
            migrations,
            "MIGRATIONS",
            fake_migrations,
        ), patch.object(migrations, "LATEST_SUPPORTED_SCHEMA_VERSION", 2):
            result = migrations.migrate_database(Path(tmpdir) / "events.db")

        self.assertEqual(order, ["one", "two"])
        self.assertEqual(
            [migration.version for migration in result.applied_migrations],
            [1, 2],
        )

    def test_failed_migration_rolls_back_and_stops_later_migrations(self) -> None:
        def migration_one(conn: sqlite3.Connection) -> None:
            conn.execute("CREATE TABLE one (id INTEGER)")

        def migration_two(conn: sqlite3.Connection) -> None:
            conn.execute("CREATE TABLE two (id INTEGER)")
            raise migrations.MigrationError("boom")

        def migration_three(conn: sqlite3.Connection) -> None:
            conn.execute("CREATE TABLE three (id INTEGER)")

        fake_migrations = [
            migrations.Migration(1, "one", migration_one),
            migrations.Migration(2, "two", migration_two),
            migrations.Migration(3, "three", migration_three),
        ]

        with tempfile.TemporaryDirectory() as tmpdir, patch.object(
            migrations,
            "MIGRATIONS",
            fake_migrations,
        ), patch.object(migrations, "LATEST_SUPPORTED_SCHEMA_VERSION", 3):
            database_path = Path(tmpdir) / "events.db"

            with self.assertRaises(migrations.MigrationError):
                migrations.migrate_database(database_path)

            with closing(sqlite3.connect(database_path)) as conn:
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                versions = [
                    row[0]
                    for row in conn.execute(
                        "SELECT version FROM schema_migrations ORDER BY version"
                    )
                ]

        self.assertIn("one", tables)
        self.assertNotIn("two", tables)
        self.assertNotIn("three", tables)
        self.assertEqual(versions, [1])

    def test_newer_schema_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"

            with closing(sqlite3.connect(database_path)) as conn:
                with conn:
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

            with self.assertRaises(migrations.UnsupportedSchemaVersion):
                migrations.database_status(database_path)

            with self.assertRaises(migrations.UnsupportedSchemaVersion):
                migrations.migrate_database(database_path)

    def test_status_for_missing_database_does_not_create_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "missing.db"

            status = migrations.database_status(database_path)

            self.assertFalse(database_path.exists())

        self.assertEqual(status.current_schema_version, 0)
        self.assertGreater(status.pending_migration_count, 0)


class DatabaseCLITests(unittest.TestCase):
    def test_db_status_json_reports_schema_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"
            migrations.migrate_database(database_path)
            patched_settings = SimpleNamespace(events_db=database_path)

            with patch("core.config.settings", patched_settings), patch(
                "sys.stdout",
                io.StringIO(),
            ) as stdout:
                exit_code = cli.main(["db", "status", "--json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            payload["current_schema_version"],
            migrations.LATEST_SUPPORTED_SCHEMA_VERSION,
        )
        self.assertEqual(payload["pending_migration_count"], 0)
        self.assertTrue(payload["compatible"])

    def test_db_migrate_json_applies_pending_migrations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"
            patched_settings = SimpleNamespace(events_db=database_path)

            with patch("core.config.settings", patched_settings), patch(
                "sys.stdout",
                io.StringIO(),
            ) as stdout:
                exit_code = cli.main(["db", "migrate", "--json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["changed"])
        self.assertEqual(
            payload["version_after"],
            migrations.LATEST_SUPPORTED_SCHEMA_VERSION,
        )

    def test_db_status_incompatible_schema_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"

            with closing(sqlite3.connect(database_path)) as conn:
                with conn:
                    conn.execute("CREATE TABLE analysis (domain TEXT PRIMARY KEY)")

            patched_settings = SimpleNamespace(events_db=database_path)

            with patch("core.config.settings", patched_settings), patch(
                "sys.stdout",
                io.StringIO(),
            ) as stdout:
                exit_code = cli.main(["db", "status"])

        self.assertEqual(exit_code, 2)
        self.assertIn("not compatible", stdout.getvalue())

    def test_db_status_uses_events_db_not_pihole_ftl_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            events_path = Path(tmpdir) / "events.db"
            pihole_path = Path(tmpdir) / "missing-pihole.db"
            migrations.migrate_database(events_path)
            patched_settings = SimpleNamespace(
                events_db=events_path,
                pihole_db=pihole_path,
            )

            with patch("core.config.settings", patched_settings), patch(
                "sys.stdout",
                io.StringIO(),
            ):
                exit_code = cli.main(["db", "status"])

        self.assertEqual(exit_code, 0)
        self.assertFalse(pihole_path.exists())

    def test_db_status_does_not_create_migration_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "events.db"
            with closing(sqlite3.connect(database_path)) as conn:
                conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY)")
                conn.commit()

            with self.assertRaises(migrations.IncompatibleSchema):
                migrations.database_status(database_path)

            with closing(sqlite3.connect(database_path)) as conn:
                row = conn.execute(
                    """
                    SELECT 1
                    FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'schema_migrations'
                    """
                ).fetchone()

        self.assertIsNone(row)


if __name__ == "__main__":
    unittest.main()
