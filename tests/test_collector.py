import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from collector import scan


class DummyLogger:
    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass


class CollectorStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logger_patch = patch.object(scan, "LOGGER", DummyLogger())
        self.logger_patch.start()

    def tearDown(self) -> None:
        self.logger_patch.stop()

    def test_load_last_query_id_defaults_to_zero(self) -> None:
        with patch.object(scan, "get_state", return_value=None):
            self.assertEqual(scan.load_last_query_id(), 0)

    def test_load_last_query_id_parses_persisted_value(self) -> None:
        with patch.object(scan, "get_state", return_value="42"):
            self.assertEqual(scan.load_last_query_id(), 42)

    def test_load_last_query_id_handles_invalid_value(self) -> None:
        with patch.object(scan, "get_state", return_value="nope"):
            self.assertEqual(scan.load_last_query_id(), 0)

    def test_save_last_query_id_persists_string_value(self) -> None:
        with patch.object(scan, "set_state") as set_state:
            scan.save_last_query_id(99)

        set_state.assert_called_once_with(
            scan.LAST_QUERY_ID_KEY,
            "99",
        )


class CollectorFetchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logger_patch = patch.object(scan, "LOGGER", DummyLogger())
        self.logger_patch.start()

    def tearDown(self) -> None:
        self.logger_patch.stop()

    def test_fetch_reads_queries_after_last_id_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "pihole-FTL.db"

            with closing(sqlite3.connect(db_path)) as conn:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE queries (
                            id INTEGER PRIMARY KEY,
                            domain TEXT NOT NULL,
                            client TEXT
                        )
                        """
                    )
                    conn.executemany(
                        """
                        INSERT INTO queries (id, domain, client)
                        VALUES (?, ?, ?)
                        """,
                        [
                            (1, "old.example", "device-a"),
                            (2, "first.example", "device-b"),
                            (3, "second.example", "device-c"),
                        ],
                    )

            fake_settings = SimpleNamespace(
                pihole_db=db_path,
                collect_batch_size=1,
            )

            with patch.object(scan, "settings", fake_settings):
                rows = scan.fetch(1)

            self.assertEqual(
                rows,
                [
                    (2, "first.example", "device-b"),
                ],
            )


class CollectorBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logger_patch = patch.object(scan, "LOGGER", DummyLogger())
        self.logger_patch.start()

    def tearDown(self) -> None:
        self.logger_patch.stop()

    def test_process_batch_returns_existing_id_when_no_rows(self) -> None:
        with patch.object(scan, "fetch", return_value=[]), \
             patch.object(scan, "insert_event") as insert_event, \
             patch.object(scan, "save_last_query_id") as save_last_query_id:

            result = scan.process_batch(10)

        self.assertEqual(result, 10)
        insert_event.assert_not_called()
        save_last_query_id.assert_not_called()

    def test_process_batch_ingests_rows_and_persists_latest_id(self) -> None:
        rows = [
            (11, "one.example", "device-a"),
            (12, "two.example", None),
        ]

        with patch.object(scan, "fetch", return_value=rows), \
             patch.object(scan, "insert_event") as insert_event, \
             patch.object(scan, "save_last_query_id") as save_last_query_id, \
             patch.object(scan.time, "time", return_value=123.45):

            result = scan.process_batch(10)

        self.assertEqual(result, 12)
        self.assertEqual(insert_event.call_count, 2)
        insert_event.assert_any_call(
            device="device-a",
            domain="one.example",
            timestamp=123.45,
        )
        insert_event.assert_any_call(
            device="unknown",
            domain="two.example",
            timestamp=123.45,
        )
        save_last_query_id.assert_called_once_with(12)


if __name__ == "__main__":
    unittest.main()
