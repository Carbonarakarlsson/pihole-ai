import unittest
from unittest.mock import patch

from core.maintenance import (
    MaintenanceResult,
    run_maintenance,
)


class DummyLogger:
    def info(self, *args, **kwargs):
        pass


class MaintenanceTests(unittest.TestCase):
    def test_run_maintenance_cleans_events_without_vacuum(self) -> None:
        with patch(
            "core.maintenance.logger",
            DummyLogger(),
        ), patch(
            "core.maintenance.database_stats",
            side_effect=[
                {
                    "events": 10,
                    "processed": 8,
                    "domains": 3,
                    "analyses": 2,
                },
                {
                    "events": 5,
                    "processed": 4,
                    "domains": 3,
                    "analyses": 2,
                },
            ],
        ), patch(
            "core.maintenance.cleanup_old_events",
            return_value=5,
        ) as cleanup_old_events, patch(
            "core.maintenance.vacuum",
        ) as vacuum:

            result = run_maintenance(
                keep_latest=5,
                vacuum_db=False,
            )

        self.assertEqual(
            result,
            MaintenanceResult(
                deleted_events=5,
                before={
                    "events": 10,
                    "processed": 8,
                    "domains": 3,
                    "analyses": 2,
                },
                after={
                    "events": 5,
                    "processed": 4,
                    "domains": 3,
                    "analyses": 2,
                },
                vacuumed=False,
            ),
        )
        cleanup_old_events.assert_called_once_with(
            keep_latest=5,
        )
        vacuum.assert_not_called()

    def test_run_maintenance_can_vacuum(self) -> None:
        with patch(
            "core.maintenance.logger",
            DummyLogger(),
        ), patch(
            "core.maintenance.database_stats",
            side_effect=[
                {
                    "events": 1,
                    "processed": 1,
                    "domains": 1,
                    "analyses": 1,
                },
                {
                    "events": 1,
                    "processed": 1,
                    "domains": 1,
                    "analyses": 1,
                },
            ],
        ), patch(
            "core.maintenance.cleanup_old_events",
            return_value=0,
        ), patch(
            "core.maintenance.vacuum",
        ) as vacuum:

            result = run_maintenance(
                keep_latest=100,
                vacuum_db=True,
            )

        self.assertTrue(result.vacuumed)
        vacuum.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
