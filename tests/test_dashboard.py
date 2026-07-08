import unittest
from unittest.mock import patch

from ui.dashboard import create_app


class DashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def test_stats_endpoint_returns_database_stats(self) -> None:
        stats = {
            "events": 3,
            "processed": 2,
            "domains": 2,
            "analyses": 1,
        }

        with patch("ui.dashboard.database_stats", return_value=stats):
            response = self.client.get("/api/stats")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), stats)

    def test_events_endpoint_returns_recent_events(self) -> None:
        rows = [
            {
                "id": 1,
                "device": "device-a",
                "domain": "example.com",
                "timestamp": 123.0,
                "processed": 1,
            }
        ]

        with patch("ui.dashboard.get_events", return_value=rows):
            response = self.client.get("/api/events")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), rows)

    def test_analysis_endpoint_returns_recent_analyses(self) -> None:
        analyses = [
            {
                "domain": "example.com",
                "risk": 10,
                "category": "benign",
                "reason": "Known test domain.",
                "model": "rule-engine",
                "analyzed_at": 123.0,
            }
        ]

        with patch("ui.dashboard.get_recent_analyses", return_value=analyses):
            response = self.client.get("/api/analysis")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), analyses)

    def test_devices_endpoint_returns_device_summary(self) -> None:
        devices = [
            {
                "device": "device-a",
                "query_count": 5,
                "domain_count": 3,
                "processed_count": 4,
            }
        ]

        with patch("ui.dashboard.get_device_summary", return_value=devices):
            response = self.client.get("/api/devices")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), devices)

    def test_health_endpoint_returns_ok_status(self) -> None:
        stats = {
            "events": 0,
            "processed": 0,
            "domains": 0,
            "analyses": 0,
        }

        with patch("ui.dashboard.database_stats", return_value=stats):
            response = self.client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "status": "ok",
                "database": stats,
            },
        )

    def test_home_endpoint_serves_dashboard(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PiHole-AI", response.data)


if __name__ == "__main__":
    unittest.main()
