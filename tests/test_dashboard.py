import unittest
from unittest.mock import patch

from ui.dashboard import create_app, parse_limit


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
            "actions": 0,
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

        with patch("ui.dashboard.get_recent_events", return_value=rows) as get_recent_events:
            response = self.client.get(
                "/api/events?q=example&limit=25&processed=1"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), rows)
        get_recent_events.assert_called_once_with(
            limit=25,
            search="example",
            processed=1,
        )

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

        with patch("ui.dashboard.get_recent_analyses", return_value=analyses) as get_recent_analyses:
            response = self.client.get(
                "/api/analysis?q=example&limit=50&min_risk=40&category=benign"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), analyses)
        get_recent_analyses.assert_called_once_with(
            limit=50,
            search="example",
            min_risk=40,
            category="benign",
        )

    def test_devices_endpoint_returns_device_summary(self) -> None:
        devices = [
            {
                "device": "device-a",
                "query_count": 5,
                "domain_count": 3,
                "processed_count": 4,
            }
        ]

        with patch("ui.dashboard.get_device_summary", return_value=devices) as get_device_summary:
            response = self.client.get("/api/devices?q=device-a&limit=10")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), devices)
        get_device_summary.assert_called_once_with(
            limit=10,
            search="device-a",
        )

    def test_actions_endpoint_returns_recent_actions(self) -> None:
        actions = [
            {
                "id": 1,
                "domain": "example.com",
                "action": "block",
                "source": "test",
                "status": "written",
                "reason": "Test.",
                "risk": 90,
                "created_at": 123.0,
            }
        ]

        with patch("ui.dashboard.get_recent_actions", return_value=actions) as get_recent_actions:
            response = self.client.get(
                "/api/actions?q=example&limit=25&action=block&status=written"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), actions)
        get_recent_actions.assert_called_once_with(
            limit=25,
            search="example",
            action="block",
            status="written",
        )

    def test_rules_endpoint_returns_domain_rules(self) -> None:
        rules = [
            {
                "domain": "example.com",
                "decision": "allow",
                "source": "cli",
                "reason": "Known safe.",
                "enabled": 1,
            }
        ]

        with patch("ui.dashboard.get_domain_rules", return_value=rules) as get_domain_rules:
            response = self.client.get(
                "/api/rules?q=example&limit=25&decision=allow"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), rules)
        get_domain_rules.assert_called_once_with(
            limit=25,
            search="example",
            decision="allow",
        )

    def test_reputations_endpoint_returns_learned_reputation(self) -> None:
        reputations = [
            {
                "domain": "bad.example",
                "score": 80,
                "confidence": 85,
                "signals": "[\"previous alert audit\"]",
                "source": "local-learning",
                "updated_at": 123.0,
            }
        ]

        with patch("ui.dashboard.get_reputations", return_value=reputations) as get_reputations:
            response = self.client.get(
                "/api/reputations?q=bad&limit=25&min_score=70"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), reputations)
        get_reputations.assert_called_once_with(
            limit=25,
            search="bad",
            min_score=70,
        )

    def test_create_rule_endpoint_saves_domain_rule(self) -> None:
        with patch("ui.dashboard.add_rule") as add_rule:
            response = self.client.post(
                "/api/rules",
                json={
                    "domain": "example.com",
                    "decision": "allow",
                    "reason": "Known safe.",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "domain": "example.com",
                "decision": "allow",
                "status": "saved",
            },
        )
        add_rule.assert_called_once_with(
            domain="example.com",
            decision="allow",
            reason="Known safe.",
            apply_block=False,
        )

    def test_create_rule_endpoint_rejects_invalid_decision(self) -> None:
        with patch("ui.dashboard.add_rule") as add_rule:
            response = self.client.post(
                "/api/rules",
                json={
                    "domain": "example.com",
                    "decision": "maybe",
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(),
            {
                "error": "decision must be allow or block",
            },
        )
        add_rule.assert_not_called()

    def test_delete_rule_endpoint_removes_domain_rule(self) -> None:
        with patch("ui.dashboard.remove_rule", return_value=True) as remove_rule:
            response = self.client.delete("/api/rules/example.com")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "domain": "example.com",
                "removed": True,
            },
        )
        remove_rule.assert_called_once_with("example.com")

    def test_health_endpoint_returns_ok_status(self) -> None:
        status = {
            "database": {
                "events": 0,
                "processed": 0,
                "domains": 0,
                "analyses": 0,
            },
            "collector": {
                "last_query_id": "0",
            },
        }

        with patch("ui.dashboard.collect_status", return_value=status) as collect_status:
            response = self.client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), status)
        collect_status.assert_called_once_with(
            include_ollama=False,
        )

    def test_health_endpoint_can_include_ollama_status(self) -> None:
        status = {
            "database": {},
            "collector": {},
            "ollama": {
                "available": True,
            },
        }

        with patch("ui.dashboard.collect_status", return_value=status) as collect_status:
            response = self.client.get("/api/health?ollama=1")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), status)
        collect_status.assert_called_once_with(
            include_ollama=True,
        )

    def test_home_endpoint_serves_dashboard(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PiHole-AI", response.data)

    def test_parse_limit_clamps_values(self) -> None:
        self.assertEqual(parse_limit("10"), 10)
        self.assertEqual(parse_limit("0"), 1)
        self.assertEqual(parse_limit("999"), 500)
        self.assertEqual(parse_limit("not-a-number"), 100)


if __name__ == "__main__":
    unittest.main()
