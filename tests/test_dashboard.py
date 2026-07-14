import logging
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ui.dashboard import create_app, parse_limit


class DashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.app.config.update(TESTING=True)
        self.app.config["PIHOLE_AI_DISABLE_AUTH_FOR_TESTS"] = True
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

    def test_decision_metrics_endpoint_returns_summary(self) -> None:
        metrics = {
            "analysis": {
                "total": 3,
                "low_risk": 1,
                "medium_risk": 1,
                "high_risk": 1,
                "zero_confidence": 0,
            },
            "categories": {
                "malware": 1,
            },
            "models": {
                "heuristics": 1,
            },
            "actions": {
                "total": 2,
                "by_action": {
                    "feedback": 1,
                },
                "by_status": {
                    "false-negative": 1,
                },
                "feedback": {
                    "false-negative": 1,
                },
            },
            "rules": {
                "block": 1,
            },
        }

        with patch("ui.dashboard.get_decision_metrics", return_value=metrics) as get_metrics:
            response = self.client.get("/api/metrics/decisions")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), metrics)
        get_metrics.assert_called_once_with()

    def test_explain_endpoint_returns_grouped_contract(self) -> None:
        explanation = {
            "domain": "bad.example",
            "decision": {
                "verdict": "malicious",
                "risk_score": 100,
                "confidence": 0.95,
                "category": "malware",
                "source": "threat-intel",
                "explanation": "Threat intel hit.",
                "created_at": 1.0,
            },
            "rule": None,
            "threat_intel": None,
            "reputation": None,
            "actions": [],
            "metadata": {"query_count": 1},
            "legacy": False,
            "decisive_evidence": [{"evidence_id": "one"}],
            "risk_evidence": [],
            "safety_evidence": [],
            "neutral_evidence": [],
            "classifier_trace": [],
            "conflicts": [],
        }

        with patch("ui.dashboard.explain_domain", return_value=explanation):
            response = self.client.get("/api/explain/bad.example")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["decision"]["risk_score"], 100)
        self.assertIn("decisive_evidence", payload)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_explain_endpoint_rejects_invalid_domain(self) -> None:
        response = self.client.get("/api/explain/%3Cscript%3E")

        self.assertEqual(response.status_code, 400)

    def test_explain_endpoint_returns_404_for_unknown_domain(self) -> None:
        explanation = {
            "domain": "missing.example",
            "decision": None,
            "rule": None,
            "threat_intel": None,
            "reputation": None,
            "actions": [],
            "metadata": {"query_count": 0},
            "legacy": False,
        }

        with patch("ui.dashboard.explain_domain", return_value=explanation):
            response = self.client.get("/api/explain/missing.example")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()["error"], "domain not found")

    def test_explain_endpoint_returns_legacy_analysis(self) -> None:
        explanation = {
            "domain": "old.example",
            "decision": {
                "legacy": True,
                "risk_score": 70,
                "category": "suspicious",
            },
            "rule": None,
            "threat_intel": None,
            "reputation": None,
            "actions": [],
            "metadata": {"query_count": 0},
            "legacy": True,
        }

        with patch("ui.dashboard.explain_domain", return_value=explanation):
            response = self.client.get("/api/explain/old.example")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["legacy"])

    def test_polling_endpoint_returns_dashboard_intervals(self) -> None:
        with patch(
            "ui.dashboard.settings",
            SimpleNamespace(
                dashboard_overview_poll_interval_ms=5000,
                dashboard_metrics_poll_interval_ms=15000,
                dashboard_tables_poll_interval_ms=10000,
                dashboard_slow_poll_interval_ms=30000,
                dashboard_username="admin",
            ),
        ):
            response = self.client.get("/api/polling")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "overview_ms": 5000,
                "metrics_ms": 15000,
                "tables_ms": 10000,
                "rules_reputation_ms": 30000,
            },
        )

    def test_setup_endpoint_returns_shared_report_shape(self) -> None:
        report = SimpleNamespace(
            to_dict=lambda: {
                "overall_stage": "ready",
                "ready": True,
                "steps": [],
                "application_version": "0.4",
                "generated_at": 1,
            }
        )

        with patch("ui.dashboard.evaluate_setup", return_value=report) as evaluate:
            response = self.client.get("/api/setup")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ready"])
        evaluate.assert_called_once_with()

    def test_settings_api_returns_current_ai_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / "pihole-ai.env"
            env_path.write_text(
                "\n".join(
                    [
                        "AI_ENABLED=false",
                        "AI_MAX_CALLS_PER_MINUTE=4",
                        "AI_COOLDOWN_SECONDS=90",
                        "AI_TIMEOUT_SECONDS=11",
                        "PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS=7000",
                        "DEV_ACCESS_LOGS=true",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with patch("ui.dashboard.SETTINGS_ENV_PATH", env_path):
                response = self.client.get("/api/settings")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertFalse(payload["ai"]["enabled"])
        self.assertEqual(payload["ai"]["max_calls_per_minute"], 4)
        self.assertEqual(payload["ai"]["cooldown_seconds"], 90)
        self.assertEqual(payload["ai"]["timeout_seconds"], 11)
        self.assertEqual(payload["dashboard"]["refresh_interval_ms"], 7000)
        self.assertTrue(payload["dashboard"]["dev_access_logs"])

    def test_settings_api_updates_env_file_and_preserves_unknown_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / "pihole-ai.env"
            env_path.write_text(
                "\n".join(
                    [
                        "# keep this comment",
                        "UNKNOWN_SETTING=still-here",
                        "AI_ENABLED=false",
                        "AI_MAX_CALLS_PER_MINUTE=2",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with patch("ui.dashboard.SETTINGS_ENV_PATH", env_path):
                response = self.client.post(
                    "/api/settings",
                    json={
                        "ai": {
                            "enabled": True,
                            "max_calls_per_minute": 5,
                            "cooldown_seconds": 45,
                            "timeout_seconds": 12,
                        },
                        "dashboard": {
                            "refresh_interval_ms": 8000,
                            "dev_access_logs": True,
                        },
                    },
                )

            content = env_path.read_text(encoding="utf-8")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["restart_required"])
        self.assertIn("# keep this comment", content)
        self.assertIn("UNKNOWN_SETTING=still-here", content)
        self.assertIn("AI_ENABLED=true", content)
        self.assertIn("AI_MAX_CALLS_PER_MINUTE=5", content)
        self.assertIn("AI_COOLDOWN_SECONDS=45", content)
        self.assertIn("AI_TIMEOUT_SECONDS=12", content)
        self.assertIn("PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS=8000", content)
        self.assertIn("DEV_ACCESS_LOGS=true", content)

    def test_service_action_returns_sudo_required_message_when_not_permitted(self) -> None:
        with patch("ui.dashboard.os.geteuid", return_value=1000):
            response = self.client.post("/api/services/restart")

        self.assertEqual(response.status_code, 403)
        payload = response.get_json()
        self.assertEqual(payload["error"], "sudo_required")
        self.assertEqual(payload["command"], "sudo pihole-ai restart")
        self.assertIn("sudo pihole-ai restart", payload["message"])

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

    def test_explain_endpoint_returns_domain_explanation(self) -> None:
        explanation = {
            "domain": "example.com",
            "summary": "cached analysis risk 10 category benign",
            "rule": None,
            "threat_intel": None,
            "reputation": None,
            "analysis": {
                "risk": 10,
                "category": "benign",
            },
            "metadata": {
                "query_count": 2,
            },
            "actions": [],
        }

        with patch("ui.dashboard.explain_domain", return_value=explanation) as explain_domain:
            response = self.client.get("/api/explain/example.com")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), explanation)
        explain_domain.assert_called_once_with("example.com")

    def test_dashboard_page_contains_evidence_explain_sections(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Final decision", html)
        self.assertIn("Decisive evidence", html)
        self.assertIn("Supporting risk evidence", html)
        self.assertIn("Classifier trace", html)

    def test_feedback_endpoint_records_domain_feedback(self) -> None:
        with patch("ui.dashboard.record_feedback") as record_feedback:
            record_feedback.return_value.domain = "bad.example"
            record_feedback.return_value.verdict = "false-negative"
            record_feedback.return_value.promoted = "block"

            response = self.client.post(
                "/api/feedback",
                json={
                    "domain": "Bad.Example",
                    "verdict": "false-negative",
                    "reason": "Dashboard false-negative",
                    "promote": True,
                    "apply": True,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "domain": "bad.example",
                "verdict": "false-negative",
                "promoted": "block",
                "status": "saved",
            },
        )
        record_feedback.assert_called_once_with(
            domain="Bad.Example",
            verdict="false-negative",
            reason="Dashboard false-negative",
            promote=True,
            apply_block=True,
        )

    def test_feedback_endpoint_rejects_invalid_verdict(self) -> None:
        with patch("ui.dashboard.record_feedback") as record_feedback:
            response = self.client.post(
                "/api/feedback",
                json={
                    "domain": "example.com",
                    "verdict": "maybe",
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(),
            {
                "error": "invalid feedback verdict",
            },
        )
        record_feedback.assert_not_called()

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

    def test_status_endpoint_returns_runtime_status(self) -> None:
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
            response = self.client.get("/api/status")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), status)
        collect_status.assert_called_once_with(
            include_ollama=False,
        )

    def test_status_endpoint_can_include_ollama_status(self) -> None:
        status = {
            "database": {},
            "collector": {},
            "ollama": {
                "available": True,
            },
        }

        with patch("ui.dashboard.collect_status", return_value=status) as collect_status:
            response = self.client.get("/api/status?ollama=1")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), status)
        collect_status.assert_called_once_with(
            include_ollama=True,
        )

    def test_home_endpoint_serves_dashboard(self) -> None:
        with patch(
            "ui.dashboard.settings",
            SimpleNamespace(
                dashboard_overview_poll_interval_ms=5000,
                dashboard_metrics_poll_interval_ms=15000,
                dashboard_tables_poll_interval_ms=10000,
                dashboard_slow_poll_interval_ms=30000,
                dashboard_username="admin",
            ),
        ):
            response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PiHole-AI", response.data)
        for label in (
            b"Overview",
            b"Activity",
            b"Domains",
            b"Devices",
            b"Intelligence",
            b"Rules",
            b"Settings",
        ):
            self.assertIn(label, response.data)
        self.assertIn(b"Companion appliance", response.data)
        self.assertIn(b'id="setup-banner"', response.data)
        self.assertIn(b"Setup complete with warnings", response.data)
        self.assertIn(
            b"PiHole-AI is operational; review recommended configuration warnings.",
            response.data,
        )
        self.assertIn(b'id="setup-steps"', response.data)
        self.assertIn(b"Derived from live state", response.data)
        self.assertIn(b"/api/setup", response.data)
        self.assertIn(b"Network Summary", response.data)
        self.assertIn(b"Recent High-Risk Domains", response.data)
        self.assertIn(b"Activity Timeline", response.data)
        self.assertIn(b"AI Controls", response.data)
        self.assertIn(b"Classifier Contribution", response.data)
        self.assertIn(b"Service control", response.data)
        self.assertIn(b"Start engine", response.data)
        self.assertIn(b"Stop engine", response.data)
        self.assertIn(b"Restart all services", response.data)
        self.assertIn(b"setting-ai-enabled", response.data)
        self.assertIn(b"setting-ai-max-calls", response.data)
        self.assertIn(b"setting-ai-cooldown", response.data)
        self.assertIn(b"setting-ai-timeout", response.data)
        self.assertIn(b"setting-refresh", response.data)
        self.assertIn(b"setting-dev-logs", response.data)
        self.assertIn(b"/api/metrics/decisions", response.data)
        self.assertIn(b"/api/settings", response.data)
        self.assertIn(b"/api/services/", response.data)
        self.assertIn(b"/api/feedback", response.data)
        self.assertIn(b'id="rules"', response.data)
        self.assertIn(b'id="reputations"', response.data)
        self.assertIn(b'id="explain"', response.data)
        self.assertIn(b"Safe", response.data)
        self.assertIn(b"False positive", response.data)
        self.assertIn(b"No rules yet", response.data)
        self.assertIn(b"No reputation data yet", response.data)
        self.assertIn(b"No threat intel imported yet", response.data)
        self.assertIn(b"setInterval(loadOverview, 5000)", response.data)
        self.assertIn(b"setInterval(loadMetrics, 15000)", response.data)
        self.assertIn(b"loadTables(), loadActivity()", response.data)
        self.assertIn(b"10000", response.data)
        self.assertNotIn(b"__POLL_INTERVAL_MS__", response.data)

    def test_dashboard_main_disables_werkzeug_access_logs_by_default(self) -> None:
        werkzeug_logger = logging.getLogger("werkzeug")
        original_level = werkzeug_logger.level

        try:
            with patch(
                "ui.dashboard.settings",
                SimpleNamespace(
                    dashboard_port=8080,
                    dev_access_logs=False,
                ),
            ), patch("ui.dashboard.app.run") as run:
                from ui.dashboard import main

                main(
                    host="127.0.0.1",
                    port=9000,
                )

            self.assertEqual(werkzeug_logger.level, logging.WARNING)
            run.assert_called_once_with(
                host="127.0.0.1",
                port=9000,
            )

        finally:
            werkzeug_logger.setLevel(original_level)

    def test_dashboard_main_can_enable_werkzeug_access_logs_for_dev(self) -> None:
        werkzeug_logger = logging.getLogger("werkzeug")
        original_level = werkzeug_logger.level

        try:
            with patch(
                "ui.dashboard.settings",
                SimpleNamespace(
                    dashboard_port=8080,
                    dev_access_logs=True,
                ),
            ), patch("ui.dashboard.app.run"):
                from ui.dashboard import main

                main(
                    host="127.0.0.1",
                    port=9000,
                )

            self.assertEqual(werkzeug_logger.level, logging.INFO)

        finally:
            werkzeug_logger.setLevel(original_level)

    def test_parse_limit_clamps_values(self) -> None:
        self.assertEqual(parse_limit("10"), 10)
        self.assertEqual(parse_limit("0"), 1)
        self.assertEqual(parse_limit("999"), 500)
        self.assertEqual(parse_limit("not-a-number"), 100)


if __name__ == "__main__":
    unittest.main()
