import io
import json
import unittest
from unittest.mock import patch

from pihole_ai.explain import (
    explain_domain,
    normalize_domain,
    parse_signals,
    print_explanation,
)


class ExplainTests(unittest.TestCase):
    def test_normalize_domain(self) -> None:
        self.assertEqual(
            normalize_domain("Example.COM."),
            "example.com",
        )

    def test_parse_signals_handles_json_lists(self) -> None:
        self.assertEqual(
            parse_signals('["recent spike", "alert"]'),
            [
                "recent spike",
                "alert",
            ],
        )
        self.assertEqual(parse_signals("not-json"), [])

    def test_explain_domain_collects_evidence_and_summarizes_threat(self) -> None:
        with patch(
            "pihole_ai.explain.get_domain_rule",
            return_value=None,
        ), patch(
            "pihole_ai.explain.get_threat_intel",
            return_value={
                "domain": "bad.example",
                "source": "test-feed",
                "category": "malware",
                "confidence": 95,
            },
        ), patch(
            "pihole_ai.explain.get_domain_reputation",
            return_value={
                "domain": "bad.example",
                "score": 10,
                "confidence": 60,
                "signals": '["manual allow rule"]',
            },
        ), patch(
            "pihole_ai.explain.get_analysis",
            return_value=None,
        ), patch(
            "pihole_ai.explain.get_decision_evidence",
            return_value=[],
        ), patch(
            "pihole_ai.explain.get_decision_record",
            return_value=None,
        ), patch(
            "pihole_ai.explain.get_domain_metadata",
            return_value={
                "domain": "bad.example",
                "query_count": 2,
            },
        ), patch(
            "pihole_ai.explain.get_recent_actions",
            return_value=[
                {
                    "domain": "bad.example",
                    "action": "alert",
                    "status": "learned",
                    "risk": 70,
                    "source": "test",
                    "reason": "Test.",
                },
                {
                    "domain": "other.example",
                    "action": "alert",
                },
            ],
        ), patch(
            "pihole_ai.explain.get_pipeline_telemetry_for_domain",
            return_value=None,
        ):
            explanation = explain_domain("Bad.Example")

        self.assertEqual(explanation["domain"], "bad.example")
        self.assertEqual(
            explanation["summary"],
            "threat-intel match from test-feed as malware",
        )
        self.assertEqual(
            explanation["reputation"]["signals"],
            [
                "manual allow rule",
            ],
        )
        self.assertEqual(len(explanation["actions"]), 1)
        self.assertFalse(explanation["telemetry"]["available"])

    def test_explain_domain_includes_stored_decision_evidence(self) -> None:
        with patch(
            "pihole_ai.explain.get_domain_rule",
            return_value=None,
        ), patch(
            "pihole_ai.explain.get_threat_intel",
            return_value=None,
        ), patch(
            "pihole_ai.explain.get_domain_reputation",
            return_value=None,
        ), patch(
            "pihole_ai.explain.get_analysis",
            return_value={
                "domain": "bad.example",
                "risk": 100,
                "confidence": 95,
                "category": "malware",
                "reason": "Threat intel hit.",
                "model": "threat-intel",
            },
        ), patch(
            "pihole_ai.explain.get_decision_evidence",
            return_value=[
                {
                    "domain": "bad.example",
                    "evidence_id": "threat-intel:bad.example:feed",
                    "classifier": "threat-intel",
                    "evidence_type": "feed_hit",
                    "polarity": "risk",
                    "score": 95,
                    "confidence": 0.95,
                    "summary": "Threat intel hit.",
                    "details": "",
                    "metadata": {"category": "malware"},
                    "decisive": True,
                    "created_at": 1.0,
                }
            ],
        ), patch(
            "pihole_ai.explain.get_decision_record",
            return_value={
                "domain": "bad.example",
                "verdict": "malicious",
                "risk_score": 100,
                "confidence": 0.95,
                "category": "malware",
                "source": "threat-intel",
                "explanation": "Threat intel hit.",
                "decisive_evidence_ids": ["threat-intel:bad.example:feed"],
                "classifier_trace": [
                    {
                        "classifier": "ThreatIntelClassifier",
                        "status": "consulted",
                        "evidence_count": 1,
                        "latency_ms": 1,
                    }
                ],
                "conflicts": [],
                "legacy": False,
                "policy_version": "evidence-policy-v1",
                "application_version": "0.5-test",
                "schema_version": 3,
                "evidence_truncated": False,
                "created_at": 1.0,
            },
        ), patch(
            "pihole_ai.explain.get_domain_metadata",
            return_value={
                "domain": "bad.example",
                "query_count": 2,
            },
        ), patch(
            "pihole_ai.explain.get_recent_actions",
            return_value=[],
        ), patch(
            "pihole_ai.explain.get_pipeline_telemetry_for_domain",
            return_value={
                "available": True,
                "run_id": "ptr_test",
                "duration_ms": 4,
                "cache_hit": False,
                "final_decision_id": "dec_" + "1" * 32,
                "pipeline_timeline": [
                    {
                        "execution_order": 1,
                        "classifier_name": "ThreatIntelClassifier",
                        "classifier_result": "malware",
                        "confidence_raw": 95,
                        "confidence_band": "very_high",
                        "duration_ms": 1,
                        "skipped": False,
                        "cache_hit": False,
                        "final_decision_id": "dec_" + "1" * 32,
                    }
                ],
            },
        ):
            explanation = explain_domain("bad.example")

        self.assertEqual(explanation["decision"]["risk_score"], 100)
        self.assertEqual(explanation["decision"]["evidence_count"], 1)
        self.assertEqual(len(explanation["decisive_evidence"]), 1)
        self.assertEqual(len(explanation["classifier_trace"]), 1)
        self.assertEqual(
            explanation["summary"],
            "decisive evidence from threat-intel",
        )
        self.assertTrue(explanation["telemetry"]["available"])
        self.assertEqual(
            explanation["pipeline_timeline"][0]["classifier_name"],
            "ThreatIntelClassifier",
        )

    def test_print_explanation_outputs_json(self) -> None:
        with patch(
            "pihole_ai.explain.explain_domain",
            return_value={
                "domain": "example.com",
                "summary": "no local evidence found",
                "rule": None,
                "threat_intel": None,
                "reputation": None,
                "analysis": None,
                "evidence": [],
                "decision": None,
                "decisive_evidence": [],
                "risk_evidence": [],
                "safety_evidence": [],
                "neutral_evidence": [],
                "classifier_trace": [],
                "telemetry": {
                    "available": False,
                    "reason": "telemetry unavailable",
                    "pipeline_timeline": [],
                },
                "pipeline_timeline": [],
                "conflicts": [],
                "legacy": False,
                "legacy_analysis": False,
                "legacy_note": "",
                "metadata": {},
                "actions": [],
            },
        ), patch("sys.stdout", io.StringIO()) as stdout:
            result = print_explanation(
                "example.com",
                as_json=True,
            )

        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(
            json.loads(stdout.getvalue())["domain"],
            "example.com",
        )
        self.assertIn("telemetry", json.loads(stdout.getvalue()))

    def test_print_explanation_outputs_pipeline_timeline(self) -> None:
        with patch(
            "pihole_ai.explain.explain_domain",
            return_value={
                "domain": "example.com",
                "summary": "stored decision risk 10 from 1 evidence item(s)",
                "rule": None,
                "threat_intel": None,
                "reputation": None,
                "analysis": {"risk": 10, "category": "benign"},
                "evidence": [],
                "decision": {
                    "verdict": "safe",
                    "risk_score": 10,
                    "confidence": 0.9,
                    "category": "benign",
                    "source": "decision-engine",
                    "explanation": "Safe.",
                },
                "decisive_evidence": [],
                "risk_evidence": [],
                "safety_evidence": [],
                "neutral_evidence": [],
                "classifier_trace": [],
                "telemetry": {
                    "available": True,
                    "run_id": "ptr_test",
                    "duration_ms": 12,
                    "cache_hit": False,
                    "final_decision_id": "dec_" + "1" * 32,
                    "pipeline_timeline": [
                        {
                            "execution_order": 1,
                            "classifier_name": "AIClassifier",
                            "classifier_result": "benign",
                            "confidence_raw": 88,
                            "confidence_band": "high",
                            "duration_ms": 12,
                            "skipped": False,
                            "cache_hit": False,
                            "ai_invoked": True,
                            "ai_model": "fake-ai-model",
                            "prompt_version": "domain-classification-v1",
                            "timeout": False,
                            "parse_failure": False,
                        }
                    ],
                },
                "pipeline_timeline": [],
                "conflicts": [],
                "legacy": False,
                "legacy_analysis": False,
                "legacy_note": "",
                "metadata": {},
                "actions": [],
            },
        ), patch("sys.stdout", io.StringIO()) as stdout:
            print_explanation("example.com")

        output = stdout.getvalue()
        self.assertIn("Pipeline telemetry", output)
        self.assertIn("AIClassifier", output)
        self.assertIn("ai_invoked=true", output)

    def test_print_explanation_without_telemetry_is_clear(self) -> None:
        with patch(
            "pihole_ai.explain.explain_domain",
            return_value={
                "domain": "example.com",
                "summary": "no local evidence found",
                "rule": None,
                "threat_intel": None,
                "reputation": None,
                "analysis": None,
                "evidence": [],
                "decision": None,
                "decisive_evidence": [],
                "risk_evidence": [],
                "safety_evidence": [],
                "neutral_evidence": [],
                "classifier_trace": [],
                "telemetry": {
                    "available": False,
                    "reason": "telemetry unavailable",
                    "pipeline_timeline": [],
                },
                "pipeline_timeline": [],
                "conflicts": [],
                "legacy": False,
                "legacy_analysis": False,
                "legacy_note": "",
                "metadata": {},
                "actions": [],
            },
        ), patch("sys.stdout", io.StringIO()) as stdout:
            print_explanation("example.com")

        self.assertIn("telemetry unavailable", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
