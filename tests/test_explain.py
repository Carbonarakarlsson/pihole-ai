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
            "pihole_ai.explain.get_domain_metadata",
            return_value={
                "domain": "bad.example",
                "query_count": 2,
            },
        ), patch(
            "pihole_ai.explain.get_recent_actions",
            return_value=[],
        ):
            explanation = explain_domain("bad.example")

        self.assertEqual(explanation["decision"]["risk"], 100)
        self.assertEqual(explanation["decision"]["evidence_count"], 1)
        self.assertEqual(len(explanation["decisive_evidence"]), 1)
        self.assertEqual(
            explanation["summary"],
            "decisive evidence from threat-intel",
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
                "legacy_analysis": False,
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


if __name__ == "__main__":
    unittest.main()
