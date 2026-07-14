import unittest

from engine.decision_engine import AI_CONFIDENCE_CEILING, DecisionEngine
from engine.evidence import EvidenceCollection, EvidenceItem, EvidencePolarity
from engine.models import DomainCategory


class EvidenceModelTests(unittest.TestCase):
    def test_evidence_item_clamps_values_and_serializes(self) -> None:
        item = EvidenceItem(
            evidence_id="test:evidence",
            classifier="test",
            evidence_type="signal",
            polarity="risk",
            score=500,
            confidence=2,
            summary="hello",
            metadata={"value": object()},
        )

        self.assertEqual(item.score, 100)
        self.assertEqual(item.confidence, 1)
        payload = item.to_dict()
        self.assertEqual(payload["polarity"], "risk")
        self.assertIn("value", payload["metadata"])


class DecisionEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DecisionEngine()

    def test_decisive_manual_block_wins_over_safety_evidence(self) -> None:
        collection = EvidenceCollection(
            domain="bad.example",
            items=(
                EvidenceItem(
                    evidence_id="safe",
                    classifier="local-reputation",
                    evidence_type="learned_reputation",
                    polarity=EvidencePolarity.SAFETY,
                    score=-80,
                    confidence=0.95,
                    summary="Historically quiet.",
                ),
                EvidenceItem(
                    evidence_id="block",
                    classifier="manual-rule",
                    evidence_type="manual_block",
                    polarity=EvidencePolarity.RISK,
                    score=100,
                    confidence=0.95,
                    summary="Manually blocked.",
                    metadata={
                        "decisive": True,
                        "precedence": 10,
                        "category": DomainCategory.SUSPICIOUS.value,
                    },
                ),
            ),
        )

        decision = self.engine.decide(collection)

        self.assertEqual(decision.risk_score, 100)
        self.assertEqual(decision.source, "manual-rule")
        self.assertEqual(decision.decisive_evidence_ids, ("block",))

    def test_ai_only_confidence_is_capped(self) -> None:
        collection = EvidenceCollection(
            domain="maybe.example",
            items=(
                EvidenceItem(
                    evidence_id="ai",
                    classifier="ai",
                    evidence_type="ai_result",
                    polarity=EvidencePolarity.RISK,
                    score=80,
                    confidence=0.99,
                    summary="AI thinks risky.",
                ),
            ),
        )

        decision = self.engine.decide(collection)

        self.assertLessEqual(decision.confidence, AI_CONFIDENCE_CEILING)

    def test_skip_ai_when_deterministic_evidence_is_sufficient(self) -> None:
        collection = EvidenceCollection(
            domain="safe.example",
            items=(
                EvidenceItem(
                    evidence_id="safe",
                    classifier="local-reputation",
                    evidence_type="learned_reputation",
                    polarity=EvidencePolarity.SAFETY,
                    score=-100,
                    confidence=0.95,
                    summary="Strong local safety signal.",
                ),
            ),
        )

        should_skip, reason = self.engine.should_skip_ai(collection)

        self.assertTrue(should_skip)
        self.assertIn("deterministic", reason)


if __name__ == "__main__":
    unittest.main()
