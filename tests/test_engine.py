import unittest
from types import SimpleNamespace
from unittest.mock import patch

from engine.engine import AnalysisEngine, is_cache_usable
from engine.models import AnalysisResult, DomainCategory


class DummyLogger:
    def info(self, *args, **kwargs):
        pass

    def exception(self, *args, **kwargs):
        pass


class FakeAnalyzer:
    def __init__(self) -> None:
        self.requests = []

    def analyze(self, request):
        self.requests.append(request)

        return AnalysisResult(
            domain=request.domain,
            risk=15,
            confidence=80,
            category=DomainCategory.BENIGN.value,
            reason="Test analysis.",
            model="fake",
            analyzed_at=123.0,
        )


class LoopEngine:
    def __init__(self) -> None:
        self.calls = 0

    def process_once(self) -> int:
        self.calls += 1
        return self.calls


class AnalysisEngineTests(unittest.TestCase):
    def test_cache_is_usable_for_positive_confidence_fresh_entry(self) -> None:
        self.assertTrue(
            is_cache_usable(
                {
                    "confidence": 80,
                    "analyzed_at": 950.0,
                },
                now=1000.0,
                cache_ttl=100,
            )
        )

    def test_cache_is_not_usable_for_zero_confidence_entry(self) -> None:
        self.assertFalse(
            is_cache_usable(
                {
                    "confidence": 0,
                    "analyzed_at": 1000.0,
                },
                now=1000.0,
                cache_ttl=100,
            )
        )

    def test_cache_is_not_usable_for_stale_entry(self) -> None:
        self.assertFalse(
            is_cache_usable(
                {
                    "confidence": 80,
                    "analyzed_at": 899.0,
                },
                now=1000.0,
                cache_ttl=100,
            )
        )

    def test_cache_ttl_zero_keeps_positive_cache_forever(self) -> None:
        self.assertTrue(
            is_cache_usable(
                {
                    "confidence": 80,
                    "analyzed_at": 1.0,
                },
                now=1000.0,
                cache_ttl=0,
            )
        )

    def test_process_once_passes_domain_metadata_to_analyzer(self) -> None:
        analyzer = FakeAnalyzer()
        engine = AnalysisEngine.__new__(AnalysisEngine)
        engine.analyzer = analyzer

        with patch(
            "engine.engine.logger",
            DummyLogger(),
        ), patch(
            "engine.engine.get_unprocessed_domains",
            return_value=[
                {
                    "id": 1,
                    "domain": "example.com",
                    "device": "device-a",
                    "timestamp": 100.0,
                }
            ],
        ), patch(
            "engine.engine.get_analysis",
            return_value=None,
        ), patch(
            "engine.engine.get_domain_metadata",
            return_value={
                "domain": "example.com",
                "query_count": 12,
                "first_seen": 10.0,
                "last_seen": 100.0,
                "device_count": 2,
                "recent_queries": 3,
                "tags": ["test"],
            },
        ) as get_domain_metadata, patch(
            "engine.engine.save_analysis",
        ) as save_analysis, patch(
            "engine.engine.apply_action_policy",
        ) as apply_action_policy, patch(
            "engine.engine.mark_processed_by_domain",
        ) as mark_processed_by_domain:

            processed = engine.process_once()

        self.assertEqual(processed, 1)
        get_domain_metadata.assert_called_once_with("example.com")
        self.assertEqual(len(analyzer.requests), 1)
        request = analyzer.requests[0]
        self.assertEqual(request.domain, "example.com")
        self.assertIsNotNone(request.metadata)
        self.assertEqual(request.metadata.query_count, 12)
        self.assertEqual(request.metadata.device_count, 2)
        self.assertEqual(request.metadata.tags, ["test"])
        save_analysis.assert_called_once_with(
            domain="example.com",
            risk=15,
            confidence=80,
            category=DomainCategory.BENIGN.value,
            reason="Test analysis.",
            model="fake",
            analyzed_at=123.0,
        )
        apply_action_policy.assert_called_once()
        self.assertEqual(
            apply_action_policy.call_args.args[0].domain,
            "example.com",
        )
        mark_processed_by_domain.assert_called_once_with("example.com")

    def test_process_once_skips_metadata_lookup_on_cache_hit(self) -> None:
        engine = AnalysisEngine.__new__(AnalysisEngine)
        engine.analyzer = FakeAnalyzer()

        with patch(
            "engine.engine.logger",
            DummyLogger(),
        ), patch(
            "engine.engine.get_unprocessed_domains",
            return_value=[
                {
                    "id": 1,
                    "domain": "cached.example",
                    "device": "device-a",
                    "timestamp": 100.0,
                }
            ],
        ), patch(
            "engine.engine.get_analysis",
            return_value={
                "domain": "cached.example",
                "confidence": 80,
                "analyzed_at": 100.0,
            },
        ), patch(
            "engine.engine.settings",
            SimpleNamespace(
                cache_ttl=0,
                engine_batch_size=500,
            ),
        ), patch(
            "engine.engine.get_domain_metadata",
        ) as get_domain_metadata, patch(
            "engine.engine.mark_processed_by_domain",
        ) as mark_processed_by_domain:

            processed = engine.process_once()

        self.assertEqual(processed, 1)
        get_domain_metadata.assert_not_called()
        mark_processed_by_domain.assert_called_once_with("cached.example")

    def test_process_once_retries_zero_confidence_cache_entry(self) -> None:
        analyzer = FakeAnalyzer()
        engine = AnalysisEngine.__new__(AnalysisEngine)
        engine.analyzer = analyzer

        with patch(
            "engine.engine.logger",
            DummyLogger(),
        ), patch(
            "engine.engine.get_unprocessed_domains",
            return_value=[
                {
                    "id": 1,
                    "domain": "retry.example",
                    "device": "device-a",
                    "timestamp": 100.0,
                }
            ],
        ), patch(
            "engine.engine.get_analysis",
            return_value={
                "domain": "retry.example",
                "confidence": 0,
            },
        ), patch(
            "engine.engine.get_domain_metadata",
            return_value={
                "domain": "retry.example",
                "query_count": 2,
            },
        ) as get_domain_metadata, patch(
            "engine.engine.save_analysis",
        ) as save_analysis, patch(
            "engine.engine.apply_action_policy",
        ) as apply_action_policy, patch(
            "engine.engine.mark_processed_by_domain",
        ) as mark_processed_by_domain:

            processed = engine.process_once()

        self.assertEqual(processed, 1)
        self.assertEqual(len(analyzer.requests), 1)
        get_domain_metadata.assert_called_once_with("retry.example")
        save_analysis.assert_called_once()
        apply_action_policy.assert_called_once()
        mark_processed_by_domain.assert_called_once_with("retry.example")

    def test_process_once_retries_stale_positive_confidence_cache_entry(self) -> None:
        analyzer = FakeAnalyzer()
        engine = AnalysisEngine.__new__(AnalysisEngine)
        engine.analyzer = analyzer

        with patch(
            "engine.engine.logger",
            DummyLogger(),
        ), patch(
            "engine.engine.get_unprocessed_domains",
            return_value=[
                {
                    "id": 1,
                    "domain": "stale.example",
                    "device": "device-a",
                    "timestamp": 100.0,
                }
            ],
        ), patch(
            "engine.engine.get_analysis",
            return_value={
                "domain": "stale.example",
                "confidence": 80,
                "analyzed_at": 1.0,
            },
        ), patch(
            "engine.engine.settings",
            SimpleNamespace(
                cache_ttl=100,
                engine_batch_size=500,
            ),
        ), patch(
            "engine.engine.time.time",
            return_value=1000.0,
        ), patch(
            "engine.engine.get_domain_metadata",
            return_value={
                "domain": "stale.example",
            },
        ) as get_domain_metadata, patch(
            "engine.engine.save_analysis",
        ) as save_analysis, patch(
            "engine.engine.apply_action_policy",
        ) as apply_action_policy, patch(
            "engine.engine.mark_processed_by_domain",
        ) as mark_processed_by_domain:

            processed = engine.process_once()

        self.assertEqual(processed, 1)
        self.assertEqual(len(analyzer.requests), 1)
        get_domain_metadata.assert_called_once_with("stale.example")
        save_analysis.assert_called_once()
        apply_action_policy.assert_called_once()
        mark_processed_by_domain.assert_called_once_with("stale.example")

    def test_process_once_saves_unknown_fallback_result(self) -> None:
        class FallbackAnalyzer:
            def analyze(self, request):
                return AnalysisResult(
                    domain=request.domain,
                    risk=50,
                    confidence=0,
                    category=DomainCategory.UNKNOWN.value,
                    reason="AI backend unavailable.",
                    model="fake-model",
                    analyzed_at=456.0,
                )

        engine = AnalysisEngine.__new__(AnalysisEngine)
        engine.analyzer = FallbackAnalyzer()

        with patch(
            "engine.engine.logger",
            DummyLogger(),
        ), patch(
            "engine.engine.get_unprocessed_domains",
            return_value=[
                {
                    "id": 1,
                    "domain": "fallback.example",
                    "device": "device-a",
                    "timestamp": 100.0,
                }
            ],
        ), patch(
            "engine.engine.get_analysis",
            return_value=None,
        ), patch(
            "engine.engine.get_domain_metadata",
            return_value={
                "domain": "fallback.example",
            },
        ), patch(
            "engine.engine.save_analysis",
        ) as save_analysis, patch(
            "engine.engine.apply_action_policy",
        ) as apply_action_policy, patch(
            "engine.engine.mark_processed_by_domain",
        ) as mark_processed_by_domain:

            processed = engine.process_once()

        self.assertEqual(processed, 1)
        save_analysis.assert_called_once_with(
            domain="fallback.example",
            risk=50,
            confidence=0,
            category=DomainCategory.UNKNOWN.value,
            reason="AI backend unavailable.",
            model="fake-model",
            analyzed_at=456.0,
        )
        apply_action_policy.assert_called_once()
        mark_processed_by_domain.assert_called_once_with("fallback.example")

    def test_run_loop_processes_until_max_cycles(self) -> None:
        engine = LoopEngine()

        with patch(
            "engine.engine.logger",
            DummyLogger(),
        ), patch(
            "engine.engine.time.sleep",
        ) as sleep:

            AnalysisEngine.run_loop(
                engine,
                interval=3,
                max_cycles=2,
            )

        self.assertEqual(engine.calls, 2)
        sleep.assert_called_once_with(3)

    def test_main_runs_continuous_loop(self) -> None:
        with patch("engine.engine.AnalysisEngine") as analysis_engine:
            from engine.engine import main

            main()

        analysis_engine.assert_called_once_with()
        analysis_engine.return_value.run_loop.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
