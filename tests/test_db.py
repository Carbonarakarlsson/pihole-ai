import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from core import db
from core import migrations
from core.migrations import IncompatibleSchema
from engine.decision_engine import DecisionEngine
from engine.evidence import EvidenceCollection, EvidenceItem, EvidencePolarity
from pihole_ai.intel import update_source
from pihole_ai.intel_feeds import FetchResult, content_sha256
from pihole_ai.intel_models import FeedSource


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.tmpdir.name) / "events.db"
        self.path_patch = patch.object(
            db,
            "DATABASE_PATH",
            self.database_path,
        )
        self.path_patch.start()
        db.init_db()

    def tearDown(self) -> None:
        self.path_patch.stop()
        self.tmpdir.cleanup()

    def test_init_db_creates_expected_tables_and_confidence_column(self) -> None:
        tables = {
            row["name"]
            for row in db.query_all(
                """
                SELECT name

                FROM sqlite_master

                WHERE type = 'table'
                """
            )
        }
        columns = {
            row["name"]
            for row in db.query_all("PRAGMA table_info(analysis)")
        }

        self.assertIn("events", tables)
        self.assertIn("domain_memory", tables)
        self.assertIn("analysis", tables)
        self.assertIn("app_state", tables)
        self.assertIn("action_audit", tables)
        self.assertIn("domain_rules", tables)
        self.assertIn("domain_reputation", tables)
        self.assertIn("threat_intel", tables)
        self.assertIn("decision_records", tables)
        self.assertIn("decision_evidence", tables)
        self.assertIn("decision_history", tables)
        self.assertIn("decision_history_evidence", tables)
        self.assertIn("schema_migrations", tables)
        self.assertIn("confidence", columns)

        migration = db.query_one(
            "SELECT version, name FROM schema_migrations ORDER BY version DESC LIMIT 1"
        )
        self.assertIsNotNone(migration)
        self.assertEqual(migration["version"], migrations.LATEST_SUPPORTED_SCHEMA_VERSION)

    def test_insert_event_updates_domain_memory(self) -> None:
        db.insert_event(
            device="device-a",
            domain="example.com",
            timestamp=10.0,
        )
        db.insert_event(
            device="device-b",
            domain="example.com",
            timestamp=20.0,
        )

        memory = db.get_domain_memory("example.com")

        self.assertIsNotNone(memory)
        self.assertEqual(memory["first_seen"], 10.0)
        self.assertEqual(memory["last_seen"], 20.0)
        self.assertEqual(memory["query_count"], 2)

    def test_get_domain_metadata_aggregates_events(self) -> None:
        db.insert_event("device-a", "example.com", 10.0)
        db.insert_event("device-b", "example.com", 20.0)
        db.insert_event("device-a", "example.com", 30.0)

        metadata = db.get_domain_metadata("example.com")

        self.assertEqual(
            metadata,
            {
                "domain": "example.com",
                "query_count": 3,
                "first_seen": 10.0,
                "last_seen": 30.0,
                "device_count": 2,
                "recent_queries": 3,
                "tags": [],
            },
        )

    def test_get_domain_metadata_returns_defaults_for_unknown_domain(self) -> None:
        self.assertEqual(
            db.get_domain_metadata("missing.example"),
            {
                "domain": "missing.example",
                "query_count": 0,
                "first_seen": 0.0,
                "last_seen": 0.0,
                "device_count": 0,
                "recent_queries": 0,
                "tags": [],
            },
        )

    def test_save_analysis_persists_and_updates_confidence(self) -> None:
        db.save_analysis(
            domain="example.com",
            risk=20,
            confidence=80,
            category="benign",
            reason="Initial result.",
            model="rule-engine",
            analyzed_at=100.0,
        )
        db.save_analysis(
            domain="example.com",
            risk=50,
            confidence=0,
            category="unknown",
            reason="Fallback result.",
            model="ollama",
            analyzed_at=200.0,
        )

        analysis = db.get_analysis("example.com")

        self.assertIsNotNone(analysis)
        self.assertEqual(analysis["risk"], 50)
        self.assertEqual(analysis["confidence"], 0)
        self.assertEqual(analysis["category"], "unknown")
        self.assertEqual(analysis["reason"], "Fallback result.")
        self.assertEqual(analysis["model"], "ollama")
        self.assertEqual(analysis["analyzed_at"], 200.0)

    def test_save_decision_evidence_replaces_existing_rows(self) -> None:
        engine = DecisionEngine()
        first = engine.decide(
            EvidenceCollection(
                domain="example.com",
                items=(
                    EvidenceItem(
                        evidence_id="first",
                        classifier="heuristics",
                        evidence_type="signal",
                        polarity=EvidencePolarity.RISK,
                        score=40,
                        confidence=0.8,
                        summary="Suspicious.",
                    ),
                ),
            )
        )
        second = engine.decide(
            EvidenceCollection(
                domain="example.com",
                items=(
                    EvidenceItem(
                        evidence_id="second",
                        classifier="manual-rule",
                        evidence_type="manual_block",
                        polarity=EvidencePolarity.RISK,
                        score=100,
                        confidence=0.95,
                        summary="Manual block.",
                        metadata={"decisive": True, "precedence": 10},
                    ),
                ),
            )
        )

        db.save_decision_evidence("example.com", first)
        db.save_decision_evidence("example.com", second)

        evidence = db.get_decision_evidence("example.com")
        record = db.get_decision_record("example.com")
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["evidence_id"], "second")
        self.assertTrue(evidence[0]["decisive"])
        self.assertEqual(evidence[0]["metadata"]["precedence"], 10)
        self.assertIsNotNone(record)
        self.assertEqual(record["risk_score"], 100)
        self.assertEqual(record["policy_version"], "evidence-policy-v1")
        history = db.list_decision_history("example.com", limit=10)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["decision_id"], record["decision_id"])
        self.assertEqual(history[0]["supersedes_decision_id"], history[1]["decision_id"])
        older = db.get_decision(history[1]["decision_id"])
        self.assertIsNotNone(older)
        self.assertEqual(older["evidence"][0]["evidence_id"], "first")

    def test_compare_decisions_reports_evidence_changes(self) -> None:
        engine = DecisionEngine()
        first = engine.decide(
            EvidenceCollection(
                domain="example.com",
                items=(
                    EvidenceItem(
                        evidence_id="one",
                        classifier="heuristics",
                        evidence_type="signal",
                        polarity=EvidencePolarity.RISK,
                        score=20,
                        confidence=0.7,
                        summary="Observed signal.",
                    ),
                ),
            )
        )
        second = engine.decide(
            EvidenceCollection(
                domain="example.com",
                items=(
                    EvidenceItem(
                        evidence_id="two",
                        classifier="heuristics",
                        evidence_type="signal",
                        polarity=EvidencePolarity.RISK,
                        score=80,
                        confidence=0.9,
                        summary="Observed signal.",
                    ),
                    EvidenceItem(
                        evidence_id="intel",
                        classifier="threat-intel",
                        evidence_type="indicator",
                        polarity=EvidencePolarity.RISK,
                        score=100,
                        confidence=0.95,
                        summary="Threat intel.",
                        metadata={"decisive": True, "source": "fixture", "precedence": 20},
                    ),
                ),
            )
        )

        older_id = db.save_decision_evidence("example.com", first)
        newer_id = db.save_decision_evidence("example.com", second)

        comparison = db.compare_decisions(older_id, newer_id)

        self.assertIsNotNone(comparison)
        self.assertGreater(comparison["risk_delta"], 0)
        self.assertTrue(comparison["decisive_evidence_changed"])
        self.assertEqual(len(comparison["added_evidence"]), 1)
        self.assertEqual(len(comparison["changed_evidence"]), 1)

    def test_decision_history_retention_preserves_latest_and_feedback_refs(self) -> None:
        engine = DecisionEngine()
        ids = []
        for index in range(3):
            decision = engine.decide(
                EvidenceCollection(
                    domain="example.com",
                    items=(
                        EvidenceItem(
                            evidence_id=f"item-{index}",
                            classifier="heuristics",
                            evidence_type="signal",
                            polarity=EvidencePolarity.RISK,
                            score=10 + index,
                            confidence=0.8,
                            summary=f"Signal {index}.",
                        ),
                    ),
                )
            )
            ids.append(db.save_decision_evidence("example.com", decision))
        db.record_action(
            domain="example.com",
            action="feedback",
            source="test",
            status="safe",
            decision_ref=ids[0],
        )

        dry_run = db.cleanup_decision_history(
            retention_days=0,
            max_per_domain=1,
            dry_run=True,
        )
        result = db.cleanup_decision_history(
            retention_days=0,
            max_per_domain=1,
            dry_run=False,
        )

        remaining = db.list_decision_history("example.com", limit=10)
        remaining_ids = {item["decision_id"] for item in remaining}
        self.assertEqual(dry_run.decisions_deleted, 0)
        self.assertEqual(result.decisions_deleted, 1)
        self.assertIn(ids[0], remaining_ids)
        self.assertIn(ids[-1], remaining_ids)
        self.assertNotIn(ids[1], remaining_ids)

    def test_save_decision_evidence_rejects_duplicate_evidence_ids(self) -> None:
        engine = DecisionEngine()
        decision = engine.decide(
            EvidenceCollection(
                domain="example.com",
                items=(
                    EvidenceItem(
                        evidence_id="duplicate",
                        classifier="one",
                        evidence_type="signal",
                        polarity=EvidencePolarity.RISK,
                        score=20,
                        confidence=0.8,
                        summary="One.",
                    ),
                    EvidenceItem(
                        evidence_id="duplicate",
                        classifier="two",
                        evidence_type="signal",
                        polarity=EvidencePolarity.RISK,
                        score=30,
                        confidence=0.8,
                        summary="Two.",
                    ),
                ),
            )
        )

        with self.assertRaises(ValueError):
            db.save_decision_evidence("example.com", decision)

    def test_save_decision_evidence_rejects_missing_decisive_reference(self) -> None:
        engine = DecisionEngine()
        decision = engine.decide(
            EvidenceCollection(
                domain="example.com",
                items=(
                    EvidenceItem(
                        evidence_id="risk",
                        classifier="test",
                        evidence_type="signal",
                        polarity=EvidencePolarity.RISK,
                        score=80,
                        confidence=0.8,
                        summary="Risk.",
                    ),
                ),
            )
        )
        broken = replace(
            decision,
            decisive_evidence_ids=("missing",),
        )

        with self.assertRaises(ValueError):
            db.save_decision_evidence("example.com", broken)

    def test_state_values_are_upserted(self) -> None:
        db.set_state("collector.last_query_id", "10")
        db.set_state("collector.last_query_id", "20")

        self.assertEqual(
            db.get_state("collector.last_query_id"),
            "20",
        )
        self.assertEqual(
            db.get_state("missing", "default"),
            "default",
        )

    def test_mark_processed_by_domain_and_stats(self) -> None:
        db.insert_event("device-a", "example.com", 10.0)
        db.insert_event("device-b", "example.com", 20.0)
        db.insert_event("device-c", "other.example", 30.0)
        db.save_analysis(
            domain="example.com",
            risk=20,
            confidence=80,
            category="benign",
            reason="Test result.",
            model="rule-engine",
            analyzed_at=100.0,
        )

        db.mark_processed_by_domain("example.com")

        stats = db.database_stats()
        events = db.get_events()
        processed_by_domain = {
            row["domain"]: row["processed"]
            for row in events
        }

        self.assertEqual(
            stats,
            {
                "events": 3,
                "processed": 2,
                "domains": 2,
                "analyses": 1,
                "actions": 0,
                "reputations": 0,
                "threat_intel": 0,
            },
        )
        self.assertEqual(processed_by_domain["example.com"], 1)
        self.assertEqual(processed_by_domain["other.example"], 0)

    def test_record_action_and_recent_actions(self) -> None:
        db.record_action(
            domain="example.com",
            action="block",
            source="test",
            status="written",
            reason="Risk threshold exceeded.",
            risk=90,
            created_at=100.0,
        )
        db.record_action(
            domain="other.example",
            action="alert",
            source="test",
            status="logged",
            reason="Manual test.",
            created_at=200.0,
        )

        rows = db.get_recent_actions(
            search="example",
            action="block",
            status="written",
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "example.com")
        self.assertEqual(rows[0]["action"], "block")
        self.assertEqual(rows[0]["status"], "written")
        self.assertEqual(rows[0]["risk"], 90)
        self.assertEqual(db.database_stats()["actions"], 2)

    def test_decision_metrics_aggregate_analysis_actions_feedback_and_rules(self) -> None:
        db.save_analysis(
            domain="safe.example",
            risk=10,
            confidence=90,
            category="benign",
            reason="Safe.",
            model="rule-engine",
            analyzed_at=10.0,
        )
        db.save_analysis(
            domain="watch.example",
            risk=55,
            confidence=80,
            category="suspicious",
            reason="Watch.",
            model="heuristics",
            analyzed_at=20.0,
        )
        db.save_analysis(
            domain="bad.example",
            risk=85,
            confidence=0,
            category="malware",
            reason="Bad.",
            model="ollama",
            analyzed_at=30.0,
        )
        db.record_action(
            domain="bad.example",
            action="suggest_block",
            source="test",
            status="dry_run",
            reason="High risk.",
            risk=85,
            created_at=40.0,
        )
        db.record_action(
            domain="bad.example",
            action="feedback",
            source="test",
            status="false-negative",
            reason="Human feedback.",
            created_at=50.0,
        )
        db.record_action(
            domain="parse.example",
            action="review",
            source="ai",
            status="parse_error",
            reason="AI returned invalid response",
            risk=0,
            created_at=55.0,
        )
        db.save_domain_rule(
            domain="bad.example",
            decision="block",
            source="test",
            reason="Confirmed.",
            created_at=60.0,
            updated_at=60.0,
        )
        db.increment_state_counter("ai.calls.total")
        db.increment_state_counter("ai.calls.total")
        db.increment_state_counter("ai.rate_limit_skips.total")
        db.increment_state_counter("ai.timeouts.total")

        metrics = db.decision_metrics()

        self.assertEqual(
            metrics["analysis"],
            {
                "total": 3,
                "low_risk": 1,
                "medium_risk": 1,
                "high_risk": 1,
                "zero_confidence": 1,
            },
        )
        self.assertEqual(metrics["categories"]["malware"], 1)
        self.assertEqual(metrics["models"]["ollama"], 1)
        self.assertEqual(metrics["actions"]["total"], 3)
        self.assertEqual(metrics["actions"]["parse_errors"], 1)
        self.assertEqual(metrics["actions"]["by_action"]["feedback"], 1)
        self.assertEqual(metrics["actions"]["by_status"]["dry_run"], 1)
        self.assertEqual(metrics["actions"]["by_status"]["parse_error"], 1)
        self.assertEqual(metrics["actions"]["feedback"]["false-negative"], 1)
        self.assertEqual(metrics["rules"]["block"], 1)
        self.assertEqual(metrics["ai"]["ai_calls"], 2)
        self.assertEqual(metrics["ai"]["ai_skipped"], 2)
        self.assertEqual(metrics["ai"]["ai_timeouts"], 1)
        self.assertEqual(metrics["ai"]["rate_limit_skips"], 1)

    def test_domain_rules_are_upserted_listed_and_deleted(self) -> None:
        db.save_domain_rule(
            domain="example.com",
            decision="allow",
            source="test",
            reason="Known safe.",
            created_at=100.0,
            updated_at=100.0,
        )
        db.save_domain_rule(
            domain="example.com",
            decision="block",
            source="test",
            reason="Changed decision.",
            created_at=100.0,
            updated_at=200.0,
        )
        db.save_domain_rule(
            domain="other.example",
            decision="allow",
            source="test",
            reason="Other.",
            created_at=150.0,
            updated_at=150.0,
        )

        rule = db.get_domain_rule("example.com")
        block_rules = db.list_domain_rules(
            decision="block",
        )

        self.assertIsNotNone(rule)
        self.assertEqual(rule["decision"], "block")
        self.assertEqual(rule["reason"], "Changed decision.")
        self.assertEqual(len(block_rules), 1)
        self.assertEqual(block_rules[0]["domain"], "example.com")
        self.assertTrue(db.delete_domain_rule("example.com"))
        self.assertIsNone(db.get_domain_rule("example.com"))
        self.assertFalse(db.delete_domain_rule("missing.example"))

    def test_domain_reputation_is_saved_and_listed(self) -> None:
        db.save_domain_reputation(
            domain="bad.example",
            score=80,
            confidence=90,
            signals=[
                "previous high-risk analysis",
            ],
            updated_at=100.0,
        )
        db.save_domain_reputation(
            domain="quiet.example",
            score=10,
            confidence=60,
            signals=[
                "no suspicious local signals",
            ],
            updated_at=90.0,
        )

        reputation = db.get_domain_reputation("bad.example")
        rows = db.list_domain_reputations(
            min_score=50,
        )

        self.assertIsNotNone(reputation)
        self.assertEqual(reputation["score"], 80)
        self.assertIn(
            "previous high-risk analysis",
            reputation["signals"],
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "bad.example")
        self.assertEqual(db.database_stats()["reputations"], 2)

    def test_reputation_candidates_include_local_history(self) -> None:
        db.insert_event("device-a", "example.com", 10.0)
        db.insert_event("device-b", "example.com", 20.0)
        db.save_analysis(
            domain="example.com",
            risk=75,
            confidence=80,
            category="suspicious",
            reason="Test result.",
            model="test",
            analyzed_at=30.0,
        )
        db.record_action(
            domain="example.com",
            action="suggest_block",
            source="test",
            status="dry_run",
            reason="Test.",
            risk=75,
            created_at=40.0,
        )

        rows = db.get_reputation_candidates()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "example.com")
        self.assertEqual(rows[0]["device_count"], 2)
        self.assertEqual(rows[0]["analysis_risk"], 75)
        self.assertEqual(rows[0]["suggest_block_count"], 1)

    def test_threat_intel_is_saved_and_listed(self) -> None:
        db.save_threat_intel(
            domain="bad.example",
            source="test-feed",
            category="malware",
            confidence=95,
            first_seen=100.0,
            last_seen=100.0,
        )
        db.save_threat_intel(
            domain="phish.example",
            source="test-feed",
            category="phishing",
            confidence=90,
            first_seen=90.0,
            last_seen=90.0,
        )

        hit = db.get_threat_intel("bad.example")
        rows = db.list_threat_intel(
            source="test-feed",
            category="malware",
        )

        self.assertIsNotNone(hit)
        self.assertEqual(hit["domain"], "bad.example")
        self.assertEqual(hit["confidence"], 95)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "bad.example")
        self.assertEqual(db.database_stats()["threat_intel"], 2)

    def test_active_threat_intel_uses_generation_entries(self) -> None:
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
                category="malware",
                confidence=92,
            )
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value="abc123",
            entries=["bad.example"],
            category="malware",
            confidence=92,
            etag="etag-a",
            last_modified="Mon, 01 Jan 2024 00:00:00 GMT",
        )

        hit = db.get_active_threat_intel("bad.example")

        self.assertIsNotNone(hit)
        self.assertEqual(hit["source"], "feed-a")
        self.assertEqual(hit["source_name"], "Feed A")
        self.assertEqual(hit["generation_id"], "gen_a")
        self.assertEqual(hit["confidence"], 92)

    def test_threat_intel_integrity_helper_reports_clean_state(self) -> None:
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
            )
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value="sha-a",
            entries=["bad.example"],
            category="malware",
            confidence=80,
            etag="etag-a",
        )

        self.assertEqual(db.check_threat_intel_integrity(), [])

    def test_threat_intel_integrity_helper_is_read_only(self) -> None:
        with patch("core.db.migrate_database", side_effect=AssertionError("mutated")):
            self.assertEqual(db.check_threat_intel_integrity(), [])

    def test_threat_intel_integrity_helper_reports_corruption(self) -> None:
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
            )
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value="sha-a",
            entries=["bad.example"],
            category="malware",
            confidence=80,
        )
        db.execute(
            """
            INSERT INTO threat_intel_generations
            (
                generation_id,
                source_id,
                status,
                content_sha256,
                entry_count,
                created_at,
                activated_at,
                previous_generation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("gen_b", "feed-a", "active", "sha-b", 1, 1.0, 1.0, "missing"),
        )
        db.execute(
            """
            UPDATE threat_intel_source_state
            SET remote_generation_id = ?, etag = ?
            WHERE source_id = ?
            """,
            ("missing-remote", "etag-a", "feed-a"),
        )
        db.execute(
            """
            INSERT INTO threat_intel_update_audit
            (
                source_id,
                attempted_at,
                result,
                active_generation,
                previous_generation
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            ("feed-a", 1.0, "success", "missing-active", "missing-previous"),
        )

        codes = {issue["code"] for issue in db.check_threat_intel_integrity()}

        self.assertIn("intel.integrity.multiple_active_generations", codes)
        self.assertIn("intel.integrity.remote_generation_missing", codes)
        self.assertIn("intel.integrity.generation_entry_count_mismatch", codes)
        self.assertIn("intel.integrity.rollback_pointer_missing", codes)
        self.assertIn("intel.integrity.audit_active_generation_missing", codes)
        self.assertIn("intel.integrity.audit_previous_generation_missing", codes)

    def test_threat_intel_generation_rollback_restores_previous_active_set(self) -> None:
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
            )
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_old",
            content_sha256_value="old",
            entries=["old.example"],
            category="malware",
            confidence=80,
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_new",
            content_sha256_value="new",
            entries=["new.example"],
            category="malware",
            confidence=80,
        )

        restored = db.rollback_intel_generation("feed-a")

        self.assertEqual(restored, "gen_old")
        self.assertIsNotNone(db.get_active_threat_intel("old.example"))
        self.assertIsNone(db.get_active_threat_intel("new.example"))

    def test_threat_intel_update_dry_run_does_not_mutate_generation_state_or_audit(self) -> None:
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
            )
        )

        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(
                status_code=200,
                content=b"bad.example\nother.example\n",
                etag="etag-a",
                last_modified="Mon, 01 Jan 2024 00:00:00 GMT",
                downloaded_bytes=26,
            ),
        ):
            result = update_source("feed-a", dry_run=True)

        self.assertTrue(result.success)
        self.assertTrue(result.dry_run)
        self.assertTrue(result.would_activate)
        self.assertEqual(result.active_generation, "")
        self.assertTrue(result.proposed_generation_id.startswith("gen_"))
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generations")["count"],
            0,
        )
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generation_entries")["count"],
            0,
        )
        state = db.get_intel_source_state("feed-a")
        self.assertEqual(state["active_generation"], "")
        self.assertEqual(state["etag"], "")
        self.assertEqual(db.list_intel_update_audit(), [])

    def test_identical_successful_update_does_not_activate_duplicate_generation(self) -> None:
        content = b"bad.example\nother.example\n"
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
            )
        )

        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(
                status_code=200,
                content=content,
                etag="etag-a",
                downloaded_bytes=len(content),
            ),
        ):
            first = update_source("feed-a")
        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(
                status_code=200,
                content=content,
                etag="etag-b",
                downloaded_bytes=len(content),
            ),
        ):
            second = update_source("feed-a")

        self.assertTrue(first.changed)
        self.assertFalse(second.changed)
        self.assertTrue(second.not_modified)
        self.assertTrue(second.content_unchanged)
        self.assertFalse(second.reused_generation)
        self.assertEqual(second.active_generation, first.active_generation)
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generations")["count"],
            1,
        )
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generation_entries")["count"],
            2,
        )

    def test_update_reactivates_inactive_generation_with_matching_content(self) -> None:
        content_a = b"a-one.example\na-two.example\n"
        content_b = b"b-one.example\nb-two.example\nb-three.example\n"
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
            )
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value=content_sha256(content_a),
            entries=["a-one.example", "a-two.example"],
            category="malware",
            confidence=80,
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_b",
            content_sha256_value=content_sha256(content_b),
            entries=["b-one.example", "b-two.example", "b-three.example"],
            category="malware",
            confidence=80,
        )
        self.assertEqual(db.rollback_intel_generation("feed-a"), "gen_a")

        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(
                status_code=200,
                content=content_b,
                etag="etag-b2",
                last_modified="Tue, 02 Jan 2024 00:00:00 GMT",
                downloaded_bytes=len(content_b),
            ),
        ):
            result = update_source("feed-a")

        self.assertTrue(result.changed)
        self.assertTrue(result.reused_generation)
        self.assertFalse(result.created_generation)
        self.assertFalse(result.not_modified)
        self.assertEqual(result.previous_generation, "gen_a")
        self.assertEqual(result.active_generation, "gen_b")
        state = db.get_intel_source_state("feed-a")
        self.assertEqual(state["active_generation"], "gen_b")
        self.assertEqual(state["etag"], "etag-b2")
        self.assertEqual(state["last_modified"], "Tue, 02 Jan 2024 00:00:00 GMT")
        self.assertEqual(state["consecutive_failures"], 0)
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generations")["count"],
            2,
        )
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generation_entries")["count"],
            5,
        )
        self.assertEqual(
            db.query_one(
                "SELECT COUNT(*) AS count FROM threat_intel_generations WHERE status = 'active'"
            )["count"],
            1,
        )
        self.assertEqual(
            db.query_one("SELECT status FROM threat_intel_generations WHERE generation_id = 'gen_a'")[
                "status"
            ],
            "inactive",
        )
        self.assertIsNotNone(db.get_active_threat_intel("b-three.example"))
        self.assertIsNone(db.get_active_threat_intel("a-one.example"))
        audit = db.list_intel_update_audit(limit=1, source_id="feed-a")[0]
        self.assertEqual(audit["operation"], "reactivate")
        self.assertEqual(audit["trigger"], "")
        self.assertTrue(audit["reused_generation"])
        self.assertFalse(audit["created_generation"])
        self.assertEqual(audit["previous_generation"], "gen_a")
        self.assertEqual(audit["active_generation"], "gen_b")
        self.assertEqual(audit["accepted_entries"], 3)

    def test_http_304_reactivates_remote_generation_after_rollback(self) -> None:
        content_a = b"a-one.example\na-two.example\n"
        content_b = b"b-one.example\nb-two.example\nb-three.example\n"
        db.save_intel_source(
            FeedSource(source_id="feed-a", name="Feed A", url="https://feeds.example/a.txt")
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value=content_sha256(content_a),
            entries=["a-one.example", "a-two.example"],
            category="malware",
            confidence=80,
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_b",
            content_sha256_value=content_sha256(content_b),
            entries=["b-one.example", "b-two.example", "b-three.example"],
            category="malware",
            confidence=80,
            etag="etag-b",
            last_modified="Tue, 02 Jan 2024 00:00:00 GMT",
        )
        self.assertEqual(db.rollback_intel_generation("feed-a"), "gen_a")
        state_after_rollback = db.get_intel_source_state("feed-a")
        self.assertEqual(state_after_rollback["active_generation"], "gen_a")
        self.assertEqual(state_after_rollback["remote_generation_id"], "gen_b")
        self.assertEqual(state_after_rollback["etag"], "etag-b")
        self.assertEqual(state_after_rollback["content_sha256"], content_sha256(content_b))

        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(
                status_code=304,
                content=b"",
                not_modified=True,
                etag="etag-b",
                last_modified="Tue, 02 Jan 2024 00:00:00 GMT",
                downloaded_bytes=0,
            ),
        ):
            result = update_source("feed-a")

        self.assertTrue(result.success)
        self.assertTrue(result.changed)
        self.assertTrue(result.not_modified)
        self.assertTrue(result.reused_generation)
        self.assertFalse(result.created_generation)
        self.assertFalse(result.content_unchanged)
        self.assertEqual(result.previous_generation, "gen_a")
        self.assertEqual(result.active_generation, "gen_b")
        self.assertEqual(result.remote_generation, "gen_b")
        state = db.get_intel_source_state("feed-a")
        self.assertEqual(state["active_generation"], "gen_b")
        self.assertEqual(state["remote_generation_id"], "gen_b")
        self.assertEqual(state["etag"], "etag-b")
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generations")["count"],
            2,
        )
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generation_entries")["count"],
            5,
        )
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generations WHERE status = 'active'")[
                "count"
            ],
            1,
        )
        self.assertIsNotNone(db.get_active_threat_intel("b-three.example"))
        audit = db.list_intel_update_audit(limit=1, source_id="feed-a")[0]
        self.assertEqual(audit["operation"], "reactivate")
        self.assertEqual(audit["trigger"], "http_not_modified")
        self.assertTrue(audit["changed"])
        self.assertTrue(audit["not_modified"])
        self.assertTrue(audit["reused_generation"])

        self.assertEqual(db.rollback_intel_generation("feed-a"), "gen_a")
        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(
                status_code=304,
                content=b"",
                not_modified=True,
                etag="etag-b",
                last_modified="Tue, 02 Jan 2024 00:00:00 GMT",
                downloaded_bytes=0,
            ),
        ):
            repeated = update_source("feed-a")

        self.assertTrue(repeated.reused_generation)
        self.assertEqual(repeated.active_generation, "gen_b")
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generations")["count"],
            2,
        )
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generation_entries")["count"],
            5,
        )

    def test_http_304_when_remote_generation_is_active_is_unchanged(self) -> None:
        db.save_intel_source(
            FeedSource(source_id="feed-a", name="Feed A", url="https://feeds.example/a.txt")
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value="sha-a",
            entries=["a.example"],
            category="malware",
            confidence=80,
            etag="etag-a",
        )

        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(status_code=304, content=b"", not_modified=True, etag="etag-a"),
        ):
            result = update_source("feed-a")

        self.assertTrue(result.success)
        self.assertFalse(result.changed)
        self.assertTrue(result.not_modified)
        self.assertTrue(result.content_unchanged)
        self.assertFalse(result.reused_generation)
        self.assertEqual(result.active_generation, "gen_a")
        self.assertEqual(result.remote_generation, "gen_a")

    def test_http_304_reactivation_can_infer_legacy_remote_generation_from_hash(self) -> None:
        content_a = b"a.example\n"
        content_b = b"b.example\n"
        db.save_intel_source(
            FeedSource(source_id="feed-a", name="Feed A", url="https://feeds.example/a.txt")
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value=content_sha256(content_a),
            entries=["a.example"],
            category="malware",
            confidence=80,
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_b",
            content_sha256_value=content_sha256(content_b),
            entries=["b.example"],
            category="malware",
            confidence=80,
            etag="etag-b",
        )
        db.rollback_intel_generation("feed-a")
        db.execute(
            "UPDATE threat_intel_source_state SET remote_generation_id = '' WHERE source_id = ?",
            ("feed-a",),
        )

        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(status_code=304, content=b"", not_modified=True, etag="etag-b"),
        ):
            result = update_source("feed-a")

        self.assertTrue(result.success)
        self.assertTrue(result.reused_generation)
        self.assertEqual(result.active_generation, "gen_b")

    def test_http_304_reactivation_can_recover_bad_remote_reference_from_audit(self) -> None:
        content_a = b"a.example\n"
        content_b = b"b.example\n"
        db.save_intel_source(
            FeedSource(source_id="feed-a", name="Feed A", url="https://feeds.example/a.txt")
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value=content_sha256(content_a),
            entries=["a.example"],
            category="malware",
            confidence=80,
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_b",
            content_sha256_value=content_sha256(content_b),
            entries=["b.example"],
            category="malware",
            confidence=80,
            etag="etag-b",
        )
        db.rollback_intel_generation("feed-a")
        db.execute(
            """
            UPDATE threat_intel_source_state
            SET remote_generation_id = ?, content_sha256 = ?
            WHERE source_id = ?
            """,
            ("gen_a", content_sha256(content_a), "feed-a"),
        )
        db.execute(
            """
            INSERT INTO threat_intel_update_audit
            (
                source_id,
                attempted_at,
                result,
                http_status,
                changed,
                not_modified,
                accepted_entries,
                previous_generation,
                active_generation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("feed-a", 1.0, "success", 200, 1, 0, 1, "gen_a", "gen_b"),
        )

        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(status_code=304, content=b"", not_modified=True, etag="etag-b"),
        ):
            result = update_source("feed-a")

        self.assertTrue(result.success)
        self.assertTrue(result.not_modified)
        self.assertTrue(result.reused_generation)
        self.assertEqual(result.active_generation, "gen_b")

    def test_http_304_missing_remote_reference_fails_safely(self) -> None:
        db.save_intel_source(
            FeedSource(source_id="feed-a", name="Feed A", url="https://feeds.example/a.txt")
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value="sha-a",
            entries=["a.example"],
            category="malware",
            confidence=80,
        )
        db.execute(
            """
            UPDATE threat_intel_source_state
            SET remote_generation_id = '', content_sha256 = ''
            WHERE source_id = ?
            """,
            ("feed-a",),
        )

        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(status_code=304, content=b"", not_modified=True),
        ):
            result = update_source("feed-a")

        self.assertFalse(result.success)
        self.assertEqual(result.error_code, "intel.generation.remote_reference_missing")
        self.assertEqual(db.get_intel_source_state("feed-a")["active_generation"], "gen_a")

    def test_http_304_cross_source_remote_reference_is_rejected(self) -> None:
        for source_id in ("feed-a", "feed-b"):
            db.save_intel_source(
                FeedSource(source_id=source_id, name=source_id, url=f"https://feeds.example/{source_id}.txt")
            )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value="sha-a",
            entries=["a.example"],
            category="malware",
            confidence=80,
        )
        db.activate_intel_generation(
            source_id="feed-b",
            generation_id="gen_b",
            content_sha256_value="sha-b",
            entries=["b.example"],
            category="malware",
            confidence=80,
        )
        db.execute(
            """
            UPDATE threat_intel_source_state
            SET remote_generation_id = ?, content_sha256 = ?
            WHERE source_id = ?
            """,
            ("gen_b", "sha-b", "feed-a"),
        )

        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(status_code=304, content=b"", not_modified=True),
        ):
            result = update_source("feed-a")

        self.assertFalse(result.success)
        self.assertEqual(result.error_code, "intel.generation.remote_reference_missing")
        self.assertEqual(db.get_intel_source_state("feed-a")["active_generation"], "gen_a")

    def test_repeated_ab_update_rollback_cycle_does_not_duplicate_generations(self) -> None:
        content_a = b"a-one.example\na-two.example\n"
        content_b = b"b-one.example\nb-two.example\nb-three.example\n"
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
            )
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value=content_sha256(content_a),
            entries=["a-one.example", "a-two.example"],
            category="malware",
            confidence=80,
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_b",
            content_sha256_value=content_sha256(content_b),
            entries=["b-one.example", "b-two.example", "b-three.example"],
            category="malware",
            confidence=80,
        )

        for _ in range(2):
            self.assertEqual(db.rollback_intel_generation("feed-a"), "gen_a")
            with patch(
                "pihole_ai.intel.fetch_feed",
                return_value=FetchResult(status_code=200, content=content_b, downloaded_bytes=len(content_b)),
            ):
                result = update_source("feed-a")
            self.assertTrue(result.reused_generation)
            self.assertEqual(result.active_generation, "gen_b")

        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generations")["count"],
            2,
        )
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generation_entries")["count"],
            5,
        )
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generations WHERE status = 'active'")[
                "count"
            ],
            1,
        )
        self.assertEqual(db.rollback_intel_generation("feed-a"), "gen_a")

    def test_matching_generation_from_other_source_or_staging_is_ignored(self) -> None:
        content_a = b"a.example\n"
        content_b = b"b.example\n"
        sha_b = content_sha256(content_b)
        for source_id in ("feed-a", "feed-b"):
            db.save_intel_source(
                FeedSource(
                    source_id=source_id,
                    name=source_id,
                    url=f"https://feeds.example/{source_id}.txt",
                )
            )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value=content_sha256(content_a),
            entries=["a.example"],
            category="malware",
            confidence=80,
        )
        db.activate_intel_generation(
            source_id="feed-b",
            generation_id="gen_other",
            content_sha256_value=sha_b,
            entries=["b.example"],
            category="malware",
            confidence=80,
        )
        db.execute(
            """
            INSERT INTO threat_intel_generations
            (
                generation_id,
                source_id,
                status,
                content_sha256,
                entry_count,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("gen_staging", "feed-a", "staging", sha_b, 1, 1.0),
        )

        with patch(
            "pihole_ai.intel.fetch_feed",
            return_value=FetchResult(status_code=200, content=content_b, downloaded_bytes=len(content_b)),
        ):
            result = update_source("feed-a")

        self.assertTrue(result.changed)
        self.assertFalse(result.reused_generation)
        self.assertTrue(result.created_generation)
        self.assertNotIn(result.active_generation, {"gen_other", "gen_staging"})

    def test_reactivation_transaction_rollback_leaves_original_active(self) -> None:
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
            )
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value="sha-a",
            entries=["a.example"],
            category="malware",
            confidence=80,
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_b",
            content_sha256_value="sha-b",
            entries=["b.example"],
            category="malware",
            confidence=80,
        )
        db.rollback_intel_generation("feed-a")

        with self.assertRaises(ValueError):
            db.activate_existing_threat_intel_generation(
                source_id="feed-a",
                generation_id="gen_b",
                previous_generation_id="not-current",
            )

        state = db.get_intel_source_state("feed-a")
        self.assertEqual(state["active_generation"], "gen_a")
        self.assertEqual(
            db.query_one("SELECT status FROM threat_intel_generations WHERE generation_id = 'gen_a'")[
                "status"
            ],
            "active",
        )

    def test_source_update_preserves_generations_and_clears_validators_for_url_change(self) -> None:
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
            )
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value="sha-a",
            entries=["a.example"],
            category="malware",
            confidence=80,
            etag="etag-a",
            last_modified="Mon, 01 Jan 2024 00:00:00 GMT",
        )
        before = db.get_intel_source("feed-a")

        updated = db.update_threat_intel_source(
            "feed-a",
            {"url": "https://feeds.example/b.txt"},
        )

        self.assertIsNotNone(updated)
        self.assertEqual(updated["source_id"], "feed-a")
        self.assertEqual(updated["active_generation"], "gen_a")
        self.assertTrue(updated["generations_preserved"])
        self.assertTrue(updated["validators_cleared"])
        self.assertGreater(updated["updated_at"], before["updated_at"])
        state = db.get_intel_source_state("feed-a")
        self.assertEqual(state["active_generation"], "gen_a")
        self.assertEqual(state["etag"], "")
        self.assertEqual(state["last_modified"], "")
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generations")["count"],
            1,
        )
        self.assertEqual(
            db.query_one("SELECT COUNT(*) AS count FROM threat_intel_generation_entries")["count"],
            1,
        )

    def test_source_update_preserves_validators_for_display_metadata_change(self) -> None:
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
            )
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value="sha-a",
            entries=["a.example"],
            category="malware",
            confidence=80,
            etag="etag-a",
            last_modified="Mon, 01 Jan 2024 00:00:00 GMT",
        )

        updated = db.update_threat_intel_source("feed-a", {"name": "Feed Alpha"})

        self.assertFalse(updated["validators_cleared"])
        state = db.get_intel_source_state("feed-a")
        self.assertEqual(state["etag"], "etag-a")
        self.assertEqual(state["last_modified"], "Mon, 01 Jan 2024 00:00:00 GMT")
        self.assertEqual(db.get_intel_source("feed-a")["name"], "Feed Alpha")

    def test_source_update_keeps_rollback_working(self) -> None:
        db.save_intel_source(
            FeedSource(
                source_id="feed-a",
                name="Feed A",
                url="https://feeds.example/a.txt",
            )
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_a",
            content_sha256_value="sha-a",
            entries=["a.example"],
            category="malware",
            confidence=80,
        )
        db.activate_intel_generation(
            source_id="feed-a",
            generation_id="gen_b",
            content_sha256_value="sha-b",
            entries=["b.example"],
            category="malware",
            confidence=80,
        )

        db.update_threat_intel_source("feed-a", {"url": "https://feeds.example/b.txt"})
        restored = db.rollback_intel_generation("feed-a")

        self.assertEqual(restored, "gen_a")
        self.assertEqual(db.get_intel_source("feed-a")["url"], "https://feeds.example/b.txt")
        self.assertIsNotNone(db.get_active_threat_intel("a.example"))


class DatabaseMigrationTests(unittest.TestCase):
    def test_init_db_rejects_malformed_legacy_analysis_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            database_path = Path(tmpdir) / "legacy.db"

            with closing(sqlite3.connect(database_path)) as conn:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE analysis (
                            domain TEXT PRIMARY KEY,
                            risk INTEGER,
                            category TEXT,
                            reason TEXT,
                            model TEXT,
                            analyzed_at REAL
                        )
                        """
                    )

            with patch.object(db, "DATABASE_PATH", database_path):
                with self.assertRaises(IncompatibleSchema):
                    db.init_db()


if __name__ == "__main__":
    unittest.main()
