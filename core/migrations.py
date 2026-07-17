"""
Explicit SQLite migrations for the PiHole-AI events database.
"""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from core.logger import get_logger
from core.sqlite_policy import (
    SQLiteAccessMode,
    SQLiteBusyError,
    SQLiteConnectionFactory,
    configured_busy_timeout_ms,
    is_busy_error,
)


logger = get_logger(__name__)

MIGRATION_TABLE = "schema_migrations"
class MigrationError(RuntimeError):
    """
    Base migration failure.
    """


class IncompatibleSchema(MigrationError):
    """
    Existing database schema cannot be safely adopted.
    """


class UnsupportedSchemaVersion(MigrationError):
    """
    Database was created by a newer PiHole-AI version.
    """


class ReadOnlyDatabaseUnavailable(MigrationError):
    """
    Existing database could not be opened for read-only inspection.
    """


class MigrationLockError(MigrationError):
    """
    Migration could not acquire the required SQLite write lock.
    """

    def __init__(
        self,
        migration_version: int,
    ) -> None:
        super().__init__(
            "Database migration could not acquire the required SQLite lock. "
            "Stop PiHole-AI services or retry shortly, then run "
            "'sudo pihole-ai upgrade'."
        )
        self.migration_version = migration_version


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


@dataclass(frozen=True)
class AppliedMigration:
    version: int
    name: str


@dataclass(frozen=True)
class MigrationResult:
    version_before: int
    version_after: int
    applied_migrations: list[AppliedMigration]
    changed: bool


@dataclass(frozen=True)
class DatabaseStatus:
    database_path: str
    current_schema_version: int
    latest_supported_schema_version: int
    pending_migration_count: int
    database_file_size: int
    compatible: bool
    journal_mode: str | None = None
    busy_timeout_ms: int = 0
    wal_file_size: int = 0
    read_only_ok: bool = False
    write_open_ok: bool = False


BASELINE_TABLE_COLUMNS = {
    "events": {"id", "device", "domain", "timestamp", "processed"},
    "domain_memory": {"domain", "first_seen", "last_seen", "query_count"},
    "analysis": {
        "domain",
        "risk",
        "confidence",
        "category",
        "reason",
        "model",
        "analyzed_at",
    },
    "app_state": {"key", "value"},
    "action_audit": {
        "id",
        "domain",
        "action",
        "source",
        "status",
        "reason",
        "risk",
        "created_at",
    },
    "domain_rules": {
        "domain",
        "decision",
        "source",
        "reason",
        "enabled",
        "created_at",
        "updated_at",
    },
    "domain_reputation": {
        "domain",
        "score",
        "confidence",
        "signals",
        "source",
        "updated_at",
    },
    "threat_intel": {
        "domain",
        "source",
        "category",
        "confidence",
        "first_seen",
        "last_seen",
    },
}


BASELINE_SCHEMA_SQL = [
    """
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device TEXT NOT NULL,
        domain TEXT NOT NULL,
        timestamp REAL NOT NULL,
        processed INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS domain_memory (
        domain TEXT PRIMARY KEY,
        first_seen REAL,
        last_seen REAL,
        query_count INTEGER DEFAULT 1
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS analysis (
        domain TEXT PRIMARY KEY,
        risk INTEGER,
        confidence INTEGER DEFAULT 0,
        category TEXT,
        reason TEXT,
        model TEXT,
        analyzed_at REAL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS app_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS action_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        action TEXT NOT NULL,
        source TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT,
        risk INTEGER,
        created_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS domain_rules (
        domain TEXT PRIMARY KEY,
        decision TEXT NOT NULL,
        source TEXT NOT NULL,
        reason TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS domain_reputation (
        domain TEXT PRIMARY KEY,
        score INTEGER NOT NULL,
        confidence INTEGER NOT NULL,
        signals TEXT NOT NULL,
        source TEXT NOT NULL,
        updated_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS threat_intel (
        domain TEXT NOT NULL,
        source TEXT NOT NULL,
        category TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        first_seen REAL NOT NULL,
        last_seen REAL NOT NULL,
        PRIMARY KEY (domain, source)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed)",
    "CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain)",
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_analysis_risk ON analysis(risk)",
    "CREATE INDEX IF NOT EXISTS idx_action_audit_created_at ON action_audit(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_action_audit_domain ON action_audit(domain)",
    "CREATE INDEX IF NOT EXISTS idx_domain_rules_decision ON domain_rules(decision)",
    "CREATE INDEX IF NOT EXISTS idx_domain_rules_enabled ON domain_rules(enabled)",
    "CREATE INDEX IF NOT EXISTS idx_domain_reputation_score ON domain_reputation(score)",
    "CREATE INDEX IF NOT EXISTS idx_threat_intel_domain ON threat_intel(domain)",
    "CREATE INDEX IF NOT EXISTS idx_threat_intel_source ON threat_intel(source)",
]


def _apply_baseline(conn: sqlite3.Connection) -> None:
    existing = _application_tables(conn)

    if existing:
        _verify_baseline_compatible(conn)

    for statement in BASELINE_SCHEMA_SQL:
        conn.execute(statement)


def _apply_decision_evidence(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS decision_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            classifier TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            polarity TEXT NOT NULL,
            score REAL NOT NULL,
            confidence REAL NOT NULL,
            summary TEXT NOT NULL,
            details TEXT,
            metadata_json TEXT NOT NULL,
            decisive INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_decision_evidence_domain
        ON decision_evidence(domain)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_decision_evidence_classifier
        ON decision_evidence(classifier)
        """
    )


def _apply_decision_records(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS decision_records (
            domain TEXT PRIMARY KEY,
            verdict TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            confidence REAL NOT NULL,
            category TEXT NOT NULL,
            source TEXT NOT NULL,
            explanation TEXT NOT NULL,
            decisive_evidence_ids_json TEXT NOT NULL,
            classifier_trace_json TEXT NOT NULL,
            conflicts_json TEXT NOT NULL,
            legacy INTEGER NOT NULL DEFAULT 0,
            policy_version TEXT NOT NULL,
            application_version TEXT,
            schema_version INTEGER,
            evidence_truncated INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )
        """
    )


def _apply_action_decision_ref(conn: sqlite3.Connection) -> None:
    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(action_audit)")
    }
    if "decision_ref" not in columns:
        conn.execute(
            """
            ALTER TABLE action_audit
            ADD COLUMN decision_ref TEXT
            """
        )


def _apply_immutable_decision_history(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS decision_history (
            decision_id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            analysis_id INTEGER,
            verdict TEXT NOT NULL,
            risk_score REAL NOT NULL,
            confidence REAL NOT NULL,
            category TEXT,
            source TEXT,
            explanation TEXT,
            decisive_evidence_ids_json TEXT NOT NULL DEFAULT '[]',
            classifier_trace_json TEXT NOT NULL DEFAULT '[]',
            conflicts_json TEXT NOT NULL DEFAULT '[]',
            policy_version TEXT NOT NULL,
            application_version TEXT NOT NULL DEFAULT '',
            schema_version INTEGER,
            trigger TEXT NOT NULL DEFAULT 'unknown',
            supersedes_decision_id TEXT,
            evidence_truncated INTEGER NOT NULL DEFAULT 0,
            legacy INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            FOREIGN KEY (supersedes_decision_id)
                REFERENCES decision_history(decision_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS decision_history_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            classifier TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            polarity TEXT NOT NULL,
            score REAL NOT NULL,
            confidence REAL NOT NULL,
            summary TEXT NOT NULL,
            details TEXT,
            metadata_json TEXT NOT NULL,
            decisive INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            UNIQUE(decision_id, evidence_id),
            FOREIGN KEY (decision_id)
                REFERENCES decision_history(decision_id)
                ON DELETE CASCADE
        )
        """
    )
    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_decision_history_domain_created ON decision_history(domain, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_decision_history_analysis_id ON decision_history(analysis_id)",
        "CREATE INDEX IF NOT EXISTS idx_decision_history_supersedes ON decision_history(supersedes_decision_id)",
        "CREATE INDEX IF NOT EXISTS idx_decision_history_verdict ON decision_history(verdict)",
        "CREATE INDEX IF NOT EXISTS idx_decision_history_policy ON decision_history(policy_version)",
        "CREATE INDEX IF NOT EXISTS idx_decision_history_evidence_decision ON decision_history_evidence(decision_id)",
    ):
        conn.execute(statement)

    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(decision_records)")
    }
    if "decision_id" not in columns:
        conn.execute("ALTER TABLE decision_records ADD COLUMN decision_id TEXT")

    existing = conn.execute(
        """
        SELECT *
        FROM decision_records
        WHERE decision_id IS NULL
        """
    ).fetchall()
    for row in existing:
        decision_id = f"dec_{uuid.uuid4().hex}"
        conn.execute(
            """
            INSERT OR IGNORE INTO decision_history
            (
                decision_id,
                domain,
                verdict,
                risk_score,
                confidence,
                category,
                source,
                explanation,
                decisive_evidence_ids_json,
                classifier_trace_json,
                conflicts_json,
                policy_version,
                application_version,
                schema_version,
                trigger,
                evidence_truncated,
                legacy,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision_id,
                row["domain"],
                row["verdict"],
                row["risk_score"],
                row["confidence"],
                row["category"],
                row["source"],
                row["explanation"],
                row["decisive_evidence_ids_json"],
                row["classifier_trace_json"],
                row["conflicts_json"],
                row["policy_version"],
                row["application_version"] or "",
                row["schema_version"],
                "unknown",
                row["evidence_truncated"],
                1,
                row["created_at"],
            ),
        )
        evidence_rows = conn.execute(
            """
            SELECT *
            FROM decision_evidence
            WHERE domain = ?
            ORDER BY id ASC
            """,
            (row["domain"],),
        ).fetchall()
        conn.executemany(
            """
            INSERT OR IGNORE INTO decision_history_evidence
            (
                decision_id,
                evidence_id,
                classifier,
                evidence_type,
                polarity,
                score,
                confidence,
                summary,
                details,
                metadata_json,
                decisive,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    decision_id,
                    evidence["evidence_id"],
                    evidence["classifier"],
                    evidence["evidence_type"],
                    evidence["polarity"],
                    evidence["score"],
                    evidence["confidence"],
                    evidence["summary"],
                    evidence["details"],
                    evidence["metadata_json"],
                    evidence["decisive"],
                    evidence["created_at"],
                )
                for evidence in evidence_rows
            ],
        )
        conn.execute(
            """
            UPDATE decision_records
            SET decision_id = ?
            WHERE domain = ?
            """,
            (decision_id, row["domain"]),
        )
        legacy_ref = f"decision:{row['domain']}:{row['created_at']}"
        conn.execute(
            """
            UPDATE action_audit
            SET decision_ref = ?
            WHERE decision_ref = ?
            """,
            (decision_id, legacy_ref),
        )


def _apply_threat_intel_feed_management(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_intel_sources (
            source_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            format TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            category TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            refresh_interval_seconds INTEGER NOT NULL,
            stale_after_seconds INTEGER NOT NULL,
            timeout_seconds INTEGER NOT NULL,
            max_download_bytes INTEGER NOT NULL,
            expected_content_type TEXT NOT NULL DEFAULT '',
            allow_http INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_intel_source_state (
            source_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'unknown',
            last_attempt_at REAL,
            last_success_at REAL,
            next_update_at REAL,
            etag TEXT NOT NULL DEFAULT '',
            last_modified TEXT NOT NULL DEFAULT '',
            content_sha256 TEXT NOT NULL DEFAULT '',
            entry_count INTEGER NOT NULL DEFAULT 0,
            active_generation TEXT NOT NULL DEFAULT '',
            last_error_code TEXT NOT NULL DEFAULT '',
            last_error_summary TEXT NOT NULL DEFAULT '',
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (source_id)
                REFERENCES threat_intel_sources(source_id)
                ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_intel_generations (
            generation_id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            status TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            entry_count INTEGER NOT NULL,
            created_at REAL NOT NULL,
            activated_at REAL,
            previous_generation TEXT,
            FOREIGN KEY (source_id)
                REFERENCES threat_intel_sources(source_id)
                ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_intel_generation_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            generation_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            category TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            UNIQUE(generation_id, domain),
            FOREIGN KEY (generation_id)
                REFERENCES threat_intel_generations(generation_id)
                ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_intel_update_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id TEXT NOT NULL,
            attempted_at REAL NOT NULL,
            result TEXT NOT NULL,
            http_status INTEGER,
            changed INTEGER NOT NULL DEFAULT 0,
            not_modified INTEGER NOT NULL DEFAULT 0,
            downloaded_bytes INTEGER NOT NULL DEFAULT 0,
            parsed_entries INTEGER NOT NULL DEFAULT 0,
            accepted_entries INTEGER NOT NULL DEFAULT 0,
            rejected_entries INTEGER NOT NULL DEFAULT 0,
            duplicate_entries INTEGER NOT NULL DEFAULT 0,
            previous_generation TEXT NOT NULL DEFAULT '',
            active_generation TEXT NOT NULL DEFAULT '',
            duration_ms INTEGER NOT NULL DEFAULT 0,
            warnings_json TEXT NOT NULL DEFAULT '[]',
            error_code TEXT NOT NULL DEFAULT '',
            error_summary TEXT NOT NULL DEFAULT ''
        )
        """
    )
    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_threat_intel_sources_enabled ON threat_intel_sources(enabled)",
        "CREATE INDEX IF NOT EXISTS idx_threat_intel_entries_domain ON threat_intel_generation_entries(domain)",
        "CREATE INDEX IF NOT EXISTS idx_threat_intel_entries_source ON threat_intel_generation_entries(source_id)",
        "CREATE INDEX IF NOT EXISTS idx_threat_intel_generations_source ON threat_intel_generations(source_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_threat_intel_update_audit_source ON threat_intel_update_audit(source_id, attempted_at DESC)",
    ):
        conn.execute(statement)

    legacy_count = conn.execute(
        "SELECT COUNT(*) AS count FROM threat_intel"
    ).fetchone()["count"]
    if legacy_count:
        now = datetime.now(timezone.utc).timestamp()
        source_id = "legacy-manual"
        generation_id = "gen_legacy_manual"
        conn.execute(
            """
            INSERT OR IGNORE INTO threat_intel_sources
            (
                source_id,
                name,
                url,
                format,
                enabled,
                category,
                confidence,
                refresh_interval_seconds,
                stale_after_seconds,
                timeout_seconds,
                max_download_bytes,
                expected_content_type,
                allow_http,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                "Legacy manual imports",
                "manual://legacy",
                "hosts",
                1,
                "malware",
                90,
                86400,
                31536000,
                20,
                2000000,
                "",
                0,
                now,
                now,
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO threat_intel_generations
            (
                generation_id,
                source_id,
                status,
                content_sha256,
                entry_count,
                created_at,
                activated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (generation_id, source_id, "active", "legacy", legacy_count, now, now),
        )
        rows = conn.execute("SELECT * FROM threat_intel").fetchall()
        conn.executemany(
            """
            INSERT OR IGNORE INTO threat_intel_generation_entries
            (
                generation_id,
                source_id,
                domain,
                category,
                confidence,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    generation_id,
                    source_id,
                    row["domain"],
                    row["category"],
                    row["confidence"],
                    row["first_seen"],
                    row["last_seen"],
                )
                for row in rows
            ],
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO threat_intel_source_state
            (
                source_id,
                status,
                last_attempt_at,
                last_success_at,
                next_update_at,
                entry_count,
                active_generation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (source_id, "active", now, now, None, legacy_count, generation_id),
        )


def _apply_threat_intel_reactivation_audit(conn: sqlite3.Connection) -> None:
    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(threat_intel_update_audit)")
    }
    additions = {
        "operation": "TEXT NOT NULL DEFAULT 'update'",
        "reused_generation": "INTEGER NOT NULL DEFAULT 0",
        "created_generation": "INTEGER NOT NULL DEFAULT 0",
        "content_unchanged": "INTEGER NOT NULL DEFAULT 0",
    }
    for column, definition in additions.items():
        if column not in columns:
            conn.execute(
                f"ALTER TABLE threat_intel_update_audit ADD COLUMN {column} {definition}"
            )


def _apply_threat_intel_remote_generation_state(conn: sqlite3.Connection) -> None:
    state_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(threat_intel_source_state)")
    }
    if "remote_generation_id" not in state_columns:
        conn.execute(
            """
            ALTER TABLE threat_intel_source_state
            ADD COLUMN remote_generation_id TEXT NOT NULL DEFAULT ''
            """
        )

    audit_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(threat_intel_update_audit)")
    }
    if "trigger" not in audit_columns:
        conn.execute(
            """
            ALTER TABLE threat_intel_update_audit
            ADD COLUMN trigger TEXT NOT NULL DEFAULT ''
            """
        )

    states = conn.execute(
        """
        SELECT source_id, content_sha256
        FROM threat_intel_source_state
        WHERE content_sha256 != ''
          AND remote_generation_id = ''
        """
    ).fetchall()
    for state in states:
        matches = conn.execute(
            """
            SELECT
                g.generation_id,
                COUNT(e.id) AS stored_entry_count
            FROM threat_intel_generations g
            LEFT JOIN threat_intel_generation_entries e
                ON e.generation_id = g.generation_id
            WHERE g.source_id = ?
              AND g.content_sha256 = ?
              AND g.status IN ('active', 'inactive')
              AND g.activated_at IS NOT NULL
            GROUP BY g.generation_id, g.entry_count
            HAVING stored_entry_count = g.entry_count
            """,
            (state["source_id"], state["content_sha256"]),
        ).fetchall()
        if len(matches) == 1:
            conn.execute(
                """
                UPDATE threat_intel_source_state
                SET remote_generation_id = ?
                WHERE source_id = ?
                """,
                (matches[0]["generation_id"], state["source_id"]),
            )


def _valid_generation_for_source(
    conn: sqlite3.Connection,
    source_id: str,
    generation_id: str,
) -> sqlite3.Row | None:
    if not generation_id:
        return None
    return conn.execute(
        """
        SELECT
            g.generation_id,
            g.source_id,
            g.status,
            g.content_sha256,
            g.entry_count,
            g.activated_at,
            COUNT(e.id) AS stored_entry_count
        FROM threat_intel_generations g
        LEFT JOIN threat_intel_generation_entries e
            ON e.generation_id = g.generation_id
        WHERE g.source_id = ?
          AND g.generation_id = ?
          AND g.status IN ('active', 'inactive')
          AND g.activated_at IS NOT NULL
        GROUP BY
            g.generation_id,
            g.source_id,
            g.status,
            g.content_sha256,
            g.entry_count,
            g.activated_at
        HAVING stored_entry_count = g.entry_count
        """,
        (source_id, generation_id),
    ).fetchone()


def _latest_successful_http_generation(
    conn: sqlite3.Connection,
    source_id: str,
) -> sqlite3.Row | None:
    audits = conn.execute(
        """
        SELECT active_generation
        FROM threat_intel_update_audit
        WHERE source_id = ?
          AND result = 'success'
          AND http_status = 200
          AND active_generation != ''
          AND COALESCE(operation, 'update') != 'rollback'
          AND COALESCE(error_code, '') = ''
        ORDER BY attempted_at DESC, id DESC
        """,
        (source_id,),
    ).fetchall()
    for audit in audits:
        generation = _valid_generation_for_source(
            conn,
            source_id,
            audit["active_generation"],
        )
        if generation is not None:
            return generation
    return None


def _apply_repair_remote_generation_identity(conn: sqlite3.Connection) -> None:
    states = conn.execute(
        """
        SELECT source_id, active_generation, remote_generation_id
        FROM threat_intel_source_state
        """
    ).fetchall()
    for state in states:
        source_id = state["source_id"]
        active_generation = state["active_generation"] or ""
        remote_generation = state["remote_generation_id"] or ""
        candidate = _latest_successful_http_generation(conn, source_id)
        if candidate is None:
            continue

        current = _valid_generation_for_source(conn, source_id, remote_generation)
        should_repair = remote_generation == "" or current is None
        should_repair = should_repair or (
            remote_generation == active_generation
            and candidate["generation_id"] != active_generation
        )
        if not should_repair:
            continue

        conn.execute(
            """
            UPDATE threat_intel_source_state
            SET remote_generation_id = ?,
                content_sha256 = ?
            WHERE source_id = ?
            """,
            (candidate["generation_id"], candidate["content_sha256"], source_id),
        )


def _apply_threat_intel_operational_metadata(conn: sqlite3.Connection) -> None:
    state_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(threat_intel_source_state)")
    }
    state_additions = {
        "last_http_status": "INTEGER",
        "last_downloaded_bytes": "INTEGER NOT NULL DEFAULT 0",
        "last_parsed_entries": "INTEGER NOT NULL DEFAULT 0",
        "last_accepted_entries": "INTEGER NOT NULL DEFAULT 0",
        "last_rejected_entries": "INTEGER NOT NULL DEFAULT 0",
        "last_duplicate_entries": "INTEGER NOT NULL DEFAULT 0",
        "last_warnings_json": "TEXT NOT NULL DEFAULT '[]'",
        "last_update_duration_ms": "INTEGER NOT NULL DEFAULT 0",
    }
    for column, definition in state_additions.items():
        if column not in state_columns:
            conn.execute(
                f"ALTER TABLE threat_intel_source_state ADD COLUMN {column} {definition}"
            )

    entry_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(threat_intel_generation_entries)")
    }
    if "expires_at" not in entry_columns:
        conn.execute(
            "ALTER TABLE threat_intel_generation_entries ADD COLUMN expires_at REAL"
        )

    generation_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(threat_intel_generations)")
    }
    if "pruned_at" not in generation_columns:
        conn.execute(
            "ALTER TABLE threat_intel_generations ADD COLUMN pruned_at REAL"
        )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_threat_intel_entries_expires_at
        ON threat_intel_generation_entries(expires_at)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_threat_intel_state_status
        ON threat_intel_source_state(status, last_success_at)
        """
    )

    conn.execute(
        """
        UPDATE threat_intel_source_state
        SET
            last_http_status = (
                SELECT audit.http_status
                FROM threat_intel_update_audit audit
                WHERE audit.source_id = threat_intel_source_state.source_id
                ORDER BY audit.attempted_at DESC, audit.id DESC
                LIMIT 1
            ),
            last_downloaded_bytes = COALESCE((
                SELECT audit.downloaded_bytes
                FROM threat_intel_update_audit audit
                WHERE audit.source_id = threat_intel_source_state.source_id
                ORDER BY audit.attempted_at DESC, audit.id DESC
                LIMIT 1
            ), last_downloaded_bytes),
            last_parsed_entries = COALESCE((
                SELECT audit.parsed_entries
                FROM threat_intel_update_audit audit
                WHERE audit.source_id = threat_intel_source_state.source_id
                ORDER BY audit.attempted_at DESC, audit.id DESC
                LIMIT 1
            ), last_parsed_entries),
            last_accepted_entries = COALESCE((
                SELECT audit.accepted_entries
                FROM threat_intel_update_audit audit
                WHERE audit.source_id = threat_intel_source_state.source_id
                ORDER BY audit.attempted_at DESC, audit.id DESC
                LIMIT 1
            ), last_accepted_entries),
            last_rejected_entries = COALESCE((
                SELECT audit.rejected_entries
                FROM threat_intel_update_audit audit
                WHERE audit.source_id = threat_intel_source_state.source_id
                ORDER BY audit.attempted_at DESC, audit.id DESC
                LIMIT 1
            ), last_rejected_entries),
            last_duplicate_entries = COALESCE((
                SELECT audit.duplicate_entries
                FROM threat_intel_update_audit audit
                WHERE audit.source_id = threat_intel_source_state.source_id
                ORDER BY audit.attempted_at DESC, audit.id DESC
                LIMIT 1
            ), last_duplicate_entries),
            last_warnings_json = COALESCE((
                SELECT audit.warnings_json
                FROM threat_intel_update_audit audit
                WHERE audit.source_id = threat_intel_source_state.source_id
                ORDER BY audit.attempted_at DESC, audit.id DESC
                LIMIT 1
            ), last_warnings_json),
            last_update_duration_ms = COALESCE((
                SELECT audit.duration_ms
                FROM threat_intel_update_audit audit
                WHERE audit.source_id = threat_intel_source_state.source_id
                ORDER BY audit.attempted_at DESC, audit.id DESC
                LIMIT 1
            ), last_update_duration_ms)
        """
    )


MIGRATIONS = [
    Migration(
        version=1,
        name="baseline_current_schema",
        apply=_apply_baseline,
    ),
    Migration(
        version=2,
        name="decision_evidence",
        apply=_apply_decision_evidence,
    ),
    Migration(
        version=3,
        name="decision_records",
        apply=_apply_decision_records,
    ),
    Migration(
        version=4,
        name="action_audit_decision_ref",
        apply=_apply_action_decision_ref,
    ),
    Migration(
        version=5,
        name="immutable_decision_history",
        apply=_apply_immutable_decision_history,
    ),
    Migration(
        version=6,
        name="threat_intel_feed_management",
        apply=_apply_threat_intel_feed_management,
    ),
    Migration(
        version=7,
        name="threat_intel_reactivation_audit",
        apply=_apply_threat_intel_reactivation_audit,
    ),
    Migration(
        version=8,
        name="threat_intel_remote_generation_state",
        apply=_apply_threat_intel_remote_generation_state,
    ),
    Migration(
        version=9,
        name="repair_remote_generation_identity",
        apply=_apply_repair_remote_generation_identity,
    ),
    Migration(
        version=10,
        name="threat_intel_operational_metadata",
        apply=_apply_threat_intel_operational_metadata,
    ),
]

LATEST_SUPPORTED_SCHEMA_VERSION = MIGRATIONS[-1].version


def open_database(
    database_path: str | Path,
) -> sqlite3.Connection:
    return SQLiteConnectionFactory.connect(
        database_path,
        SQLiteAccessMode.MIGRATION,
    )


def open_database_readonly(
    database_path: str | Path,
) -> sqlite3.Connection:
    """
    Open an existing SQLite database without creating or modifying it.
    """

    path = Path(database_path)

    if not path.exists():
        raise FileNotFoundError(path)

    return SQLiteConnectionFactory.connect(
        path,
        SQLiteAccessMode.READ_ONLY,
    )


def ensure_migration_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )


def current_schema_version(
    conn: sqlite3.Connection,
) -> int:
    if not _table_exists(conn, MIGRATION_TABLE):
        return 0

    row = conn.execute(
        "SELECT MAX(version) AS version FROM schema_migrations"
    ).fetchone()

    return int(row["version"] or 0)


def pending_migrations(
    current_version: int,
) -> list[Migration]:
    return [
        migration
        for migration in MIGRATIONS
        if migration.version > current_version
    ]


def migrate_database(
    database_path: str | Path,
) -> MigrationResult:
    with closing(open_database(database_path)) as conn:
        return migrate_connection(conn)


def migrate_connection(
    conn: sqlite3.Connection,
) -> MigrationResult:
    logger.info("Starting database migration.")
    conn.execute(f"PRAGMA busy_timeout = {configured_busy_timeout_ms()}")
    ensure_migration_table(conn)
    conn.commit()

    before = current_schema_version(conn)
    _raise_if_future_schema(before)
    applied: list[AppliedMigration] = []

    for migration in pending_migrations(before):
        logger.info(
            "Applying database migration %s: %s",
            migration.version,
            migration.name,
        )

        try:
            conn.execute("BEGIN IMMEDIATE")
            migration.apply(conn)
            conn.execute(
                """
                INSERT INTO schema_migrations
                (
                    version,
                    name,
                    applied_at
                )
                VALUES (?, ?, ?)
                """,
                (
                    migration.version,
                    migration.name,
                    _utc_now(),
                ),
            )
            conn.commit()

        except Exception as exc:
            conn.rollback()
            if isinstance(exc, SQLiteBusyError) or is_busy_error(exc):
                logger.warning(
                    "Database migration could not acquire required SQLite lock.",
                    extra={
                        "database_path": "configured events database",
                        "migration_version": migration.version,
                    },
                )
                raise MigrationLockError(migration.version) from exc
            logger.exception(
                "Database migration %s failed.",
                migration.version,
            )
            raise

        applied.append(
            AppliedMigration(
                version=migration.version,
                name=migration.name,
            )
        )

    after = current_schema_version(conn)
    logger.info("Database migration complete at version %s.", after)

    return MigrationResult(
        version_before=before,
        version_after=after,
        applied_migrations=applied,
        changed=bool(applied),
    )


def database_status(
    database_path: str | Path,
) -> DatabaseStatus:
    path = Path(database_path)

    if not path.exists():
        return DatabaseStatus(
            database_path=str(path),
            current_schema_version=0,
            latest_supported_schema_version=LATEST_SUPPORTED_SCHEMA_VERSION,
            pending_migration_count=len(MIGRATIONS),
            database_file_size=0,
            compatible=True,
            busy_timeout_ms=0,
            wal_file_size=0,
            read_only_ok=False,
            write_open_ok=False,
        )

    with closing(open_database_readonly(path)) as conn:
        current = current_schema_version(conn)
        _raise_if_future_schema(current)

        if current == 0 and _application_tables(conn):
            _verify_baseline_compatible(conn)

        compatible = True

    pending = len(pending_migrations(current))
    file_size = path.stat().st_size if path.exists() else 0
    diagnostics = SQLiteConnectionFactory.diagnostics(path)

    return DatabaseStatus(
        database_path=str(path),
        current_schema_version=current,
        latest_supported_schema_version=LATEST_SUPPORTED_SCHEMA_VERSION,
        pending_migration_count=pending,
        database_file_size=file_size,
        compatible=compatible,
        journal_mode=diagnostics.journal_mode,
        busy_timeout_ms=diagnostics.busy_timeout_ms,
        wal_file_size=diagnostics.wal_file_size,
        read_only_ok=diagnostics.read_only_ok,
        write_open_ok=diagnostics.write_open_ok,
    )


def migration_history(
    conn: sqlite3.Connection,
) -> list[sqlite3.Row]:
    ensure_migration_table(conn)
    return conn.execute(
        """
        SELECT version, name, applied_at
        FROM schema_migrations
        ORDER BY version ASC
        """
    ).fetchall()


def _raise_if_future_schema(
    version: int,
) -> None:
    if version > LATEST_SUPPORTED_SCHEMA_VERSION:
        raise UnsupportedSchemaVersion(
            "Database was created by a newer PiHole-AI version."
        )


def _application_tables(
    conn: sqlite3.Connection,
) -> set[str]:
    rows = conn.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
          AND name != ?
        """,
        (MIGRATION_TABLE,),
    ).fetchall()
    return {str(row["name"]) for row in rows}


def _table_exists(
    conn: sqlite3.Connection,
    table: str,
) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        """,
        (table,),
    ).fetchone()
    return row is not None


def _verify_baseline_compatible(
    conn: sqlite3.Connection,
) -> None:
    existing = _application_tables(conn)
    required_tables = set(BASELINE_TABLE_COLUMNS)
    missing_tables = required_tables - existing

    if missing_tables:
        raise IncompatibleSchema(
            "Existing database is missing required PiHole-AI tables."
        )

    for table, expected_columns in BASELINE_TABLE_COLUMNS.items():
        columns = {
            str(row["name"])
            for row in conn.execute(f"PRAGMA table_info({table})")
        }
        missing_columns = expected_columns - columns

        if missing_columns:
            raise IncompatibleSchema(
                f"Existing table '{table}' is missing required columns."
            )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
