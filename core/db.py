"""
PiHole-AI Database Layer

This module provides the single database interface for the entire project.

Features
--------
* SQLite WAL mode
* Foreign key support
* Explicit schema migrations
* Context-managed transactions
* Generic execute/query helpers
* Event management
* Domain memory
* AI analysis storage

Every module should import functions from this module instead of importing
sqlite3 directly.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import closing, contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from core.config import settings
from core.migrations import (
    LATEST_SUPPORTED_SCHEMA_VERSION,
    UnsupportedSchemaVersion,
    current_schema_version,
    migrate_database,
    open_database_readonly,
)
from engine.evidence import (
    MAX_EVIDENCE_ITEMS,
    serialize_decision,
    serialize_evidence_item,
)
from pihole_ai.intel_models import FeedSource, FeedState, FeedStatus, FeedUpdateResult


DATABASE_PATH: Path | None = None
_initialized_database_paths: set[Path] = set()
_readonly_database_mode = False
DEFAULT_DECISION_HISTORY_LIMIT = 20
MAX_DECISION_HISTORY_LIMIT = 100
DECISION_ID_PREFIX = "dec_"
LEGACY_INTEL_SOURCE_ID = "legacy-manual"
LEGACY_INTEL_GENERATION_ID = "gen_legacy_manual"


class ReadOnlyMigrationRequired(RuntimeError):
    """
    Raised when a read-only command sees a database that needs migration.
    """

    def __init__(self, current_version: int) -> None:
        self.current_version = current_version
        super().__init__("migration required")


class DatabaseAccessMode(str, Enum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    MIGRATION = "migration"


class DatabaseError(RuntimeError):
    """
    Base runtime database access error.
    """


class DatabaseNotFoundError(DatabaseError):
    """
    Raised when read-only access targets a missing database.
    """


class DatabaseMigrationRequiredError(ReadOnlyMigrationRequired, DatabaseError):
    """
    Raised when read-only access sees an older supported schema.
    """


class DatabaseSchemaTooNewError(DatabaseError):
    """
    Raised when read-only access sees a schema from a newer PiHole-AI version.
    """


class DatabaseReadOnlyError(DatabaseError):
    """
    Raised when a read-only SQLite connection refuses an operation.
    """


class Database:
    """
    Explicit database access-mode entry points.
    """

    @staticmethod
    def open_read_only(database_path: str | Path) -> sqlite3.Connection:
        path = Path(database_path)
        try:
            conn = open_database_readonly(path)
            version = current_schema_version(conn)
            if version > LATEST_SUPPORTED_SCHEMA_VERSION:
                conn.close()
                raise DatabaseSchemaTooNewError(
                    f"Database schema version {version} is newer than supported "
                    f"{LATEST_SUPPORTED_SCHEMA_VERSION}."
                )
            if version < LATEST_SUPPORTED_SCHEMA_VERSION:
                conn.close()
                raise DatabaseMigrationRequiredError(version)
            return conn
        except FileNotFoundError as exc:
            raise DatabaseNotFoundError(f"Database does not exist: {path}") from exc
        except UnsupportedSchemaVersion as exc:
            raise DatabaseSchemaTooNewError(str(exc)) from exc
        except sqlite3.OperationalError as exc:
            message = str(exc).lower()
            if "readonly" in message or "attempt to write" in message:
                raise DatabaseReadOnlyError(str(exc)) from exc
            raise

    @staticmethod
    def open_read_write(database_path: str | Path) -> sqlite3.Connection:
        path = Path(database_path)
        _ensure_database_initialized(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, timeout=30)
        _configure_connection(conn)
        return conn

    @staticmethod
    def open_for_migration(database_path: str | Path) -> sqlite3.Connection:
        path = Path(database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, timeout=30)
        _configure_connection(conn)
        return conn


def _database_path() -> Path:
    """
    Resolve the runtime database path lazily.

    Tests and embedded callers may still patch DATABASE_PATH directly; the
    default path is read from configuration only when a connection is opened.
    """

    if DATABASE_PATH is not None:
        return Path(DATABASE_PATH)
    return Path(settings.events_db)


def _ensure_database_initialized(database_path: Path) -> None:
    """
    Apply migrations once before opening a runtime database connection.
    """

    resolved = database_path.resolve()
    if resolved in _initialized_database_paths:
        return

    migrate_database(database_path)
    _initialized_database_paths.add(resolved)


# ============================================================================
# Connection Management
# ============================================================================


def _configure_connection(conn: sqlite3.Connection) -> None:
    """
    Configure SQLite for better reliability and performance.
    """

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA temp_store = MEMORY;")
    conn.execute("PRAGMA cache_size = -20000;")


def get_connection() -> sqlite3.Connection:
    """
    Return a configured SQLite connection.
    """

    database_path = _database_path()
    if _readonly_database_mode:
        return Database.open_read_only(database_path)

    return Database.open_read_write(database_path)


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    """
    Database transaction context.

    Automatically commits or rolls back.
    """

    conn = get_connection()

    try:
        yield conn
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


@contextmanager
def readonly_database() -> Iterator[None]:
    """
    Force query helpers to use read-only SQLite connections without migration.
    """

    global _readonly_database_mode
    previous = _readonly_database_mode
    _readonly_database_mode = True
    try:
        yield
    finally:
        _readonly_database_mode = previous


# ============================================================================
# Schema
# ============================================================================


def init_db() -> None:
    """
    Apply pending PiHole-AI database migrations.
    """
    database_path = _database_path()
    migrate_database(database_path)
    _initialized_database_paths.add(database_path.resolve())


# ============================================================================
# Generic Database Helpers
# ============================================================================


def execute(
    sql: str,
    parameters: tuple[Any, ...] = (),
) -> int:
    """
    Execute an INSERT, UPDATE or DELETE statement.

    Returns
    -------
    int
        lastrowid
    """

    with transaction() as conn:

        cursor = conn.execute(sql, parameters)

        return cursor.lastrowid


def query_all(
    sql: str,
    parameters: tuple[Any, ...] = (),
) -> list[sqlite3.Row]:
    """
    Execute a SELECT query returning all rows.
    """

    with closing(get_connection()) as conn:

        cursor = conn.execute(sql, parameters)

        return cursor.fetchall()


def query_all_readonly(
    sql: str,
    parameters: tuple[Any, ...] = (),
    database_path: str | Path | None = None,
) -> list[sqlite3.Row]:
    """
    Execute a SELECT query against an existing database without mutation.
    """

    path = Path(database_path) if database_path is not None else _database_path()
    with closing(Database.open_read_only(path)) as conn:
        cursor = conn.execute(sql, parameters)
        return cursor.fetchall()


def query_one(
    sql: str,
    parameters: tuple[Any, ...] = (),
) -> sqlite3.Row | None:
    """
    Execute a SELECT query returning one row.
    """

    with closing(get_connection()) as conn:

        cursor = conn.execute(sql, parameters)

        return cursor.fetchone()


def query_one_readonly(
    sql: str,
    parameters: tuple[Any, ...] = (),
    database_path: str | Path | None = None,
) -> sqlite3.Row | None:
    """
    Execute a SELECT query against an existing database without mutation.
    """

    path = Path(database_path) if database_path is not None else _database_path()
    with closing(Database.open_read_only(path)) as conn:
        cursor = conn.execute(sql, parameters)
        return cursor.fetchone()


# ============================================================================
# Event Management
# ============================================================================


def insert_event(
    device: str,
    domain: str,
    timestamp: float,
) -> None:
    """
    Insert a DNS event and update domain statistics.
    """

    with transaction() as conn:

        conn.execute(
            """
            INSERT INTO events
            (
                device,
                domain,
                timestamp
            )
            VALUES (?, ?, ?)
            """,
            (
                device,
                domain,
                timestamp,
            ),
        )

        conn.execute(
            """
            INSERT INTO domain_memory
            (
                domain,
                first_seen,
                last_seen,
                query_count
            )
            VALUES
            (
                ?, ?, ?, 1
            )

            ON CONFLICT(domain)

            DO UPDATE SET

                last_seen = excluded.last_seen,

                query_count = query_count + 1
            """,
            (
                domain,
                timestamp,
                timestamp,
            ),
        )


def get_events(
    limit: int = 500,
) -> list[sqlite3.Row]:
    """
    Return the newest events.
    """

    return query_all(
        """
        SELECT

            id,
            device,
            domain,
            timestamp,
            processed

        FROM events

        ORDER BY id DESC

        LIMIT ?
        """,
        (limit,),
    )


def get_unprocessed_domains(
    limit: int = 100,
) -> list[sqlite3.Row]:
    """
    Return one row for each unprocessed domain.

    This avoids returning duplicate domains that would
    otherwise be analyzed multiple times.
    """

    return query_all(
        """
        SELECT

            MIN(id) AS id,
            domain,
            MIN(device) AS device,
            MIN(timestamp) AS timestamp

        FROM events

        WHERE processed = 0

        GROUP BY domain

        ORDER BY id ASC

        LIMIT ?
        """,
        (limit,),
    )


def mark_processed(event_id: int) -> None:
    """
    Mark an event as processed.
    """

    execute(
        """
        UPDATE events

        SET processed = 1

        WHERE id = ?
        """,
        (event_id,),
    )


def mark_processed_batch(
    event_ids: list[int],
) -> None:
    """
    Mark multiple events as processed.
    """

    if not event_ids:
        return

    with transaction() as conn:

        conn.executemany(
            """
            UPDATE events

            SET processed = 1

            WHERE id = ?
            """,
            [(event_id,) for event_id in event_ids],
        )
        # ============================================================================
# AI Analysis
# ============================================================================


def save_analysis(
    domain: str,
    risk: int,
    confidence: int,
    category: str,
    reason: str,
    model: str,
    analyzed_at: float,
) -> None:
    """
    Save or update an AI analysis for a domain.
    """

    execute(
        """
        INSERT INTO analysis
        (
            domain,
            risk,
            confidence,
            category,
            reason,
            model,
            analyzed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(domain)

        DO UPDATE SET

            risk = excluded.risk,
            confidence = excluded.confidence,
            category = excluded.category,
            reason = excluded.reason,
            model = excluded.model,
            analyzed_at = excluded.analyzed_at
        """,
        (
            domain,
            risk,
            confidence,
            category,
            reason,
            model,
            analyzed_at,
        ),
    )


def _generate_decision_id() -> str:
    return f"{DECISION_ID_PREFIX}{uuid.uuid4().hex}"


def _validate_decision_payload(payload: dict[str, Any], items: list[dict[str, Any]]) -> None:
    evidence_ids = [
        item["evidence_id"]
        for item in items
        if item["evidence_id"]
    ]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("Decision contains duplicate evidence IDs.")
    missing_decisive = [
        evidence_id
        for evidence_id in payload["decisive_evidence_ids"]
        if evidence_id not in set(evidence_ids)
    ]
    if missing_decisive:
        raise ValueError("Decision references missing decisive evidence.")


def _latest_decision_id(
    conn: sqlite3.Connection,
    domain: str,
) -> str | None:
    row = conn.execute(
        """
        SELECT decision_id
        FROM decision_records
        WHERE domain = ?
        """,
        (domain,),
    ).fetchone()
    if row is None:
        return None
    return row["decision_id"]


def _insert_analysis(
    conn: sqlite3.Connection,
    *,
    domain: str,
    risk: int,
    confidence: int,
    category: str,
    reason: str,
    model: str,
    analyzed_at: float,
) -> None:
    conn.execute(
        """
        INSERT INTO analysis
        (
            domain,
            risk,
            confidence,
            category,
            reason,
            model,
            analyzed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(domain)

        DO UPDATE SET

            risk = excluded.risk,
            confidence = excluded.confidence,
            category = excluded.category,
            reason = excluded.reason,
            model = excluded.model,
            analyzed_at = excluded.analyzed_at
        """,
        (
            domain,
            risk,
            confidence,
            category,
            reason,
            model,
            analyzed_at,
        ),
    )


def _insert_decision_projection_and_history(
    conn: sqlite3.Connection,
    *,
    domain: str,
    decision: Any,
    trigger: str = "unknown",
    analysis_id: int | None = None,
) -> str:
    payload = serialize_decision(decision)
    if payload.get("schema_version") is None:
        payload["schema_version"] = LATEST_SUPPORTED_SCHEMA_VERSION
    items = payload["evidence"][:MAX_EVIDENCE_ITEMS]
    _validate_decision_payload(payload, items)

    decision_id = _generate_decision_id()
    supersedes = _latest_decision_id(conn, domain)

    conn.execute(
        """
        INSERT INTO decision_history
        (
            decision_id,
            domain,
            analysis_id,
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
            supersedes_decision_id,
            evidence_truncated,
            legacy,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            decision_id,
            domain,
            analysis_id,
            payload["verdict"],
            payload["risk_score"],
            payload["confidence"],
            payload["category"],
            payload["source"],
            payload["explanation"],
            json.dumps(payload["decisive_evidence_ids"]),
            json.dumps(payload["classifier_trace"]),
            json.dumps(payload["conflicts"]),
            payload["policy_version"],
            payload["application_version"],
            payload["schema_version"],
            trigger,
            supersedes,
            1 if payload["evidence_truncated"] else 0,
            1 if payload["legacy"] else 0,
            payload["created_at"],
        ),
    )
    conn.executemany(
        """
        INSERT INTO decision_history_evidence
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
                item["evidence_id"],
                item["classifier"],
                item["evidence_type"],
                item["polarity"],
                item["score"],
                item["confidence"],
                item["summary"],
                item["details"],
                json.dumps(item["metadata"], sort_keys=True),
                1 if item["decisive"] else 0,
                item["created_at"],
            )
            for item in items
        ],
    )

    conn.execute(
        """
        INSERT INTO decision_records
        (
            domain,
            decision_id,
            verdict,
            risk_score,
            confidence,
            category,
            source,
            explanation,
            decisive_evidence_ids_json,
            classifier_trace_json,
            conflicts_json,
            legacy,
            policy_version,
            application_version,
            schema_version,
            evidence_truncated,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(domain)

        DO UPDATE SET
            decision_id = excluded.decision_id,
            verdict = excluded.verdict,
            risk_score = excluded.risk_score,
            confidence = excluded.confidence,
            category = excluded.category,
            source = excluded.source,
            explanation = excluded.explanation,
            decisive_evidence_ids_json = excluded.decisive_evidence_ids_json,
            classifier_trace_json = excluded.classifier_trace_json,
            conflicts_json = excluded.conflicts_json,
            legacy = excluded.legacy,
            policy_version = excluded.policy_version,
            application_version = excluded.application_version,
            schema_version = excluded.schema_version,
            evidence_truncated = excluded.evidence_truncated,
            created_at = excluded.created_at
        """,
        (
            domain,
            decision_id,
            payload["verdict"],
            payload["risk_score"],
            payload["confidence"],
            payload["category"],
            payload["source"],
            payload["explanation"],
            json.dumps(payload["decisive_evidence_ids"]),
            json.dumps(payload["classifier_trace"]),
            json.dumps(payload["conflicts"]),
            1 if payload["legacy"] else 0,
            payload["policy_version"],
            payload["application_version"],
            payload["schema_version"],
            1 if payload["evidence_truncated"] else 0,
            payload["created_at"],
        ),
    )

    conn.execute(
        """
        DELETE FROM decision_evidence

        WHERE domain = ?
        """,
        (domain,),
    )
    conn.executemany(
        """
        INSERT INTO decision_evidence
        (
            domain,
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
                domain,
                item["evidence_id"],
                item["classifier"],
                item["evidence_type"],
                item["polarity"],
                item["score"],
                item["confidence"],
                item["summary"],
                item["details"],
                json.dumps(item["metadata"], sort_keys=True),
                1 if item["decisive"] else 0,
                item["created_at"],
            )
            for item in items
        ],
    )

    return decision_id


def save_analysis_with_decision(
    *,
    domain: str,
    risk: int,
    confidence: int,
    category: str,
    reason: str,
    model: str,
    analyzed_at: float,
    decision: Any | None,
    trigger: str = "unknown",
) -> str | None:
    """
    Atomically save the latest analysis and optional immutable decision history.
    """

    with transaction() as conn:
        _insert_analysis(
            conn,
            domain=domain,
            risk=risk,
            confidence=confidence,
            category=category,
            reason=reason,
            model=model,
            analyzed_at=analyzed_at,
        )
        if decision is None:
            return None
        return _insert_decision_projection_and_history(
            conn,
            domain=domain,
            decision=decision,
            trigger=trigger,
        )


def get_analysis(
    domain: str,
) -> sqlite3.Row | None:
    """
    Return the cached AI analysis for a domain.
    """

    return query_one(
        """
        SELECT *

        FROM analysis

        WHERE domain = ?
        """,
        (domain,),
    )


def save_decision_evidence(
    domain: str,
    decision: Any,
) -> str:
    """
    Persist structured evidence for a fresh decision and update latest views.
    """

    payload = serialize_decision(decision)
    if payload.get("schema_version") is None:
        payload["schema_version"] = LATEST_SUPPORTED_SCHEMA_VERSION
    items = payload["evidence"][:MAX_EVIDENCE_ITEMS]
    _validate_decision_payload(payload, items)

    with transaction() as conn:
        return _insert_decision_projection_and_history(
            conn,
            domain=domain,
            decision=decision,
            trigger="unknown",
        )


def get_decision_evidence(
    domain: str,
) -> list[dict[str, Any]]:
    """
    Return stored decision evidence for a domain.
    """

    rows = query_all(
        """
        SELECT
            id,
            domain,
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

        FROM decision_evidence

        WHERE domain = ?

        ORDER BY decisive DESC, ABS(score) DESC, confidence DESC, id ASC
        """,
        (domain,),
    )

    evidence = []
    for row in rows:
        item = dict(row)
        try:
            item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        except json.JSONDecodeError:
            item["metadata"] = {
                "_degraded": True,
            }
        item["decisive"] = bool(item.get("decisive"))
        evidence.append(serialize_evidence_item(item))

    return evidence


def get_decision_record(
    domain: str,
) -> dict[str, Any] | None:
    """
    Return the stored final decision contract for a domain.
    """

    row = query_one(
        """
        SELECT *

        FROM decision_records

        WHERE domain = ?
        """,
        (domain,),
    )
    if row is None:
        return None

    record = dict(row)
    for key, target in (
        ("decisive_evidence_ids_json", "decisive_evidence_ids"),
        ("classifier_trace_json", "classifier_trace"),
        ("conflicts_json", "conflicts"),
    ):
        try:
            record[target] = json.loads(record.pop(key) or "[]")
        except json.JSONDecodeError:
            record[target] = []
            record["_degraded"] = True

    record["legacy"] = bool(record["legacy"])
    record["evidence_truncated"] = bool(record["evidence_truncated"])
    return record


def _parse_decision_record(
    row: sqlite3.Row | dict[str, Any] | None,
) -> dict[str, Any] | None:
    if row is None:
        return None

    record = dict(row)
    for key, target in (
        ("decisive_evidence_ids_json", "decisive_evidence_ids"),
        ("classifier_trace_json", "classifier_trace"),
        ("conflicts_json", "conflicts"),
    ):
        try:
            record[target] = json.loads(record.pop(key) or "[]")
        except json.JSONDecodeError:
            record[target] = []
            record["_degraded"] = True

    record["legacy"] = bool(record.get("legacy"))
    record["evidence_truncated"] = bool(record.get("evidence_truncated"))
    return record


def _parse_evidence_rows(
    rows: list[sqlite3.Row],
) -> list[dict[str, Any]]:
    evidence = []
    for row in rows:
        item = dict(row)
        try:
            item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        except json.JSONDecodeError:
            item["metadata"] = {
                "_degraded": True,
            }
        item["decisive"] = bool(item.get("decisive"))
        evidence.append(serialize_evidence_item(item))

    return evidence


def get_latest_decision(
    domain: str,
) -> dict[str, Any] | None:
    """
    Return the latest immutable decision for a domain.
    """

    record = get_decision_record(domain)
    if record is None:
        return None
    decision_id = record.get("decision_id")
    if not decision_id:
        return record
    return get_decision(str(decision_id))


def get_decision(
    decision_id: str,
) -> dict[str, Any] | None:
    """
    Return one immutable decision plus its persisted evidence.
    """

    if not is_valid_decision_id(decision_id):
        return None

    row = query_one(
        """
        SELECT *
        FROM decision_history
        WHERE decision_id = ?
        """,
        (decision_id,),
    )
    record = _parse_decision_record(row)
    if record is None:
        return None
    record["evidence"] = get_decision_history_evidence(decision_id)
    return record


def get_decision_history_evidence(
    decision_id: str,
) -> list[dict[str, Any]]:
    """
    Return persisted evidence for one immutable decision.
    """

    if not is_valid_decision_id(decision_id):
        return []

    rows = query_all(
        """
        SELECT
            id,
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
        FROM decision_history_evidence
        WHERE decision_id = ?
        ORDER BY decisive DESC, ABS(score) DESC, confidence DESC, id ASC
        """,
        (decision_id,),
    )
    return _parse_evidence_rows(rows)


def list_decision_history(
    domain: str,
    limit: int = DEFAULT_DECISION_HISTORY_LIMIT,
    before: float | None = None,
) -> list[dict[str, Any]]:
    """
    Return bounded decision history for a domain newest first.
    """

    limit = max(1, min(MAX_DECISION_HISTORY_LIMIT, int(limit or DEFAULT_DECISION_HISTORY_LIMIT)))
    params: list[Any] = [domain]
    where = "domain = ?"
    if before is not None:
        where += " AND created_at < ?"
        params.append(float(before))

    rows = query_all(
        f"""
        SELECT *
        FROM decision_history
        WHERE {where}
        ORDER BY created_at DESC, decision_id DESC
        LIMIT ?
        """,
        tuple(params + [limit]),
    )
    return [
        record
        for row in rows
        if (record := _parse_decision_record(row)) is not None
    ]


def is_valid_decision_id(
    decision_id: str,
) -> bool:
    return bool(
        isinstance(decision_id, str)
        and len(decision_id) == len(DECISION_ID_PREFIX) + 32
        and decision_id.startswith(DECISION_ID_PREFIX)
        and all(ch in "0123456789abcdef" for ch in decision_id[len(DECISION_ID_PREFIX):])
    )


def _semantic_evidence_key(
    item: dict[str, Any],
) -> str:
    metadata = item.get("metadata") or {}
    identity = {
        key: metadata.get(key)
        for key in ("source", "domain", "decision", "category", "policy_reason", "precedence")
        if key in metadata
    }
    return json.dumps(
        {
            "classifier": item.get("classifier", ""),
            "evidence_type": item.get("evidence_type", ""),
            "identity": identity,
            "summary": item.get("summary", ""),
        },
        sort_keys=True,
    )


def compare_decisions(
    older_id: str,
    newer_id: str,
) -> dict[str, Any] | None:
    """
    Compare two immutable decisions using semantic evidence keys.
    """

    older = get_decision(older_id)
    newer = get_decision(newer_id)
    if older is None or newer is None:
        return None
    if older["domain"] != newer["domain"]:
        return None

    older_items = {
        _semantic_evidence_key(item): item
        for item in older.get("evidence", [])
    }
    newer_items = {
        _semantic_evidence_key(item): item
        for item in newer.get("evidence", [])
    }
    added_keys = sorted(set(newer_items) - set(older_items))
    removed_keys = sorted(set(older_items) - set(newer_items))
    shared_keys = sorted(set(older_items) & set(newer_items))
    changed = []
    decisive_changed = False
    for key in shared_keys:
        before = older_items[key]
        after = newer_items[key]
        fields = [
            field
            for field in ("polarity", "score", "confidence", "summary", "details", "decisive")
            if before.get(field) != after.get(field)
        ]
        if fields:
            changed.append(
                {
                    "key": key,
                    "before": before,
                    "after": after,
                    "changed_fields": fields,
                }
            )
        if bool(before.get("decisive")) != bool(after.get("decisive")):
            decisive_changed = True

    risk_delta = float(newer["risk_score"]) - float(older["risk_score"])
    confidence_delta = float(newer["confidence"]) - float(older["confidence"])
    summary_parts = []
    if older["verdict"] != newer["verdict"]:
        summary_parts.append(f"verdict changed from {older['verdict']} to {newer['verdict']}")
    if risk_delta:
        summary_parts.append(f"risk changed by {risk_delta:+.0f}")
    if added_keys:
        summary_parts.append(f"{len(added_keys)} evidence item(s) added")
    if removed_keys:
        summary_parts.append(f"{len(removed_keys)} evidence item(s) removed")
    if not summary_parts:
        summary_parts.append("decisions are semantically similar")

    return {
        "domain": older["domain"],
        "older_decision_id": older_id,
        "newer_decision_id": newer_id,
        "verdict_changed": older["verdict"] != newer["verdict"],
        "risk_delta": risk_delta,
        "confidence_delta": confidence_delta,
        "category_changed": older.get("category") != newer.get("category"),
        "source_changed": older.get("source") != newer.get("source"),
        "policy_changed": older.get("policy_version") != newer.get("policy_version"),
        "added_evidence": [newer_items[key] for key in added_keys],
        "removed_evidence": [older_items[key] for key in removed_keys],
        "changed_evidence": changed,
        "decisive_evidence_changed": decisive_changed
        or any(item.get("decisive") for item in [*(newer_items[key] for key in added_keys), *(older_items[key] for key in removed_keys)]),
        "classifier_trace_changes": {
            "older": older.get("classifier_trace", []),
            "newer": newer.get("classifier_trace", []),
        },
        "summary": "; ".join(summary_parts),
    }


@dataclass(frozen=True)
class DecisionHistoryRetentionResult:
    domains_inspected: int
    decisions_inspected: int
    decisions_eligible: int
    decisions_deleted: int
    evidence_rows_deleted: int
    protected_by_latest: int
    protected_by_feedback: int
    protected_by_retention: int
    errors: list[str]
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "domains_inspected": self.domains_inspected,
            "decisions_inspected": self.decisions_inspected,
            "decisions_eligible": self.decisions_eligible,
            "decisions_deleted": self.decisions_deleted,
            "evidence_rows_deleted": self.evidence_rows_deleted,
            "protected_by_latest": self.protected_by_latest,
            "protected_by_feedback": self.protected_by_feedback,
            "protected_by_retention": self.protected_by_retention,
            "errors": list(self.errors),
            "dry_run": self.dry_run,
        }


def cleanup_decision_history(
    *,
    retention_days: int,
    max_per_domain: int,
    dry_run: bool = False,
    batch_size: int = 500,
) -> DecisionHistoryRetentionResult:
    """
    Delete old decision history while preserving latest and feedback references.
    """

    cutoff = time.time() - max(0, int(retention_days)) * 86400
    max_per_domain = max(1, int(max_per_domain))

    with transaction() as conn:
        domains = [
            row["domain"]
            for row in conn.execute("SELECT DISTINCT domain FROM decision_history")
        ]
        latest_ids = {
            row["decision_id"]
            for row in conn.execute(
                "SELECT decision_id FROM decision_records WHERE decision_id IS NOT NULL"
            )
        }
        feedback_ids = {
            row["decision_ref"]
            for row in conn.execute(
                """
                SELECT DISTINCT decision_ref
                FROM action_audit
                WHERE decision_ref LIKE 'dec_%'
                """
            )
            if row["decision_ref"]
        }

        inspected = eligible = deleted = evidence_deleted = 0
        protected_latest = protected_feedback = protected_retention = 0
        delete_ids: list[str] = []

        for domain in domains:
            rows = conn.execute(
                """
                SELECT decision_id, created_at
                FROM decision_history
                WHERE domain = ?
                ORDER BY created_at DESC, decision_id DESC
                """,
                (domain,),
            ).fetchall()
            inspected += len(rows)
            for index, row in enumerate(rows):
                decision_id = row["decision_id"]
                if decision_id in latest_ids:
                    protected_latest += 1
                    continue
                if decision_id in feedback_ids:
                    protected_feedback += 1
                    continue
                within_count = index < max_per_domain
                within_age = float(row["created_at"]) >= cutoff
                if within_count and within_age:
                    protected_retention += 1
                    continue
                eligible += 1
                if len(delete_ids) < batch_size:
                    delete_ids.append(decision_id)

        if not dry_run and delete_ids:
            for decision_id in delete_ids:
                row = conn.execute(
                    """
                    SELECT supersedes_decision_id
                    FROM decision_history
                    WHERE decision_id = ?
                    """,
                    (decision_id,),
                ).fetchone()
                predecessor = row["supersedes_decision_id"] if row else None
                conn.execute(
                    """
                    UPDATE decision_history
                    SET supersedes_decision_id = ?
                    WHERE supersedes_decision_id = ?
                    """,
                    (predecessor, decision_id),
                )
            placeholders = ",".join("?" for _ in delete_ids)
            evidence_deleted = conn.execute(
                f"""
                DELETE FROM decision_history_evidence
                WHERE decision_id IN ({placeholders})
                """,
                tuple(delete_ids),
            ).rowcount
            deleted = conn.execute(
                f"""
                DELETE FROM decision_history
                WHERE decision_id IN ({placeholders})
                """,
                tuple(delete_ids),
            ).rowcount

    return DecisionHistoryRetentionResult(
        domains_inspected=len(domains),
        decisions_inspected=inspected,
        decisions_eligible=eligible,
        decisions_deleted=0 if dry_run else deleted,
        evidence_rows_deleted=0 if dry_run else evidence_deleted,
        protected_by_latest=protected_latest,
        protected_by_feedback=protected_feedback,
        protected_by_retention=protected_retention,
        errors=[],
        dry_run=dry_run,
    )


def analysis_exists(
    domain: str,
) -> bool:
    """
    Return True if a domain has already been analyzed.
    """

    return get_analysis(domain) is not None

def mark_processed_by_domain(
    domain: str,
) -> None:
    """
    Mark every event for a domain as processed.
    """

    execute(
        """
        UPDATE events

        SET processed = 1

        WHERE domain = ?
        """,
        (domain,),
    )


# ============================================================================
# Action Audit
# ============================================================================


def record_action(
    domain: str,
    action: str,
    source: str,
    status: str,
    reason: str = "",
    risk: int | None = None,
    created_at: float | None = None,
    decision_ref: str | None = None,
) -> int:
    """
    Record an action taken by PiHole-AI.
    """

    if created_at is None:
        import time

        created_at = time.time()

    return execute(
        """
        INSERT INTO action_audit
        (
            domain,
            action,
            source,
            status,
            reason,
            risk,
            created_at,
            decision_ref
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            domain,
            action,
            source,
            status,
            reason,
            risk,
            created_at,
            decision_ref,
        ),
    )


def get_recent_actions(
    limit: int = 100,
    search: str = "",
    action: str = "",
    status: str = "",
) -> list[sqlite3.Row]:
    """
    Return recent audited actions.
    """

    where = []
    params: list[Any] = []

    if search:
        where.append("(domain LIKE ? OR source LIKE ? OR reason LIKE ?)")
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern])

    if action:
        where.append("action = ?")
        params.append(action)

    if status:
        where.append("status = ?")
        params.append(status)

    where_sql = ""

    if where:
        where_sql = "WHERE " + " AND ".join(where)

    return query_all(
        f"""
        SELECT

            id,
            domain,
            action,
            source,
            status,
            reason,
            risk,
            created_at,
            decision_ref

        FROM action_audit

        {where_sql}

        ORDER BY id DESC

        LIMIT ?
        """,
        tuple(params + [limit]),
    )


# ============================================================================
# Domain Rules
# ============================================================================


def save_domain_rule(
    domain: str,
    decision: str,
    source: str = "manual",
    reason: str = "",
    enabled: bool = True,
    created_at: float | None = None,
    updated_at: float | None = None,
) -> None:
    """
    Create or update an allow/block rule for a domain.
    """

    if decision not in {"allow", "block"}:
        raise ValueError(
            "Domain rule decision must be 'allow' or 'block'."
        )

    if created_at is None or updated_at is None:
        import time

        now = time.time()

        if created_at is None:
            created_at = now

        if updated_at is None:
            updated_at = now

    execute(
        """
        INSERT INTO domain_rules
        (
            domain,
            decision,
            source,
            reason,
            enabled,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)

        ON CONFLICT(domain)

        DO UPDATE SET

            decision = excluded.decision,
            source = excluded.source,
            reason = excluded.reason,
            enabled = excluded.enabled,
            updated_at = excluded.updated_at
        """,
        (
            domain,
            decision,
            source,
            reason,
            1 if enabled else 0,
            created_at,
            updated_at,
        ),
    )


def get_domain_rule(
    domain: str,
) -> sqlite3.Row | None:
    """
    Return the active rule for a domain, if one exists.
    """

    return query_one(
        """
        SELECT

            domain,
            decision,
            source,
            reason,
            enabled,
            created_at,
            updated_at

        FROM domain_rules

        WHERE domain = ?
          AND enabled = 1
        """,
        (domain,),
    )


def list_domain_rules(
    limit: int = 100,
    search: str = "",
    decision: str = "",
    enabled: bool | None = True,
) -> list[sqlite3.Row]:
    """
    Return domain rules with optional filters.
    """

    where = []
    params: list[Any] = []

    if search:
        where.append("(domain LIKE ? OR reason LIKE ? OR source LIKE ?)")
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern])

    if decision:
        where.append("decision = ?")
        params.append(decision)

    if enabled is not None:
        where.append("enabled = ?")
        params.append(1 if enabled else 0)

    where_sql = ""

    if where:
        where_sql = "WHERE " + " AND ".join(where)

    return query_all(
        f"""
        SELECT

            domain,
            decision,
            source,
            reason,
            enabled,
            created_at,
            updated_at

        FROM domain_rules

        {where_sql}

        ORDER BY updated_at DESC, domain ASC

        LIMIT ?
        """,
        tuple(params + [limit]),
    )


def delete_domain_rule(
    domain: str,
) -> bool:
    """
    Delete a domain rule.
    """

    with transaction() as conn:
        cursor = conn.execute(
            """
            DELETE FROM domain_rules

            WHERE domain = ?
            """,
            (domain,),
        )

        return cursor.rowcount > 0


# ============================================================================
# Domain Reputation
# ============================================================================


def save_domain_reputation(
    domain: str,
    score: int,
    confidence: int,
    signals: list[str],
    source: str = "local-learning",
    updated_at: float | None = None,
) -> None:
    """
    Save a learned reputation score for a domain.
    """

    if updated_at is None:
        import time

        updated_at = time.time()

    execute(
        """
        INSERT INTO domain_reputation
        (
            domain,
            score,
            confidence,
            signals,
            source,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?)

        ON CONFLICT(domain)

        DO UPDATE SET

            score = excluded.score,
            confidence = excluded.confidence,
            signals = excluded.signals,
            source = excluded.source,
            updated_at = excluded.updated_at
        """,
        (
            domain,
            max(0, min(score, 100)),
            max(0, min(confidence, 100)),
            json.dumps(signals),
            source,
            updated_at,
        ),
    )


def get_domain_reputation(
    domain: str,
) -> sqlite3.Row | None:
    """
    Return a learned reputation row.
    """

    return query_one(
        """
        SELECT

            domain,
            score,
            confidence,
            signals,
            source,
            updated_at

        FROM domain_reputation

        WHERE domain = ?
        """,
        (domain,),
    )


def list_domain_reputations(
    limit: int = 100,
    search: str = "",
    min_score: int = 0,
) -> list[sqlite3.Row]:
    """
    Return learned reputation rows.
    """

    where = []
    params: list[Any] = []

    if search:
        where.append("domain LIKE ?")
        params.append(f"%{search}%")

    if min_score > 0:
        where.append("score >= ?")
        params.append(min_score)

    where_sql = ""

    if where:
        where_sql = "WHERE " + " AND ".join(where)

    return query_all(
        f"""
        SELECT

            domain,
            score,
            confidence,
            signals,
            source,
            updated_at

        FROM domain_reputation

        {where_sql}

        ORDER BY score DESC, updated_at DESC

        LIMIT ?
        """,
        tuple(params + [limit]),
    )


def get_reputation_candidates(
    limit: int = 500,
) -> list[sqlite3.Row]:
    """
    Return domain history rows used by the local learner.
    """

    return query_all(
        """
        SELECT

            dm.domain,
            dm.query_count,
            dm.first_seen,
            dm.last_seen,
            COUNT(DISTINCT e.device) AS device_count,
            SUM(
                CASE
                    WHEN e.timestamp >= dm.last_seen - 3600 THEN 1
                    ELSE 0
                END
            ) AS recent_queries,
            a.risk AS analysis_risk,
            a.confidence AS analysis_confidence,
            a.category AS analysis_category,
            dr.decision AS rule_decision,
            (
                SELECT COUNT(*)
                FROM action_audit aa
                WHERE aa.domain = dm.domain
                  AND aa.action = 'suggest_block'
            ) AS suggest_block_count,
            (
                SELECT COUNT(*)
                FROM action_audit aa
                WHERE aa.domain = dm.domain
                  AND aa.action = 'alert'
            ) AS alert_count,
            (
                SELECT COUNT(*)
                FROM action_audit aa
                WHERE aa.domain = dm.domain
                  AND aa.action = 'review'
            ) AS review_count

        FROM domain_memory dm

        LEFT JOIN events e
            ON e.domain = dm.domain

        LEFT JOIN analysis a
            ON a.domain = dm.domain

        LEFT JOIN domain_rules dr
            ON dr.domain = dm.domain
           AND dr.enabled = 1

        GROUP BY
            dm.domain,
            dm.query_count,
            dm.first_seen,
            dm.last_seen,
            a.risk,
            a.confidence,
            a.category,
            dr.decision

        ORDER BY dm.last_seen DESC

        LIMIT ?
        """,
        (limit,),
    )


# ============================================================================
# Threat Intelligence
# ============================================================================


def save_threat_intel(
    domain: str,
    source: str,
    category: str = "malware",
    confidence: int = 90,
    first_seen: float | None = None,
    last_seen: float | None = None,
) -> None:
    """
    Save or update a threat-intel domain hit.
    """

    if first_seen is None or last_seen is None:
        import time

        now = time.time()

        if first_seen is None:
            first_seen = now

        if last_seen is None:
            last_seen = now

    confidence = max(0, min(confidence, 100))
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO threat_intel
            (
                domain,
                source,
                category,
                confidence,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?)

            ON CONFLICT(domain, source)

            DO UPDATE SET

                category = excluded.category,
                confidence = excluded.confidence,
                last_seen = excluded.last_seen
            """,
            (
                domain,
                source,
                category,
                confidence,
                first_seen,
                last_seen,
            ),
        )
        _ensure_legacy_intel_generation(conn)
        conn.execute(
            """
            INSERT INTO threat_intel_generation_entries
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

            ON CONFLICT(generation_id, domain)

            DO UPDATE SET
                category = excluded.category,
                confidence = excluded.confidence,
                last_seen = excluded.last_seen
            """,
            (
                LEGACY_INTEL_GENERATION_ID,
                LEGACY_INTEL_SOURCE_ID,
                domain,
                category,
                confidence,
                first_seen,
                last_seen,
            ),
        )
        count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM threat_intel_generation_entries
            WHERE generation_id = ?
            """,
            (LEGACY_INTEL_GENERATION_ID,),
        ).fetchone()["count"]
        conn.execute(
            """
            UPDATE threat_intel_generations
            SET entry_count = ?
            WHERE generation_id = ?
            """,
            (count, LEGACY_INTEL_GENERATION_ID),
        )
        conn.execute(
            """
            UPDATE threat_intel_source_state
            SET entry_count = ?, status = 'active', last_success_at = ?
            WHERE source_id = ?
            """,
            (count, last_seen, LEGACY_INTEL_SOURCE_ID),
        )


def get_threat_intel(
    domain: str,
) -> sqlite3.Row | None:
    """
    Return the highest-confidence threat-intel hit for a domain.
    """

    return query_one(
        """
        SELECT

            domain,
            source,
            category,
            confidence,
            first_seen,
            last_seen

        FROM threat_intel

        WHERE domain = ?

        ORDER BY confidence DESC, last_seen DESC

        LIMIT 1
        """,
        (domain,),
    )


def list_threat_intel(
    limit: int = 100,
    search: str = "",
    source: str = "",
    category: str = "",
) -> list[sqlite3.Row]:
    """
    Return threat-intel rows with optional filters.
    """

    where = []
    params: list[Any] = []

    if search:
        where.append("domain LIKE ?")
        params.append(f"%{search}%")

    if source:
        where.append("source = ?")
        params.append(source)

    if category:
        where.append("category = ?")
        params.append(category)

    where_sql = ""

    if where:
        where_sql = "WHERE " + " AND ".join(where)

    return query_all(
        f"""
        SELECT

            domain,
            source,
            category,
            confidence,
            first_seen,
            last_seen

        FROM threat_intel

        {where_sql}

        ORDER BY last_seen DESC, domain ASC

        LIMIT ?
        """,
        tuple(params + [limit]),
    )


def _ensure_legacy_intel_generation(conn: sqlite3.Connection) -> None:
    now = time.time()
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
            LEGACY_INTEL_SOURCE_ID,
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
        (LEGACY_INTEL_GENERATION_ID, LEGACY_INTEL_SOURCE_ID, "active", "manual", 0, now, now),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO threat_intel_source_state
        (
            source_id,
            status,
            last_success_at,
            entry_count,
            active_generation
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (LEGACY_INTEL_SOURCE_ID, "active", now, 0, LEGACY_INTEL_GENERATION_ID),
    )


def save_intel_source(
    source: FeedSource,
) -> None:
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO threat_intel_sources
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

            ON CONFLICT(source_id)

            DO UPDATE SET
                name = excluded.name,
                url = excluded.url,
                format = excluded.format,
                enabled = excluded.enabled,
                category = excluded.category,
                confidence = excluded.confidence,
                refresh_interval_seconds = excluded.refresh_interval_seconds,
                stale_after_seconds = excluded.stale_after_seconds,
                timeout_seconds = excluded.timeout_seconds,
                max_download_bytes = excluded.max_download_bytes,
                expected_content_type = excluded.expected_content_type,
                allow_http = excluded.allow_http,
                updated_at = excluded.updated_at
            """,
            (
                source.source_id,
                source.name,
                source.url,
                source.format,
                1 if source.enabled else 0,
                source.category,
                max(0, min(source.confidence, 100)),
                source.refresh_interval_seconds,
                source.stale_after_seconds,
                source.timeout_seconds,
                source.max_download_bytes,
                source.expected_content_type,
                1 if source.allow_http else 0,
                source.created_at or time.time(),
                source.updated_at or time.time(),
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO threat_intel_source_state (source_id, status)
            VALUES (?, ?)
            """,
            (source.source_id, FeedStatus.UNKNOWN.value),
        )


def get_intel_source(source_id: str) -> dict[str, Any] | None:
    row = query_one(
        """
        SELECT *
        FROM threat_intel_sources
        WHERE source_id = ?
        """,
        (source_id,),
    )
    if row is None:
        return None
    item = dict(row)
    item["enabled"] = bool(item["enabled"])
    item["allow_http"] = bool(item["allow_http"])
    return item


def list_intel_sources() -> list[dict[str, Any]]:
    return [
        _source_row_to_dict(row)
        for row in query_all(
            """
            SELECT *
            FROM threat_intel_sources
            ORDER BY source_id ASC
            """
        )
    ]


def _source_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["enabled"] = bool(item["enabled"])
    item["allow_http"] = bool(item["allow_http"])
    return item


def remove_intel_source(source_id: str) -> bool:
    with transaction() as conn:
        row = conn.execute(
            "SELECT source_id FROM threat_intel_sources WHERE source_id = ?",
            (source_id,),
        ).fetchone()
        if row is None:
            return False
        conn.execute("DELETE FROM threat_intel_sources WHERE source_id = ?", (source_id,))
        return True


SOURCE_UPDATE_COLUMNS = {
    "name",
    "url",
    "format",
    "enabled",
    "category",
    "confidence",
    "refresh_interval_seconds",
    "stale_after_seconds",
    "timeout_seconds",
    "max_download_bytes",
    "expected_content_type",
    "allow_http",
}
SOURCE_FETCH_SETTING_COLUMNS = {
    "url",
    "format",
    "timeout_seconds",
    "max_download_bytes",
    "expected_content_type",
    "allow_http",
}


def update_threat_intel_source(
    source_id: str,
    changes: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Partially update one configured feed source without touching generations.
    """

    unknown = sorted(set(changes) - SOURCE_UPDATE_COLUMNS)
    if unknown:
        raise ValueError(f"Unsupported source field(s): {', '.join(unknown)}")
    if not changes:
        raise ValueError("No source changes provided.")

    now = time.time()
    changed_fields = sorted(changes)
    validators_cleared = bool(SOURCE_FETCH_SETTING_COLUMNS.intersection(changes))
    assignments = ", ".join(f"{field} = ?" for field in changed_fields)
    values = [
        int(value) if field in {"enabled", "allow_http"} else value
        for field, value in ((field, changes[field]) for field in changed_fields)
    ]

    with transaction() as conn:
        existing = conn.execute(
            """
            SELECT s.*, st.active_generation
            FROM threat_intel_sources s
            LEFT JOIN threat_intel_source_state st
                ON st.source_id = s.source_id
            WHERE s.source_id = ?
            """,
            (source_id,),
        ).fetchone()
        if existing is None:
            return None
        conn.execute(
            f"""
            UPDATE threat_intel_sources
            SET {assignments}, updated_at = ?
            WHERE source_id = ?
            """,
            tuple(values + [now, source_id]),
        )
        if validators_cleared:
            conn.execute(
                """
                UPDATE threat_intel_source_state
                SET etag = '',
                    last_modified = ''
                WHERE source_id = ?
                """,
                (source_id,),
            )
        result = conn.execute(
            """
            SELECT s.*, st.active_generation, st.etag, st.last_modified
            FROM threat_intel_sources s
            LEFT JOIN threat_intel_source_state st
                ON st.source_id = s.source_id
            WHERE s.source_id = ?
            """,
            (source_id,),
        ).fetchone()
        active_generation = existing["active_generation"] or ""

    updated = _source_row_to_dict(result)
    updated["active_generation"] = active_generation
    updated["changed_fields"] = changed_fields
    updated["validators_cleared"] = validators_cleared
    updated["generations_preserved"] = True
    updated["updated_at"] = now
    return updated


def set_intel_source_enabled(source_id: str, enabled: bool) -> bool:
    rowid = execute(
        """
        UPDATE threat_intel_sources
        SET enabled = ?, updated_at = ?
        WHERE source_id = ?
        """,
        (1 if enabled else 0, time.time(), source_id),
    )
    return rowid >= 0


def get_intel_source_state(source_id: str) -> dict[str, Any] | None:
    row = query_one(
        """
        SELECT *
        FROM threat_intel_source_state
        WHERE source_id = ?
        """,
        (source_id,),
    )
    return dict(row) if row is not None else None


def list_intel_source_status() -> list[dict[str, Any]]:
    rows = query_all(
        """
        SELECT
            s.*,
            st.status,
            st.last_attempt_at,
            st.last_success_at,
            st.next_update_at,
            st.etag,
            st.last_modified,
            st.content_sha256,
            st.entry_count,
            st.active_generation,
            st.remote_generation_id,
            st.last_error_code,
            st.last_error_summary,
            st.consecutive_failures
        FROM threat_intel_sources s
        LEFT JOIN threat_intel_source_state st
            ON st.source_id = s.source_id
        ORDER BY s.source_id ASC
        """
    )
    result = []
    for row in rows:
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        item["allow_http"] = bool(item["allow_http"])
        result.append(item)
    return result


def activate_intel_generation(
    *,
    source_id: str,
    generation_id: str,
    content_sha256_value: str,
    entries: list[str],
    category: str,
    confidence: int,
    etag: str = "",
    last_modified: str = "",
) -> tuple[str, str]:
    now = time.time()
    confidence = max(0, min(confidence, 100))
    with transaction() as conn:
        state = conn.execute(
            "SELECT active_generation FROM threat_intel_source_state WHERE source_id = ?",
            (source_id,),
        ).fetchone()
        previous = state["active_generation"] if state and state["active_generation"] else ""
        conn.execute(
            """
            INSERT INTO threat_intel_generations
            (
                generation_id,
                source_id,
                status,
                content_sha256,
                entry_count,
                created_at,
                previous_generation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (generation_id, source_id, "staging", content_sha256_value, len(entries), now, previous),
        )
        conn.executemany(
            """
            INSERT INTO threat_intel_generation_entries
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
                (generation_id, source_id, domain, category, confidence, now, now)
                for domain in entries
            ],
        )
        if previous:
            conn.execute(
                """
                UPDATE threat_intel_generations
                SET status = 'inactive'
                WHERE generation_id = ?
                """,
                (previous,),
            )
        conn.execute(
            """
            UPDATE threat_intel_generations
            SET status = 'active', activated_at = ?
            WHERE generation_id = ?
            """,
            (now, generation_id),
        )
        conn.execute(
            """
            INSERT INTO threat_intel_source_state
            (
                source_id,
                status,
                last_attempt_at,
                last_success_at,
                next_update_at,
                etag,
                last_modified,
                content_sha256,
                entry_count,
                active_generation,
                remote_generation_id,
                last_error_code,
                last_error_summary,
                consecutive_failures
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(source_id)

            DO UPDATE SET
                status = excluded.status,
                last_attempt_at = excluded.last_attempt_at,
                last_success_at = excluded.last_success_at,
                next_update_at = excluded.next_update_at,
                etag = excluded.etag,
                last_modified = excluded.last_modified,
                content_sha256 = excluded.content_sha256,
                entry_count = excluded.entry_count,
                active_generation = excluded.active_generation,
                remote_generation_id = excluded.remote_generation_id,
                last_error_code = '',
                last_error_summary = '',
                consecutive_failures = 0
            """,
            (
                source_id,
                FeedStatus.ACTIVE.value,
                now,
                now,
                None,
                etag,
                last_modified,
                content_sha256_value,
                len(entries),
                generation_id,
                generation_id,
                "",
                "",
                0,
            ),
        )
    return previous, generation_id


def find_reusable_threat_intel_generation(
    source_id: str,
    content_sha256_value: str,
) -> dict[str, Any] | None:
    row = query_one(
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
          AND g.content_sha256 = ?
          AND g.status = 'inactive'
          AND g.activated_at IS NOT NULL
        GROUP BY
            g.generation_id,
            g.source_id,
            g.status,
            g.content_sha256,
            g.entry_count,
            g.activated_at
        HAVING stored_entry_count = g.entry_count
        ORDER BY g.activated_at DESC, g.created_at DESC
        LIMIT 1
        """,
        (source_id, content_sha256_value),
    )
    return dict(row) if row is not None else None


def get_threat_intel_generation(
    source_id: str,
    generation_id: str,
) -> dict[str, Any] | None:
    row = query_one(
        """
        SELECT
            g.generation_id,
            g.source_id,
            g.status,
            g.content_sha256,
            g.entry_count,
            g.activated_at,
            g.previous_generation,
            COUNT(e.id) AS stored_entry_count
        FROM threat_intel_generations g
        LEFT JOIN threat_intel_generation_entries e
            ON e.generation_id = g.generation_id
        WHERE g.source_id = ?
          AND g.generation_id = ?
        GROUP BY
            g.generation_id,
            g.source_id,
            g.status,
            g.content_sha256,
            g.entry_count,
            g.activated_at,
            g.previous_generation
        """,
        (source_id, generation_id),
    )
    return dict(row) if row is not None else None


def get_latest_successful_remote_generation(source_id: str) -> dict[str, Any] | None:
    audits = query_all(
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
    )
    for audit in audits:
        generation = get_threat_intel_generation(
            source_id,
            str(audit["active_generation"] or ""),
        )
        if (
            generation
            and generation.get("status") in {"active", "inactive"}
            and generation.get("activated_at") is not None
            and int(generation.get("stored_entry_count") or -1)
            == int(generation.get("entry_count") or 0)
        ):
            return generation
    return None


def activate_existing_threat_intel_generation(
    *,
    source_id: str,
    generation_id: str,
    previous_generation_id: str = "",
    etag: str = "",
    last_modified: str = "",
) -> tuple[str, str]:
    now = time.time()
    with transaction() as conn:
        state = conn.execute(
            "SELECT active_generation FROM threat_intel_source_state WHERE source_id = ?",
            (source_id,),
        ).fetchone()
        previous = state["active_generation"] if state and state["active_generation"] else ""
        if previous_generation_id and previous_generation_id != previous:
            raise ValueError("active generation changed before reactivation")
        generation = conn.execute(
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
            WHERE g.generation_id = ?
            GROUP BY
                g.generation_id,
                g.source_id,
                g.status,
                g.content_sha256,
                g.entry_count,
                g.activated_at
            """,
            (generation_id,),
        ).fetchone()
        if generation is None:
            raise ValueError("generation not found")
        if generation["source_id"] != source_id:
            raise ValueError("generation belongs to another source")
        if generation["status"] != "inactive" or generation["activated_at"] is None:
            raise ValueError("generation is not reusable")
        if int(generation["stored_entry_count"]) != int(generation["entry_count"]):
            raise ValueError("generation entries are incomplete")

        conn.execute(
            """
            UPDATE threat_intel_generations
            SET status = 'inactive'
            WHERE source_id = ?
              AND status = 'active'
            """,
            (source_id,),
        )
        conn.execute(
            """
            UPDATE threat_intel_generations
            SET status = 'active',
                activated_at = ?,
                previous_generation = ?
            WHERE generation_id = ?
            """,
            (now, previous, generation_id),
        )
        conn.execute(
            """
            INSERT INTO threat_intel_source_state
            (
                source_id,
                status,
                last_attempt_at,
                last_success_at,
                next_update_at,
                etag,
                last_modified,
                content_sha256,
                entry_count,
                active_generation,
                remote_generation_id,
                last_error_code,
                last_error_summary,
                consecutive_failures
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(source_id)

            DO UPDATE SET
                status = excluded.status,
                last_attempt_at = excluded.last_attempt_at,
                last_success_at = excluded.last_success_at,
                next_update_at = excluded.next_update_at,
                etag = excluded.etag,
                last_modified = excluded.last_modified,
                content_sha256 = excluded.content_sha256,
                entry_count = excluded.entry_count,
                active_generation = excluded.active_generation,
                remote_generation_id = excluded.remote_generation_id,
                last_error_code = '',
                last_error_summary = '',
                consecutive_failures = 0
            """,
            (
                source_id,
                FeedStatus.ACTIVE.value,
                now,
                now,
                None,
                etag,
                last_modified,
                generation["content_sha256"],
                generation["entry_count"],
                generation_id,
                generation_id,
                "",
                "",
                0,
            ),
        )
    return previous, generation_id


def get_active_threat_intel(domain: str) -> sqlite3.Row | None:
    return query_one(
        """
        SELECT
            e.domain,
            e.source_id AS source,
            s.name AS source_name,
            e.category,
            e.confidence,
            e.first_seen,
            e.last_seen,
            g.generation_id,
            st.last_success_at,
            st.status,
            s.stale_after_seconds
        FROM threat_intel_generation_entries e
        JOIN threat_intel_generations g
            ON g.generation_id = e.generation_id
            AND g.status = 'active'
        JOIN threat_intel_sources s
            ON s.source_id = e.source_id
            AND s.enabled = 1
        LEFT JOIN threat_intel_source_state st
            ON st.source_id = s.source_id
        WHERE e.domain = ?
        ORDER BY e.confidence DESC, e.last_seen DESC
        LIMIT 1
        """,
        (domain,),
    )


def list_managed_threat_intel_entries(
    *,
    limit: int = 100,
    search: str = "",
    source_id: str = "",
    category: str = "",
    generation_id: str = "",
) -> list[sqlite3.Row]:
    where = ["s.source_id != ?"]
    params: list[Any] = [LEGACY_INTEL_SOURCE_ID]

    if source_id:
        where.append("s.source_id = ?")
        params.append(source_id)

    if generation_id:
        where.append("g.generation_id = ?")
        params.append(generation_id)
    else:
        where.append("g.status = 'active'")
        where.append("st.active_generation = g.generation_id")

    if search:
        where.append("e.domain LIKE ?")
        params.append(f"%{search}%")

    if category:
        where.append("e.category = ?")
        params.append(category)

    return query_all(
        f"""
        SELECT
            e.domain,
            e.source_id,
            s.name AS source_name,
            e.generation_id,
            g.status AS generation_status,
            CASE WHEN st.active_generation = e.generation_id THEN 1 ELSE 0 END AS active,
            e.category,
            e.confidence,
            e.first_seen,
            e.last_seen
        FROM threat_intel_generation_entries e
        JOIN threat_intel_generations g
            ON g.generation_id = e.generation_id
        JOIN threat_intel_sources s
            ON s.source_id = e.source_id
        LEFT JOIN threat_intel_source_state st
            ON st.source_id = s.source_id
        WHERE {" AND ".join(where)}
        ORDER BY e.last_seen DESC, e.domain ASC
        LIMIT ?
        """,
        tuple(params + [limit]),
    )


def record_intel_update_audit(
    result: FeedUpdateResult,
    *,
    http_status: int | None = None,
) -> int:
    return execute(
        """
        INSERT INTO threat_intel_update_audit
        (
            source_id,
            attempted_at,
            result,
            http_status,
            changed,
            not_modified,
            downloaded_bytes,
            parsed_entries,
            accepted_entries,
            rejected_entries,
            duplicate_entries,
            previous_generation,
            active_generation,
            duration_ms,
            warnings_json,
            error_code,
            error_summary,
            operation,
            reused_generation,
            created_generation,
            content_unchanged,
            trigger
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result.source_id,
            time.time(),
            "success" if result.success else "failed",
            http_status,
            1 if result.changed else 0,
            1 if result.not_modified else 0,
            result.downloaded_bytes,
            result.parsed_entries,
            result.accepted_entries,
            result.rejected_entries,
            result.duplicate_entries,
            result.previous_generation,
            result.active_generation,
            result.duration_ms,
            json.dumps(result.warnings),
            result.error_code,
            result.error_summary,
            "reactivate" if result.reused_generation else "update",
            1 if result.reused_generation else 0,
            1 if result.created_generation else 0,
            1 if result.content_unchanged else 0,
            result.trigger,
        ),
    )


def list_intel_update_audit(limit: int = 100, source_id: str = "") -> list[dict[str, Any]]:
    where = ""
    params: list[Any] = []
    if source_id:
        where = "WHERE source_id = ?"
        params.append(source_id)
    rows = query_all(
        f"""
        SELECT *
        FROM threat_intel_update_audit
        {where}
        ORDER BY id DESC
        LIMIT ?
        """,
        tuple(params + [limit]),
    )
    result = []
    for row in rows:
        item = dict(row)
        try:
            item["warnings"] = json.loads(item.pop("warnings_json") or "[]")
        except json.JSONDecodeError:
            item["warnings"] = []
        item["changed"] = bool(item["changed"])
        item["not_modified"] = bool(item["not_modified"])
        item["reused_generation"] = bool(item.get("reused_generation", 0))
        item["created_generation"] = bool(item.get("created_generation", 0))
        item["content_unchanged"] = bool(item.get("content_unchanged", 0))
        result.append(item)
    return result


def check_threat_intel_integrity(
    database_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """
    Inspect managed threat-intelligence generation state without mutation.
    """

    issues: list[dict[str, Any]] = []

    def add(code: str, **details: Any) -> None:
        issues.append({"code": code, **details})

    def select(sql: str) -> list[sqlite3.Row]:
        return query_all_readonly(sql, database_path=database_path)

    for row in select(
        """
        SELECT source_id, COUNT(*) AS count
        FROM threat_intel_generations
        WHERE status = 'active'
        GROUP BY source_id
        HAVING COUNT(*) > 1
        """
    ):
        add("intel.integrity.multiple_active_generations", source_id=row["source_id"], count=row["count"])

    for row in select(
        """
        SELECT st.source_id, st.active_generation
        FROM threat_intel_source_state st
        LEFT JOIN threat_intel_generations g
            ON g.generation_id = st.active_generation
        WHERE st.active_generation != ''
          AND g.generation_id IS NULL
        """
    ):
        add("intel.integrity.active_generation_missing", source_id=row["source_id"], generation_id=row["active_generation"])

    for row in select(
        """
        SELECT st.source_id, st.active_generation, g.source_id AS generation_source
        FROM threat_intel_source_state st
        JOIN threat_intel_generations g
            ON g.generation_id = st.active_generation
        WHERE st.active_generation != ''
          AND g.source_id != st.source_id
        """
    ):
        add(
            "intel.integrity.active_generation_wrong_source",
            source_id=row["source_id"],
            generation_id=row["active_generation"],
            generation_source=row["generation_source"],
        )

    for row in select(
        """
        SELECT st.source_id, st.remote_generation_id
        FROM threat_intel_source_state st
        LEFT JOIN threat_intel_generations g
            ON g.generation_id = st.remote_generation_id
        WHERE st.remote_generation_id != ''
          AND g.generation_id IS NULL
        """
    ):
        add("intel.integrity.remote_generation_missing", source_id=row["source_id"], generation_id=row["remote_generation_id"])

    for row in select(
        """
        SELECT st.source_id, st.remote_generation_id, g.source_id AS generation_source
        FROM threat_intel_source_state st
        JOIN threat_intel_generations g
            ON g.generation_id = st.remote_generation_id
        WHERE st.remote_generation_id != ''
          AND g.source_id != st.source_id
        """
    ):
        add(
            "intel.integrity.remote_generation_wrong_source",
            source_id=row["source_id"],
            generation_id=row["remote_generation_id"],
            generation_source=row["generation_source"],
        )

    for row in select(
        """
        SELECT g.source_id, g.generation_id, g.entry_count, COUNT(e.id) AS actual_count
        FROM threat_intel_generations g
        LEFT JOIN threat_intel_generation_entries e
            ON e.generation_id = g.generation_id
        GROUP BY g.source_id, g.generation_id, g.entry_count
        HAVING actual_count != g.entry_count
        """
    ):
        add(
            "intel.integrity.generation_entry_count_mismatch",
            source_id=row["source_id"],
            generation_id=row["generation_id"],
            expected=row["entry_count"],
            actual=row["actual_count"],
        )

    for row in select(
        """
        SELECT generation_id, domain, COUNT(*) AS count
        FROM threat_intel_generation_entries
        GROUP BY generation_id, domain
        HAVING COUNT(*) > 1
        """
    ):
        add("intel.integrity.duplicate_generation_domain", generation_id=row["generation_id"], domain=row["domain"], count=row["count"])

    for row in select(
        """
        SELECT g.source_id, g.generation_id, g.previous_generation
        FROM threat_intel_generations g
        LEFT JOIN threat_intel_generations previous
            ON previous.generation_id = g.previous_generation
        WHERE g.previous_generation IS NOT NULL
          AND g.previous_generation != ''
          AND previous.generation_id IS NULL
        """
    ):
        add(
            "intel.integrity.rollback_pointer_missing",
            source_id=row["source_id"],
            generation_id=row["generation_id"],
            previous_generation=row["previous_generation"],
        )

    for row in select(
        """
        SELECT source_id, active_generation
        FROM threat_intel_update_audit audit
        WHERE active_generation != ''
          AND NOT EXISTS (
              SELECT 1
              FROM threat_intel_generations g
              WHERE g.source_id = audit.source_id
                AND g.generation_id = audit.active_generation
          )
        """
    ):
        add("intel.integrity.audit_active_generation_missing", source_id=row["source_id"], generation_id=row["active_generation"])

    for row in select(
        """
        SELECT source_id, previous_generation
        FROM threat_intel_update_audit audit
        WHERE previous_generation != ''
          AND NOT EXISTS (
              SELECT 1
              FROM threat_intel_generations g
              WHERE g.source_id = audit.source_id
                AND g.generation_id = audit.previous_generation
          )
        """
    ):
        add("intel.integrity.audit_previous_generation_missing", source_id=row["source_id"], generation_id=row["previous_generation"])

    for row in select(
        """
        SELECT source_id, etag, last_modified
        FROM threat_intel_source_state
        WHERE (etag != '' OR last_modified != '')
          AND (remote_generation_id = '' OR content_sha256 = '')
        """
    ):
        add("intel.integrity.invalid_source_state_validators", source_id=row["source_id"])

    for row in select(
        """
        SELECT st.source_id, st.active_generation, g.status
        FROM threat_intel_source_state st
        JOIN threat_intel_generations g
            ON g.generation_id = st.active_generation
        WHERE st.active_generation != ''
          AND g.status != 'active'
        """
    ):
        add("intel.integrity.active_pointer_not_active_status", source_id=row["source_id"], generation_id=row["active_generation"], status=row["status"])

    for row in select(
        """
        SELECT source_id, generation_id, status
        FROM threat_intel_generations
        WHERE status = 'active'
          AND activated_at IS NULL
        """
    ):
        add("intel.integrity.active_generation_not_activated", source_id=row["source_id"], generation_id=row["generation_id"], status=row["status"])

    return issues


def mark_intel_update_not_modified(
    source_id: str,
    etag: str = "",
    last_modified: str = "",
    remote_generation_id: str = "",
) -> None:
    now = time.time()
    execute(
        """
        UPDATE threat_intel_source_state
        SET
            status = CASE WHEN active_generation = '' THEN 'unknown' ELSE 'active' END,
            last_attempt_at = ?,
            etag = CASE WHEN ? != '' THEN ? ELSE etag END,
            last_modified = CASE WHEN ? != '' THEN ? ELSE last_modified END,
            remote_generation_id = CASE WHEN ? != '' THEN ? ELSE remote_generation_id END,
            last_error_code = '',
            last_error_summary = '',
            consecutive_failures = 0
        WHERE source_id = ?
        """,
        (
            now,
            etag,
            etag,
            last_modified,
            last_modified,
            remote_generation_id,
            remote_generation_id,
            source_id,
        ),
    )


def mark_intel_update_failed(source_id: str, code: str, summary: str) -> None:
    now = time.time()
    execute(
        """
        INSERT INTO threat_intel_source_state
        (
            source_id,
            status,
            last_attempt_at,
            last_error_code,
            last_error_summary,
            consecutive_failures
        )
        VALUES (?, ?, ?, ?, ?, 1)

        ON CONFLICT(source_id)

        DO UPDATE SET
            status = 'failed',
            last_attempt_at = excluded.last_attempt_at,
            last_error_code = excluded.last_error_code,
            last_error_summary = excluded.last_error_summary,
            consecutive_failures = consecutive_failures + 1
        """,
        (source_id, FeedStatus.FAILED.value, now, code, summary[:240]),
    )


def rollback_intel_generation(source_id: str) -> str | None:
    with transaction() as conn:
        state = conn.execute(
            "SELECT active_generation FROM threat_intel_source_state WHERE source_id = ?",
            (source_id,),
        ).fetchone()
        if state is None or not state["active_generation"]:
            return None
        active = state["active_generation"]
        active_row = conn.execute(
            "SELECT previous_generation FROM threat_intel_generations WHERE generation_id = ?",
            (active,),
        ).fetchone()
        previous = active_row["previous_generation"] if active_row else ""
        if not previous:
            return None
        previous_row = conn.execute(
            "SELECT entry_count FROM threat_intel_generations WHERE generation_id = ?",
            (previous,),
        ).fetchone()
        if previous_row is None:
            return None
        now = time.time()
        conn.execute("UPDATE threat_intel_generations SET status = 'inactive' WHERE generation_id = ?", (active,))
        conn.execute(
            "UPDATE threat_intel_generations SET status = 'active', activated_at = ? WHERE generation_id = ?",
            (now, previous),
        )
        conn.execute(
            """
            UPDATE threat_intel_source_state
            SET active_generation = ?,
                entry_count = ?,
                status = 'active',
                last_success_at = ?
            WHERE source_id = ?
            """,
            (previous, previous_row["entry_count"], now, source_id),
        )
        return previous


# ============================================================================
# Domain Memory
# ============================================================================


def get_domain_memory(
    domain: str,
) -> sqlite3.Row | None:
    """
    Return statistics for a domain.
    """

    return query_one(
        """
        SELECT *

        FROM domain_memory

        WHERE domain = ?
        """,
        (domain,),
    )


def get_domain_metadata(
    domain: str,
) -> dict[str, object]:
    """
    Return analysis metadata for a domain.
    """

    row = query_one(
        """
        SELECT

            dm.domain,
            dm.query_count,
            dm.first_seen,
            dm.last_seen,
            COUNT(DISTINCT e.device) AS device_count,
            SUM(
                CASE
                    WHEN e.timestamp >= dm.last_seen - 3600 THEN 1
                    ELSE 0
                END
            ) AS recent_queries

        FROM domain_memory dm

        LEFT JOIN events e
            ON e.domain = dm.domain

        WHERE dm.domain = ?

        GROUP BY
            dm.domain,
            dm.query_count,
            dm.first_seen,
            dm.last_seen
        """,
        (domain,),
    )

    if row is None:
        return {
            "domain": domain,
            "query_count": 0,
            "first_seen": 0.0,
            "last_seen": 0.0,
            "device_count": 0,
            "recent_queries": 0,
            "tags": [],
        }

    return {
        "domain": row["domain"],
        "query_count": row["query_count"] or 0,
        "first_seen": row["first_seen"] or 0.0,
        "last_seen": row["last_seen"] or 0.0,
        "device_count": row["device_count"] or 0,
        "recent_queries": row["recent_queries"] or 0,
        "tags": [],
    }


# ============================================================================
# Application State
# ============================================================================


def get_state(
    key: str,
    default: str | None = None,
) -> str | None:
    """
    Return a persisted application state value.
    """

    row = query_one(
        """
        SELECT value

        FROM app_state

        WHERE key = ?
        """,
        (key,),
    )

    if row is None:
        return default

    return row["value"]


def get_state_readonly(
    key: str,
    default: str | None = None,
    database_path: str | Path | None = None,
) -> str | None:
    """
    Return a persisted application state value without opening a writable DB.
    """

    try:
        row = query_one_readonly(
            """
            SELECT value
            FROM app_state
            WHERE key = ?
            """,
            (key,),
            database_path=database_path,
        )
    except (sqlite3.DatabaseError, FileNotFoundError, OSError):
        return default

    if row is None:
        return default

    return row["value"]


def set_state(
    key: str,
    value: str,
) -> None:
    """
    Persist an application state value.
    """

    execute(
        """
        INSERT INTO app_state
        (
            key,
            value
        )
        VALUES (?, ?)

        ON CONFLICT(key)

        DO UPDATE SET

            value = excluded.value
        """,
        (
            key,
            value,
        ),
    )


def get_int_state(
    key: str,
    default: int = 0,
) -> int:
    """
    Return a persisted application state value as an integer.
    """

    value = get_state(
        key,
        str(default),
    )

    try:
        return int(value or default)

    except (TypeError, ValueError):
        return default


def increment_state_counter(
    key: str,
    amount: int = 1,
) -> int:
    """
    Increment a persisted integer counter and return the new value.
    """

    with transaction() as conn:
        row = conn.execute(
            """
            SELECT value

            FROM app_state

            WHERE key = ?
            """,
            (key,),
        ).fetchone()

        try:
            current = int(row["value"]) if row else 0

        except (TypeError, ValueError):
            current = 0

        updated = current + amount

        conn.execute(
            """
            INSERT INTO app_state
            (
                key,
                value
            )
            VALUES (?, ?)

            ON CONFLICT(key)

            DO UPDATE SET

                value = excluded.value
            """,
            (
                key,
                str(updated),
            ),
        )

        return updated


def ai_metrics() -> dict[str, int]:
    """
    Return persisted AI call and skip counters.
    """

    calls = get_int_state("ai.calls.total", 0)
    rate_limit_skips = get_int_state("ai.rate_limit_skips.total", 0)
    disabled_skips = get_int_state("ai.disabled_skips.total", 0)
    cooldown_skips = get_int_state("ai.cooldown_skips.total", 0)
    parse_errors = get_int_state("ai.parse_errors.total", 0)
    timeouts = get_int_state("ai.timeouts.total", 0)
    slow_responses = get_int_state("ai.slow_responses.total", 0)
    skipped = rate_limit_skips + disabled_skips + cooldown_skips + timeouts

    return {
        "ai_calls": calls,
        "ai_skipped": skipped,
        "ai_parse_errors": parse_errors,
        "ai_timeouts": timeouts,
        "calls": calls,
        "rate_limit_skips": rate_limit_skips,
        "disabled_skips": disabled_skips,
        "cooldown_skips": cooldown_skips,
        "parse_errors": parse_errors,
        "timeouts": timeouts,
        "slow_responses": slow_responses,
        "cooldown_until": get_int_state("ai.cooldown_until", 0),
    }


# ============================================================================
# Maintenance
# ============================================================================


def cleanup_old_events(
    keep_latest: int = 100000,
) -> int:
    """
    Delete old events while keeping the newest records.

    Returns
    -------
    int
        Number of deleted rows.
    """

    row = query_one(
        """
        SELECT COUNT(*) AS count

        FROM events
        """
    )

    total = row["count"] if row else 0

    if total <= keep_latest:
        return 0

    delete_count = total - keep_latest

    execute(
        """
        DELETE FROM events

        WHERE id IN
        (
            SELECT id

            FROM events

            ORDER BY id ASC

            LIMIT ?
        )
        """,
        (delete_count,),
    )

    return delete_count


def database_stats() -> dict[str, int]:
    """
    Return basic database statistics.
    """

    event_count = query_one(
        "SELECT COUNT(*) AS count FROM events"
    )

    processed_count = query_one(
        """
        SELECT COUNT(*) AS count

        FROM events

        WHERE processed = 1
        """
    )

    domain_count = query_one(
        """
        SELECT COUNT(*) AS count

        FROM domain_memory
        """
    )

    analysis_count = query_one(
        """
        SELECT COUNT(*) AS count

        FROM analysis
        """
    )

    action_count = query_one(
        """
        SELECT COUNT(*) AS count

        FROM action_audit
        """
    )

    reputation_count = query_one(
        """
        SELECT COUNT(*) AS count

        FROM domain_reputation
        """
    )

    threat_intel_count = query_one(
        """
        SELECT COUNT(*) AS count

        FROM threat_intel
        """
    )

    return {
        "events": event_count["count"] if event_count else 0,
        "processed": processed_count["count"] if processed_count else 0,
        "domains": domain_count["count"] if domain_count else 0,
        "analyses": analysis_count["count"] if analysis_count else 0,
        "actions": action_count["count"] if action_count else 0,
        "reputations": reputation_count["count"] if reputation_count else 0,
        "threat_intel": threat_intel_count["count"] if threat_intel_count else 0,
    }


def database_stats_readonly(
    database_path: str | Path | None = None,
) -> dict[str, int]:
    """
    Return basic database statistics without migrating or writing.
    """

    path = Path(database_path) if database_path is not None else _database_path()
    queries = {
        "events": "SELECT COUNT(*) AS count FROM events",
        "processed": "SELECT COUNT(*) AS count FROM events WHERE processed = 1",
        "domains": "SELECT COUNT(*) AS count FROM domain_memory",
        "analyses": "SELECT COUNT(*) AS count FROM analysis",
        "actions": "SELECT COUNT(*) AS count FROM action_audit",
        "reputations": "SELECT COUNT(*) AS count FROM domain_reputation",
        "threat_intel": "SELECT COUNT(*) AS count FROM threat_intel",
    }
    stats: dict[str, int] = {key: 0 for key in queries}

    with closing(Database.open_read_only(path)) as conn:
        for key, sql in queries.items():
            try:
                row = conn.execute(sql).fetchone()
            except sqlite3.DatabaseError:
                continue
            stats[key] = int(row["count"]) if row else 0

    return stats


def _count_rows_by(
    sql: str,
    parameters: tuple[Any, ...] = (),
) -> dict[str, int]:
    """
    Return grouped count rows as a plain dictionary.
    """

    return {
        str(row["name"]): int(row["count"])
        for row in query_all(sql, parameters)
        if row["name"] is not None
    }


def decision_metrics() -> dict[str, Any]:
    """
    Return aggregate decision metrics for dashboard and API consumers.
    """

    analysis = query_one(
        """
        SELECT

            COUNT(*) AS total,
            SUM(CASE WHEN risk < 40 THEN 1 ELSE 0 END) AS low_risk,
            SUM(CASE WHEN risk >= 40 AND risk < 70 THEN 1 ELSE 0 END) AS medium_risk,
            SUM(CASE WHEN risk >= 70 THEN 1 ELSE 0 END) AS high_risk,
            SUM(CASE WHEN confidence = 0 THEN 1 ELSE 0 END) AS zero_confidence

        FROM analysis
        """
    )

    action = query_one(
        """
        SELECT COUNT(*) AS total

        FROM action_audit
        """
    )
    parse_error = query_one(
        """
        SELECT COUNT(*) AS count

        FROM action_audit

        WHERE status = 'parse_error'
        """
    )

    metrics = {
        "analysis": {
            "total": int(analysis["total"] or 0) if analysis else 0,
            "low_risk": int(analysis["low_risk"] or 0) if analysis else 0,
            "medium_risk": int(analysis["medium_risk"] or 0) if analysis else 0,
            "high_risk": int(analysis["high_risk"] or 0) if analysis else 0,
            "zero_confidence": int(analysis["zero_confidence"] or 0) if analysis else 0,
        },
        "categories": _count_rows_by(
            """
            SELECT category AS name, COUNT(*) AS count

            FROM analysis

            GROUP BY category

            ORDER BY count DESC, category ASC
            """
        ),
        "models": _count_rows_by(
            """
            SELECT model AS name, COUNT(*) AS count

            FROM analysis

            GROUP BY model

            ORDER BY count DESC, model ASC
            """
        ),
        "actions": {
            "total": int(action["total"] or 0) if action else 0,
            "parse_errors": int(parse_error["count"] or 0) if parse_error else 0,
            "by_action": _count_rows_by(
                """
                SELECT action AS name, COUNT(*) AS count

                FROM action_audit

                GROUP BY action

                ORDER BY count DESC, action ASC
                """
            ),
            "by_status": _count_rows_by(
                """
                SELECT status AS name, COUNT(*) AS count

                FROM action_audit

                GROUP BY status

                ORDER BY count DESC, status ASC
                """
            ),
            "feedback": _count_rows_by(
                """
                SELECT status AS name, COUNT(*) AS count

                FROM action_audit

                WHERE action = ?

                GROUP BY status

                ORDER BY count DESC, status ASC
                """,
                ("feedback",),
            ),
        },
        "rules": _count_rows_by(
            """
            SELECT decision AS name, COUNT(*) AS count

            FROM domain_rules

            WHERE enabled = 1

            GROUP BY decision

            ORDER BY count DESC, decision ASC
            """
        ),
    }

    metrics["ai"] = ai_metrics()

    return metrics


def vacuum() -> None:
    """
    Optimize the SQLite database.
    """

    with closing(get_connection()) as conn:
        conn.execute("VACUUM")
