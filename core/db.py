"""
PiHole-AI Database Layer

This module provides the single database interface for the entire project.

Features
--------
* SQLite WAL mode
* Foreign key support
* Automatic schema creation
* Automatic indexes
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
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Iterator

from core.config import settings


DATABASE_PATH = Path(settings.events_db)


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

    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
    )

    _configure_connection(conn)

    return conn


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


# ============================================================================
# Schema
# ============================================================================


def init_db() -> None:
    """
    Create all required database tables.
    """

    with transaction() as conn:

        cur = conn.cursor()

        # --------------------------------------------------------------
        # Events
        # --------------------------------------------------------------

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                device TEXT NOT NULL,

                domain TEXT NOT NULL,

                timestamp REAL NOT NULL,

                processed INTEGER NOT NULL DEFAULT 0

            )
            """
        )

        # --------------------------------------------------------------
        # Domain Memory
        # --------------------------------------------------------------

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_memory (

                domain TEXT PRIMARY KEY,

                first_seen REAL,

                last_seen REAL,

                query_count INTEGER DEFAULT 1

            )
            """
        )

        # --------------------------------------------------------------
        # AI Analysis
        # --------------------------------------------------------------

        cur.execute(
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
            """
        )

        # --------------------------------------------------------------
        # Application State
        # --------------------------------------------------------------

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS app_state (

                key TEXT PRIMARY KEY,

                value TEXT NOT NULL

            )
            """
        )

        # --------------------------------------------------------------
        # Action Audit
        # --------------------------------------------------------------

        cur.execute(
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
            """
        )

        # --------------------------------------------------------------
        # Domain Rules
        # --------------------------------------------------------------

        cur.execute(
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
            """
        )

        # --------------------------------------------------------------
        # Domain Reputation
        # --------------------------------------------------------------

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_reputation (

                domain TEXT PRIMARY KEY,

                score INTEGER NOT NULL,

                confidence INTEGER NOT NULL,

                signals TEXT NOT NULL,

                source TEXT NOT NULL,

                updated_at REAL NOT NULL

            )
            """
        )

        # --------------------------------------------------------------
        # Threat Intelligence
        # --------------------------------------------------------------

        cur.execute(
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
            """
        )

        _create_indexes(cur)
        _migrate_schema(cur)


def _create_indexes(cursor: sqlite3.Cursor) -> None:
    """
    Create indexes used by the application.
    """

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_events_processed
        ON events(processed)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_events_domain
        ON events(domain)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
        ON events(timestamp)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_analysis_risk
        ON analysis(risk)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_action_audit_created_at
        ON action_audit(created_at)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_action_audit_domain
        ON action_audit(domain)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_domain_rules_decision
        ON domain_rules(decision)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_domain_rules_enabled
        ON domain_rules(enabled)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_domain_reputation_score
        ON domain_reputation(score)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_threat_intel_domain
        ON threat_intel(domain)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_threat_intel_source
        ON threat_intel(source)
        """
    )
    # ============================================================================


def _migrate_schema(cursor: sqlite3.Cursor) -> None:
    """
    Apply lightweight schema migrations for existing databases.
    """

    analysis_columns = {
        row["name"]
        for row in cursor.execute("PRAGMA table_info(analysis)")
    }

    if "confidence" not in analysis_columns:
        cursor.execute(
            """
            ALTER TABLE analysis

            ADD COLUMN confidence INTEGER DEFAULT 0
            """
        )


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
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            domain,
            action,
            source,
            status,
            reason,
            risk,
            created_at,
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
            created_at

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

    execute(
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
            max(0, min(confidence, 100)),
            first_seen,
            last_seen,
        ),
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

    return {
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


def vacuum() -> None:
    """
    Optimize the SQLite database.
    """

    with closing(get_connection()) as conn:
        conn.execute("VACUUM")


# ============================================================================
# Initialize Database
# ============================================================================

init_db()
