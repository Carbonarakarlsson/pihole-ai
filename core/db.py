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

import sqlite3
from contextlib import contextmanager
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

                category TEXT,

                reason TEXT,

                model TEXT,

                analyzed_at REAL

            )
            """
        )

        _create_indexes(cur)


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

    with get_connection() as conn:

        cursor = conn.execute(sql, parameters)

        return cursor.fetchall()


def query_one(
    sql: str,
    parameters: tuple[Any, ...] = (),
) -> sqlite3.Row | None:
    """
    Execute a SELECT query returning one row.
    """

    with get_connection() as conn:

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


def get_unprocessed_events(
    limit: int = 100,
) -> list[sqlite3.Row]:
    """
    Return events waiting for AI analysis.
    """

    return query_all(
        """
        SELECT

            id,
            device,
            domain,
            timestamp

        FROM events

        WHERE processed = 0

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
            category,
            reason,
            model,
            analyzed_at
        )
        VALUES (?, ?, ?, ?, ?, ?)

        ON CONFLICT(domain)

        DO UPDATE SET

            risk = excluded.risk,
            category = excluded.category,
            reason = excluded.reason,
            model = excluded.model,
            analyzed_at = excluded.analyzed_at
        """,
        (
            domain,
            risk,
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

    return {
        "events": event_count["count"] if event_count else 0,
        "processed": processed_count["count"] if processed_count else 0,
        "domains": domain_count["count"] if domain_count else 0,
        "analyses": analysis_count["count"] if analysis_count else 0,
    }


def vacuum() -> None:
    """
    Optimize the SQLite database.
    """

    with get_connection() as conn:
        conn.execute("VACUUM")


# ============================================================================
# Initialize Database
# ============================================================================

init_db()
