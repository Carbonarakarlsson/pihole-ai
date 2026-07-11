"""
Explicit SQLite migrations for the PiHole-AI events database.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from core.logger import get_logger


logger = get_logger(__name__)

MIGRATION_TABLE = "schema_migrations"
SQLITE_TIMEOUT_SECONDS = 30


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


MIGRATIONS = [
    Migration(
        version=1,
        name="baseline_current_schema",
        apply=_apply_baseline,
    ),
]

LATEST_SUPPORTED_SCHEMA_VERSION = MIGRATIONS[-1].version


def open_database(
    database_path: str | Path,
) -> sqlite3.Connection:
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        path,
        timeout=SQLITE_TIMEOUT_SECONDS,
    )
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {SQLITE_TIMEOUT_SECONDS * 1000}")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def open_database_readonly(
    database_path: str | Path,
) -> sqlite3.Connection:
    """
    Open an existing SQLite database without creating or modifying it.
    """

    path = Path(database_path)

    if not path.exists():
        raise FileNotFoundError(path)

    uri = f"file:{path}?mode=ro"
    conn = sqlite3.connect(
        uri,
        timeout=SQLITE_TIMEOUT_SECONDS,
        uri=True,
    )
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {SQLITE_TIMEOUT_SECONDS * 1000}")
    conn.execute("PRAGMA query_only = ON")
    return conn


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
    conn.execute(f"PRAGMA busy_timeout = {SQLITE_TIMEOUT_SECONDS * 1000}")
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

        except Exception:
            conn.rollback()
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
        )

    with closing(open_database_readonly(path)) as conn:
        current = current_schema_version(conn)
        _raise_if_future_schema(current)

        if current == 0 and _application_tables(conn):
            _verify_baseline_compatible(conn)

        compatible = True

    pending = len(pending_migrations(current))
    file_size = path.stat().st_size if path.exists() else 0

    return DatabaseStatus(
        database_path=str(path),
        current_schema_version=current,
        latest_supported_schema_version=LATEST_SUPPORTED_SCHEMA_VERSION,
        pending_migration_count=pending,
        database_file_size=file_size,
        compatible=compatible,
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
