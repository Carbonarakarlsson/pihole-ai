"""
Central SQLite connection policy for PiHole-AI.

Connections are short lived and owned by the operation that opens them. They
must not be shared across threads, so the default sqlite3 thread check remains
enabled.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
from typing import Any

from core.config import ProtectedConfigurationAccessError, settings
from core.logger import get_logger


logger = get_logger(__name__)
DEFAULT_DB_TIMEOUT_SECONDS = 30
DEFAULT_DB_MIGRATION_TIMEOUT_SECONDS = 60
DEFAULT_DB_BUSY_TIMEOUT_MS = 30000


class SQLiteAccessMode(str, Enum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    MIGRATION = "migration"


class SQLitePolicyError(RuntimeError):
    """
    Base SQLite policy failure.
    """


class SQLiteBusyError(SQLitePolicyError):
    """
    Raised when SQLite cannot acquire a required lock in time.
    """

    def __init__(
        self,
        database_path: str | Path,
        mode: SQLiteAccessMode,
        original: BaseException,
    ) -> None:
        self.database_path = str(database_path)
        self.mode = mode
        super().__init__(
            f"Database is busy for {mode.value} access at {self.database_path}. "
            "Another PiHole-AI process may be writing. Retry shortly, or check "
            "service logs if the condition persists."
        )
        self.__cause__ = original


@dataclass(frozen=True)
class SQLiteDiagnostics:
    database_path: str
    journal_mode: str | None
    busy_timeout_ms: int
    database_file_size: int
    wal_file_size: int
    read_only_ok: bool
    write_open_ok: bool


class SQLiteConnectionFactory:
    """
    Authoritative SQLite connection factory.
    """

    @staticmethod
    def connect(
        database_path: str | Path,
        mode: SQLiteAccessMode,
    ) -> sqlite3.Connection:
        path = Path(database_path)
        started_at = time.perf_counter()

        try:
            if mode == SQLiteAccessMode.READ_ONLY:
                return SQLiteConnectionFactory._connect_read_only(path)
            if mode == SQLiteAccessMode.MIGRATION:
                return SQLiteConnectionFactory._connect_writable(
                    path,
                    mode=mode,
                    timeout_seconds=_config_int(
                        "db_migration_timeout_seconds",
                        "PIHOLE_AI_DB_MIGRATION_TIMEOUT_SECONDS",
                        DEFAULT_DB_MIGRATION_TIMEOUT_SECONDS,
                    ),
                )
            return SQLiteConnectionFactory._connect_writable(
                path,
                mode=mode,
                timeout_seconds=_config_int(
                    "db_timeout_seconds",
                    "PIHOLE_AI_DB_TIMEOUT_SECONDS",
                    DEFAULT_DB_TIMEOUT_SECONDS,
                ),
            )
        except sqlite3.OperationalError as exc:
            if _is_busy_error(exc):
                elapsed_ms = int((time.perf_counter() - started_at) * 1000)
                logger.warning(
                    "SQLite busy timeout opening database.",
                    extra={
                        "database_path": str(path),
                        "access_mode": mode.value,
                        "elapsed_ms": elapsed_ms,
                    },
                )
                raise SQLiteBusyError(path, mode, exc) from exc
            logger.warning(
                "SQLite connection open failed.",
                extra={
                    "database_path": str(path),
                    "access_mode": mode.value,
                },
            )
            raise

    @staticmethod
    def _connect_read_only(path: Path) -> sqlite3.Connection:
        if not path.exists():
            raise FileNotFoundError(path)

        uri = f"file:{path}?mode=ro"
        conn = sqlite3.connect(
            uri,
            timeout=_config_int(
                "db_timeout_seconds",
                "PIHOLE_AI_DB_TIMEOUT_SECONDS",
                DEFAULT_DB_TIMEOUT_SECONDS,
            ),
            uri=True,
        )
        try:
            SQLiteConnectionFactory._configure_common(conn)
            conn.execute("PRAGMA query_only = ON")
            return conn
        except Exception:
            conn.close()
            raise

    @staticmethod
    def _connect_writable(
        path: Path,
        mode: SQLiteAccessMode,
        timeout_seconds: int,
    ) -> sqlite3.Connection:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            path,
            timeout=timeout_seconds,
            isolation_level=None,
        )
        try:
            SQLiteConnectionFactory._configure_common(conn)
            conn.execute("PRAGMA foreign_keys = ON")
            if mode == SQLiteAccessMode.MIGRATION:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
            return conn
        except Exception:
            conn.close()
            raise

    @staticmethod
    def _configure_common(conn: sqlite3.Connection) -> None:
        conn.row_factory = sqlite3.Row
        conn.execute(
            "PRAGMA busy_timeout = "
            f"{_config_int('db_busy_timeout_ms', 'PIHOLE_AI_DB_BUSY_TIMEOUT_MS', DEFAULT_DB_BUSY_TIMEOUT_MS)}"
        )

    @staticmethod
    def diagnostics(
        database_path: str | Path,
    ) -> SQLiteDiagnostics:
        path = Path(database_path)
        journal_mode: str | None = None
        busy_timeout_ms = _config_int(
            "db_busy_timeout_ms",
            "PIHOLE_AI_DB_BUSY_TIMEOUT_MS",
            DEFAULT_DB_BUSY_TIMEOUT_MS,
        )
        read_only_ok = False
        write_open_ok = False

        if path.exists():
            try:
                conn = SQLiteConnectionFactory.connect(
                    path,
                    SQLiteAccessMode.READ_ONLY,
                )
                try:
                    journal_row = conn.execute("PRAGMA journal_mode").fetchone()
                    timeout_row = conn.execute("PRAGMA busy_timeout").fetchone()
                    journal_mode = str(journal_row[0]) if journal_row else None
                    busy_timeout_ms = int(timeout_row[0]) if timeout_row else busy_timeout_ms
                    read_only_ok = True
                finally:
                    conn.close()
            except Exception:
                read_only_ok = False

            try:
                conn = SQLiteConnectionFactory.connect(
                    path,
                    SQLiteAccessMode.READ_WRITE,
                )
                conn.close()
                write_open_ok = True
            except Exception:
                write_open_ok = False

        return SQLiteDiagnostics(
            database_path=str(path),
            journal_mode=journal_mode,
            busy_timeout_ms=busy_timeout_ms,
            database_file_size=path.stat().st_size if path.exists() else 0,
            wal_file_size=_wal_size(path),
            read_only_ok=read_only_ok,
            write_open_ok=write_open_ok,
        )


def _wal_size(path: Path) -> int:
    wal_path = path.with_name(path.name + "-wal")
    try:
        return wal_path.stat().st_size
    except OSError:
        return 0


def _is_busy_error(exc: sqlite3.OperationalError) -> bool:
    message = str(exc).lower()
    return (
        "database is locked" in message
        or "database table is locked" in message
        or "database is busy" in message
    )


def _config_int(
    attr: str,
    env_key: str,
    default: int,
) -> int:
    raw = os.environ.get(env_key)
    if raw is not None:
        try:
            value = int(raw)
            if value > 0:
                return value
        except (TypeError, ValueError):
            return default

    try:
        value = int(getattr(settings, attr))
        if value > 0:
            return value
    except (AttributeError, ProtectedConfigurationAccessError, TypeError, ValueError):
        return default

    return default


def is_busy_error(exc: BaseException) -> bool:
    return isinstance(exc, sqlite3.OperationalError) and _is_busy_error(exc)


def configured_busy_timeout_ms() -> int:
    return _config_int(
        "db_busy_timeout_ms",
        "PIHOLE_AI_DB_BUSY_TIMEOUT_MS",
        DEFAULT_DB_BUSY_TIMEOUT_MS,
    )


def safe_rollback(
    conn: sqlite3.Connection,
    *,
    database_path: str | Path,
    operation: str,
) -> None:
    try:
        conn.rollback()
    except Exception:
        logger.exception(
            "SQLite transaction rollback failed.",
            extra={
                "database_path": str(database_path),
                "operation": operation,
            },
        )
