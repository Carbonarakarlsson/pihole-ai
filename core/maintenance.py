"""
Database maintenance utilities.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from core.config import settings
from core.db import (
    cleanup_old_events,
    database_stats,
    vacuum,
)
from core.logger import get_logger


logger = get_logger(__name__)


@dataclass(frozen=True)
class MaintenanceResult:
    """
    Summary of one maintenance run.
    """

    deleted_events: int
    before: dict[str, int]
    after: dict[str, int]
    vacuumed: bool = False


def run_maintenance(
    keep_latest: int | None = None,
    vacuum_db: bool = False,
) -> MaintenanceResult:
    """
    Clean old events and optionally vacuum the database.
    """

    if keep_latest is None:
        keep_latest = settings.keep_latest_events

    before = database_stats()
    deleted = cleanup_old_events(
        keep_latest=keep_latest,
    )

    if vacuum_db:
        vacuum()

    after = database_stats()

    result = MaintenanceResult(
        deleted_events=deleted,
        before=before,
        after=after,
        vacuumed=vacuum_db,
    )

    logger.info(
        "Maintenance complete (deleted_events=%d, vacuumed=%s).",
        result.deleted_events,
        result.vacuumed,
    )

    return result


def build_parser() -> argparse.ArgumentParser:
    """
    Build the maintenance CLI parser.
    """

    parser = argparse.ArgumentParser(
        description="Run PiHole-AI database maintenance.",
    )
    parser.add_argument(
        "--keep-latest",
        type=int,
        default=None,
        help="Number of newest events to keep.",
    )
    parser.add_argument(
        "--vacuum",
        action="store_true",
        help="Run SQLite VACUUM after cleanup.",
    )

    return parser


def main() -> None:
    """
    Run database maintenance from the command line.
    """

    args = build_parser().parse_args()
    result = run_maintenance(
        keep_latest=args.keep_latest,
        vacuum_db=args.vacuum,
    )

    print(
        "Maintenance complete: "
        f"deleted_events={result.deleted_events}, "
        f"events_before={result.before['events']}, "
        f"events_after={result.after['events']}, "
        f"vacuumed={result.vacuumed}"
    )


if __name__ == "__main__":
    main()
