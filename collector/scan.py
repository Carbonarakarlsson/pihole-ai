import time
from contextlib import closing

from core.config import settings
from core.db import (
    get_state,
    init_db,
    insert_event,
    set_state,
)
from core.logger import get_logger
from core.sqlite_policy import SQLiteAccessMode, SQLiteConnectionFactory


LOGGER = get_logger(__name__)
LAST_QUERY_ID_KEY = "collector.last_query_id"


def load_last_query_id() -> int:
    """
    Return the last processed Pi-hole query ID.
    """

    value = get_state(
        LAST_QUERY_ID_KEY,
        "0",
    )

    try:
        return int(value or "0")

    except ValueError:
        LOGGER.warning(
            "Invalid collector state for %s: %r. Starting from 0.",
            LAST_QUERY_ID_KEY,
            value,
        )
        return 0


def save_last_query_id(
    query_id: int,
) -> None:
    """
    Persist the last processed Pi-hole query ID.
    """

    set_state(
        LAST_QUERY_ID_KEY,
        str(query_id),
    )


def fetch(
    last_query_id: int,
) -> list[tuple[int, str, str]]:
    """
    Fetch new Pi-hole queries after the given query ID.
    """

    with closing(
        SQLiteConnectionFactory.connect(
            settings.pihole_db,
            SQLiteAccessMode.READ_ONLY,
        )
    ) as conn:
        cur = conn.execute(
            """
            SELECT id, domain, client

            FROM queries

            WHERE id > ?

            ORDER BY id ASC

            LIMIT ?
            """,
            (
                last_query_id,
                settings.collect_batch_size,
            ),
        )

        return [
            (
                row["id"],
                row["domain"],
                row["client"],
            )
            for row in cur.fetchall()
        ]


def process_batch(
    last_query_id: int,
) -> int:
    """
    Ingest one batch of Pi-hole queries.

    Returns the latest processed Pi-hole query ID.
    """

    rows = fetch(
        last_query_id,
    )

    if not rows:
        return last_query_id

    current_id = last_query_id

    for query_id, domain, device in rows:

        current_id = max(
            current_id,
            query_id,
        )

        insert_event(
            device=device or "unknown",
            domain=domain,
            timestamp=time.time(),
        )

        LOGGER.info(
            "Ingested DNS query: %s -> %s",
            device or "unknown",
            domain,
        )

    save_last_query_id(
        current_id,
    )

    LOGGER.info(
        "Collector ingested %d query(s).",
        len(rows),
    )

    return current_id


def main() -> None:
    """
    Continuously ingest new Pi-hole queries.
    """

    init_db()

    last_query_id = load_last_query_id()

    LOGGER.info(
        "Collector running (pihole_db=%s, last_query_id=%d).",
        settings.pihole_db,
        last_query_id,
    )

    while True:

        last_query_id = process_batch(
            last_query_id,
        )

        time.sleep(
            settings.collect_interval,
        )


if __name__ == "__main__":
    main()
