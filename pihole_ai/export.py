"""
Export helpers for PiHole-AI.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any, Iterable, TextIO

from ui.dashboard import (
    get_recent_actions,
    get_recent_analyses,
    get_recent_events,
    get_reputations,
)


EXPORT_FIELDS = {
    "analysis": [
        "domain",
        "risk",
        "confidence",
        "category",
        "reason",
        "model",
        "analyzed_at",
    ],
    "events": [
        "id",
        "device",
        "domain",
        "timestamp",
        "processed",
    ],
    "actions": [
        "id",
        "domain",
        "action",
        "source",
        "status",
        "reason",
        "risk",
        "created_at",
    ],
    "reputations": [
        "domain",
        "score",
        "confidence",
        "signals",
        "source",
        "updated_at",
    ],
}


def get_export_rows(
    dataset: str,
    limit: int = 500,
    search: str = "",
    min_risk: int = 0,
    category: str = "",
) -> list[dict[str, Any]]:
    """
    Return rows for an export dataset.
    """

    if dataset == "analysis":
        return get_recent_analyses(
            limit=limit,
            search=search,
            min_risk=min_risk,
            category=category,
        )

    if dataset == "events":
        return get_recent_events(
            limit=limit,
            search=search,
        )

    if dataset == "actions":
        return get_recent_actions(
            limit=limit,
            search=search,
        )

    if dataset == "reputations":
        return get_reputations(
            limit=limit,
            search=search,
            min_score=min_risk,
        )

    raise ValueError(
        f"Unknown export dataset: {dataset}"
    )


def write_json(
    rows: Iterable[dict[str, Any]],
    output: TextIO,
) -> None:
    """
    Write rows as JSON.
    """

    json.dump(
        list(rows),
        output,
        indent=2,
    )
    output.write("\n")


def write_csv(
    rows: Iterable[dict[str, Any]],
    output: TextIO,
    fields: list[str],
) -> None:
    """
    Write rows as CSV.
    """

    writer = csv.DictWriter(
        output,
        fieldnames=fields,
        extrasaction="ignore",
    )
    writer.writeheader()

    for row in rows:
        writer.writerow(row)


def export_rows(
    dataset: str,
    export_format: str,
    path: str | None = None,
    limit: int = 500,
    search: str = "",
    min_risk: int = 0,
    category: str = "",
) -> int:
    """
    Export rows to a file or stdout.
    """

    rows = get_export_rows(
        dataset=dataset,
        limit=limit,
        search=search,
        min_risk=min_risk,
        category=category,
    )

    if path is None:
        output = sys.stdout

        if export_format == "json":
            write_json(rows, output)
        else:
            write_csv(
                rows,
                output,
                EXPORT_FIELDS[dataset],
            )

        return len(rows)

    output_path = Path(path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as output:
        if export_format == "json":
            write_json(rows, output)
        else:
            write_csv(
                rows,
                output,
                EXPORT_FIELDS[dataset],
            )

    return len(rows)
