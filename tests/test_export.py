import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pihole_ai.export import (
    export_rows,
    get_export_rows,
    write_csv,
    write_json,
)


class ExportTests(unittest.TestCase):
    def test_get_export_rows_for_analysis(self) -> None:
        rows = [
            {
                "domain": "example.com",
            }
        ]

        with patch(
            "pihole_ai.export.get_recent_analyses",
            return_value=rows,
        ) as get_recent_analyses:
            result = get_export_rows(
                dataset="analysis",
                limit=10,
                search="example",
                min_risk=40,
                category="benign",
            )

        self.assertEqual(result, rows)
        get_recent_analyses.assert_called_once_with(
            limit=10,
            search="example",
            min_risk=40,
            category="benign",
        )

    def test_get_export_rows_for_events(self) -> None:
        rows = [
            {
                "domain": "example.com",
            }
        ]

        with patch(
            "pihole_ai.export.get_recent_events",
            return_value=rows,
        ) as get_recent_events:
            result = get_export_rows(
                dataset="events",
                limit=10,
                search="device-a",
            )

        self.assertEqual(result, rows)
        get_recent_events.assert_called_once_with(
            limit=10,
            search="device-a",
        )

    def test_get_export_rows_for_actions(self) -> None:
        rows = [
            {
                "domain": "example.com",
                "action": "block",
            }
        ]

        with patch(
            "pihole_ai.export.get_recent_actions",
            return_value=rows,
        ) as get_recent_actions:
            result = get_export_rows(
                dataset="actions",
                limit=10,
                search="example",
            )

        self.assertEqual(result, rows)
        get_recent_actions.assert_called_once_with(
            limit=10,
            search="example",
        )

    def test_get_export_rows_for_reputations(self) -> None:
        rows = [
            {
                "domain": "bad.example",
                "score": 80,
            }
        ]

        with patch(
            "pihole_ai.export.get_reputations",
            return_value=rows,
        ) as get_reputations:
            result = get_export_rows(
                dataset="reputations",
                limit=10,
                search="bad",
                min_risk=70,
            )

        self.assertEqual(result, rows)
        get_reputations.assert_called_once_with(
            limit=10,
            search="bad",
            min_score=70,
        )

    def test_write_json(self) -> None:
        output = io.StringIO()

        write_json(
            [
                {
                    "domain": "example.com",
                }
            ],
            output,
        )

        self.assertEqual(
            json.loads(output.getvalue()),
            [
                {
                    "domain": "example.com",
                }
            ],
        )

    def test_write_csv(self) -> None:
        output = io.StringIO()

        write_csv(
            [
                {
                    "domain": "example.com",
                    "risk": 10,
                }
            ],
            output,
            [
                "domain",
                "risk",
            ],
        )

        output.seek(0)
        rows = list(csv.DictReader(output))

        self.assertEqual(
            rows,
            [
                {
                    "domain": "example.com",
                    "risk": "10",
                }
            ],
        )

    def test_export_rows_writes_file(self) -> None:
        rows = [
            {
                "domain": "example.com",
                "risk": 10,
                "confidence": 90,
                "category": "benign",
                "reason": "Test.",
                "model": "fake",
                "analyzed_at": 1.0,
            }
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "analysis.json"

            with patch(
                "pihole_ai.export.get_export_rows",
                return_value=rows,
            ):
                count = export_rows(
                    dataset="analysis",
                    export_format="json",
                    path=str(path),
                )

            self.assertEqual(count, 1)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                rows,
            )


if __name__ == "__main__":
    unittest.main()
