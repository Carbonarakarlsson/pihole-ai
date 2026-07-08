import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pihole_ai.intel import (
    import_hosts_file,
    normalize_domain,
    parse_hosts_domains,
    print_intel,
)


class ThreatIntelTests(unittest.TestCase):
    def test_normalize_domain_rejects_invalid_values(self) -> None:
        self.assertEqual(
            normalize_domain("Bad.Example."),
            "bad.example",
        )
        self.assertIsNone(normalize_domain("localhost"))
        self.assertIsNone(normalize_domain("bad/example"))
        self.assertIsNone(normalize_domain("singlelabel"))

    def test_parse_hosts_domains_supports_hosts_and_plain_lines(self) -> None:
        domains = parse_hosts_domains(
            [
                "# comment",
                "0.0.0.0 bad.example # trailing comment",
                "127.0.0.1 phish.example other.example",
                "plain.example",
                "0.0.0.0 bad.example",
                ":: ipv6blocked.example",
            ]
        )

        self.assertEqual(
            domains,
            [
                "bad.example",
                "phish.example",
                "other.example",
                "plain.example",
                "ipv6blocked.example",
            ],
        )

    def test_import_hosts_file_saves_unique_domains(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "hosts.txt"
            path.write_text(
                "0.0.0.0 bad.example\nbad.example\nplain.example\n",
                encoding="utf-8",
            )

            with patch("pihole_ai.intel.save_threat_intel") as save_threat_intel:
                count = import_hosts_file(
                    path=str(path),
                    source="test-feed",
                    category="malware",
                    confidence=85,
                )

        self.assertEqual(count, 2)
        self.assertEqual(save_threat_intel.call_count, 2)
        save_threat_intel.assert_any_call(
            domain="bad.example",
            source="test-feed",
            category="malware",
            confidence=85,
        )

    def test_print_intel_outputs_rows(self) -> None:
        rows = [
            {
                "domain": "bad.example",
                "source": "test-feed",
                "category": "malware",
                "confidence": 90,
            }
        ]

        with patch("pihole_ai.intel.get_intel_rows", return_value=rows), \
             patch("sys.stdout", io.StringIO()) as stdout:
            count = print_intel()

        self.assertEqual(count, 1)
        self.assertIn("bad.example", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
