import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pihole_ai.intel import (
    add_source,
    import_hosts_file,
    normalize_domain,
    parse_hosts_domains,
    print_intel,
)
from pihole_ai.intel_feeds import (
    ERROR_INSECURE_URL,
    ERROR_PRIVATE_ADDRESS,
    FeedError,
    parse_feed,
    validate_feed_url,
)
from pihole_ai.intel_models import FeedFormat, FeedSource


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

    def test_parse_feed_deduplicates_and_rejects_invalid_domains(self) -> None:
        source = FeedSource(
            source_id="test-feed",
            name="Test Feed",
            url="https://feeds.example/hosts.txt",
            format=FeedFormat.HOSTS.value,
        )

        parsed = parse_feed(
            b"0.0.0.0 bad.example\nbad.example\nlocalhost\nbad/example\n",
            FeedFormat.HOSTS.value,
            source,
        )

        self.assertEqual(parsed.accepted_entries, ["bad.example"])
        self.assertEqual(parsed.duplicate_count, 1)
        self.assertEqual(parsed.rejected_count, 2)

    def test_validate_feed_url_rejects_http_without_opt_in(self) -> None:
        with self.assertRaises(FeedError) as raised:
            validate_feed_url("http://feeds.example/hosts.txt")

        self.assertEqual(raised.exception.code, ERROR_INSECURE_URL)

    def test_validate_feed_url_rejects_private_addresses(self) -> None:
        with patch(
            "pihole_ai.intel_feeds.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("127.0.0.1", 0))],
        ):
            with self.assertRaises(FeedError) as raised:
                validate_feed_url("https://localhost/hosts.txt")

        self.assertEqual(raised.exception.code, ERROR_PRIVATE_ADDRESS)

    def test_add_source_validates_and_persists_feed_source(self) -> None:
        with patch(
            "pihole_ai.intel.validate_feed_url",
            return_value=None,
        ), patch("pihole_ai.intel.save_intel_source") as save_intel_source:
            source = add_source(
                source_id="malware-feed",
                name="Malware Feed",
                url="https://feeds.example/hosts.txt",
                feed_format=FeedFormat.HOSTS.value,
            )

        self.assertEqual(source.source_id, "malware-feed")
        self.assertEqual(source.url, "https://feeds.example/hosts.txt")
        save_intel_source.assert_called_once()


if __name__ == "__main__":
    unittest.main()
