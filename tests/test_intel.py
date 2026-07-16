import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pihole_ai.intel import (
    add_source,
    get_intel_rows,
    intel_update_lock,
    import_hosts_file,
    normalize_domain,
    parse_hosts_domains,
    print_intel,
    update_source_config,
    update_sources,
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
                "source_type": "manual",
                "source_id": "test-feed",
                "generation_id": "",
                "active": True,
                "entries": [
                    {
                        "domain": "bad.example",
                        "source": "test-feed",
                        "category": "malware",
                        "confidence": 90,
                    }
                ],
            }
        ]

        with patch("pihole_ai.intel.get_intel_rows", return_value=rows), \
             patch("sys.stdout", io.StringIO()) as stdout:
            count = print_intel()

        self.assertEqual(count, 1)
        self.assertIn("bad.example", stdout.getvalue())

    def test_get_intel_rows_includes_managed_active_generation_entries(self) -> None:
        with patch(
            "pihole_ai.intel.get_intel_source",
            return_value={"source_id": "managed-feed"},
        ), patch(
            "pihole_ai.intel.list_managed_threat_intel_entries",
            return_value=[
                {
                    "domain": "bad.example",
                    "source_id": "managed-feed",
                    "source_name": "Managed Feed",
                    "generation_id": "gen_active",
                    "active": 1,
                    "category": "malware",
                    "confidence": 90,
                }
            ],
        ):
            rows = get_intel_rows(source="managed-feed")

        self.assertEqual(rows[0]["source_type"], "managed")
        self.assertEqual(rows[0]["source_id"], "managed-feed")
        self.assertEqual(rows[0]["generation_id"], "gen_active")
        self.assertTrue(rows[0]["active"])
        self.assertEqual(rows[0]["entries"][0]["domain"], "bad.example")

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

    def test_update_source_config_validates_and_persists_partial_changes(self) -> None:
        with patch(
            "pihole_ai.intel.get_intel_source",
            return_value={"source_id": "feed-a", "url": "https://feeds.example/a.txt", "allow_http": False},
        ), patch("pihole_ai.intel.validate_feed_url") as validate_url, \
             patch("pihole_ai.intel.update_threat_intel_source", return_value={"source_id": "feed-a"}) as update_source:
            result = update_source_config(
                "feed-a",
                {
                    "url": "https://feeds.example/b.txt",
                    "confidence": 0,
                    "timeout_seconds": 10,
                },
            )

        self.assertEqual(result["source_id"], "feed-a")
        validate_url.assert_called_once_with("https://feeds.example/b.txt", allow_http=False)
        update_source.assert_called_once_with(
            "feed-a",
            {
                "url": "https://feeds.example/b.txt",
                "confidence": 0,
                "timeout_seconds": 10,
            },
        )

    def test_update_source_config_accepts_confidence_100(self) -> None:
        with patch(
            "pihole_ai.intel.update_threat_intel_source",
            return_value={"source_id": "feed-a"},
        ) as update_source:
            update_source_config("feed-a", {"confidence": 100})

        update_source.assert_called_once_with("feed-a", {"confidence": 100})

    def test_update_source_config_rejects_invalid_values(self) -> None:
        invalid_changes = [
            {"confidence": -1},
            {"confidence": 101},
            {"refresh_interval_seconds": 0},
            {"max_download_bytes": -1},
            {"format": "csv"},
        ]
        for changes in invalid_changes:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    update_source_config("feed-a", changes)

    def test_update_source_config_rejects_url_credentials_and_http_by_default(self) -> None:
        for url in (
            "https://user:pass@feeds.example/a.txt",
            "http://feeds.example/a.txt",
        ):
            with self.subTest(url=url):
                with patch(
                    "pihole_ai.intel.get_intel_source",
                    return_value={
                        "source_id": "feed-a",
                        "url": "https://feeds.example/a.txt",
                        "allow_http": False,
                    },
                ), self.assertRaises(FeedError):
                    update_source_config("feed-a", {"url": url})

    def test_update_source_config_allows_http_when_explicitly_enabled(self) -> None:
        with patch(
            "pihole_ai.intel.get_intel_source",
            return_value={
                "source_id": "feed-a",
                "url": "https://feeds.example/a.txt",
                "allow_http": False,
            },
        ), patch(
            "pihole_ai.intel.validate_feed_url",
            return_value=None,
        ) as validate_url, patch(
            "pihole_ai.intel.update_threat_intel_source",
            return_value={"source_id": "feed-a"},
        ):
            update_source_config(
                "feed-a",
                {
                    "url": "http://feeds.example/a.txt",
                    "allow_http": True,
                },
            )

        validate_url.assert_called_once_with("http://feeds.example/a.txt", allow_http=True)

    def test_update_lock_uses_exclusive_file_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_path = Path(tmpdir) / "run" / "pihole-ai" / "intel-update.lock"
            with intel_update_lock(lock_path):
                with self.assertRaises(RuntimeError):
                    with intel_update_lock(lock_path):
                        pass
            self.assertTrue(lock_path.exists())

    def test_automatic_update_respects_auto_update_setting(self) -> None:
        with patch("pihole_ai.intel.settings.intel_auto_update_enabled", False), \
             patch("pihole_ai.intel.intel_update_lock") as intel_lock:
            results = update_sources(all_sources=True, automatic=True)

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].success)
        self.assertEqual(results[0].error_code, "intel.auto_update.disabled")
        intel_lock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
