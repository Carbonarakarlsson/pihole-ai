import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.migrations import LATEST_SUPPORTED_SCHEMA_VERSION, MIGRATIONS
from pihole_ai.cli import build_parser
from scripts.clean import assert_safe_path, cleanup_candidates
from scripts.repository_audit import audit


ROOT = Path(__file__).resolve().parents[1]


def env_keys(path: Path) -> set[str]:
    keys: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        keys.add(line.split("=", 1)[0])
    return keys


def parser_commands(parser: argparse.ArgumentParser) -> set[str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    return set()


class RepositoryMaintenanceTests(unittest.TestCase):
    def test_cleanup_dry_run_candidates_are_repository_local(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / ".git").mkdir()
            (root / "build").mkdir()
            (root / "build" / "artifact.txt").write_text("x", encoding="utf-8")
            (root / ".env.example").write_text("EVENTS_DB_PATH=x\n", encoding="utf-8")
            (root / "pkg").mkdir()
            (root / "pkg" / "__pycache__").mkdir()
            (root / "pkg" / "__pycache__" / "mod.pyc").write_bytes(b"x")

            candidates = cleanup_candidates(root)

            self.assertIn(root / "build", candidates)
            self.assertIn(root / "pkg" / "__pycache__", candidates)
            self.assertNotIn(root / ".env.example", candidates)
            for path in candidates:
                assert_safe_path(path, root)

    def test_cleanup_rejects_paths_outside_repository(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            outside = root.parent / "outside.log"
            outside.write_text("x", encoding="utf-8")
            try:
                with self.assertRaises(ValueError):
                    assert_safe_path(outside, root)
            finally:
                outside.unlink(missing_ok=True)

    def test_cleanup_rejects_live_appliance_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            with self.assertRaises(ValueError):
                assert_safe_path(Path("/etc/pihole-ai/pihole-ai.env"), root)

    def test_cli_reference_documents_all_top_level_commands(self):
        documented = (ROOT / "docs/CLI_REFERENCE.md").read_text(encoding="utf-8")
        commands = parser_commands(build_parser())

        self.assertGreaterEqual(len(commands), 20)
        for command in commands:
            self.assertIn(f"`{command}`", documented)
            with patch("sys.stdout"):
                with self.assertRaises(SystemExit) as raised:
                    build_parser().parse_args([command, "--help"])
            self.assertEqual(raised.exception.code, 0)

    def test_no_duplicate_top_level_cli_routes(self):
        commands = parser_commands(build_parser())
        self.assertEqual(len(commands), len(set(commands)))

    def test_config_docs_examples_and_packaged_defaults_are_synchronized(self):
        example_keys = env_keys(ROOT / ".env.example")
        default_keys = env_keys(ROOT / "pihole_ai/defaults/pihole-ai.env")
        docs = (ROOT / "docs/CONFIGURATION.md").read_text(encoding="utf-8")

        self.assertEqual(example_keys, default_keys)
        for key in sorted(example_keys):
            self.assertIn(f"`{key}`", docs)
        self.assertNotIn("password=", (ROOT / ".env.example").read_text(encoding="utf-8").lower())

    def test_migration_registry_is_ordered_complete_and_current(self):
        versions = [migration.version for migration in MIGRATIONS]
        self.assertEqual(versions, sorted(versions))
        self.assertEqual(len(versions), len(set(versions)))
        self.assertEqual(versions, list(range(1, LATEST_SUPPORTED_SCHEMA_VERSION + 1)))
        for migration in MIGRATIONS:
            self.assertTrue(migration.name)
        database_doc = (ROOT / "docs/DATABASE.md").read_text(encoding="utf-8")
        self.assertIn(f"Latest supported schema version: `{LATEST_SUPPORTED_SCHEMA_VERSION}`", database_doc)

    def test_repository_audit_passes_current_tree(self):
        self.assertEqual(audit(ROOT), [])


if __name__ == "__main__":
    unittest.main()
