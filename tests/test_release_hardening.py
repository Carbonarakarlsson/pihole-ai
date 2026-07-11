import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pihole_ai import cli
from pihole_ai.version import get_version
from scripts.package_audit import audit
from ui.dashboard import ROUTE_SECURITY


PRIMARY_IMPORTS = [
    "core.config",
    "core.db",
    "core.migrations",
    "pihole_ai.cli",
    "pihole_ai.health",
    "pihole_ai.setup",
    "pihole_ai.service",
    "pihole_ai.dashboard_auth",
    "ui.dashboard",
]


class ReleaseHardeningTests(unittest.TestCase):
    def test_pyproject_version_is_authoritative_in_checkout(self):
        self.assertEqual(get_version(), "0.4.0rc2")

    def test_cli_version_outputs_metadata_version(self):
        with patch("sys.stdout") as stdout:
            with self.assertRaises(SystemExit) as raised:
                cli.build_parser().parse_args(["--version"])

        self.assertEqual(raised.exception.code, 0)
        written = "".join(call.args[0] for call in stdout.write.call_args_list)
        self.assertIn("0.4.0rc2", written)

    def test_primary_imports_do_not_mutate_runtime_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env = os.environ.copy()
            repo_root = str(Path(__file__).resolve().parents[1])
            env.update(
                {
                    "EVENTS_DB_PATH": str(tmp / "events.db"),
                    "LOG_PATH": str(tmp / "pihole-ai.log"),
                    "PIHOLE_AI_PIHOLE_DB": str(tmp / "pihole-FTL.db"),
                    "PIHOLE_AI_DASHBOARD_AUTH_ENABLED": "false",
                    "PIHOLE_AI_DASHBOARD_HOST": "127.0.0.1",
                    "PYTHONPATH": repo_root,
                }
            )
            code = "; ".join(f"import {name}" for name in PRIMARY_IMPORTS)
            completed = subprocess.run(
                [sys.executable, "-c", code],
                cwd=tmp,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(sorted(path.name for path in tmp.iterdir()), [])

    def test_dashboard_route_security_inventory_covers_mutations(self):
        self.assertEqual(ROUTE_SECURITY["GET /live"], "public_liveness")
        self.assertEqual(ROUTE_SECURITY["POST /login"], "public_state_changing_csrf")
        for route, classification in ROUTE_SECURITY.items():
            if route.startswith(("POST ", "PUT ", "PATCH ", "DELETE ")) and route != "POST /login":
                self.assertIn("authenticated", classification)
                self.assertIn("csrf", classification)

    def test_package_audit_rejects_forbidden_local_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            import zipfile

            wheel = Path(tmpdir) / "bad.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("pihole_ai/defaults/pihole-ai.env", "")
                archive.writestr("README.md", "")
                archive.writestr("data/events.db", "")

            errors = audit(wheel)

        self.assertTrue(any("forbidden" in error for error in errors))

    def test_documented_json_commands_emit_json_when_mocked(self):
        commands = [
            (["health", "--json"], {"overall_status": "healthy", "checks": [], "version": "0.4.0rc2", "checked_at": 1}),
            (["doctor", "--json"], {"overall_status": "healthy", "diagnostics": [], "version": "0.4.0rc2"}),
        ]

        for argv, payload in commands:
            with self.subTest(argv=argv), patch("sys.stdout") as stdout:
                if argv[0] == "health":
                    from pihole_ai.health import HealthReport

                    with patch("pihole_ai.health.run_health_checks", return_value=HealthReport("healthy", [], "0.4.0rc2", 1)):
                        exit_code = cli.main(argv)
                else:
                    from pihole_ai.doctor import DoctorReport

                    with patch("pihole_ai.doctor.run_doctor", return_value=DoctorReport("healthy", [], "0.4.0rc2")):
                        exit_code = cli.main(argv)
                written = "".join(call.args[0] for call in stdout.write.call_args_list)
                decoded = json.loads(written)
                self.assertEqual(exit_code, 0)
                self.assertEqual(decoded["version"], payload["version"])


if __name__ == "__main__":
    unittest.main()
