import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

from pihole_ai.service import (
    SERVICE_NAMES,
    SERVICE_DEFINITIONS,
    generate_unit_file,
    service_action,
    service_disable,
    service_enable,
    service_install,
    service_logs,
    service_status,
    service_uninstall,
)


class ServiceTests(unittest.TestCase):
    def test_generate_unit_file_uses_python_and_project_directory(self) -> None:
        unit = generate_unit_file(
            service=SERVICE_DEFINITIONS[0],
            python_path="/project/.venv/bin/python",
            project_dir="/project/pihole-ai",
        )

        self.assertIn("Description=PiHole-AI Collector", unit)
        self.assertIn("WorkingDirectory=/project/pihole-ai", unit)
        self.assertIn("EnvironmentFile=-/project/pihole-ai/.env", unit)
        self.assertIn(
            "ExecStart=/project/.venv/bin/python -m pihole_ai.cli collect",
            unit,
        )
        self.assertIn("Restart=always", unit)
        self.assertIn("WantedBy=multi-user.target", unit)

    def test_dashboard_unit_uses_appliance_dashboard_command(self) -> None:
        unit = generate_unit_file(
            service=SERVICE_DEFINITIONS[2],
            python_path="/project/.venv/bin/python",
            project_dir="/project/pihole-ai",
        )

        self.assertIn(
            "ExecStart=/project/.venv/bin/python -m pihole_ai.cli "
            "dashboard --host 0.0.0.0 --port 8080",
            unit,
        )

    def test_service_install_writes_units_and_enables_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("sys.stdout", io.StringIO()):
            service_install(
                systemd_dir=tmpdir,
                python_path="/venv/bin/python",
                project_dir="/app",
            )

            for name in SERVICE_NAMES:
                self.assertTrue((Path(tmpdir) / name).exists())

        run.assert_has_calls(
            [
                call(
                    ["systemctl", "daemon-reload"],
                    check=True,
                ),
            ]
        )

    def test_service_install_dry_run_does_not_write_or_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("sys.stdout", io.StringIO()) as stdout:
            service_install(
                dry_run=True,
                systemd_dir=tmpdir,
                python_path="/venv/bin/python",
                project_dir="/app",
            )

            files = list(Path(tmpdir).iterdir())

        self.assertEqual(files, [])
        run.assert_not_called()
        self.assertIn("Would write", stdout.getvalue())
        self.assertIn("Would run: systemctl daemon-reload", stdout.getvalue())

    def test_service_enable_and_disable_dispatch_systemctl(self) -> None:
        with patch("pihole_ai.service.subprocess.run") as run, patch(
            "sys.stdout",
            io.StringIO(),
        ):
            service_enable()
            service_disable()

        run.assert_has_calls(
            [
                call(
                    ["systemctl", "enable", *SERVICE_NAMES],
                    check=True,
                ),
                call(
                    ["systemctl", "disable", *SERVICE_NAMES],
                    check=True,
                ),
            ]
        )

    def test_service_uninstall_removes_units_and_disables_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("sys.stdout", io.StringIO()):
            for name in SERVICE_NAMES:
                (Path(tmpdir) / name).write_text(
                    "unit",
                    encoding="utf-8",
                )

            service_uninstall(
                systemd_dir=tmpdir,
            )

            for name in SERVICE_NAMES:
                self.assertFalse((Path(tmpdir) / name).exists())

        run.assert_has_calls(
            [
                call(
                    ["systemctl", "disable", "--now", *SERVICE_NAMES],
                    check=True,
                ),
                call(
                    ["systemctl", "daemon-reload"],
                    check=True,
                ),
            ]
        )

    def test_service_action_dispatches_systemctl(self) -> None:
        with patch("pihole_ai.service.subprocess.run") as run, patch(
            "sys.stdout",
            io.StringIO(),
        ):
            service_action("restart")

        run.assert_called_once_with(
            ["systemctl", "restart", *SERVICE_NAMES],
            check=True,
        )

    def test_service_status_prints_service_and_project_state(self) -> None:
        status = {
            "database": {
                "events": 3,
                "processed": 2,
                "domains": 1,
                "analyses": 1,
                "actions": 1,
                "reputations": 0,
                "threat_intel": 0,
            },
            "collector": {
                "last_query_id": "42",
            },
            "config": {
                "events_db": "data/events.db",
                "pihole_db": "/etc/pihole/pihole-FTL.db",
                "dashboard_port": 8080,
            },
        }

        with patch(
            "pihole_ai.service.collect_status",
            return_value=status,
        ), patch("pihole_ai.service.subprocess.run") as run, patch(
            "sys.stdout",
            io.StringIO(),
        ) as stdout:
            run.side_effect = [
                type("Result", (), {"stdout": "active\n", "stderr": ""})(),
                type("Result", (), {"stdout": "enabled\n", "stderr": ""})(),
                type("Result", (), {"stdout": "inactive\n", "stderr": ""})(),
                type("Result", (), {"stdout": "disabled\n", "stderr": ""})(),
                type("Result", (), {"stdout": "active\n", "stderr": ""})(),
                type("Result", (), {"stdout": "enabled\n", "stderr": ""})(),
            ]

            service_status(
                include_ollama=False,
            )

        output = stdout.getvalue()
        self.assertIn("PiHole-AI appliance status", output)
        self.assertIn("pihole-ai-collector.service: active=active enabled=enabled", output)
        self.assertIn("events: 3", output)

    def test_service_logs_dispatches_journalctl(self) -> None:
        with patch("pihole_ai.service.subprocess.run") as run, patch(
            "sys.stdout",
            io.StringIO(),
        ):
            service_logs(
                lines=50,
                follow=True,
            )

        run.assert_called_once_with(
            [
                "journalctl",
                "-u",
                "pihole-ai-collector.service",
                "-u",
                "pihole-ai-engine.service",
                "-u",
                "pihole-ai-dashboard.service",
                "-n",
                "50",
                "-f",
            ],
            check=True,
        )


if __name__ == "__main__":
    unittest.main()
