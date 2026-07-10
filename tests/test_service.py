import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import ANY, call, patch

from pihole_ai.service import (
    InstallationLayout,
    SERVICE_NAMES,
    SERVICE_DEFINITIONS,
    ServiceError,
    _atomic_write_managed,
    build_install_plan,
    generate_unit_file,
    installation_status,
    launcher_content,
    launcher_target,
    run_preflight,
    service_action,
    service_disable,
    service_enable,
    service_install,
    service_logs,
    service_status,
    service_uninstall,
    service_upgrade,
)


class ServiceTests(unittest.TestCase):
    def test_generate_unit_file_uses_python_and_project_directory(self) -> None:
        unit = generate_unit_file(
            service=SERVICE_DEFINITIONS[0],
            python_path="/project/.venv/bin/python",
            project_dir="/project/pihole-ai",
            user="pihole",
            group="pihole",
        )

        self.assertIn("Description=PiHole-AI Collector", unit)
        self.assertIn("User=pihole", unit)
        self.assertIn("Group=pihole", unit)
        self.assertIn("WorkingDirectory=/project/pihole-ai", unit)
        self.assertIn("EnvironmentFile=/etc/pihole-ai/pihole-ai.env", unit)
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

    def test_install_plan_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            layout = InstallationLayout(
                config_dir=Path(tmpdir) / "etc" / "pihole-ai",
                config_file=Path(tmpdir) / "etc" / "pihole-ai" / "pihole-ai.env",
                data_dir=Path(tmpdir) / "var" / "lib" / "pihole-ai",
                events_db=Path(tmpdir) / "var" / "lib" / "pihole-ai" / "events.db",
                log_dir=Path(tmpdir) / "var" / "log" / "pihole-ai",
                log_file=Path(tmpdir) / "var" / "log" / "pihole-ai" / "pihole-ai.log",
                runtime_dir=Path(tmpdir) / "run" / "pihole-ai",
                systemd_dir=Path(tmpdir) / "systemd",
                wrapper_path=Path(tmpdir) / "bin" / "pihole-ai",
            )
            plan = build_install_plan(
                python_path="/usr/bin/python3",
                project_dir="/app",
                layout=layout,
                user="pihole-ai",
                group="pihole-ai",
                enable_services=False,
                start_services=False,
            )

        self.assertEqual(plan.service_user, "pihole-ai")
        self.assertFalse(plan.enable_services)
        self.assertIn("pihole-ai-collector.service", plan.unit_paths)
        self.assertIn(layout.config_file, plan.files_to_write)

    def test_preflight_collects_multiple_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.shutil.which",
            return_value=None,
        ), patch("pihole_ai.service._effective_uid", return_value=1000), patch(
            "pihole_ai.service.sys.platform",
            "linux",
        ):
            plan = build_install_plan(
                python_path=str(Path(tmpdir) / "missing-python"),
                project_dir=tmpdir,
                layout=InstallationLayout(systemd_dir=Path(tmpdir) / "systemd"),
            )
            result = run_preflight(
                plan,
                dry_run=False,
            )

        codes = {issue.code for issue in result.issues}
        self.assertIn("install.systemd.unavailable", codes)
        self.assertIn("install.privileges.required", codes)
        self.assertIn("install.python.missing", codes)

    def test_generated_unit_has_hardening_and_no_secrets(self) -> None:
        unit = generate_unit_file(
            service=SERVICE_DEFINITIONS[0],
            python_path="/usr/bin/python3",
            project_dir="/app",
            env_file="/etc/pihole-ai/pihole-ai.env",
            user="pihole-ai",
            group="pihole-ai",
        )

        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("PrivateTmp=true", unit)
        self.assertIn("ProtectSystem=full", unit)
        self.assertIn("ReadWritePaths=", unit)
        self.assertIn("ReadOnlyPaths=/etc/pihole", unit)
        self.assertNotIn("secret", unit.lower())

    def test_atomic_write_refuses_unmanaged_file_and_updates_managed_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "unit.service"
            path.write_text("unrelated", encoding="utf-8")

            with self.assertRaises(ServiceError):
                _atomic_write_managed(
                    path=path,
                    content="# PiHole-AI\n# Managed by PiHole-AI\nnew",
                    mode=0o644,
                    backup=True,
                )

            path.write_text("# PiHole-AI\n# Managed by PiHole-AI\nold", encoding="utf-8")
            _atomic_write_managed(
                path=path,
                content="# PiHole-AI\n# Managed by PiHole-AI\nnew",
                mode=0o644,
                backup=True,
            )

            self.assertIn("new", path.read_text(encoding="utf-8"))
            self.assertTrue((Path(tmpdir) / "unit.service.bak").exists())

    def test_install_status_detects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            systemd = Path(tmpdir) / "systemd"
            systemd.mkdir()
            layout = InstallationLayout(
                config_dir=Path(tmpdir) / "etc" / "pihole-ai",
                config_file=Path(tmpdir) / "etc" / "pihole-ai" / "pihole-ai.env",
                data_dir=Path(tmpdir) / "data",
                events_db=Path(tmpdir) / "data" / "events.db",
                log_dir=Path(tmpdir) / "logs",
                log_file=Path(tmpdir) / "logs" / "pihole-ai.log",
                runtime_dir=Path(tmpdir) / "run",
                systemd_dir=systemd,
                wrapper_path=Path(tmpdir) / "bin" / "pihole-ai",
            )
            unit = generate_unit_file(
                service=SERVICE_DEFINITIONS[0],
                python_path="/usr/bin/python3",
                project_dir="/app",
                user="pihole-ai",
                group="pihole-ai",
                layout=layout,
            )
            (systemd / SERVICE_NAMES[0]).write_text(unit + "\n# drift", encoding="utf-8")

            with patch("pihole_ai.service._run_capture", return_value="inactive"):
                status = installation_status(
                    layout=layout,
                    project_dir="/app",
                    python_path="/usr/bin/python3",
                )

        self.assertEqual(status.state, "drifted")
        self.assertTrue(status.unit_files[SERVICE_NAMES[0]]["drifted"])

    def test_service_install_writes_units_and_enables_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "sys.stdout",
            io.StringIO(),
        ):
            wrapper = Path(tmpdir) / "pihole-ai"
            config_dir = Path(tmpdir) / "etc" / "pihole-ai"
            data_dir = Path(tmpdir) / "var" / "lib" / "pihole-ai"
            log_dir = Path(tmpdir) / "var" / "log" / "pihole-ai"
            service_install(
                systemd_dir=Path(tmpdir) / "systemd",
                python_path="/venv/bin/python",
                project_dir="/app",
                wrapper_path=wrapper,
                config_dir=config_dir,
                data_dir=data_dir,
                log_dir=log_dir,
            )

            for name in SERVICE_NAMES:
                self.assertTrue((Path(tmpdir) / "systemd" / name).exists())
            self.assertTrue(wrapper.exists())
            self.assertTrue(config_dir.exists())
            self.assertTrue(data_dir.exists())
            self.assertTrue(log_dir.exists())
            self.assertTrue((config_dir / "pihole-ai.env").exists())

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
                wrapper_path=Path(tmpdir) / "pihole-ai",
                config_dir=Path(tmpdir) / "etc" / "pihole-ai",
                data_dir=Path(tmpdir) / "var" / "lib" / "pihole-ai",
                log_dir=Path(tmpdir) / "var" / "log" / "pihole-ai",
            )

            files = list(Path(tmpdir).iterdir())

        self.assertEqual(files, [])
        run.assert_not_called()
        self.assertIn("Would write", stdout.getvalue())
        self.assertIn("Would run: systemctl daemon-reload", stdout.getvalue())

    def test_service_enable_and_disable_dispatch_systemctl(self) -> None:
        with patch("pihole_ai.service.subprocess.run") as run, patch(
            "pihole_ai.service.os.geteuid",
            return_value=0,
        ), patch(
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
        ) as run, patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "sys.stdout",
            io.StringIO(),
        ):
            wrapper = Path(tmpdir) / "pihole-ai"
            wrapper.write_text(
                launcher_content("/app"),
                encoding="utf-8",
            )
            for name in SERVICE_NAMES:
                (Path(tmpdir) / name).write_text(
                    "unit",
                    encoding="utf-8",
                )

            service_uninstall(
                systemd_dir=tmpdir,
                project_dir="/app",
                wrapper_path=wrapper,
            )

            for name in SERVICE_NAMES:
                self.assertFalse((Path(tmpdir) / name).exists())
            self.assertFalse(wrapper.exists())

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
            "pihole_ai.service.os.geteuid",
            return_value=0,
        ), patch(
            "sys.stdout",
            io.StringIO(),
        ):
            service_action("restart")

        run.assert_called_once_with(
            ["systemctl", "restart", *SERVICE_NAMES],
            check=True,
        )

    def test_service_action_shows_sudo_hint_when_not_root(self) -> None:
        with patch("pihole_ai.service.os.geteuid", return_value=1000), patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("sys.stdout", io.StringIO()):
            with self.assertRaises(ServiceError) as context:
                service_action("start")

        self.assertIn(
            "Run: sudo /usr/local/bin/pihole-ai start",
            str(context.exception),
        )
        run.assert_not_called()

    def test_failed_systemctl_raises_clean_error(self) -> None:
        with patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "pihole_ai.service.subprocess.run",
            side_effect=subprocess.CalledProcessError(
                returncode=1,
                cmd=["systemctl", "restart", *SERVICE_NAMES],
            ),
        ), patch("sys.stdout", io.StringIO()):
            with self.assertRaises(ServiceError) as context:
                service_action("restart")

        message = str(context.exception)
        self.assertIn("Command failed: systemctl restart", message)
        self.assertIn("Exit code: 1", message)
        self.assertNotIn("Traceback", message)

    def test_launcher_content_points_to_project_venv_executable(self) -> None:
        self.assertEqual(
            launcher_target("/app"),
            Path("/app/.venv/bin/pihole-ai"),
        )
        content = launcher_content("/app")

        self.assertIn("# Managed by PiHole-AI", content)
        self.assertIn("# Project: /app", content)
        self.assertIn("# Target: /app/.venv/bin/pihole-ai", content)
        self.assertIn("exec /app/.venv/bin/pihole-ai \"$@\"", content)

    def test_service_install_creates_launcher_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ), patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "sys.stdout",
            io.StringIO(),
        ):
            wrapper = Path(tmpdir) / "pihole-ai"
            service_install(
                systemd_dir=Path(tmpdir) / "systemd",
                python_path="/venv/bin/python",
                project_dir="/app",
                wrapper_path=wrapper,
                config_dir=Path(tmpdir) / "etc" / "pihole-ai",
                data_dir=Path(tmpdir) / "var" / "lib" / "pihole-ai",
                log_dir=Path(tmpdir) / "var" / "log" / "pihole-ai",
            )

            self.assertTrue(wrapper.exists())
            self.assertIn(
                "exec /app/.venv/bin/pihole-ai",
                wrapper.read_text(encoding="utf-8"),
            )

    def test_service_uninstall_keeps_non_matching_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ), patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "sys.stdout",
            io.StringIO(),
        ):
            wrapper = Path(tmpdir) / "pihole-ai"
            wrapper.write_text(
                launcher_content("/other-project"),
                encoding="utf-8",
            )

            service_uninstall(
                systemd_dir=Path(tmpdir) / "systemd",
                project_dir="/app",
                wrapper_path=wrapper,
            )

            self.assertTrue(wrapper.exists())

    def test_service_install_creates_runtime_paths_and_migrates_project_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "sys.stdout",
            io.StringIO(),
        ) as stdout:
            root = Path(tmpdir)
            project = root / "project"
            project_data = project / "data"
            config_dir = root / "etc" / "pihole-ai"
            data_dir = root / "var" / "lib" / "pihole-ai"
            log_dir = root / "var" / "log" / "pihole-ai"
            project_data.mkdir(parents=True)
            (project / ".env.example").write_text(
                "AI_ENABLED=true\n",
                encoding="utf-8",
            )
            (project_data / "events.db").write_text(
                "old-db",
                encoding="utf-8",
            )

            service_install(
                systemd_dir=root / "systemd",
                python_path="/venv/bin/python",
                project_dir=project,
                wrapper_path=root / "pihole-ai",
                config_dir=config_dir,
                data_dir=data_dir,
                log_dir=log_dir,
            )

            env_content = (config_dir / "pihole-ai.env").read_text(
                encoding="utf-8",
            )
            migrated = (data_dir / "events.db").read_text(
                encoding="utf-8",
            )

            self.assertTrue(config_dir.exists())
            self.assertTrue(data_dir.exists())
            self.assertTrue(log_dir.exists())
            self.assertEqual(migrated, "old-db")
            self.assertIn(f"EVENTS_DB_PATH={data_dir / 'events.db'}", env_content)
            self.assertIn(f"LOG_PATH={log_dir / 'pihole-ai.log'}", env_content)
            self.assertIn("Migrating existing project database", stdout.getvalue())
            run.assert_any_call(
                ["chown", "-R", ANY, str(data_dir)],
                check=True,
            )
            run.assert_any_call(
                ["chown", "-R", ANY, str(log_dir)],
                check=True,
            )

    def test_service_install_dry_run_does_not_migrate_project_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("sys.stdout", io.StringIO()) as stdout:
            root = Path(tmpdir)
            project = root / "project"
            project_data = project / "data"
            config_dir = root / "etc" / "pihole-ai"
            data_dir = root / "var" / "lib" / "pihole-ai"
            log_dir = root / "var" / "log" / "pihole-ai"
            project_data.mkdir(parents=True)
            (project_data / "events.db").write_text(
                "old-db",
                encoding="utf-8",
            )

            service_install(
                dry_run=True,
                systemd_dir=root / "systemd",
                python_path="/venv/bin/python",
                project_dir=project,
                wrapper_path=root / "pihole-ai",
                config_dir=config_dir,
                data_dir=data_dir,
                log_dir=log_dir,
            )

        self.assertFalse((data_dir / "events.db").exists())
        self.assertIn("Would migrate existing project database", stdout.getvalue())
        run.assert_not_called()

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
            "ai": {
                "ai_calls": 2,
                "ai_skipped": 1,
                "ai_parse_errors": 0,
                "ai_timeouts": 0,
                "calls": 2,
                "rate_limit_skips": 1,
                "disabled_skips": 0,
                "cooldown_skips": 0,
                "parse_errors": 0,
                "timeouts": 0,
                "slow_responses": 0,
                "cooldown_until": 0,
            },
            "config": {
                "events_db": "data/events.db",
                "pihole_db": "/etc/pihole/pihole-FTL.db",
                "ai_enabled": True,
                "ai_max_calls_per_minute": 2,
                "ai_cooldown_seconds": 60,
                "ai_timeout_seconds": 20,
                "dashboard_port": 8080,
            },
        }

        with patch(
            "pihole_ai.status.collect_status",
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
        self.assertIn("ai_skipped: 1", output)

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
                "--no-pager",
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

    def test_service_logs_handles_keyboard_interrupt_cleanly(self) -> None:
        with patch(
            "pihole_ai.service.subprocess.run",
            side_effect=KeyboardInterrupt,
        ), patch("sys.stdout", io.StringIO()) as stdout:
            service_logs(
                follow=True,
            )

        self.assertIn("Stopped log tail.", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
