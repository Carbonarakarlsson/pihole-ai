import io
import subprocess
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, call, patch

from pihole_ai import service as service_module
from pihole_ai.service import (
    InstallationLayout,
    SERVICE_NAMES,
    SERVICE_DEFINITIONS,
    ServiceError,
    SimpleCompletedProcess,
    _atomic_write_managed,
    build_install_plan,
    discover_executable_target,
    generate_unit_file,
    generated_units,
    installation_status,
    launcher_content,
    launcher_target,
    lifecycle_lock,
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
    def _valid_python_check(self, interpreter, args, capture=False):
        if capture:
            return SimpleCompletedProcess(returncode=0, stdout="pihole-ai 0.4.0rc3\n")
        return True

    def _invalid_python_check(self, interpreter, args, capture=False):
        if capture:
            return SimpleCompletedProcess(returncode=1, stdout="")
        return False

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
        self.assertEqual(plan.executable_path, Path("/usr/bin/pihole-ai"))

    def test_install_plan_defaults_to_runtime_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            layout = InstallationLayout(
                data_dir=Path(tmpdir) / "var" / "lib" / "pihole-ai",
            )
            plan = build_install_plan(
                python_path="/opt/pihole-ai/venv/bin/python",
                layout=layout,
            )

        self.assertEqual(plan.project_dir, Path(tmpdir) / "var" / "lib" / "pihole-ai")
        self.assertEqual(
            plan.executable_path,
            Path("/opt/pihole-ai/venv/bin/pihole-ai"),
        )

    def test_install_plan_defaults_to_dedicated_appliance_identity(self) -> None:
        plan = build_install_plan(
            python_path="/usr/bin/python3",
            project_dir="/app",
        )

        self.assertEqual(plan.service_user, "pihole-ai")
        self.assertEqual(plan.service_group, "pihole-ai")

    def test_system_python_without_package_is_rejected(self) -> None:
        with patch("pihole_ai.service._run_python_check", side_effect=self._invalid_python_check):
            target = discover_executable_target(python_path="/usr/bin/python3")

        self.assertFalse(target.package_importable)
        self.assertEqual(target.source, "explicit")

    def test_console_script_with_invalid_interpreter_is_rejected(self) -> None:
        def exists(self):
            return str(self) == "/missing/python"

        with patch("pihole_ai.service.Path.exists", exists), \
             patch("pihole_ai.service.shutil.which", return_value="/opt/pihole-ai/venv/bin/pihole-ai"), \
             patch("pihole_ai.service.sys.executable", "/missing/python"), \
             patch("pihole_ai.service._run_python_check", side_effect=self._invalid_python_check):
            target = discover_executable_target()

        self.assertFalse(target.package_importable)
        self.assertIn(target.source, {"current_console_script", "current_interpreter"})

    def test_preflight_blocks_non_importable_python_before_mutation(self) -> None:
        with patch("pihole_ai.service._run_python_check", side_effect=self._invalid_python_check), \
             patch("pihole_ai.service.shutil.which", return_value="/usr/bin/systemctl"), \
             patch("pihole_ai.service._check_service_identity"), \
             patch("pihole_ai.service._check_config_for_install"), \
             patch("pihole_ai.service._check_pihole_db_access"), \
             patch("pihole_ai.service._check_database_schema"), \
             patch("pihole_ai.service._check_unit_conflicts"), \
             patch("pihole_ai.service._check_install_disk_space"):
            plan = build_install_plan(python_path="/usr/bin/python3")
            result = run_preflight(plan, dry_run=True)

        self.assertTrue(any(
            issue.code == "install.executable.package_not_importable"
            for issue in result.issues
        ))

    def test_dry_run_reports_executable_block_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service._run_python_check",
            side_effect=self._invalid_python_check,
        ), patch("pihole_ai.service.subprocess.run") as run, patch(
            "sys.stdout",
            io.StringIO(),
        ) as stdout:
            service_install(
                dry_run=True,
                systemd_dir=Path(tmpdir) / "systemd",
                python_path="/usr/bin/python3",
                wrapper_path=Path(tmpdir) / "bin" / "pihole-ai",
                config_dir=Path(tmpdir) / "etc" / "pihole-ai",
                data_dir=Path(tmpdir) / "var" / "lib" / "pihole-ai",
                log_dir=Path(tmpdir) / "var" / "log" / "pihole-ai",
            )

        self.assertIn("install.executable.package_not_importable", stdout.getvalue())
        run.assert_not_called()

    def test_system_python_with_importable_package_is_accepted(self) -> None:
        with patch("pihole_ai.service._run_python_check", side_effect=self._valid_python_check):
            target = discover_executable_target(python_path="/usr/bin/python3")

        self.assertTrue(target.package_importable)
        self.assertTrue(target.stable)
        self.assertEqual(target.interpreter_path, Path("/usr/bin/python3"))

    def test_dedicated_appliance_venv_is_accepted_when_importable(self) -> None:
        def exists(self):
            return str(self) == "/opt/pihole-ai/venv/bin/python"

        with patch("pihole_ai.service.Path.exists", exists), \
             patch("pihole_ai.service._run_python_check", side_effect=self._valid_python_check), \
             patch("pihole_ai.service.shutil.which", return_value=None), \
             patch("pihole_ai.service.sys.executable", "/missing/python"):
            target = discover_executable_target()

        self.assertEqual(target.source, "dedicated_appliance_venv")
        self.assertEqual(target.interpreter_path, Path("/opt/pihole-ai/venv/bin/python"))
        self.assertTrue(target.package_importable)

    def test_project_venv_rejected_for_appliance_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("pihole_ai.service._run_python_check", side_effect=self._valid_python_check):
            python = Path(tmpdir) / ".venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.touch()
            target = discover_executable_target(
                python_path=python,
                project_dir=tmpdir,
            )

        self.assertTrue(target.package_importable)
        self.assertFalse(target.stable)
        self.assertTrue(target.references_developer_venv)

    def test_project_venv_allowed_only_in_development_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("pihole_ai.service._run_python_check", side_effect=self._valid_python_check):
            python = Path(tmpdir) / ".venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.touch()
            target = discover_executable_target(
                python_path=python,
                project_dir=tmpdir,
                development_mode=True,
            )

        self.assertTrue(target.package_importable)
        self.assertTrue(target.stable)

    def test_generated_units_and_launcher_use_validated_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("pihole_ai.service._run_python_check", side_effect=self._valid_python_check):
            layout = InstallationLayout(
                systemd_dir=Path(tmpdir) / "systemd",
                wrapper_path=Path(tmpdir) / "bin" / "pihole-ai",
            )
            plan = build_install_plan(
                python_path="/opt/pihole-ai/venv/bin/python",
                layout=layout,
            )
            units = generated_units(
                python_path=str(plan.python_path),
                project_dir=plan.project_dir,
                layout=layout,
            )
            launcher = launcher_content(
                plan.project_dir,
                executable_path=plan.executable_path,
            )

        for unit in units.values():
            self.assertIn(
                "ExecStart=/opt/pihole-ai/venv/bin/python -m pihole_ai.cli",
                unit,
            )
        self.assertIn("# Target: /opt/pihole-ai/venv/bin/pihole-ai", launcher)

    def test_install_status_reports_executable_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service._run_python_check",
            side_effect=self._invalid_python_check,
        ), patch("pihole_ai.service._run_capture", return_value="missing"):
            layout = InstallationLayout(
                systemd_dir=Path(tmpdir) / "systemd",
                data_dir=Path(tmpdir) / "var" / "lib" / "pihole-ai",
                events_db=Path(tmpdir) / "var" / "lib" / "pihole-ai" / "events.db",
            )
            status = installation_status(
                layout=layout,
                python_path="/usr/bin/python3",
            )

        self.assertIn("executable", status.to_dict())
        self.assertFalse(status.executable["package_importable"])

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

    def test_preflight_marks_blocking_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.shutil.which",
            return_value=None,
        ), patch("pihole_ai.service._effective_uid", return_value=1000):
            result = run_preflight(
                build_install_plan(
                    python_path=str(Path(tmpdir) / "missing-python"),
                    project_dir=tmpdir,
                    layout=InstallationLayout(systemd_dir=Path(tmpdir) / "systemd"),
                ),
                dry_run=False,
            )

        self.assertGreater(result.blocking_count, 0)
        self.assertFalse(result.ok)

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
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ReadWritePaths=", unit)
        self.assertIn("ReadOnlyPaths=/etc/pihole", unit)
        self.assertIn("MemoryDenyWriteExecute=true", unit)
        self.assertIn("StateDirectory=pihole-ai", unit)
        self.assertIn("LogsDirectory=pihole-ai", unit)
        self.assertIn("RuntimeDirectory=pihole-ai", unit)
        self.assertNotIn("secret", unit.lower())

    def test_engine_unit_does_not_get_pihole_read_path(self) -> None:
        unit = generate_unit_file(
            service=SERVICE_DEFINITIONS[1],
            python_path="/usr/bin/python3",
            project_dir="/app",
            user="pihole-ai",
            group="pihole-ai",
        )

        self.assertNotIn("ReadOnlyPaths=/etc/pihole", unit)

    def test_install_preflight_blocks_before_mutation(self) -> None:
        blocking_result = type(
            "Result",
            (),
            {
                "blocking_count": 1,
                "issues": [
                    type(
                        "Issue",
                        (),
                        {
                            "blocking": True,
                            "code": "install.test.blocked",
                            "summary": "blocked",
                            "remediation": "fix",
                        },
                    )()
                ],
            },
        )()

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.run_preflight",
            return_value=blocking_result,
        ), patch("pihole_ai.service._run_python_check", side_effect=self._valid_python_check), patch(
            "pihole_ai.service.subprocess.run"
        ) as run, patch(
            "sys.stdout",
            io.StringIO(),
        ):
            with self.assertRaises(ServiceError):
                service_install(
                    systemd_dir=Path(tmpdir) / "systemd",
                    python_path="/usr/bin/python3",
                    project_dir="/app",
                    wrapper_path=Path(tmpdir) / "pihole-ai",
                    config_dir=Path(tmpdir) / "etc" / "pihole-ai",
                    data_dir=Path(tmpdir) / "var" / "lib" / "pihole-ai",
                    log_dir=Path(tmpdir) / "var" / "log" / "pihole-ai",
                )

            self.assertFalse((Path(tmpdir) / "systemd").exists())
            run.assert_not_called()

    def test_lifecycle_lock_blocks_concurrent_operation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            layout = InstallationLayout(runtime_dir=Path(tmpdir) / "run")

            with lifecycle_lock("install", layout=layout):
                with self.assertRaises(ServiceError):
                    with lifecycle_lock("upgrade", layout=layout):
                        pass

    def test_service_identity_creation_uses_system_group_and_user(self) -> None:
        with patch("pihole_ai.service._group_exists", return_value=False), patch(
            "pihole_ai.service._user_exists",
            return_value=False,
        ), patch("pihole_ai.service._command_path", side_effect=lambda value: value), patch(
            "pihole_ai.service._nologin_shell",
            return_value="/usr/sbin/nologin",
        ), patch("pihole_ai.service.subprocess.run") as run:
            actions = service_module._ensure_service_identity(
                user="pihole-ai",
                group="pihole-ai",
                dry_run=False,
            )

        self.assertIn("created group pihole-ai", actions)
        self.assertIn("created user pihole-ai", actions)
        run.assert_any_call(["groupadd", "--system", "pihole-ai"], check=True)
        run.assert_any_call(
            [
                "useradd",
                "--system",
                "--gid",
                "pihole-ai",
                "--home-dir",
                "/var/lib/pihole-ai",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "pihole-ai",
            ],
            check=True,
        )

    def test_pihole_group_access_uses_existing_read_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pihole_db = Path(tmpdir) / "pihole-FTL.db"
            pihole_db.write_text("", encoding="utf-8")
            pihole_db.chmod(0o640)
            config = SimpleNamespace(pihole_db=pihole_db)

            with patch(
                "pihole_ai.service.load_config_with_result",
                return_value=(config, object()),
            ), patch("pihole_ai.service.grp.getgrgid") as getgrgid, patch(
                "pihole_ai.service._command_path",
                side_effect=lambda value: value,
            ), patch("pihole_ai.service.subprocess.run") as run:
                getgrgid.return_value.gr_name = "pihole"
                actions = service_module._ensure_pihole_group_access(
                    user="pihole-ai",
                    dry_run=False,
                )

        self.assertEqual(actions, ["added pihole-ai to group pihole"])
        run.assert_called_once_with(
            ["usermod", "-a", "-G", "pihole", "pihole-ai"],
            check=True,
        )

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
        ), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
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

    def test_dry_run_runtime_env_permission_error_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / "etc" / "pihole-ai" / "pihole-ai.env"
            original_exists = Path.exists

            def exists(path):
                if path == env_file:
                    raise PermissionError("permission denied")
                return original_exists(path)

            with patch("pathlib.Path.exists", exists), patch(
                "sys.stdout",
                io.StringIO(),
            ) as stdout:
                service_module._ensure_runtime_env(
                    project_dir=Path(tmpdir),
                    env_file=env_file,
                    runtime_db_path=Path(tmpdir) / "events.db",
                    runtime_log_path=Path(tmpdir) / "pihole-ai.log",
                    dry_run=True,
                )

            self.assertFalse(env_file.exists())
            self.assertIn("Cannot inspect", stdout.getvalue())
            self.assertIn("Would leave", stdout.getvalue())

    def test_dry_run_database_migration_permission_error_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / "project"
            old_db = project_dir / "data" / "events.db"
            original_exists = Path.exists

            def exists(path):
                if path == old_db:
                    raise PermissionError("permission denied")
                return original_exists(path)

            with patch("pathlib.Path.exists", exists), patch(
                "sys.stdout",
                io.StringIO(),
            ) as stdout:
                service_module._migrate_project_database(
                    project_dir=project_dir,
                    runtime_db_path=Path(tmpdir) / "runtime" / "events.db",
                    dry_run=True,
                )

            self.assertIn("Cannot inspect", stdout.getvalue())
            self.assertIn("Would skip project database migration check", stdout.getvalue())

    def test_service_enable_and_disable_dispatch_systemctl(self) -> None:
        with patch("pihole_ai.service.subprocess.run") as run, patch(
            "pihole_ai.service.os.geteuid",
            return_value=0,
        ), patch(
            "sys.stdout",
            io.StringIO(),
        ), patch(
            "pihole_ai.service._enforce_service_control_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
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
        ), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
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
        ), patch(
            "pihole_ai.service._enforce_service_control_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
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

        self.assertIn("start preflight failed", str(context.exception))
        run.assert_not_called()

    def test_failed_systemctl_raises_clean_error(self) -> None:
        with patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "pihole_ai.service.subprocess.run",
            side_effect=subprocess.CalledProcessError(
                returncode=1,
                cmd=["systemctl", "restart", *SERVICE_NAMES],
            ),
        ), patch("sys.stdout", io.StringIO()), patch(
            "pihole_ai.service._enforce_service_control_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
        ):
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

    def test_launcher_content_can_point_to_installed_cli_executable(self) -> None:
        self.assertEqual(
            launcher_target(
                "/var/lib/pihole-ai",
                executable_path="/opt/pihole-ai/venv/bin/pihole-ai",
            ),
            Path("/opt/pihole-ai/venv/bin/pihole-ai"),
        )
        content = launcher_content(
            "/var/lib/pihole-ai",
            executable_path="/opt/pihole-ai/venv/bin/pihole-ai",
        )

        self.assertIn("# Managed by PiHole-AI", content)
        self.assertIn("# Project: /var/lib/pihole-ai", content)
        self.assertIn("# Target: /opt/pihole-ai/venv/bin/pihole-ai", content)
        self.assertIn("exec /opt/pihole-ai/venv/bin/pihole-ai \"$@\"", content)

    def test_service_install_creates_launcher_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ), patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "sys.stdout",
            io.StringIO(),
        ), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
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
                "exec /venv/bin/pihole-ai",
                wrapper.read_text(encoding="utf-8"),
            )

    def test_service_install_dry_run_uses_runtime_directory_for_wheel_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ), patch("sys.stdout", io.StringIO()) as stdout:
            service_install(
                dry_run=True,
                systemd_dir=Path(tmpdir) / "systemd",
                python_path="/opt/pihole-ai/venv/bin/python",
                wrapper_path=Path(tmpdir) / "bin" / "pihole-ai",
                config_dir=Path(tmpdir) / "etc" / "pihole-ai",
                data_dir=Path(tmpdir) / "var" / "lib" / "pihole-ai",
                log_dir=Path(tmpdir) / "var" / "log" / "pihole-ai",
            )

        output = stdout.getvalue()
        self.assertIn(
            f"WorkingDirectory={Path(tmpdir) / 'var' / 'lib' / 'pihole-ai'}",
            output,
        )
        self.assertIn("# Target: /opt/pihole-ai/venv/bin/pihole-ai", output)
        self.assertNotIn(f"WorkingDirectory={Path.cwd()}", output)

    def test_service_uninstall_keeps_non_matching_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ), patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "sys.stdout",
            io.StringIO(),
        ), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
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
        ) as stdout, patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
        ):
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
                ["chown", ANY, str(data_dir)],
                check=True,
            )
            run.assert_any_call(
                ["chown", ANY, str(log_dir)],
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

    def test_database_ownership_repair_targets_sqlite_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service._run_command",
        ) as run:
            database_path = Path(tmpdir) / "events.db"
            wal_path = Path(f"{database_path}-wal")
            shm_path = Path(f"{database_path}-shm")
            for path in (database_path, wal_path, shm_path):
                path.write_text("", encoding="utf-8")

            service_module._repair_database_ownership(
                database_path=database_path,
                user="pihole-ai",
                group="pihole-ai",
                dry_run=False,
            )

            run.assert_has_calls(
                [
                    call(["chown", "pihole-ai:pihole-ai", str(database_path)], dry_run=False),
                    call(["chown", "pihole-ai:pihole-ai", str(wal_path)], dry_run=False),
                    call(["chown", "pihole-ai:pihole-ai", str(shm_path)], dry_run=False),
                ]
            )
            self.assertEqual(database_path.stat().st_mode & 0o777, 0o660)

    def test_config_permission_repair_targets_appliance_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.grp.getgrnam",
            return_value=SimpleNamespace(gr_gid=123),
        ), patch("pihole_ai.service._effective_uid", return_value=0), patch(
            "pihole_ai.service.os.chown",
        ) as chown:
            config_dir = Path(tmpdir) / "pihole-ai"
            env_file = config_dir / "pihole-ai.env"
            config_dir.mkdir()
            env_file.write_text("SECRET=value\n", encoding="utf-8")
            config_dir.chmod(0o777)
            env_file.chmod(0o666)

            service_module._repair_config_permissions(
                config_dir=config_dir,
                env_file=env_file,
                group="pihole-ai",
                dry_run=False,
            )

            self.assertEqual(config_dir.stat().st_mode & 0o777, 0o750)
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o640)
            chown.assert_has_calls(
                [
                    call(config_dir, 0, 123),
                    call(env_file, 0, 123),
                ]
            )

    def test_config_permission_repair_rejects_symlink_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "pihole-ai"
            config_dir.mkdir()
            target = Path(tmpdir) / "target.env"
            target.write_text("x=1\n", encoding="utf-8")
            env_file = config_dir / "pihole-ai.env"
            env_file.symlink_to(target)

            with self.assertRaises(ServiceError):
                service_module._repair_config_permissions(
                    config_dir=config_dir,
                    env_file=env_file,
                    group="pihole-ai",
                    dry_run=False,
                )

    def test_config_access_failure_blocks_before_service_start(self) -> None:
        issue = service_module._preflight_issue(
            "install.config.not_service_readable",
            "error",
            "Configuration file is not readable.",
            "Run: sudo pihole-ai install",
        )
        with patch("pihole_ai.service._effective_uid", return_value=0), patch(
            "pihole_ai.service._verify_config_access_for_service",
            return_value=[issue],
        ), patch("sys.stdout", io.StringIO()) as stdout:
            with self.assertRaises(ServiceError):
                service_module._enforce_config_access(
                    operation="install",
                    config_dir=service_module.CONFIG_DIR,
                    env_file=service_module.CONFIG_FILE,
                    user="pihole-ai",
                    group="pihole-ai",
                )

        self.assertIn("install.config.not_service_readable", stdout.getvalue())

    def test_config_access_verifier_checks_service_identity(self) -> None:
        config_dir = Path("/etc/pihole-ai")
        env_file = config_dir / "pihole-ai.env"

        def fake_lstat(path: Path):
            if path == config_dir:
                return SimpleNamespace(
                    st_mode=service_module.stat.S_IFDIR | 0o750,
                    st_uid=0,
                    st_gid=123,
                )
            if path == env_file:
                return SimpleNamespace(
                    st_mode=service_module.stat.S_IFREG | 0o640,
                    st_uid=0,
                    st_gid=123,
                )
            raise FileNotFoundError(path)

        completed = SimpleNamespace(returncode=0)
        with patch(
            "pihole_ai.service.grp.getgrnam",
            return_value=SimpleNamespace(gr_gid=123),
        ), patch("pathlib.Path.lstat", fake_lstat), patch(
            "pihole_ai.service.subprocess.run",
            return_value=completed,
        ) as run:
            issues = service_module._verify_config_access_for_service(
                config_dir=config_dir,
                env_file=env_file,
                user="pihole-ai",
                group="pihole-ai",
            )

        self.assertEqual(issues, [])
        run.assert_has_calls(
            [
                call(
                    ["sudo", "-u", "pihole-ai", "test", "-x", str(config_dir)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ),
                call(
                    ["sudo", "-u", "pihole-ai", "test", "-r", str(env_file)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ),
            ]
        )


if __name__ == "__main__":
    unittest.main()
