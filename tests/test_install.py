import io
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

from core.config_schema import CONFIG_SCHEMA_ENV
from pihole_ai import service as service_module
from pihole_ai.service import (
    ENABLE_UNIT_NAMES,
    MANAGED_UNIT_NAMES,
    SERVICE_NAMES,
    START_ORDER,
    ServiceError,
    launcher_content,
    service_install,
    service_uninstall,
)


FAKE_SERVICE_UID = 991
FAKE_SERVICE_GID = 992


class InstallLifecycleTests(unittest.TestCase):
    def _paths(self, tmpdir: str) -> dict[str, Path]:
        root = Path(tmpdir)
        return {
            "systemd": root / "systemd",
            "wrapper": root / "bin" / "pihole-ai",
            "config_dir": root / "etc" / "pihole-ai",
            "env_file": root / "etc" / "pihole-ai" / "pihole-ai.env",
            "data_dir": root / "var" / "lib" / "pihole-ai",
            "log_dir": root / "var" / "log" / "pihole-ai",
            "runtime_dir": root / "run" / "pihole-ai",
        }

    def _valid_config(self, paths: dict[str, Path]) -> str:
        return service_module.MANAGED_FILE_HEADER + service_module._runtime_env_content(
            project_dir=Path("/app"),
            runtime_db_path=paths["data_dir"] / "events.db",
            runtime_log_path=paths["log_dir"] / "pihole-ai.log",
        )

    def _install_kwargs(self, paths: dict[str, Path]) -> dict[str, object]:
        return {
            "systemd_dir": paths["systemd"],
            "python_path": "/venv/bin/python",
            "project_dir": "/app",
            "wrapper_path": paths["wrapper"],
            "config_dir": paths["config_dir"],
            "data_dir": paths["data_dir"],
            "log_dir": paths["log_dir"],
            "runtime_dir": paths["runtime_dir"],
        }

    def test_install_creates_current_schema_config_and_starts_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
        ), patch(
            "pihole_ai.service.pwd.getpwnam",
            return_value=SimpleNamespace(pw_uid=FAKE_SERVICE_UID, pw_gid=FAKE_SERVICE_GID),
        ), patch(
            "pihole_ai.service.grp.getgrnam",
            return_value=SimpleNamespace(gr_gid=FAKE_SERVICE_GID),
        ), patch(
            "pihole_ai.service.os.chown",
        ), patch(
            "sys.stdout",
            io.StringIO(),
        ) as stdout:
            paths = self._paths(tmpdir)

            service_install(**self._install_kwargs(paths))

            config_text = paths["env_file"].read_text(encoding="utf-8")
            self.assertIn(f"{CONFIG_SCHEMA_ENV}=1", config_text)
            self.assertTrue((paths["systemd"] / SERVICE_NAMES[0]).exists())
            self.assertIn("Configuration:", stdout.getvalue())
            self.assertIn("Services:", stdout.getvalue())
            run.assert_has_calls(
                [
                    call(["systemctl", "daemon-reload"], check=True),
                    call(["systemctl", "enable", *ENABLE_UNIT_NAMES], check=True),
                    call(["systemctl", "start", *START_ORDER], check=True),
                ]
            )

    def test_install_no_start_enables_without_starting(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
        ), patch(
            "pihole_ai.service.pwd.getpwnam",
            return_value=SimpleNamespace(pw_uid=FAKE_SERVICE_UID, pw_gid=FAKE_SERVICE_GID),
        ), patch(
            "pihole_ai.service.grp.getgrnam",
            return_value=SimpleNamespace(gr_gid=FAKE_SERVICE_GID),
        ), patch(
            "pihole_ai.service.os.chown",
        ), patch(
            "sys.stdout",
            io.StringIO(),
        ) as stdout:
            paths = self._paths(tmpdir)

            service_install(start_services=False, **self._install_kwargs(paths))

            commands = [item.args[0] for item in run.call_args_list]
            self.assertIn(["systemctl", "enable", *ENABLE_UNIT_NAMES], commands)
            self.assertNotIn(["systemctl", "start", *START_ORDER], commands)
            self.assertIn(
                "Install complete. Run 'pihole-ai start' when ready.",
                stdout.getvalue(),
            )

    def test_install_legacy_config_aborts_before_systemd_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
        ), patch(
            "sys.stdout",
            io.StringIO(),
        ) as stdout:
            paths = self._paths(tmpdir)
            paths["config_dir"].mkdir(parents=True)
            paths["env_file"].write_text("PIHOLE_AI_DASHBOARD_PORT=8080\n", encoding="utf-8")

            with self.assertRaises(ServiceError) as context:
                service_install(**self._install_kwargs(paths))

        self.assertIn("Configuration migration required", str(context.exception))
        self.assertIn("pihole-ai config migrate --dry-run", stdout.getvalue())
        self.assertFalse((paths["systemd"] / SERVICE_NAMES[0]).exists())
        systemctl_commands = [
            item.args[0]
            for item in run.call_args_list
            if item.args and item.args[0][0] == "systemctl"
        ]
        self.assertEqual(systemctl_commands, [])

    def test_install_invalid_current_config_aborts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
        ), patch("sys.stdout", io.StringIO()):
            paths = self._paths(tmpdir)
            paths["config_dir"].mkdir(parents=True)
            paths["env_file"].write_text(
                f"{CONFIG_SCHEMA_ENV}=1\nPIHOLE_AI_DASHBOARD_PORT=99999\n",
                encoding="utf-8",
            )

            with self.assertRaises(ServiceError) as context:
                service_install(**self._install_kwargs(paths))

        self.assertIn("Configuration validation failed", str(context.exception))
        self.assertFalse((paths["systemd"] / SERVICE_NAMES[0]).exists())
        systemctl_commands = [
            item.args[0]
            for item in run.call_args_list
            if item.args and item.args[0][0] == "systemctl"
        ]
        self.assertEqual(systemctl_commands, [])

    def test_install_dry_run_creates_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ) as run, patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch("sys.stdout", io.StringIO()) as stdout:
            paths = self._paths(tmpdir)

            service_install(dry_run=True, **self._install_kwargs(paths))

        self.assertFalse(paths["env_file"].exists())
        self.assertFalse(paths["systemd"].exists())
        self.assertIn("[ok] Would create", stdout.getvalue())
        self.assertNotIn("[ok] Created", stdout.getvalue())
        run.assert_not_called()

    def test_install_preserves_valid_current_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ), patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
        ), patch(
            "pihole_ai.service.pwd.getpwnam",
            return_value=SimpleNamespace(pw_uid=FAKE_SERVICE_UID, pw_gid=FAKE_SERVICE_GID),
        ), patch(
            "pihole_ai.service.grp.getgrnam",
            return_value=SimpleNamespace(gr_gid=FAKE_SERVICE_GID),
        ), patch(
            "pihole_ai.service.os.chown",
        ), patch("sys.stdout", io.StringIO()):
            paths = self._paths(tmpdir)
            paths["config_dir"].mkdir(parents=True)
            content = self._valid_config(paths) + "PIHOLE_AI_CUSTOM=preserved\n"
            paths["env_file"].write_text(content, encoding="utf-8")

            service_install(**self._install_kwargs(paths))

            self.assertEqual(paths["env_file"].read_text(encoding="utf-8"), content)

    def test_uninstall_preserves_config_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ), patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
        ), patch("sys.stdout", io.StringIO()):
            paths = self._paths(tmpdir)
            paths["systemd"].mkdir(parents=True)
            paths["config_dir"].mkdir(parents=True)
            paths["wrapper"].parent.mkdir(parents=True)
            paths["env_file"].write_text(self._valid_config(paths), encoding="utf-8")
            paths["wrapper"].write_text(launcher_content("/app"), encoding="utf-8")
            for name in MANAGED_UNIT_NAMES:
                (paths["systemd"] / name).write_text("unit", encoding="utf-8")

            service_uninstall(**self._install_kwargs(paths))

            self.assertTrue(paths["env_file"].exists())

    def test_uninstall_removes_config_only_with_explicit_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "pihole_ai.service.subprocess.run",
        ), patch("pihole_ai.service.os.geteuid", return_value=0), patch(
            "pihole_ai.service._enforce_preflight",
        ), patch(
            "pihole_ai.service.lifecycle_lock",
            return_value=nullcontext(),
        ), patch("sys.stdout", io.StringIO()):
            paths = self._paths(tmpdir)
            paths["systemd"].mkdir(parents=True)
            paths["config_dir"].mkdir(parents=True)
            paths["wrapper"].parent.mkdir(parents=True)
            paths["env_file"].write_text(self._valid_config(paths), encoding="utf-8")
            paths["wrapper"].write_text(launcher_content("/app"), encoding="utf-8")
            for name in MANAGED_UNIT_NAMES:
                (paths["systemd"] / name).write_text("unit", encoding="utf-8")

            service_uninstall(remove_config=True, keep_config=False, **self._install_kwargs(paths))

            self.assertFalse(paths["env_file"].exists())


if __name__ == "__main__":
    unittest.main()
