import contextlib
import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core import migrations
from core.config_schema import CONFIG_SCHEMA_ENV
from pihole_ai import cli
from pihole_ai import service as service_module
from pihole_ai.service import (
    CONFIG_FILE_MODE,
    CONFIG_DIR_MODE,
    DEFAULT_SERVICE_GROUP,
    DEFAULT_SERVICE_USER,
    ENABLE_UNIT_NAMES,
    ExecutableTarget,
    InstallationLayout,
    SERVICE_NAMES,
    START_ORDER,
    STOP_ORDER,
    ServiceError,
)
from pihole_ai.version import get_version


class ApplianceHarness:
    def __init__(self, test_case: unittest.TestCase):
        self.test_case = test_case
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.layout = InstallationLayout(
            config_dir=self.root / "etc" / "pihole-ai",
            config_file=self.root / "etc" / "pihole-ai" / "pihole-ai.env",
            data_dir=self.root / "var" / "lib" / "pihole-ai",
            events_db=self.root / "var" / "lib" / "pihole-ai" / "events.db",
            log_dir=self.root / "var" / "log" / "pihole-ai",
            log_file=self.root / "var" / "log" / "pihole-ai" / "pihole-ai.log",
            runtime_dir=self.root / "run" / "pihole-ai",
            systemd_dir=self.root / "etc" / "systemd" / "system",
            wrapper_path=self.root / "usr" / "local" / "bin" / "pihole-ai",
        )
        self.project_dir = self.layout.data_dir
        self.python = self.root / "opt" / "pihole-ai" / "venv" / "bin" / "python"
        self.console = self.python.with_name("pihole-ai")
        self.commands: list[tuple[list[str], dict]] = []
        self.chowns: list[tuple[Path, int, int]] = []
        self.fail_command_prefix: list[str] | None = None
        self.service_states = {
            name: {"active": "inactive", "enabled": "disabled"}
            for name in SERVICE_NAMES
        }
        self.stack = contextlib.ExitStack()

    def __enter__(self):
        self.python.parent.mkdir(parents=True)
        self.python.write_text("# fake python\n", encoding="utf-8")
        self.console.write_text("# fake console\n", encoding="utf-8")
        self.python.chmod(0o755)
        self.console.chmod(0o755)

        self.stack.enter_context(
            patch("pihole_ai.service.discover_executable_target", return_value=self.target())
        )
        self.stack.enter_context(
            patch("pihole_ai.service.shutil.which", side_effect=lambda name: f"/usr/bin/{name}")
        )
        self.stack.enter_context(
            patch("pihole_ai.service._effective_uid", return_value=0)
        )
        self.stack.enter_context(
            patch("pihole_ai.service.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=991))
        )
        self.stack.enter_context(
            patch("pihole_ai.service.grp.getgrnam", return_value=SimpleNamespace(gr_gid=992))
        )
        self.stack.enter_context(
            patch("pihole_ai.service.grp.getgrgid", return_value=SimpleNamespace(gr_name="pihole"))
        )
        self.stack.enter_context(
            patch("pihole_ai.service.load_config_with_result", side_effect=self.load_config)
        )
        self.stack.enter_context(
            patch("pihole_ai.service._service_state", side_effect=self.service_state)
        )
        self.stack.enter_context(
            patch("pihole_ai.service.subprocess.run", side_effect=self.run_command)
        )
        self.stack.enter_context(
            patch("pihole_ai.service.os.chown", side_effect=self.chown)
        )
        self.stack.enter_context(
            patch("pihole_ai.service.RUNTIME_STATE_DIR", self.layout.runtime_dir)
        )
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stack.close()
        self.tmpdir.cleanup()

    def target(self) -> ExecutableTarget:
        return ExecutableTarget(
            executable_path=self.console,
            invocation=[str(self.python), "-m", "pihole_ai.cli"],
            interpreter_path=self.python,
            package_importable=True,
            version=f"pihole-ai {get_version()}",
            source="test_appliance_venv",
            stable=True,
            reason="ok",
        )

    def kwargs(self) -> dict:
        return {
            "systemd_dir": self.layout.systemd_dir,
            "python_path": str(self.python),
            "project_dir": self.project_dir,
            "wrapper_path": self.layout.wrapper_path,
            "config_dir": self.layout.config_dir,
            "data_dir": self.layout.data_dir,
            "log_dir": self.layout.log_dir,
            "env_file": self.layout.config_file,
            "runtime_db_path": self.layout.events_db,
            "runtime_log_path": self.layout.log_file,
            "runtime_dir": self.layout.runtime_dir,
        }

    def uninstall_kwargs(self) -> dict:
        kwargs = self.kwargs()
        kwargs.pop("runtime_log_path")
        return kwargs

    def load_config(self, *args, **kwargs):
        config = SimpleNamespace(
            pihole_db=self.root / "etc" / "pihole" / "pihole-FTL.db",
        )
        return config, SimpleNamespace(issues=[])

    def service_state(self, name: str, dry_run: bool = False):
        return self.service_states[name]

    def run_command(self, command, *args, **kwargs):
        self.test_case.assertIsInstance(command, list)
        self.test_case.assertFalse(kwargs.get("shell", False))
        self.commands.append((list(command), dict(kwargs)))
        if self.fail_command_prefix and command[: len(self.fail_command_prefix)] == self.fail_command_prefix:
            raise subprocess.CalledProcessError(1, command, stderr="simulated failure")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def chown(self, path, uid, gid):
        self.chowns.append((Path(path), uid, gid))


def snapshot_tree(root: Path) -> dict[str, tuple]:
    snapshot: dict[str, tuple] = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if path.is_symlink():
            snapshot[relative] = ("symlink", mode, os.readlink(path))
        elif path.is_dir():
            snapshot[relative] = ("dir", mode)
        elif path.is_file():
            snapshot[relative] = ("file", mode, path.read_bytes())
        else:
            snapshot[relative] = ("other", mode)
    return snapshot


def schema_version(path: Path) -> int:
    with contextlib.closing(sqlite3.connect(path)) as conn:
        row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return int(row[0] or 0)


class ApplianceLifecycleIntegrationTests(unittest.TestCase):
    def test_install_dry_run_plans_without_mutating_filesystem(self):
        with ApplianceHarness(self) as harness, patch("pihole_ai.service.os.chmod") as chmod:
            before = snapshot_tree(harness.root)
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                result = service_module.service_install(
                    dry_run=True,
                    enable_services=True,
                    start_services=True,
                    **harness.kwargs(),
                )

            after = snapshot_tree(harness.root)

        self.assertEqual(before, after)
        self.assertFalse(result.changed)
        self.assertEqual(harness.commands, [])
        self.assertEqual(harness.chowns, [])
        chmod.assert_not_called()
        output = stdout.getvalue()
        self.assertIn("Would create", output)
        self.assertIn("User=pihole-ai", output)
        self.assertIn("pihole-ai-collector.service", output)
        self.assertIn("Would run: systemctl daemon-reload", output)
        self.assertIn("Dry-run complete", output)

    def test_fresh_install_creates_appliance_files_and_migrates_database(self):
        with ApplianceHarness(self) as harness:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                service_module.service_install(
                    dry_run=False,
                    enable_services=True,
                    start_services=True,
                    **harness.kwargs(),
                )

            self.assertTrue(harness.layout.config_dir.is_dir())
            self.assertTrue(harness.layout.config_file.is_file())
            self.assertTrue(harness.layout.data_dir.is_dir())
            self.assertTrue(harness.layout.log_dir.is_dir())
            self.assertTrue(harness.layout.runtime_dir.is_dir())
            self.assertTrue(harness.layout.wrapper_path.is_file())
            self.assertTrue(harness.layout.events_db.is_file())
            self.assertEqual(schema_version(harness.layout.events_db), migrations.LATEST_SUPPORTED_SCHEMA_VERSION)
            self.assertEqual(stat.S_IMODE(harness.layout.config_dir.stat().st_mode), CONFIG_DIR_MODE)
            self.assertEqual(stat.S_IMODE(harness.layout.config_file.stat().st_mode), CONFIG_FILE_MODE)

            for name in SERVICE_NAMES:
                unit = harness.layout.systemd_dir / name
                self.assertTrue(unit.is_file())
                self.assertIn(str(harness.layout.config_file), unit.read_text(encoding="utf-8"))

            commands = [command for command, _kwargs in harness.commands]
            self.assertIn(["systemctl", "daemon-reload"], commands)
            self.assertIn(["systemctl", "enable", *ENABLE_UNIT_NAMES], commands)
            self.assertIn(["systemctl", "start", *START_ORDER], commands)
            self.assertIn(["chown", "pihole-ai:pihole-ai", str(harness.layout.data_dir)], commands)
            self.assertIn(["chown", "pihole-ai:pihole-ai", str(harness.layout.log_dir)], commands)
            self.assertTrue(
                any(path == harness.layout.config_dir and uid == 0 and gid == 992 for path, uid, gid in harness.chowns)
            )
            self.assertTrue(
                any(path == harness.layout.config_file and uid == 0 and gid == 992 for path, uid, gid in harness.chowns)
            )
            self.assertIn("Install complete. Services are enabled and started.", stdout.getvalue())

    def test_install_no_start_enables_without_starting_services(self):
        with ApplianceHarness(self) as harness:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                service_module.service_install(
                    dry_run=False,
                    enable_services=True,
                    start_services=False,
                    **harness.kwargs(),
                )

            commands = [command for command, _kwargs in harness.commands]
            self.assertIn(["systemctl", "enable", *ENABLE_UNIT_NAMES], commands)
            self.assertNotIn(["systemctl", "start", *START_ORDER], commands)
            self.assertFalse(any(command[:2] == ["systemctl", "start"] for command in commands))
            self.assertIn("Install complete. Run 'pihole-ai start' when ready.", stdout.getvalue())

    def test_install_no_enable_starts_without_enabling_services(self):
        with ApplianceHarness(self) as harness:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                service_module.service_install(
                    dry_run=False,
                    enable_services=False,
                    start_services=True,
                    **harness.kwargs(),
                )

            commands = [command for command, _kwargs in harness.commands]
            self.assertNotIn(["systemctl", "enable", *ENABLE_UNIT_NAMES], commands)
            self.assertIn(["systemctl", "start", *START_ORDER], commands)
            self.assertIn(
                "Install complete. Services were started. Run 'pihole-ai enable' to start at boot.",
                stdout.getvalue(),
            )

    def test_install_no_enable_no_start_completion_message(self):
        with ApplianceHarness(self) as harness:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                service_module.service_install(
                    dry_run=False,
                    enable_services=False,
                    start_services=False,
                    **harness.kwargs(),
                )

            commands = [command for command, _kwargs in harness.commands]
            self.assertNotIn(["systemctl", "enable", *ENABLE_UNIT_NAMES], commands)
            self.assertNotIn(["systemctl", "start", *START_ORDER], commands)
            self.assertIn(
                "Install complete. Run 'pihole-ai enable' and 'pihole-ai start' when ready.",
                stdout.getvalue(),
            )

    def test_install_is_idempotent_and_preserves_existing_config(self):
        with ApplianceHarness(self) as harness:
            service_module.service_install(
                dry_run=False,
                enable_services=False,
                start_services=False,
                **harness.kwargs(),
            )
            harness.layout.config_file.write_text(
                harness.layout.config_file.read_text(encoding="utf-8")
                + "CUSTOM_SECRET=keep-me\n",
                encoding="utf-8",
            )
            first_units = {
                name: (harness.layout.systemd_dir / name).read_text(encoding="utf-8")
                for name in SERVICE_NAMES
            }

            service_module.service_install(
                dry_run=False,
                enable_services=False,
                start_services=False,
                **harness.kwargs(),
            )

            self.assertIn("CUSTOM_SECRET=keep-me", harness.layout.config_file.read_text(encoding="utf-8"))
            self.assertEqual(schema_version(harness.layout.events_db), migrations.LATEST_SUPPORTED_SCHEMA_VERSION)
            self.assertFalse(list(harness.layout.events_db.parent.glob("events.db*.bak")))
            for name, content in first_units.items():
                self.assertEqual((harness.layout.systemd_dir / name).read_text(encoding="utf-8"), content)

    def test_upgrade_refreshes_units_preserves_data_and_repairs_metadata(self):
        with ApplianceHarness(self) as harness:
            harness.layout.config_dir.mkdir(parents=True)
            harness.layout.config_file.write_text(
                service_module.MANAGED_FILE_HEADER
                + f"{CONFIG_SCHEMA_ENV}=1\nCUSTOM_SECRET=keep-me\n",
                encoding="utf-8",
            )
            harness.layout.data_dir.mkdir(parents=True)
            migrations.migrate_database(harness.layout.events_db)
            with contextlib.closing(sqlite3.connect(harness.layout.events_db)) as conn:
                conn.execute(
                    "INSERT INTO domain_reputation(domain, score, confidence, signals, source, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    ("example.test", 1, 1, "{}", "test", 1.0),
                )
                conn.commit()
            harness.layout.systemd_dir.mkdir(parents=True)
            for name in SERVICE_NAMES:
                (harness.layout.systemd_dir / name).write_text(
                    service_module.MANAGED_FILE_HEADER + f"old {name}\n",
                    encoding="utf-8",
                )

            service_module.service_upgrade(
                dry_run=False,
                **harness.kwargs(),
            )

            self.assertIn("CUSTOM_SECRET=keep-me", harness.layout.config_file.read_text(encoding="utf-8"))
            with contextlib.closing(sqlite3.connect(harness.layout.events_db)) as conn:
                reputation_count = conn.execute("SELECT COUNT(*) FROM domain_reputation").fetchone()[0]
            self.assertEqual(reputation_count, 1)
            self.assertEqual(schema_version(harness.layout.events_db), migrations.LATEST_SUPPORTED_SCHEMA_VERSION)
            for name in SERVICE_NAMES:
                unit_content = (harness.layout.systemd_dir / name).read_text(encoding="utf-8")
                self.assertIn("ExecStart=", unit_content)
                self.assertTrue((harness.layout.systemd_dir / f"{name}.bak").is_file())

            commands = [command for command, _kwargs in harness.commands]
            self.assertIn(["systemctl", "daemon-reload"], commands)
            self.assertIn(["systemctl", "disable", SERVICE_NAMES[0]], commands)
            self.assertIn(["systemctl", "stop", SERVICE_NAMES[0]], commands)

    def test_upgrade_failure_restores_managed_units_and_does_not_claim_success(self):
        with ApplianceHarness(self) as harness:
            harness.layout.config_dir.mkdir(parents=True)
            harness.layout.config_file.write_text(
                service_module.MANAGED_FILE_HEADER + f"{CONFIG_SCHEMA_ENV}=1\n",
                encoding="utf-8",
            )
            harness.layout.data_dir.mkdir(parents=True)
            migrations.migrate_database(harness.layout.events_db)
            harness.layout.systemd_dir.mkdir(parents=True)
            old_units = {}
            for name in SERVICE_NAMES:
                content = service_module.MANAGED_FILE_HEADER + f"old {name}\n"
                old_units[name] = content
                (harness.layout.systemd_dir / name).write_text(content, encoding="utf-8")
            harness.fail_command_prefix = ["systemctl", "daemon-reload"]

            with self.assertRaises(ServiceError):
                service_module.service_upgrade(
                    dry_run=False,
                    **harness.kwargs(),
                )

            for name, content in old_units.items():
                self.assertEqual((harness.layout.systemd_dir / name).read_text(encoding="utf-8"), content)
            commands = [command for command, _kwargs in harness.commands]
            self.assertNotIn(["systemctl", "restart", *SERVICE_NAMES], commands)

    def test_service_lifecycle_command_order_and_failure(self):
        with ApplianceHarness(self) as harness:
            def fake_lifecycle_lock(*args, **kwargs):
                return contextlib.nullcontext()

            lifecycle_patches = [
                patch(
                    "pihole_ai.service.build_install_plan",
                    return_value=SimpleNamespace(
                        layout=harness.layout,
                        project_dir=harness.root,
                    ),
                ),
                patch("pihole_ai.service.lifecycle_lock", side_effect=fake_lifecycle_lock),
                patch(
                    "pihole_ai.service._configuration_lifecycle_report",
                    return_value=service_module.ConfigLifecycleReport(
                        exists=True,
                        schema_version=1,
                        status="valid",
                        migration_required=False,
                        config_file=str(harness.layout.config_file),
                    ),
                ),
            ]
            with contextlib.ExitStack() as stack:
                for lifecycle_patch in lifecycle_patches:
                    stack.enter_context(lifecycle_patch)
                service_module.service_enable()
                service_module.service_disable()
                service_module.service_action("start")
                service_module.service_action("stop")
                service_module.service_action("restart")

            commands = [command for command, _kwargs in harness.commands]
            self.assertEqual(commands[0], ["systemctl", "enable", *ENABLE_UNIT_NAMES])
            self.assertEqual(commands[1], ["systemctl", "disable", *ENABLE_UNIT_NAMES])
            self.assertEqual(commands[2:5], [["systemctl", "start", name] for name in START_ORDER])
            self.assertEqual(commands[5:8], [["systemctl", "stop", name] for name in STOP_ORDER])
            self.assertEqual(commands[8], ["systemctl", "restart", *SERVICE_NAMES])

        with ApplianceHarness(self) as failing:
            failing.fail_command_prefix = ["systemctl", "start", START_ORDER[1]]

            def fake_lifecycle_lock(*args, **kwargs):
                return contextlib.nullcontext()

            with patch(
                "pihole_ai.service.build_install_plan",
                return_value=SimpleNamespace(
                    layout=failing.layout,
                    project_dir=failing.root,
                ),
            ), patch(
                "pihole_ai.service.lifecycle_lock",
                side_effect=fake_lifecycle_lock,
            ), patch(
                "pihole_ai.service._configuration_lifecycle_report",
                return_value=service_module.ConfigLifecycleReport(
                    exists=True,
                    schema_version=1,
                    status="valid",
                    migration_required=False,
                    config_file=str(failing.layout.config_file),
                ),
            ):
                with self.assertRaises(ServiceError):
                    service_module.service_action("start")
            commands = [command for command, _kwargs in failing.commands]
            self.assertEqual(commands, [["systemctl", "start", START_ORDER[0]], ["systemctl", "start", START_ORDER[1]]])

    def test_uninstall_preserves_data_by_default_and_requires_purge_confirmation(self):
        with ApplianceHarness(self) as harness:
            service_module.service_install(
                dry_run=False,
                enable_services=False,
                start_services=False,
                **harness.kwargs(),
            )
            with contextlib.closing(sqlite3.connect(harness.layout.events_db)) as conn:
                conn.execute("INSERT INTO domain_reputation(domain, score, confidence, signals, source, updated_at) VALUES (?, ?, ?, ?, ?, ?)", ("example.test", 1, 1, "{}", "test", 1.0))
                conn.execute("INSERT INTO threat_intel(domain, source, category, confidence, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)", ("bad.test", "test", "malware", 99, 1.0, 1.0))
                conn.commit()
            harness.layout.log_dir.mkdir(parents=True, exist_ok=True)
            (harness.layout.log_dir / "pihole-ai.log").write_text("log\n", encoding="utf-8")

            result = service_module.service_uninstall(
                dry_run=False,
                purge=False,
                **harness.uninstall_kwargs(),
            )

            self.assertFalse(any((harness.layout.systemd_dir / name).exists() for name in SERVICE_NAMES))
            self.assertFalse(harness.layout.wrapper_path.exists())
            self.assertTrue(harness.layout.config_file.exists())
            self.assertTrue(harness.layout.events_db.exists())
            with contextlib.closing(sqlite3.connect(harness.layout.events_db)) as conn:
                reputation_count = conn.execute("SELECT COUNT(*) FROM domain_reputation").fetchone()[0]
                intel_count = conn.execute("SELECT COUNT(*) FROM threat_intel").fetchone()[0]
            self.assertEqual(reputation_count, 1)
            self.assertEqual(intel_count, 1)
            self.assertIn(str(harness.layout.events_db), result.preserved_paths)

            with self.assertRaises(ServiceError):
                service_module.service_uninstall(
                    dry_run=False,
                    purge=True,
                    confirm_purge=False,
                    **harness.uninstall_kwargs(),
                )
            service_module.service_uninstall(
                dry_run=False,
                purge=True,
                confirm_purge=True,
                **harness.uninstall_kwargs(),
            )
            self.assertFalse(harness.layout.log_dir.exists())

    def test_uninstall_does_not_require_importable_or_existing_executable(self):
        with ApplianceHarness(self) as harness:
            service_module.service_install(
                dry_run=False,
                enable_services=False,
                start_services=False,
                **harness.kwargs(),
            )
            harness.python.unlink()
            with patch(
                "pihole_ai.service.discover_executable_target",
                side_effect=AssertionError("uninstall must not validate executable"),
            ):
                service_module.service_uninstall(
                    dry_run=False,
                    purge=False,
                    **harness.uninstall_kwargs(),
                )

            self.assertFalse(harness.layout.wrapper_path.exists())
            self.assertFalse(any((harness.layout.systemd_dir / name).exists() for name in SERVICE_NAMES))

    def test_readme_no_start_example_matches_enabled_but_stopped_contract(self):
        readme = Path("README.md").read_text(encoding="utf-8")
        self.assertIn("`pihole-ai install` installs files, enables services", readme)
        self.assertIn(
            "`pihole-ai install --no-start` installs files and enables\n"
            "services without starting them",
            readme,
        )
        self.assertIn("sudo /usr/local/bin/pihole-ai start", readme)
        self.assertNotIn("pihole-aienable", readme)

    def test_protected_config_validation_reports_permission_failures(self):
        with ApplianceHarness(self) as harness:
            harness.layout.config_dir.mkdir(parents=True)
            harness.layout.config_file.write_text("SECRET=value\n", encoding="utf-8")
            harness.layout.config_dir.chmod(0o755)
            harness.layout.config_file.chmod(0o644)

            issues = service_module._verify_config_access_for_service(
                harness.layout.config_dir,
                harness.layout.config_file,
                DEFAULT_SERVICE_USER,
                DEFAULT_SERVICE_GROUP,
            )
            codes = {issue.code for issue in issues}
            self.assertIn("install.config.unsafe_permissions", codes)
            self.assertIn("install.config.invalid_owner", codes)

            harness.layout.config_file.unlink()
            target = harness.root / "outside.env"
            target.write_text("SECRET=value\n", encoding="utf-8")
            harness.layout.config_file.symlink_to(target)
            with self.assertRaises(ServiceError):
                service_module._repair_config_permissions(
                    harness.layout.config_dir,
                    harness.layout.config_file,
                    DEFAULT_SERVICE_GROUP,
                    dry_run=False,
                )

    def test_database_compatibility_and_transactional_failure_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            empty = root / "empty.db"
            result = migrations.migrate_database(empty)
            self.assertTrue(result.changed)
            self.assertEqual(schema_version(empty), migrations.LATEST_SUPPORTED_SCHEMA_VERSION)

            current = migrations.database_status(empty)
            self.assertEqual(current.pending_migration_count, 0)

            future = root / "future.db"
            with contextlib.closing(sqlite3.connect(future)) as conn:
                migrations.ensure_migration_table(conn)
                conn.execute(
                    "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                    (migrations.LATEST_SUPPORTED_SCHEMA_VERSION + 1, "future", "now"),
                )
                conn.commit()
            before = future.read_bytes()
            with self.assertRaises(migrations.UnsupportedSchemaVersion):
                migrations.database_status(future)
            self.assertEqual(future.read_bytes(), before)

            def ok(conn):
                conn.execute("CREATE TABLE ok_table(value TEXT)")

            def fail(conn):
                conn.execute("CREATE TABLE fail_table(value TEXT)")
                raise migrations.MigrationError("boom")

            custom = [
                migrations.Migration(1, "ok", ok),
                migrations.Migration(2, "fail", fail),
            ]
            failed = root / "failed.db"
            with patch("core.migrations.MIGRATIONS", custom):
                with self.assertRaises(migrations.MigrationError):
                    migrations.migrate_database(failed)
            with contextlib.closing(sqlite3.connect(failed)) as conn:
                tables = {
                    row[0]
                    for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                versions = [row[0] for row in conn.execute("SELECT version FROM schema_migrations")]
            self.assertIn("ok_table", tables)
            self.assertNotIn("fail_table", tables)
            self.assertEqual(versions, [1])

    def test_lifecycle_json_output_is_clean_and_does_not_leak_secrets(self):
        with ApplianceHarness(self) as harness:
            original_install = service_module.service_install

            def harness_install(**kwargs):
                return original_install(
                    **kwargs,
                    **harness.kwargs(),
                )

            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch(
                "pihole_ai.service.service_install",
                side_effect=harness_install,
            ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = cli.main(["install", "--dry-run", "--json"])

            decoded = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(decoded["command"], "install")
            self.assertTrue(decoded["dry_run"])
            self.assertNotIn("SECRET", stdout.getvalue())
            self.assertNotIn("PASSWORD_HASH", stdout.getvalue())
            self.assertIn("Installing PiHole-AI", stderr.getvalue())
            for _command, kwargs in harness.commands:
                self.assertFalse(kwargs.get("shell", False))


if __name__ == "__main__":
    unittest.main()
