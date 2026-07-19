import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.config_schema import CONFIG_SCHEMA_ENV
from core.service_control import ServiceRestartResult
from pihole_ai import cli
from pihole_ai import service as service_module
from pihole_ai.service import (
    ENABLE_UNIT_NAMES,
    ExecutableTarget,
    InstallationLayout,
    SERVICE_NAMES,
    START_ORDER,
    ServiceError,
)
from pihole_ai.version import get_version
from ui.dashboard import AUTH_SESSION_KEY, CSRF_SESSION_KEY, create_app


SECRET = "phase-two-c-secret-value-that-must-not-leak"


class ApplianceConfigHarness:
    def __init__(self, test_case: unittest.TestCase):
        self.test_case = test_case
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.project_dir = self.root / "project"
        self.project_dir.mkdir()
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
        self.python = self.root / "opt" / "pihole-ai" / "venv" / "bin" / "python"
        self.console = self.python.with_name("pihole-ai")
        self.commands: list[list[str]] = []
        self.stack = contextlib.ExitStack()

    def __enter__(self):
        self.python.parent.mkdir(parents=True)
        self.python.write_text("# fake python\n", encoding="utf-8")
        self.console.write_text("# fake console\n", encoding="utf-8")
        self.python.chmod(0o755)
        self.console.chmod(0o755)
        self.stack.enter_context(patch.dict(os.environ, {}, clear=True))
        self.stack.enter_context(
            patch("pihole_ai.service.discover_executable_target", return_value=self.target())
        )
        self.stack.enter_context(
            patch("pihole_ai.service.shutil.which", side_effect=lambda name: f"/usr/bin/{name}")
        )
        self.stack.enter_context(patch("pihole_ai.service._effective_uid", return_value=0))
        self.stack.enter_context(
            patch("pihole_ai.service.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=991))
        )
        self.stack.enter_context(
            patch("pihole_ai.service.grp.getgrnam", return_value=SimpleNamespace(gr_gid=992))
        )
        self.stack.enter_context(patch("pihole_ai.service.os.chown"))
        self.stack.enter_context(
            patch("pihole_ai.service.load_config_with_result", side_effect=self.load_config)
        )
        self.stack.enter_context(
            patch("pihole_ai.service.subprocess.run", side_effect=self.run_command)
        )
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stack.close()
        self.tmp.cleanup()

    def target(self) -> ExecutableTarget:
        return ExecutableTarget(
            executable_path=self.console,
            invocation=[str(self.python), "-m", "pihole_ai.cli"],
            interpreter_path=self.python,
            package_importable=True,
            version=f"pihole-ai {get_version()}",
            source="phase2c-test",
            stable=True,
            reason="ok",
        )

    def load_config(self, *args, **kwargs):
        return (
            SimpleNamespace(pihole_db=self.root / "etc" / "pihole" / "pihole-FTL.db"),
            SimpleNamespace(issues=[]),
        )

    def run_command(self, command, *args, **kwargs):
        self.test_case.assertNotIn(command[0], {"sudo", "pkexec"})
        self.commands.append(list(command))
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    def install_kwargs(self) -> dict[str, object]:
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

    def uninstall_kwargs(self) -> dict[str, object]:
        kwargs = self.install_kwargs()
        kwargs.pop("runtime_log_path")
        return kwargs

    def run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        with patch("core.config_manager.runtime_config.PROJECT_ROOT", self.project_dir), \
             patch("core.config_manager.runtime_config.CONFIG_FILE", self.layout.config_file), \
             patch("pihole_ai.config_cli.runtime_config.PROJECT_ROOT", self.project_dir), \
             patch("pihole_ai.config_cli.runtime_config.CONFIG_FILE", self.layout.config_file), \
             patch("sys.stdout", io.StringIO()) as stdout, \
             patch("sys.stderr", io.StringIO()) as stderr, \
             patch("sys.stdin", io.StringIO()):
            exit_code = cli.main(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def app_client(self):
        patches = [
            patch("ui.dashboard.SETTINGS_ENV_PATH", self.layout.config_file),
            patch("core.config_operations.runtime_config.PROJECT_ROOT", self.project_dir),
            patch("core.config_operations.runtime_config.CONFIG_FILE", self.layout.config_file),
        ]
        for item in patches:
            self.stack.enter_context(item)
        app = create_app()
        app.config.update(TESTING=True)
        app.config["PIHOLE_AI_DISABLE_AUTH_FOR_TESTS"] = True
        return app, app.test_client()

    def authenticated_client(self):
        app, client = self.app_client()
        app.config["PIHOLE_AI_DISABLE_AUTH_FOR_TESTS"] = False
        with client.session_transaction() as session:
            session[AUTH_SESSION_KEY] = True
            session[CSRF_SESSION_KEY] = "csrf-token"
        return app, client

    def write_config(self, text: str) -> None:
        self.layout.config_dir.mkdir(parents=True, exist_ok=True)
        self.layout.config_file.write_text(text, encoding="utf-8")

    def current_config(self) -> str:
        return self.layout.config_file.read_text(encoding="utf-8")


class ApplianceConfigIntegrationTests(unittest.TestCase):
    def test_cli_change_is_visible_to_dashboard_and_settings_markup_is_secret_safe(self):
        with ApplianceConfigHarness(self) as harness:
            harness.write_config(
                f"{CONFIG_SCHEMA_ENV}=1\n"
                "PIHOLE_AI_OLLAMA_MODEL=old-model\n"
                f"PIHOLE_AI_DASHBOARD_SECRET_KEY={SECRET}\n"
            )

            exit_code, stdout, stderr = harness.run_cli(
                [
                    "config",
                    "set",
                    "ollama_model",
                    "cli-model",
                    "--yes",
                    "--config-file",
                    str(harness.layout.config_file),
                ]
            )
            self.assertEqual((exit_code, stderr), (0, ""))
            self.assertNotIn(SECRET, stdout)

            _app, client = harness.app_client()
            payload = client.get("/api/config").get_json()
            model = next(item for item in payload["settings"] if item["key"] == "ollama_model")
            secret = next(item for item in payload["settings"] if item["key"] == "dashboard_secret_key")
            self.assertEqual(model["value"], "cli-model")
            self.assertTrue(model["source"].startswith("env_file:"))
            self.assertTrue(secret["masked"])
            self.assertIsNone(secret["value"])

            html = client.get("/settings").get_data(as_text=True)
            self.assertIn("/api/config", html)
            self.assertNotIn("cli-model", html)
            self.assertNotIn(SECRET, html)

    def test_dashboard_update_and_unset_are_visible_to_cli(self):
        with ApplianceConfigHarness(self) as harness:
            harness.write_config(
                f"{CONFIG_SCHEMA_ENV}=1\nPIHOLE_AI_OLLAMA_MODEL=old-model\n"
            )
            _app, client = harness.app_client()
            revision = client.get("/api/config").get_json()["revision"]

            response = client.put(
                "/api/config",
                json={
                    "revision": revision,
                    "changes": {"ollama_model": "dashboard-model"},
                },
            )
            self.assertEqual(response.status_code, 200)

            exit_code, stdout, _stderr = harness.run_cli(
                ["config", "get", "ollama_model", "--json", "--details"]
            )
            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout)
            self.assertEqual(payload["value"], "dashboard-model")
            self.assertTrue(payload["source"].startswith("env_file:"))
            self.assertEqual(payload["restart"], ["pihole-ai-engine.service"])

            revision = client.get("/api/config").get_json()["revision"]
            unset = client.put(
                "/api/config",
                json={
                    "revision": revision,
                    "changes": {"ollama_model": {"operation": "unset"}},
                },
            )
            self.assertEqual(unset.status_code, 200)
            self.assertNotIn("PIHOLE_AI_OLLAMA_MODEL=", harness.current_config())
            exit_code, stdout, _stderr = harness.run_cli(
                ["config", "get", "ollama_model", "--json", "--details"]
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(stdout)["source"], "default")

    def test_legacy_migration_then_install_preserves_content_and_updates_status(self):
        with ApplianceConfigHarness(self) as harness:
            legacy = (
                "# operator comment\n"
                "OLLAMA_MODEL=legacy-model\n"
                "UNKNOWN_KEEP=value\n"
                f"PIHOLE_AI_DASHBOARD_SECRET_KEY={SECRET}\n"
            )
            harness.write_config(legacy)

            with patch("sys.stdout", io.StringIO()):
                with self.assertRaises(ServiceError):
                    service_module.service_install(**harness.install_kwargs())
            self.assertEqual(harness.current_config(), legacy)
            self.assertFalse(harness.layout.systemd_dir.exists())
            self.assertEqual(harness.commands, [])

            code, stdout, stderr = harness.run_cli(
                [
                    "config",
                    "migrate",
                    "--dry-run",
                    "--json",
                    "--config-file",
                    str(harness.layout.config_file),
                ]
            )
            self.assertEqual((code, stderr), (0, ""))
            self.assertTrue(json.loads(stdout)["changed"])
            self.assertEqual(harness.current_config(), legacy)
            self.assertFalse(harness.layout.config_file.with_suffix(".env.bak").exists())

            code, stdout, stderr = harness.run_cli(
                [
                    "config",
                    "migrate",
                    "--yes",
                    "--json",
                    "--config-file",
                    str(harness.layout.config_file),
                ]
            )
            self.assertEqual((code, stderr), (0, ""))
            self.assertTrue(json.loads(stdout)["written"])
            backups = list(
                harness.layout.config_file.parent.glob(
                    "pihole-ai.env.migration-v0-to-v1.bak*"
                )
            )
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(encoding="utf-8"), legacy)
            migrated = harness.current_config()
            self.assertIn(f"{CONFIG_SCHEMA_ENV}=1", migrated)
            self.assertIn("PIHOLE_AI_OLLAMA_MODEL=legacy-model", migrated)
            self.assertIn("# operator comment", migrated)
            self.assertIn("UNKNOWN_KEEP=value", migrated)
            self.assertIn(SECRET, migrated)

            with patch("sys.stdout", io.StringIO()):
                service_module.service_install(**harness.install_kwargs())
            self.assertTrue((harness.layout.systemd_dir / SERVICE_NAMES[0]).exists())
            status = service_module.installation_status(
                layout=harness.layout,
                project_dir=harness.project_dir,
                python_path=str(harness.python),
            )
            self.assertEqual(status.state, "installed")
            from pihole_ai.status import configuration_status

            config_status = configuration_status(str(harness.layout.config_file))
            self.assertEqual(config_status["schema_status"], "current")
            self.assertFalse(config_status["migration_required"])

    def test_import_export_round_trips_without_leaking_normal_secrets_or_restarting(self):
        with ApplianceConfigHarness(self) as harness:
            harness.write_config(
                f"{CONFIG_SCHEMA_ENV}=1\n"
                "PIHOLE_AI_OLLAMA_MODEL=roundtrip-model\n"
                f"PIHOLE_AI_DASHBOARD_SECRET_KEY={SECRET}\n"
            )

            code, stdout, stderr = harness.run_cli(["config", "export", "--format", "json"])
            self.assertEqual((code, stderr), (0, ""))
            self.assertNotIn(SECRET, stdout)
            exported = harness.root / "export.json"
            exported.write_text(stdout, encoding="utf-8")

            secure = harness.run_cli(["config", "export", "--secure", "--format", "json"])
            self.assertEqual(secure[0], 0)
            self.assertIn(SECRET, secure[1])

            harness.layout.config_file.write_text(f"{CONFIG_SCHEMA_ENV}=1\n", encoding="utf-8")
            code, stdout, stderr = harness.run_cli(
                [
                    "config",
                    "import",
                    str(exported),
                    "--yes",
                    "--json",
                    "--config-file",
                    str(harness.layout.config_file),
                ]
            )
            self.assertEqual((code, stderr), (0, ""))
            payload = json.loads(stdout)
            self.assertTrue(payload["written"])
            self.assertFalse(payload["restart_attempted"])
            self.assertIn("PIHOLE_AI_OLLAMA_MODEL=roundtrip-model", harness.current_config())
            self.assertNotIn(SECRET, harness.current_config())

            env_export = harness.root / "export.env"
            code, stdout, _stderr = harness.run_cli(["config", "export", "--format", "env"])
            self.assertEqual(code, 0)
            env_export.write_text(stdout, encoding="utf-8")
            code, stdout, _stderr = harness.run_cli(
                [
                    "config",
                    "import",
                    str(env_export),
                    "--dry-run",
                    "--json",
                    "--config-file",
                    str(harness.layout.config_file),
                ]
            )
            self.assertEqual(code, 0)
            self.assertFalse(json.loads(stdout)["written"])

    def test_secret_lifecycle_masks_outputs_and_revision_conflict_blocks_stale_write(self):
        with ApplianceConfigHarness(self) as harness:
            harness.write_config(
                f"{CONFIG_SCHEMA_ENV}=1\nPIHOLE_AI_OLLAMA_MODEL=old-model\n"
            )
            code, stdout, stderr = harness.run_cli(
                [
                    "config",
                    "set",
                    "dashboard_secret_key",
                    SECRET,
                    "--yes",
                    "--json",
                    "--config-file",
                    str(harness.layout.config_file),
                ]
            )
            self.assertEqual((code, stderr), (0, ""))
            self.assertNotIn(SECRET, stdout)
            self.assertIn(SECRET, harness.current_config())
            self.assertNotIn(SECRET, harness.layout.config_file.with_suffix(".env.bak").read_text(encoding="utf-8"))

            _app, client = harness.app_client()
            revision_a = client.get("/api/config").get_json()["revision"]
            code, _stdout, _stderr = harness.run_cli(
                [
                    "config",
                    "set",
                    "ollama_model",
                    "external-change",
                    "--yes",
                    "--config-file",
                    str(harness.layout.config_file),
                ]
            )
            self.assertEqual(code, 0)

            stale = client.put(
                "/api/config",
                json={
                    "revision": revision_a,
                    "changes": {"ollama_model": "stale-dashboard-write"},
                },
            )
            self.assertEqual(stale.status_code, 409)
            self.assertNotIn("stale-dashboard-write", harness.current_config())
            self.assertNotIn(SECRET, stale.get_data(as_text=True))

            revision_b = client.get("/api/config").get_json()["revision"]
            ok = client.put(
                "/api/config",
                json={
                    "revision": revision_b,
                    "changes": {"ollama_model": "fresh-dashboard-write"},
                },
            )
            self.assertEqual(ok.status_code, 200)
            self.assertIn("fresh-dashboard-write", harness.current_config())

    def test_restart_orchestration_persists_before_restart_and_reports_failures(self):
        with ApplianceConfigHarness(self) as harness:
            harness.write_config(
                f"{CONFIG_SCHEMA_ENV}=1\nPIHOLE_AI_OLLAMA_MODEL=old-model\n"
            )
            calls: list[str] = []

            def fake_restart(services):
                calls.append(harness.current_config())
                self.assertEqual(services, ["pihole-ai-engine.service"])
                return [
                    ServiceRestartResult(
                        "pihole-ai-engine.service",
                        True,
                        False,
                        1,
                        "authorization_required",
                        "denied",
                    )
                ]

            with patch(
                "pihole_ai.config_cli.service_control.restart_services",
                side_effect=fake_restart,
            ):
                code, stdout, stderr = harness.run_cli(
                    [
                        "config",
                        "set",
                        "ollama_model",
                        "new-model",
                        "--yes",
                        "--restart",
                        "--config-file",
                        str(harness.layout.config_file),
                    ]
                )

            self.assertEqual((code, stderr), (1, ""))
            self.assertEqual(len(calls), 1)
            self.assertIn("PIHOLE_AI_OLLAMA_MODEL=new-model", calls[0])
            self.assertIn("PIHOLE_AI_OLLAMA_MODEL=new-model", harness.current_config())
            self.assertIn("sudo systemctl restart pihole-ai-engine.service", stdout)


if __name__ == "__main__":
    unittest.main()
