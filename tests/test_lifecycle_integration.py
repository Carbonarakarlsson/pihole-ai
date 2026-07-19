import io
import unittest
from unittest.mock import patch

from core.config_schema import CONFIG_SCHEMA_ENV
from pihole_ai import service as service_module
from pihole_ai.service import ENABLE_UNIT_NAMES, SERVICE_NAMES, START_ORDER, ServiceError
from tests.test_appliance_config_integration import ApplianceConfigHarness


class LifecycleIntegrationTests(unittest.TestCase):
    def test_fresh_install_dry_run_real_install_status_enable_and_start(self):
        with ApplianceConfigHarness(self) as harness:
            with patch("sys.stdout", io.StringIO()):
                service_module.service_install(dry_run=True, **harness.install_kwargs())
            self.assertFalse(harness.layout.config_file.exists())
            self.assertFalse(harness.layout.systemd_dir.exists())
            self.assertEqual(harness.commands, [])

            with patch("sys.stdout", io.StringIO()):
                service_module.service_install(**harness.install_kwargs())
            self.assertIn(f"{CONFIG_SCHEMA_ENV}=1", harness.current_config())
            for name in SERVICE_NAMES:
                self.assertTrue((harness.layout.systemd_dir / name).exists())

            from pihole_ai.status import configuration_status

            config_status = configuration_status(str(harness.layout.config_file))
            self.assertTrue(config_status["valid"])
            self.assertEqual(config_status["schema_status"], "current")
            self.assertFalse(config_status["migration_required"])

            commands = harness.commands
            daemon_reload_index = commands.index(["systemctl", "daemon-reload"])
            enable_index = commands.index(["systemctl", "enable", *ENABLE_UNIT_NAMES])
            start_index = commands.index(["systemctl", "start", *START_ORDER])
            self.assertLess(daemon_reload_index, enable_index)
            self.assertLess(enable_index, start_index)

            harness.commands.clear()
            with patch(
                "pihole_ai.service.build_install_plan",
                return_value=type(
                    "Plan",
                    (),
                    {"layout": harness.layout, "project_dir": harness.project_dir},
                )(),
            ), patch("sys.stdout", io.StringIO()):
                service_module.service_enable()
                service_module.service_action("start")
            self.assertEqual(
                harness.commands,
                [
                    ["systemctl", "enable", *ENABLE_UNIT_NAMES],
                    *[["systemctl", "start", name] for name in START_ORDER],
                ],
            )

    def test_invalid_config_blocks_install_enable_start_and_restart_without_mutation(self):
        with ApplianceConfigHarness(self) as harness:
            harness.write_config(f"{CONFIG_SCHEMA_ENV}=1\nPIHOLE_AI_DASHBOARD_PORT=99999\n")

            with patch("sys.stdout", io.StringIO()):
                with self.assertRaises(ServiceError):
                    service_module.service_install(**harness.install_kwargs())
            self.assertFalse(harness.layout.systemd_dir.exists())
            self.assertEqual(harness.commands, [])

            invalid_report = service_module.ConfigLifecycleReport(
                exists=True,
                schema_version=1,
                status="invalid",
                migration_required=False,
                config_file=str(harness.layout.config_file),
                errors=[
                    {
                        "code": "config.validation.invalid_port",
                        "key": "PIHOLE_AI_DASHBOARD_PORT",
                        "message": "Invalid port.",
                    }
                ],
            )
            with patch(
                "pihole_ai.service.build_install_plan",
                return_value=type(
                    "Plan",
                    (),
                    {"layout": harness.layout, "project_dir": harness.project_dir},
                )(),
            ), patch(
                "pihole_ai.service._configuration_lifecycle_report",
                return_value=invalid_report,
            ), patch(
                "pihole_ai.service.lifecycle_lock",
                return_value=__import__("contextlib").nullcontext(),
            ), patch("sys.stdout", io.StringIO()):
                for operation in (
                    service_module.service_enable,
                    lambda: service_module.service_action("start"),
                    lambda: service_module.service_action("restart"),
                ):
                    with self.subTest(operation=operation):
                        with self.assertRaises(ServiceError):
                            operation()

            self.assertEqual(harness.commands, [])
            from pihole_ai.status import configuration_status

            status = configuration_status(str(harness.layout.config_file))
            self.assertEqual(status["last_validation_status"], "invalid")

            _app, client = harness.app_client()
            api = client.get("/api/config")
            self.assertIn(api.status_code, {200, 409})
            html = client.get("/settings").get_data(as_text=True)
            self.assertIn("settings", html)

    def test_install_failure_during_config_creation_prevents_unit_creation(self):
        with ApplianceConfigHarness(self) as harness:
            with patch(
                "pihole_ai.service._atomic_write_managed",
                side_effect=OSError("write failed"),
            ), patch("sys.stdout", io.StringIO()):
                with self.assertRaises(OSError):
                    service_module.service_install(**harness.install_kwargs())

            self.assertFalse(harness.layout.systemd_dir.exists())
            self.assertNotIn(["systemctl", "daemon-reload"], harness.commands)

    def test_uninstall_config_preservation_and_reinstall_paths(self):
        with ApplianceConfigHarness(self) as harness:
            with patch("sys.stdout", io.StringIO()):
                service_module.service_install(
                    enable_services=False,
                    start_services=False,
                    **harness.install_kwargs(),
                )
            original = harness.current_config() + "UNKNOWN_KEEP=value\n"
            harness.layout.config_file.write_text(original, encoding="utf-8")

            with patch("sys.stdout", io.StringIO()):
                service_module.service_uninstall(**harness.uninstall_kwargs())
            self.assertEqual(harness.current_config(), original)

            with patch("sys.stdout", io.StringIO()):
                service_module.service_install(
                    enable_services=False,
                    start_services=False,
                    **harness.install_kwargs(),
                )
            self.assertIn("UNKNOWN_KEEP=value", harness.current_config())

            with patch("sys.stdout", io.StringIO()):
                service_module.service_uninstall(
                    remove_config=True,
                    keep_config=False,
                    **harness.uninstall_kwargs(),
                )
            self.assertFalse(harness.layout.config_file.exists())

            with patch("sys.stdout", io.StringIO()):
                service_module.service_install(
                    enable_services=False,
                    start_services=False,
                    **harness.install_kwargs(),
                )
            self.assertIn(f"{CONFIG_SCHEMA_ENV}=1", harness.current_config())
            self.assertNotIn("UNKNOWN_KEEP=value", harness.current_config())

    def test_partial_installation_recovery_preserves_valid_config(self):
        with ApplianceConfigHarness(self) as harness:
            preserved = f"{CONFIG_SCHEMA_ENV}=1\nUNKNOWN_KEEP=value\n"
            harness.write_config(preserved)
            harness.layout.systemd_dir.mkdir(parents=True)
            (harness.layout.systemd_dir / SERVICE_NAMES[0]).write_text(
                service_module.MANAGED_FILE_HEADER + "partial\n",
                encoding="utf-8",
            )

            with patch("sys.stdout", io.StringIO()):
                service_module.service_install(
                    enable_services=False,
                    start_services=False,
                    **harness.install_kwargs(),
                )

            self.assertIn("UNKNOWN_KEEP=value", harness.current_config())
            for name in SERVICE_NAMES:
                self.assertTrue((harness.layout.systemd_dir / name).exists())

    def test_malformed_unit_destination_blocks_without_deleting_config(self):
        with ApplianceConfigHarness(self) as harness:
            config = f"{CONFIG_SCHEMA_ENV}=1\nUNKNOWN_KEEP=value\n"
            harness.write_config(config)
            harness.layout.systemd_dir.parent.mkdir(parents=True)
            harness.layout.systemd_dir.write_text("not a directory", encoding="utf-8")

            with patch("sys.stdout", io.StringIO()):
                with self.assertRaises(ServiceError):
                    service_module.service_install(**harness.install_kwargs())

            self.assertEqual(harness.current_config(), config)
            self.assertFalse(harness.layout.wrapper_path.exists())


if __name__ == "__main__":
    unittest.main()
