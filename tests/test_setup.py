import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.config import ConfigurationValidationResult, ValidationSeverity
from core.migrations import DatabaseStatus
from pihole_ai import cli
from pihole_ai.health import HealthCheck, HealthReport, HealthStatus
from pihole_ai.service import InstallationStatus
from pihole_ai.setup import (
    PiholeDatabaseCandidate,
    SetupStage,
    detect_pihole_databases,
    evaluate_setup,
    print_setup_status,
    run_setup,
    setup_exit_code,
    update_setup_config,
)


def valid_config(**overrides):
    values = {
        "events_db": Path("/tmp/events.db"),
        "pihole_db": Path("/tmp/pihole-FTL.db"),
        "ai_enabled": True,
        "intel_auto_update_enabled": False,
        "ollama_url": "http://127.0.0.1:11434",
        "ollama_model": "llama3.2:1b",
        "dashboard_host": "0.0.0.0",
        "dashboard_port": 8080,
        "config_file": Path("/etc/pihole-ai/pihole-ai.env"),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def validation_result(errors=0, warnings=0):
    issues = []
    for index in range(errors):
        issues.append(
            SimpleNamespace(
                code=f"error.{index}",
                severity=ValidationSeverity.ERROR.value,
                setting="TEST",
                summary="broken",
                remediation="fix it",
                details={},
            )
        )
    for index in range(warnings):
        issues.append(
            SimpleNamespace(
                code=f"warning.{index}",
                severity=ValidationSeverity.WARNING.value,
                setting="TEST",
                summary="warning",
                remediation="review it",
                details={},
            )
        )
    return ConfigurationValidationResult(mode="runtime", issues=issues)


def dashboard_non_loopback_warning_result():
    return ConfigurationValidationResult(
        mode="runtime",
        issues=[
            SimpleNamespace(
                code="config.dashboard.non_loopback_bind",
                severity=ValidationSeverity.WARNING.value,
                setting="PIHOLE_AI_DASHBOARD_HOST",
                summary="Dashboard binds outside loopback.",
                remediation="Restrict network access.",
                details={},
            )
        ],
    )


def install_status(
    state="installed",
    active=True,
    *,
    inactive_unit: str | None = None,
    timer_active: bool = True,
    timer_enabled: bool = True,
    oneshot_active: str = "inactive",
    oneshot_result: str = "success",
):
    units = {}
    for name in (
        "pihole-ai-collector.service",
        "pihole-ai-engine.service",
        "pihole-ai-dashboard.service",
    ):
        units[name] = {
            "path": f"/etc/systemd/system/{name}",
            "exists": state == "installed",
            "managed": state == "installed",
            "drifted": False,
            "role": "daemon",
            "active": "inactive" if name == inactive_unit else "active" if active else "inactive",
            "enabled": "enabled",
            "result": "",
        }
    units["pihole-ai-intel-update.timer"] = {
        "path": "/etc/systemd/system/pihole-ai-intel-update.timer",
        "exists": state == "installed",
        "managed": state == "installed",
        "drifted": False,
        "role": "timer",
        "active": "active" if timer_active else "inactive",
        "enabled": "enabled" if timer_enabled else "disabled",
        "result": "",
    }
    units["pihole-ai-intel-update.service"] = {
        "path": "/etc/systemd/system/pihole-ai-intel-update.service",
        "exists": state == "installed",
        "managed": state == "installed",
        "drifted": False,
        "role": "oneshot",
        "active": oneshot_active,
        "enabled": "static",
        "result": oneshot_result,
    }
    return InstallationStatus(
        state=state,
        managed=state == "installed",
        version="0.4",
        service_user="pihole-ai",
        service_group="pihole-ai",
        config_file="/etc/pihole-ai/pihole-ai.env",
        data_dir="/var/lib/pihole-ai",
        events_db="/var/lib/pihole-ai/events.db",
        unit_files=units,
        database={"compatible": True},
        legacy={"detected": False},
    )


def health_report(
    *,
    events=HealthStatus.HEALTHY.value,
    pihole=HealthStatus.HEALTHY.value,
    ollama=HealthStatus.HEALTHY.value,
    overall=HealthStatus.HEALTHY.value,
):
    checks = [
        HealthCheck("configuration", HealthStatus.HEALTHY.value, "Configuration loaded.", {}, 1, 1),
        HealthCheck("events_database", events, "Events database status.", {}, 1, 1),
        HealthCheck("pihole_ftl_database", pihole, "Pi-hole database status.", {}, 1, 1),
        HealthCheck("disk_space", HealthStatus.HEALTHY.value, "Disk ok.", {}, 1, 1),
        HealthCheck("ollama", ollama, "Ollama status.", {}, 1, 1),
    ]
    return HealthReport(overall, checks, "0.4", 1)


def db_status(pending=0):
    return DatabaseStatus(
        database_path="/var/lib/pihole-ai/events.db",
        current_schema_version=1,
        latest_supported_schema_version=1,
        pending_migration_count=pending,
        database_file_size=100,
        compatible=True,
    )


def valid_candidate(path="/tmp/pihole-FTL.db"):
    return PiholeDatabaseCandidate(
        path=path,
        exists=True,
        readable=True,
        regular_file=True,
        service_user_accessible=True,
    )


class SetupStateTests(unittest.TestCase):
    def evaluate_with(
        self,
        *,
        status=None,
        config=None,
        result=None,
        health=None,
        candidates=None,
        database=None,
    ):
        with (
            patch("pihole_ai.setup.installation_status", return_value=status or install_status()),
            patch("pihole_ai.setup.load_config_with_result", return_value=(config or valid_config(), result or validation_result())),
            patch("pihole_ai.setup.run_health_checks", return_value=health or health_report()),
            patch("pihole_ai.setup.detect_pihole_databases", return_value=[valid_candidate()] if candidates is None else candidates),
            patch("pihole_ai.setup.database_status", return_value=database or db_status()),
        ):
            return evaluate_setup()

    def test_fully_ready_installation(self):
        report = self.evaluate_with()
        self.assertTrue(report.ready)
        self.assertEqual(report.overall_stage, SetupStage.READY.value)
        self.assertEqual(setup_exit_code(report), 0)

    def test_not_installed(self):
        report = self.evaluate_with(status=install_status(state="not_installed"))
        self.assertFalse(report.ready)
        self.assertEqual(report.overall_stage, SetupStage.NOT_INSTALLED.value)

    def test_invalid_configuration_blocks(self):
        report = self.evaluate_with(result=validation_result(errors=1))
        self.assertEqual(report.overall_stage, SetupStage.BLOCKED.value)
        self.assertEqual(setup_exit_code(report), 2)

    def test_missing_pihole_database_blocks(self):
        report = self.evaluate_with(candidates=[])
        self.assertEqual(report.overall_stage, SetupStage.BLOCKED.value)
        self.assertEqual(self._step(report, "pihole_database").status, "blocked")

    def test_unsupported_schema_blocks(self):
        from core.migrations import UnsupportedSchemaVersion

        with (
            patch("pihole_ai.setup.installation_status", return_value=install_status()),
            patch("pihole_ai.setup.load_config_with_result", return_value=(valid_config(), validation_result())),
            patch("pihole_ai.setup.run_health_checks", return_value=health_report()),
            patch("pihole_ai.setup.detect_pihole_databases", return_value=[valid_candidate()]),
            patch("pihole_ai.setup.database_status", side_effect=UnsupportedSchemaVersion("newer")),
        ):
            report = evaluate_setup()
        self.assertEqual(report.overall_stage, SetupStage.BLOCKED.value)
        self.assertEqual(self._step(report, "database_schema").status, "blocked")

    def test_pending_schema_migration_blocks_with_upgrade_guidance(self):
        report = self.evaluate_with(database=db_status(pending=1))

        self.assertEqual(report.overall_stage, SetupStage.BLOCKED.value)
        schema = self._step(report, "database_schema")
        self.assertEqual(schema.status, "pending")
        self.assertEqual(schema.remediation, "Run: sudo pihole-ai upgrade")

    def test_inactive_service_blocks(self):
        report = self.evaluate_with(status=install_status(active=False))
        self.assertEqual(report.overall_stage, SetupStage.BLOCKED.value)
        self.assertEqual(self._step(report, "services").status, "blocked")

    def test_successful_inactive_updater_oneshot_does_not_block_readiness(self):
        report = self.evaluate_with(
            result=dashboard_non_loopback_warning_result(),
            health=health_report(overall=HealthStatus.DEGRADED.value),
            status=install_status(
                timer_active=True,
                timer_enabled=True,
                oneshot_active="inactive",
                oneshot_result="success",
            ),
        )

        self.assertEqual(report.overall_stage, SetupStage.DEGRADED.value)
        self.assertTrue(report.ready)
        self.assertEqual(setup_exit_code(report), 0)
        self.assertEqual(self._step(report, "services").status, "complete")

    def test_inactive_collector_blocks_readiness(self):
        report = self.evaluate_with(
            status=install_status(inactive_unit="pihole-ai-collector.service")
        )
        self.assertEqual(report.overall_stage, SetupStage.BLOCKED.value)
        self.assertFalse(report.ready)
        self.assertEqual(self._step(report, "services").status, "blocked")

    def test_inactive_engine_blocks_readiness(self):
        report = self.evaluate_with(
            status=install_status(inactive_unit="pihole-ai-engine.service")
        )
        self.assertEqual(report.overall_stage, SetupStage.BLOCKED.value)
        self.assertFalse(report.ready)
        self.assertEqual(self._step(report, "services").status, "blocked")

    def test_inactive_dashboard_blocks_readiness(self):
        report = self.evaluate_with(
            status=install_status(inactive_unit="pihole-ai-dashboard.service")
        )
        self.assertEqual(report.overall_stage, SetupStage.BLOCKED.value)
        self.assertFalse(report.ready)
        self.assertEqual(self._step(report, "services").status, "blocked")

    def test_disabled_timer_with_auto_update_enabled_degrades_but_does_not_block(self):
        report = self.evaluate_with(
            config=valid_config(intel_auto_update_enabled=True),
            status=install_status(timer_active=False, timer_enabled=False),
        )

        self.assertEqual(report.overall_stage, SetupStage.DEGRADED.value)
        self.assertTrue(report.ready)
        self.assertEqual(self._step(report, "services").status, "warning")

    def test_disabled_timer_with_auto_update_disabled_does_not_block(self):
        report = self.evaluate_with(
            config=valid_config(intel_auto_update_enabled=False),
            status=install_status(timer_active=False, timer_enabled=False),
        )

        self.assertTrue(report.ready)
        self.assertEqual(self._step(report, "services").status, "complete")

    def test_failed_updater_oneshot_degrades_but_does_not_block(self):
        report = self.evaluate_with(
            status=install_status(oneshot_active="failed", oneshot_result="exit-code"),
        )

        self.assertEqual(report.overall_stage, SetupStage.DEGRADED.value)
        self.assertTrue(report.ready)
        services = self._step(report, "services")
        self.assertEqual(services.status, "warning")
        self.assertIn("journalctl -u pihole-ai-intel-update.service", services.remediation)

    def test_ollama_unavailable_is_degraded_not_blocked(self):
        report = self.evaluate_with(
            health=health_report(
                ollama=HealthStatus.DEGRADED.value,
                overall=HealthStatus.DEGRADED.value,
            )
        )
        self.assertEqual(report.overall_stage, SetupStage.DEGRADED.value)
        self.assertTrue(report.ready)
        self.assertEqual(setup_exit_code(report), 0)
        self.assertEqual(self._step(report, "ollama").status, "warning")

    def test_warning_only_configuration_is_degraded_ready_not_unconfigured(self):
        report = self.evaluate_with(
            result=validation_result(warnings=1),
            health=health_report(overall=HealthStatus.DEGRADED.value),
        )

        self.assertEqual(report.overall_stage, SetupStage.DEGRADED.value)
        self.assertTrue(report.ready)
        self.assertTrue(report.has_warnings)
        self.assertEqual(report.warning_count, 2)
        self.assertEqual(report.blocking_issue_count, 0)
        configuration = self._step(report, "configuration")
        self.assertEqual(configuration.status, "warning")
        self.assertTrue(configuration.complete)

    def test_required_health_failure_blocks(self):
        report = self.evaluate_with(
            health=health_report(
                events=HealthStatus.UNHEALTHY.value,
                overall=HealthStatus.UNHEALTHY.value,
            )
        )
        self.assertEqual(report.overall_stage, SetupStage.BLOCKED.value)

    def test_readiness_is_derived_each_time(self):
        first = self.evaluate_with()
        second = self.evaluate_with(status=install_status(active=False))
        self.assertTrue(first.ready)
        self.assertFalse(second.ready)

    def test_setup_uses_shared_subsystems(self):
        with (
            patch("pihole_ai.setup.installation_status", return_value=install_status()) as install,
            patch("pihole_ai.setup.load_config_with_result", return_value=(valid_config(), validation_result())) as config,
            patch("pihole_ai.setup.run_health_checks", return_value=health_report()) as health,
            patch("pihole_ai.setup.database_status", return_value=db_status()) as migration,
            patch("pihole_ai.setup.detect_pihole_databases", return_value=[valid_candidate()]),
        ):
            evaluate_setup()
        install.assert_called_once()
        config.assert_called()
        health.assert_called_once()
        migration.assert_called_once()

    def _step(self, report, step_id):
        return next(step for step in report.steps if step.id == step_id)


class SetupCliTests(unittest.TestCase):
    def test_status_text_output(self):
        report = SetupStateTests().evaluate_with()
        with patch("pihole_ai.setup.evaluate_setup", return_value=report):
            output = io.StringIO()
            with redirect_stdout(output):
                code = print_setup_status()
        self.assertEqual(code, 0)
        self.assertIn("PiHole-AI setup: ready", output.getvalue())

    def test_status_json_output(self):
        report = SetupStateTests().evaluate_with()
        with patch("pihole_ai.setup.evaluate_setup", return_value=report):
            output = io.StringIO()
            with redirect_stdout(output):
                code = print_setup_status(as_json=True)
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())["ready"])

    def test_cli_dispatches_setup_status(self):
        with patch("pihole_ai.setup.print_setup_status", return_value=1) as status:
            code = cli.main(["setup", "status", "--json"])
        self.assertEqual(code, 1)
        status.assert_called_once_with(as_json=True, skip_ollama_check=False)

    def test_non_interactive_never_prompts(self):
        report = SetupStateTests().evaluate_with()
        with (
            patch("pihole_ai.setup.evaluate_setup", return_value=report),
            patch("builtins.input", side_effect=AssertionError("prompted")),
        ):
            with redirect_stdout(io.StringIO()):
                code = run_setup(non_interactive=True)
        self.assertEqual(code, 0)

    def test_non_interactive_mutation_requires_flags(self):
        report = SetupStateTests().evaluate_with()
        with (
            patch("pihole_ai.setup.evaluate_setup", return_value=report),
            patch("pihole_ai.setup.service_install") as install,
            patch("pihole_ai.setup.service_action") as action,
            patch("pihole_ai.setup.service_enable") as enable,
        ):
            with redirect_stdout(io.StringIO()):
                run_setup(non_interactive=True)
        install.assert_not_called()
        action.assert_not_called()
        enable.assert_not_called()

    def test_dry_run_performs_no_mutations(self):
        report = SetupStateTests().evaluate_with()
        with (
            patch("pihole_ai.setup.evaluate_setup", return_value=report),
            patch("pihole_ai.setup.service_install") as install,
            patch("pihole_ai.setup.service_action") as action,
        ):
            with redirect_stdout(io.StringIO()):
                run_setup(non_interactive=True, dry_run=True, install=True, start=True)
        install.assert_not_called()
        action.assert_not_called()

    def test_blocking_failure_prevents_later_actions(self):
        report = SetupStateTests().evaluate_with(result=validation_result(errors=1))
        with (
            patch("pihole_ai.setup.evaluate_setup", return_value=report),
            patch("pihole_ai.setup.service_install") as install,
        ):
            with redirect_stdout(io.StringIO()):
                code = run_setup(non_interactive=True, install=True)
        self.assertEqual(code, 2)
        install.assert_not_called()

    def test_interactive_accepts_valid_defaults_and_deterministic_mode(self):
        report = SetupStateTests().evaluate_with(config=valid_config(ai_enabled=True))
        with (
            patch("pihole_ai.setup.evaluate_setup", return_value=report),
            patch("pihole_ai.setup.detect_pihole_databases", return_value=[]),
            patch("builtins.input", side_effect=["n", "", "", ""]),
            patch("pihole_ai.setup.update_setup_config") as update_config,
            patch("pihole_ai.setup.service_install") as install,
        ):
            with redirect_stdout(io.StringIO()):
                code = run_setup(dry_run=True)
        self.assertEqual(code, 0)
        update_config.assert_not_called()
        install.assert_not_called()


class SetupConfigWriterTests(unittest.TestCase):
    def test_atomic_replacement_backup_and_preserves_unknown_lines(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pihole-ai.env"
            path.write_text(
                "\n".join(
                    [
                        "# keep",
                        "UNKNOWN=yes",
                        "AI_ENABLED=true",
                        "PIHOLE_AI_DASHBOARD_AUTH_ENABLED=true",
                        "PIHOLE_AI_DASHBOARD_PASSWORD_HASH=scrypt:32768:8:1$salt$hash",
                        f"PIHOLE_AI_DASHBOARD_SECRET_KEY={'x' * 48}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            os.chmod(path, 0o640)

            update_setup_config({"AI_ENABLED": False}, path=path)

            content = path.read_text(encoding="utf-8")
            self.assertIn("# keep", content)
            self.assertIn("UNKNOWN=yes", content)
            self.assertIn("AI_ENABLED=false", content)
            self.assertTrue(path.with_suffix(".env.bak").exists())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_appliance_config_update_repairs_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pihole-ai.env"
            path.write_text(
                "\n".join(
                    [
                        "AI_ENABLED=true",
                        "PIHOLE_AI_DASHBOARD_AUTH_ENABLED=true",
                        "PIHOLE_AI_DASHBOARD_PASSWORD_HASH=scrypt:32768:8:1$salt$hash",
                        f"PIHOLE_AI_DASHBOARD_SECRET_KEY={'x' * 48}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with patch("pihole_ai.setup.CONFIG_FILE", path), patch(
                "pihole_ai.setup._repair_config_permissions",
            ) as repair:
                update_setup_config({"AI_ENABLED": False}, path=path)

            repair.assert_called_once_with(
                config_dir=path.parent,
                env_file=path,
                group="pihole-ai",
                dry_run=False,
            )

    def test_invalid_proposed_config_is_not_installed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pihole-ai.env"
            path.write_text("AI_ENABLED=true\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                update_setup_config({"AI_TIMEOUT_SECONDS": "bad"}, path=path)

            self.assertEqual(path.read_text(encoding="utf-8"), "AI_ENABLED=true\n")

    def test_rejects_unsupported_settings_and_secret_urls(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pihole-ai.env"
            with self.assertRaises(ValueError):
                update_setup_config({"SECRET": "x"}, path=path)
            with self.assertRaises(ValueError):
                update_setup_config(
                    {"PIHOLE_AI_OLLAMA_URL": "http://user:pass@example.test"},
                    path=path,
                )


class PiholeDetectionTests(unittest.TestCase):
    def test_configured_path_preferred_and_common_path_deduped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "pihole-FTL.db"
            db.write_text("", encoding="utf-8")
            candidates = detect_pihole_databases(
                configured_path=db,
                common_paths=[db],
            )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].path, str(db))

    def test_common_path_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "pihole-FTL.db"
            db.write_text("", encoding="utf-8")
            with patch("pihole_ai.setup.load_config_with_result", return_value=(None, validation_result())):
                candidates = detect_pihole_databases(common_paths=[db])
        self.assertTrue(candidates[0].exists)
        self.assertTrue(candidates[0].regular_file)

    def test_unreadable_candidate_rejected_without_permission_mutation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "pihole-FTL.db"
            db.write_text("", encoding="utf-8")
            before = stat.S_IMODE(db.stat().st_mode)
            with patch("pihole_ai.setup.os.access", return_value=False):
                candidate = detect_pihole_databases(
                    configured_path=db,
                    common_paths=[],
                )[0]
            self.assertFalse(candidate.readable)
            self.assertEqual(stat.S_IMODE(db.stat().st_mode), before)

    def test_multiple_candidates_can_be_ambiguous(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = Path(tmpdir) / "one.db"
            second = Path(tmpdir) / "two.db"
            first.write_text("", encoding="utf-8")
            second.write_text("", encoding="utf-8")
            candidates = detect_pihole_databases(
                configured_path=first,
                common_paths=[second],
            )
        self.assertEqual(len(candidates), 2)
