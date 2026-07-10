import json
import unittest
from dataclasses import dataclass
from unittest.mock import patch

from pihole_ai import cli
from pihole_ai.doctor import Diagnostic, DoctorReport, run_doctor
from pihole_ai.health import HealthCheck, HealthStatus


@dataclass(frozen=True)
class FakeStatus:
    database_path: str = "/tmp/events.db"
    current_schema_version: int = 1
    latest_supported_schema_version: int = 1
    pending_migration_count: int = 0
    database_file_size: int = 0
    compatible: bool = True


def health_check(
    name: str,
    status: str = HealthStatus.HEALTHY.value,
) -> HealthCheck:
    return HealthCheck(
        name=name,
        status=status,
        summary=f"{name} {status}",
        details={},
        latency_ms=1.0,
        checked_at=1.0,
    )


class DoctorTests(unittest.TestCase):
    def test_doctor_healthy_result(self) -> None:
        with patch("pihole_ai.doctor._configuration_diagnostic", return_value=Diagnostic("configuration", "healthy", "ok", {})), \
             patch("pihole_ai.doctor._database_diagnostic", return_value=Diagnostic("database_schema", "healthy", "ok", {})), \
             patch("pihole_ai.doctor.check_events_database", return_value=health_check("events_database")), \
             patch("pihole_ai.doctor.check_pihole_ftl_database", return_value=health_check("pihole_ftl_database")), \
             patch("pihole_ai.doctor.check_disk_space", return_value=health_check("disk_space")), \
             patch("pihole_ai.doctor.check_ollama", return_value=health_check("ollama")), \
             patch("pihole_ai.doctor._systemd_diagnostic", return_value=Diagnostic("systemd", "healthy", "ok", {})):
            report = run_doctor()

        self.assertEqual(report.overall_status, HealthStatus.HEALTHY.value)

    def test_doctor_degraded_result(self) -> None:
        report = DoctorReport(
            overall_status=HealthStatus.DEGRADED.value,
            diagnostics=[
                Diagnostic("configuration", "degraded", "warn", {}),
            ],
            version="test",
        )

        with patch("pihole_ai.doctor.run_doctor", return_value=report), patch("sys.stdout"):
            exit_code = cli.main(["doctor"])

        self.assertEqual(exit_code, 1)

    def test_doctor_unhealthy_result(self) -> None:
        report = DoctorReport(
            overall_status=HealthStatus.UNHEALTHY.value,
            diagnostics=[
                Diagnostic("configuration", "unhealthy", "bad", {}),
            ],
            version="test",
        )

        with patch("pihole_ai.doctor.run_doctor", return_value=report), patch("sys.stdout"):
            exit_code = cli.main(["doctor"])

        self.assertEqual(exit_code, 2)

    def test_doctor_json_shape(self) -> None:
        report = DoctorReport(
            overall_status=HealthStatus.HEALTHY.value,
            diagnostics=[
                Diagnostic("configuration", "healthy", "ok", {}),
            ],
            version="test",
        )

        with patch("pihole_ai.doctor.run_doctor", return_value=report), patch("sys.stdout") as stdout:
            exit_code = cli.main(["doctor", "--json"])

        self.assertEqual(exit_code, 0)
        written = "".join(call.args[0] for call in stdout.write.call_args_list)
        payload = json.loads(written)
        self.assertEqual(payload["overall_status"], HealthStatus.HEALTHY.value)
        self.assertEqual(payload["diagnostics"][0]["name"], "configuration")

    def test_doctor_does_not_migrate_database(self) -> None:
        with patch("pihole_ai.doctor.database_status", return_value=FakeStatus()) as status, \
             patch("core.migrations.migrate_database") as migrate, \
             patch("pihole_ai.doctor._configuration_diagnostic", return_value=Diagnostic("configuration", "healthy", "ok", {})), \
             patch("pihole_ai.doctor._database_diagnostic", return_value=Diagnostic("database_schema", "healthy", "ok", {})), \
             patch("pihole_ai.doctor.check_events_database", return_value=health_check("events_database")), \
             patch("pihole_ai.doctor.check_pihole_ftl_database", return_value=health_check("pihole_ftl_database")), \
             patch("pihole_ai.doctor.check_disk_space", return_value=health_check("disk_space")), \
             patch("pihole_ai.doctor.check_ollama", return_value=health_check("ollama")), \
             patch("pihole_ai.doctor._systemd_diagnostic", return_value=Diagnostic("systemd", "healthy", "ok", {})):
            run_doctor()

        status.assert_not_called()
        migrate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
