import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ui.dashboard import AUTH_SESSION_KEY
from ui.dashboard import CSRF_SESSION_KEY
from ui.dashboard import create_app


class DashboardConfigAPITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config_file = self.root / "pihole-ai.env"
        self.project_root = self.root / "project"
        self.project_root.mkdir()
        self.config_file.write_text(
            "PIHOLE_AI_OLLAMA_MODEL=llama3.2:1b\n"
            "PIHOLE_AI_DASHBOARD_SECRET_KEY=super-secret-session-key\n",
            encoding="utf-8",
        )
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.patches = [
            patch("ui.dashboard.SETTINGS_ENV_PATH", self.config_file),
            patch("core.config_operations.runtime_config.PROJECT_ROOT", self.project_root),
            patch("core.config_operations.runtime_config.CONFIG_FILE", self.config_file),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.app = create_app()
        self.app.config.update(TESTING=True)
        self.app.config["PIHOLE_AI_DISABLE_AUTH_FOR_TESTS"] = True
        self.client = self.app.test_client()

    def revision(self) -> str:
        return self.client.get("/api/config").get_json()["revision"]

    def authenticated_client(self):
        self.app.config["PIHOLE_AI_DISABLE_AUTH_FOR_TESTS"] = False
        client = self.app.test_client()
        with client.session_transaction() as session:
            session[AUTH_SESSION_KEY] = True
            session[CSRF_SESSION_KEY] = "csrf-token"
        return client

    def test_get_config_returns_ordered_masked_inventory_and_headers(self) -> None:
        response = self.client.get("/api/config")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["schema_version"], 1)
        self.assertTrue(payload["revision"].startswith("sha256:"))
        keys = [item["key"] for item in payload["settings"]]
        self.assertEqual(keys, sorted(keys, key=keys.index))
        secret = next(item for item in payload["settings"] if item["key"] == "dashboard_secret_key")
        self.assertTrue(secret["configured"])
        self.assertTrue(secret["masked"])
        self.assertIsNone(secret["value"])
        model = next(item for item in payload["settings"] if item["key"] == "ollama_model")
        self.assertEqual(model["type"], "ollama_model")
        self.assertIn("allowed_values", model)
        threshold = next(item for item in payload["settings"] if item["key"] == "high_risk_threshold")
        self.assertEqual(threshold["minimum"], 0)
        self.assertEqual(threshold["maximum"], 100)
        self.assertEqual(response.headers["Pragma"], "no-cache")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_get_config_category_filter_and_invalid_filter(self) -> None:
        response = self.client.get("/api/config?category=Dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["settings"])
        self.assertTrue(
            all(item["category"] == "Dashboard" for item in response.get_json()["settings"])
        )

        bad = self.client.get("/api/config?category=NotAThing")
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.get_json()["error"]["code"], "invalid_config_filter")

    def test_auth_and_csrf_are_enforced_for_config_api(self) -> None:
        revision = self.revision()
        client = self.authenticated_client()

        with client.session_transaction() as session:
            session.clear()
        unauthenticated = client.get("/api/config")
        self.assertEqual(unauthenticated.status_code, 401)

        client = self.authenticated_client()
        missing_csrf = client.put(
            "/api/config",
            json={
                "revision": revision,
                "changes": {"ollama_model": "llama3.2:3b"},
            },
        )
        self.assertEqual(missing_csrf.status_code, 403)

        allowed = client.put(
            "/api/config",
            headers={"X-CSRF-Token": "csrf-token"},
            json={
                "revision": revision,
                "changes": {"ollama_model": "llama3.2:3b"},
                "dry_run": True,
            },
        )
        self.assertEqual(allowed.status_code, 200)

    def test_validate_is_dry_run_and_rejects_bad_changes(self) -> None:
        original = self.config_file.read_text(encoding="utf-8")
        response = self.client.post(
            "/api/config/validate",
            json={
                "revision": self.revision(),
                "changes": {"OLLAMA_MODEL": "llama3.2:3b"},
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["changed"])
        self.assertTrue(payload["dry_run"])
        self.assertFalse(payload["written"])
        self.assertEqual(payload["affected_services"], ["pihole-ai-engine.service"])
        self.assertEqual(self.config_file.read_text(encoding="utf-8"), original)

        duplicate = self.client.post(
            "/api/config/validate",
            json={
                "revision": self.revision(),
                "changes": {
                    "ollama_model": "a",
                    "PIHOLE_AI_OLLAMA_MODEL": "b",
                },
            },
        )
        self.assertEqual(duplicate.status_code, 400)
        self.assertEqual(duplicate.get_json()["error"]["code"], "duplicate_config_key")

        unknown = self.client.post(
            "/api/config/validate",
            json={"revision": self.revision(), "changes": {"NOPE": "value"}},
        )
        self.assertEqual(unknown.status_code, 400)
        self.assertEqual(unknown.get_json()["error"]["code"], "unknown_config_key")

        empty = self.client.post(
            "/api/config/validate",
            json={"revision": self.revision(), "changes": {}},
        )
        self.assertEqual(empty.status_code, 400)
        self.assertEqual(empty.get_json()["error"]["code"], "empty_change_set")

    def test_secret_placeholder_is_rejected_and_real_secret_is_never_returned(self) -> None:
        placeholder = self.client.post(
            "/api/config/validate",
            json={
                "revision": self.revision(),
                "changes": {
                    "dashboard_secret_key": {
                        "operation": "replace",
                        "value": "********",
                    }
                },
            },
        )
        self.assertEqual(placeholder.status_code, 400)
        self.assertEqual(
            placeholder.get_json()["error"]["code"],
            "masked_secret_placeholder_rejected",
        )

        secret = "new-secret-value-that-is-long-enough"
        response = self.client.put(
            "/api/config",
            json={
                "revision": self.revision(),
                "changes": {
                    "dashboard_secret_key": {
                        "operation": "replace",
                        "value": secret,
                    }
                },
                "dry_run": True,
            },
        )
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(secret, body)

    def test_put_writes_partial_update_and_creates_backup(self) -> None:
        old_revision = self.revision()
        response = self.client.put(
            "/api/config",
            json={
                "revision": old_revision,
                "changes": {"ollama_model": "llama3.2:3b"},
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["changed"])
        self.assertTrue(payload["written"])
        self.assertNotEqual(payload["revision"], old_revision)
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=llama3.2:3b", self.config_file.read_text(encoding="utf-8"))
        self.assertTrue(self.config_file.with_suffix(".env.bak").exists())

    def test_put_dry_run_and_stale_revision_do_not_write(self) -> None:
        old_revision = self.revision()
        dry = self.client.put(
            "/api/config",
            json={
                "revision": old_revision,
                "changes": {"ollama_model": "llama3.2:3b"},
                "dry_run": True,
            },
        )
        self.assertEqual(dry.status_code, 200)
        self.assertFalse(dry.get_json()["written"])
        self.assertIn("llama3.2:1b", self.config_file.read_text(encoding="utf-8"))
        self.assertFalse(self.config_file.with_suffix(".env.bak").exists())

        self.config_file.write_text("PIHOLE_AI_OLLAMA_MODEL=external\n", encoding="utf-8")
        stale = self.client.put(
            "/api/config",
            json={
                "revision": old_revision,
                "changes": {"ollama_model": "new"},
            },
        )
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.get_json()["error"]["code"], "configuration_revision_conflict")
        self.assertIn("external", self.config_file.read_text(encoding="utf-8"))

    def test_put_unset_removes_key_without_implicit_restart(self) -> None:
        with patch("core.config_operations.service_control.restart_services") as restart:
            response = self.client.put(
                "/api/config",
                json={
                    "revision": self.revision(),
                    "changes": {"ollama_model": {"operation": "unset"}},
                },
            )

        self.assertEqual(response.status_code, 200)
        restart.assert_not_called()
        self.assertNotIn("PIHOLE_AI_OLLAMA_MODEL=", self.config_file.read_text(encoding="utf-8"))

    def test_restart_failure_does_not_roll_back_written_config(self) -> None:
        class Result:
            service = "pihole-ai-engine.service"
            success = False

            def to_dict(self):
                return {
                    "service": self.service,
                    "success": self.success,
                    "error": "boom",
                }

        with patch(
            "core.config_operations.service_control.restart_services",
            return_value=[Result()],
        ):
            response = self.client.put(
                "/api/config",
                json={
                    "revision": self.revision(),
                    "changes": {"ollama_model": "llama3.2:3b"},
                    "restart": True,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["written"])
        self.assertTrue(payload["restart_attempted"])
        self.assertFalse(payload["restart_success"])
        self.assertIn("llama3.2:3b", self.config_file.read_text(encoding="utf-8"))

    def test_impact_dedupes_keys_and_does_not_restart_services(self) -> None:
        with patch("core.config_operations.service_control.restart_services") as restart:
            response = self.client.get(
                "/api/config/impact?key=OLLAMA_MODEL&key=ollama_model&key=dashboard_port"
            )

        self.assertEqual(response.status_code, 200)
        restart.assert_not_called()
        self.assertEqual(response.get_json()["keys"], ["ollama_model", "dashboard_port"])
        self.assertEqual(
            response.get_json()["affected_services"],
            ["pihole-ai-engine.service", "pihole-ai-dashboard.service"],
        )

        bad = self.client.get("/api/config/impact?key=NOPE")
        self.assertEqual(bad.status_code, 400)

    def test_export_json_and_env_exclude_secrets_and_secure_api_export_is_rejected(self) -> None:
        response = self.client.get("/api/config/export?format=json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment; filename=pihole-ai-config.json", response.headers["Content-Disposition"])
        payload = response.get_json()
        self.assertNotIn("dashboard_secret_key", [item["key"] for item in payload["settings"]])
        self.assertNotIn("super-secret-session-key", response.get_data(as_text=True))

        env = self.client.get("/api/config/export?format=env")
        self.assertEqual(env.status_code, 200)
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=", env.get_data(as_text=True))
        self.assertNotIn("super-secret-session-key", env.get_data(as_text=True))

        secure = self.client.get("/api/config/export?secure=true")
        self.assertEqual(secure.status_code, 403)
        self.assertEqual(secure.get_json()["error"]["code"], "secure_export_cli_only")

    def test_import_supports_dry_run_strict_mode_and_persistent_write(self) -> None:
        import_content = json.dumps(
            {
                "schema_version": 1,
                "settings": [
                    {"key": "ollama_model", "value": "imported-model"},
                    {"key": "UNKNOWN_IMPORT", "value": "ignored"},
                ],
            }
        )
        dry = self.client.post(
            "/api/config/import",
            json={
                "revision": self.revision(),
                "format": "json",
                "content": import_content,
                "dry_run": True,
            },
        )

        self.assertEqual(dry.status_code, 200)
        self.assertFalse(dry.get_json()["written"])
        self.assertIn("Unknown import setting ignored", dry.get_json()["warnings"][0])
        self.assertIn("llama3.2:1b", self.config_file.read_text(encoding="utf-8"))

        strict = self.client.post(
            "/api/config/import",
            json={
                "revision": self.revision(),
                "format": "json",
                "content": import_content,
                "strict": True,
            },
        )
        self.assertEqual(strict.status_code, 400)
        self.assertEqual(strict.get_json()["error"]["code"], "unknown_config_key")

        written = self.client.post(
            "/api/config/import",
            json={
                "revision": self.revision(),
                "format": "env",
                "content": "PIHOLE_AI_OLLAMA_MODEL=from-env\n",
            },
        )
        self.assertEqual(written.status_code, 200)
        self.assertTrue(written.get_json()["written"])
        self.assertIn("PIHOLE_AI_OLLAMA_MODEL=from-env", self.config_file.read_text(encoding="utf-8"))

    def test_import_rejects_large_or_malformed_payloads(self) -> None:
        too_large = self.client.post(
            "/api/config/import",
            json={
                "revision": self.revision(),
                "format": "env",
                "content": "A=" + ("x" * (65 * 1024)),
            },
        )
        self.assertEqual(too_large.status_code, 413)

        malformed = self.client.post(
            "/api/config/import",
            json={
                "revision": self.revision(),
                "format": "json",
                "content": "{",
            },
        )
        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(malformed.get_json()["error"]["code"], "malformed_json")
