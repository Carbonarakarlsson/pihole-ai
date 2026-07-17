import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ui.dashboard import AUTH_SESSION_KEY
from ui.dashboard import CSRF_SESSION_KEY
from ui.dashboard import create_app


class DashboardSettingsPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config_file = self.root / "pihole-ai.env"
        self.config_file.write_text(
            "PIHOLE_AI_OLLAMA_MODEL=field-test-model\n"
            "PIHOLE_AI_DASHBOARD_SECRET_KEY=raw-secret-that-must-not-render\n",
            encoding="utf-8",
        )
        self.project_root = self.root / "project"
        self.project_root.mkdir()
        patches = [
            patch("ui.dashboard.SETTINGS_ENV_PATH", self.config_file),
            patch("core.config_operations.runtime_config.PROJECT_ROOT", self.project_root),
            patch("core.config_operations.runtime_config.CONFIG_FILE", self.config_file),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def make_app(self, *, auth_disabled: bool = True):
        app = create_app()
        app.config.update(TESTING=True)
        app.config["PIHOLE_AI_DISABLE_AUTH_FOR_TESTS"] = auth_disabled
        return app

    def test_settings_route_renders_config_api_client_without_raw_config(self) -> None:
        app = self.make_app()
        response = app.test_client().get("/settings")

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn('const initialPage = "settings";', html)
        self.assertIn('id="config-status"', html)
        self.assertIn('id="config-categories"', html)
        self.assertIn('id="config-settings"', html)
        self.assertIn("Preview changes", html)
        self.assertIn("Save & Restart", html)
        self.assertIn("Download export", html)
        self.assertIn("Preview import", html)
        self.assertIn("/api/config/validate", html)
        self.assertIn("/api/config/export", html)
        self.assertIn("/api/config/import", html)
        self.assertIn("X-CSRF-Token", html)
        self.assertNotIn("raw-secret-that-must-not-render", html)
        self.assertNotIn("field-test-model", html)

    def test_settings_route_is_authenticated(self) -> None:
        app = self.make_app(auth_disabled=False)
        client = app.test_client()

        response = client.get("/settings")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_authenticated_settings_route_has_csrf_meta_only(self) -> None:
        app = self.make_app(auth_disabled=False)
        client = app.test_client()
        with client.session_transaction() as session:
            session[AUTH_SESSION_KEY] = True
            session[CSRF_SESSION_KEY] = "known-token"

        response = client.get("/settings")

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn('meta name="csrf-token"', html)
        self.assertIn("known-token", html)
        self.assertNotIn("dashboard_password_hash", html)

    def test_home_route_keeps_overview_initial_page_and_navigation_link(self) -> None:
        app = self.make_app()
        response = app.test_client().get("/")

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn('const initialPage = "overview";', html)
        self.assertIn('data-page="settings"', html)
        self.assertIn("Settings", html)

    def test_settings_page_uses_safe_dom_rendering_patterns(self) -> None:
        app = self.make_app()
        html = app.test_client().get("/settings").get_data(as_text=True)

        self.assertIn("textContent", html)
        self.assertIn("createElement", html)
        self.assertNotIn("innerHTML", html)
        self.assertNotIn("eval(", html)
        self.assertNotIn("localStorage", html)
        self.assertNotIn("sessionStorage", html)


if __name__ == "__main__":
    unittest.main()
