import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from werkzeug.security import check_password_hash, generate_password_hash

from pihole_ai import cli
from ui.dashboard import LOGIN_FAILURES, ROUTE_SECURITY, create_app


def auth_settings(tmp_path: Path | None = None, host: str = "127.0.0.1"):
    return SimpleNamespace(
        config_file=tmp_path or Path("/tmp/pihole-ai.env"),
        dashboard_auth_enabled=True,
        dashboard_username="admin",
        dashboard_password_hash=generate_password_hash("correct-password"),
        dashboard_secret_key="s" * 48,
        dashboard_session_lifetime_minutes=30,
        dashboard_trust_proxy=False,
        dashboard_host=host,
        dashboard_port=8080,
        dashboard_overview_poll_interval_ms=5000,
        dashboard_metrics_poll_interval_ms=15000,
        dashboard_tables_poll_interval_ms=10000,
        dashboard_slow_poll_interval_ms=30000,
        dev_access_logs=False,
        ai_enabled=True,
        ai_max_calls_per_minute=2,
        ai_cooldown_seconds=60,
        ai_timeout_seconds=20,
    )


def csrf_from_html(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


class DashboardSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        LOGIN_FAILURES.clear()
        self.settings = auth_settings()
        patcher = patch("ui.dashboard.settings", self.settings)
        self.addCleanup(patcher.stop)
        patcher.start()
        self.app = create_app()
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def login(self, password: str = "correct-password"):
        response = self.client.get("/login")
        token = csrf_from_html(response.get_data(as_text=True))
        return self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": password,
                "csrf_token": token,
                "next": "/",
            },
            follow_redirects=False,
        )

    def csrf_token(self) -> str:
        response = self.client.get("/")
        html = response.get_data(as_text=True)
        match = re.search(r'<meta name="csrf-token" content="([^"]+)">', html)
        self.assertIsNotNone(match)
        return match.group(1)

    def test_login_page_is_public_and_dashboard_requires_login(self):
        self.assertEqual(self.client.get("/login").status_code, 200)
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_protected_api_returns_json_401(self):
        response = self.client.get("/api/setup")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"], "authentication_required")

    def test_successful_login_sets_secure_session_cookie_attributes(self):
        response = self.login()
        cookie = response.headers["Set-Cookie"]
        self.assertEqual(response.status_code, 302)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        with self.client.session_transaction() as session:
            self.assertTrue(session["authenticated"])
            self.assertEqual(session["username"], "admin")
            self.assertNotIn("correct-password", json.dumps(dict(session)))

    def test_failed_login_is_generic(self):
        response = self.login(password="wrong-password")
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid username or password", response.data)
        self.assertNotIn(b"wrong-password", response.data)

    def test_unsafe_redirect_target_rejected_and_safe_target_accepted(self):
        response = self.client.get("/login?next=https://evil.test/")
        token = csrf_from_html(response.get_data(as_text=True))
        response = self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": "correct-password",
                "csrf_token": token,
                "next": "https://evil.test/",
            },
        )
        self.assertEqual(response.headers["Location"], "/")

        client = self.app.test_client()
        token = csrf_from_html(client.get("/login?next=/api/setup").get_data(as_text=True))
        response = client.post(
            "/login",
            data={
                "username": "admin",
                "password": "correct-password",
                "csrf_token": token,
                "next": "/api/setup",
            },
        )
        self.assertEqual(response.headers["Location"], "/api/setup")

    def test_logout_requires_post_and_csrf_and_clears_session(self):
        self.login()
        self.assertEqual(self.client.get("/logout").status_code, 405)
        self.assertEqual(self.client.post("/logout").status_code, 403)
        token = self.csrf_token()
        response = self.client.post("/logout", headers={"X-CSRF-Token": token})
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertNotIn("authenticated", session)

    def test_write_endpoints_require_csrf_header(self):
        self.login()
        self.assertEqual(self.client.post("/api/feedback", json={}).status_code, 403)
        token = self.csrf_token()
        with patch("ui.dashboard.record_feedback") as record_feedback:
            record_feedback.return_value.domain = "example.com"
            record_feedback.return_value.verdict = "safe"
            record_feedback.return_value.promoted = None
            response = self.client.post(
                "/api/feedback",
                json={"domain": "example.com", "verdict": "safe"},
                headers={"X-CSRF-Token": token},
            )
        self.assertEqual(response.status_code, 200)

    def test_live_is_public_and_minimal(self):
        response = self.client.get("/live")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "alive"})

    def test_security_headers_present(self):
        response = self.client.get("/login")
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_oversized_request_returns_413(self):
        self.login()
        token = self.csrf_token()
        response = self.client.post(
            "/api/settings",
            data="x" * (40 * 1024),
            headers={
                "X-CSRF-Token": token,
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(response.status_code, 413)

    def test_login_throttling_is_generic(self):
        for _index in range(5):
            self.login(password="wrong-password")
        response = self.login(password="wrong-password")
        self.assertEqual(response.status_code, 429)
        self.assertIn(b"Invalid username or password", response.data)

    def test_route_inventory_classifies_write_routes(self):
        self.assertEqual(ROUTE_SECURITY["GET /live"], "public_liveness")
        for route, classification in ROUTE_SECURITY.items():
            if route.startswith(("POST ", "DELETE ", "PUT ", "PATCH ")) and route != "POST /login":
                self.assertIn("csrf", classification)
                self.assertIn("authenticated", classification)


class DashboardAuthCliTests(unittest.TestCase):
    def test_set_password_uses_hash_and_generates_secret_without_printing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pihole-ai.env"
            path.write_text(
                "\n".join(
                    [
                        "PIHOLE_AI_DASHBOARD_HOST=127.0.0.1",
                        "PIHOLE_AI_DASHBOARD_AUTH_ENABLED=true",
                        "PIHOLE_AI_DASHBOARD_USERNAME=admin",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            settings = auth_settings(path)
            settings.dashboard_password_hash = ""
            settings.dashboard_secret_key = ""

            with (
                patch("pihole_ai.dashboard_auth.load_config", return_value=settings),
                patch("pihole_ai.setup.CONFIG_FILE", path),
                patch("pihole_ai.dashboard_auth.sys.stdin", io.StringIO("new-strong-password\n")),
                patch(
                    "pihole_ai.service.grp.getgrnam",
                    return_value=SimpleNamespace(gr_gid=992),
                ),
                patch("pihole_ai.service.os.chown"),
                patch("pihole_ai.setup.os.chown"),
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    code = cli.main(["dashboard", "auth", "set-password", "--password-stdin"])

            content = path.read_text(encoding="utf-8")

        self.assertEqual(code, 0)
        self.assertNotIn("new-strong-password", content)
        self.assertNotIn("new-strong-password", output.getvalue())
        values = dict(
            line.split("=", 1)
            for line in content.splitlines()
            if "=" in line
        )
        self.assertTrue(check_password_hash(values["PIHOLE_AI_DASHBOARD_PASSWORD_HASH"], "new-strong-password"))
        self.assertGreaterEqual(len(values["PIHOLE_AI_DASHBOARD_SECRET_KEY"]), 32)

    def test_weak_password_rejected(self):
        settings = auth_settings()
        with (
            patch("pihole_ai.dashboard_auth.load_config", return_value=settings),
            patch("pihole_ai.dashboard_auth.sys.stdin", io.StringIO("short\n")),
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                code = cli.main(["dashboard", "auth", "set-password", "--password-stdin"])
        self.assertEqual(code, 1)

    def test_disable_requires_confirmation_and_rejects_exposed_bind(self):
        settings = auth_settings(host="0.0.0.0")
        with patch("pihole_ai.dashboard_auth.load_config", return_value=settings):
            output = io.StringIO()
            with redirect_stdout(output):
                code = cli.main(["dashboard", "auth", "disable"])
        self.assertEqual(code, 1)

        with patch("pihole_ai.dashboard_auth.load_config", return_value=settings):
            output = io.StringIO()
            with redirect_stdout(output):
                code = cli.main(["dashboard", "auth", "disable", "--confirm-disable-auth"])
        self.assertEqual(code, 1)

    def test_auth_status_json_omits_secrets(self):
        status = {
            "enabled": True,
            "username": "admin",
            "credentials_configured": True,
            "secret_key_configured": True,
            "session_lifetime_minutes": 30,
            "dashboard_bind_exposed": False,
            "trust_proxy": False,
            "configuration_valid": True,
            "issues": [],
        }
        with patch("pihole_ai.dashboard_auth.auth_status") as auth_status:
            auth_status.return_value.to_dict.return_value = status
            auth_status.return_value.configuration_valid = True
            output = io.StringIO()
            with redirect_stdout(output):
                code = cli.main(["dashboard", "auth", "status", "--json"])
        self.assertEqual(code, 0)
        self.assertNotIn("ssss", output.getvalue().lower())
        self.assertNotIn("hash", output.getvalue().lower())
