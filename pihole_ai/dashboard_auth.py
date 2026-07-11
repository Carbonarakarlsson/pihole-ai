"""
Dashboard authentication credential management.
"""

from __future__ import annotations

import getpass
import json
import secrets
import sys
from dataclasses import dataclass
from typing import Any

from werkzeug.security import generate_password_hash

from core.config import ValidationMode, load_config, load_config_with_result
from pihole_ai.setup import update_setup_config


MIN_PASSWORD_LENGTH = 12


class DashboardAuthError(RuntimeError):
    """
    Clean dashboard auth CLI error.
    """


@dataclass(frozen=True)
class DashboardAuthStatus:
    enabled: bool
    username: str
    credentials_configured: bool
    secret_key_configured: bool
    session_lifetime_minutes: int
    dashboard_bind_exposed: bool
    trust_proxy: bool
    configuration_valid: bool
    issues: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "username": self.username,
            "credentials_configured": self.credentials_configured,
            "secret_key_configured": self.secret_key_configured,
            "session_lifetime_minutes": self.session_lifetime_minutes,
            "dashboard_bind_exposed": self.dashboard_bind_exposed,
            "trust_proxy": self.trust_proxy,
            "configuration_valid": self.configuration_valid,
            "issues": self.issues,
        }


def auth_status() -> DashboardAuthStatus:
    config, result = load_config_with_result(mode=ValidationMode.RUNTIME)
    if config is None:
        return DashboardAuthStatus(
            enabled=True,
            username="admin",
            credentials_configured=False,
            secret_key_configured=False,
            session_lifetime_minutes=0,
            dashboard_bind_exposed=True,
            trust_proxy=False,
            configuration_valid=False,
            issues=result.to_dict()["issues"],
        )

    return DashboardAuthStatus(
        enabled=config.dashboard_auth_enabled,
        username=config.dashboard_username,
        credentials_configured=bool(config.dashboard_password_hash.strip()),
        secret_key_configured=bool(config.dashboard_secret_key.strip()),
        session_lifetime_minutes=config.dashboard_session_lifetime_minutes,
        dashboard_bind_exposed=config.dashboard_host not in {"127.0.0.1", "::1", "localhost"},
        trust_proxy=config.dashboard_trust_proxy,
        configuration_valid=result.error_count == 0,
        issues=[
            issue
            for issue in result.to_dict()["issues"]
            if str(issue["code"]).startswith("config.dashboard.")
        ],
    )


def print_auth_status(*, as_json: bool = False) -> int:
    status = auth_status()
    if as_json:
        print(json.dumps(status.to_dict(), sort_keys=True))
    else:
        print("PiHole-AI dashboard auth")
        print(f"  enabled: {status.enabled}")
        print(f"  username: {status.username}")
        print(f"  credentials_configured: {status.credentials_configured}")
        print(f"  secret_key_configured: {status.secret_key_configured}")
        print(f"  session_lifetime_minutes: {status.session_lifetime_minutes}")
        print(f"  dashboard_bind_exposed: {status.dashboard_bind_exposed}")
        print(f"  trust_proxy: {status.trust_proxy}")
        print(f"  configuration_valid: {status.configuration_valid}")
        for issue in status.issues:
            print(f"  issue: {issue['code']} - {issue['summary']}")
    return 0 if status.configuration_valid else 1


def set_password(
    *,
    password_stdin: bool = False,
    as_json: bool = False,
) -> int:
    password = _read_password(password_stdin=password_stdin)
    _validate_password(password)
    config = load_config(validate=False)
    secret = config.dashboard_secret_key.strip() or secrets.token_urlsafe(48)
    updates = {
        "PIHOLE_AI_DASHBOARD_AUTH_ENABLED": "true",
        "PIHOLE_AI_DASHBOARD_USERNAME": config.dashboard_username or "admin",
        "PIHOLE_AI_DASHBOARD_PASSWORD_HASH": generate_password_hash(password),
        "PIHOLE_AI_DASHBOARD_SECRET_KEY": secret,
    }
    update_setup_config(updates)
    if as_json:
        print(json.dumps({"status": "updated", "restart_required": True}, sort_keys=True))
    else:
        print("Dashboard password updated. Restart required.")
    return 0


def set_auth_enabled(
    *,
    enabled: bool,
    confirm_disable_auth: bool = False,
    as_json: bool = False,
) -> int:
    config = load_config(validate=False)
    if not enabled:
        if not confirm_disable_auth:
            raise DashboardAuthError(
                "Disabling dashboard authentication requires --confirm-disable-auth."
            )
        if config.dashboard_host not in {"127.0.0.1", "::1", "localhost"}:
            raise DashboardAuthError(
                "Refusing to disable dashboard authentication on a non-loopback bind."
            )
    update_setup_config(
        {
            "PIHOLE_AI_DASHBOARD_AUTH_ENABLED": "true" if enabled else "false",
        }
    )
    if as_json:
        print(json.dumps({"enabled": enabled, "restart_required": True}, sort_keys=True))
    else:
        print(
            "Dashboard authentication enabled. Restart required."
            if enabled
            else "Dashboard authentication disabled for loopback development. Restart required."
        )
    return 0


def _read_password(*, password_stdin: bool) -> str:
    if password_stdin:
        return sys.stdin.readline().rstrip("\n")

    first = getpass.getpass("New dashboard password: ")
    second = getpass.getpass("Confirm dashboard password: ")
    if first != second:
        raise DashboardAuthError("Password confirmation did not match.")
    return first


def _validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise DashboardAuthError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
