"""
Centralized PiHole-AI configuration loading and validation.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = PROJECT_ROOT / "logs"
CONFIG_DIR = Path("/etc/pihole-ai")
CONFIG_FILE = CONFIG_DIR / "pihole-ai.env"
RUNTIME_DATA_DIR = Path("/var/lib/pihole-ai")
RUNTIME_LOG_DIR = Path("/var/log/pihole-ai")
RUNTIME_EVENTS_DB = RUNTIME_DATA_DIR / "events.db"
RUNTIME_LOG_FILE = RUNTIME_LOG_DIR / "pihole-ai.log"
RUNTIME_ALERT_LOG = RUNTIME_LOG_DIR / "alerts.log"


class ConfigurationError(RuntimeError):
    """
    Base configuration failure.
    """


class ConfigurationParseError(ConfigurationError):
    """
    Configuration could not be parsed into typed values.
    """

    def __init__(
        self,
        issues: list["ConfigurationIssue"],
    ) -> None:
        self.issues = issues
        super().__init__(
            "Configuration could not be parsed. Run 'pihole-ai config check'."
        )


class ProtectedConfigurationAccessError(ConfigurationError):
    """
    Appliance configuration exists but is not readable by this process.
    """

    def __init__(
        self,
        path: Path,
        cause: OSError,
    ) -> None:
        self.path = path
        self.cause = cause
        super().__init__(
            "Appliance configuration is protected. "
            "Re-run with sudo: sudo pihole-ai"
        )

    def issue(
        self,
    ) -> "ConfigurationIssue":
        return _issue(
            code="config.appliance.permission_denied",
            severity=ValidationSeverity.ERROR,
            setting="PIHOLE_AI_CONFIG",
            summary="Appliance configuration is protected.",
            remediation="Re-run with sudo: sudo pihole-ai",
            details={
                "path": str(self.path),
                "error": self.cause.__class__.__name__,
            },
        )


class ValidationSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class ValidationMode(str, Enum):
    SYNTAX = "syntax"
    INSTALL = "install"
    RUNTIME = "runtime"


@dataclass(frozen=True)
class ConfigurationIssue:
    code: str
    severity: str
    setting: str
    summary: str
    remediation: str
    details: dict[str, Any] | None = None


@dataclass(frozen=True)
class ConfigurationValidationResult:
    mode: str
    issues: list[ConfigurationIssue]

    @property
    def error_count(self) -> int:
        return sum(
            1
            for issue in self.issues
            if issue.severity == ValidationSeverity.ERROR.value
        )

    @property
    def warning_count(self) -> int:
        return sum(
            1
            for issue in self.issues
            if issue.severity == ValidationSeverity.WARNING.value
        )

    @property
    def is_valid(self) -> bool:
        return self.error_count == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "valid": self.is_valid,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issues": [
                {
                    "code": issue.code,
                    "severity": issue.severity,
                    "setting": issue.setting,
                    "summary": issue.summary,
                    "remediation": issue.remediation,
                    "details": issue.details or {},
                }
                for issue in self.issues
            ],
        }


@dataclass(frozen=True, init=False)
class Settings:
    """
    Immutable, typed PiHole-AI configuration.
    """

    project_root: Path
    data_dir: Path
    log_dir: Path
    config_file: Path
    events_db: Path
    log_file: Path
    pihole_db: Path
    alert_log: Path
    collect_batch_size: int
    collect_interval: int
    engine_batch_size: int
    engine_interval: int
    high_risk_threshold: int
    alert_threshold: int
    action_mode: str
    beacon_history: int
    beacon_min_events: int
    beacon_repeat_threshold: int
    ollama_url: str
    ollama_model: str
    ai_enabled: bool
    ai_max_calls_per_minute: int
    ai_cooldown_seconds: int
    ai_timeout_seconds: int
    ai_minimum_score: int
    http_timeout: int
    debug: bool
    log_level: str
    dashboard_host: str
    dashboard_port: int
    dashboard_poll_interval_ms: int
    dashboard_overview_poll_interval_ms: int
    dashboard_metrics_poll_interval_ms: int
    dashboard_tables_poll_interval_ms: int
    dashboard_slow_poll_interval_ms: int
    dev_access_logs: bool
    dashboard_auth_enabled: bool
    dashboard_username: str
    dashboard_password_hash: str
    dashboard_secret_key: str
    dashboard_session_lifetime_minutes: int
    dashboard_trust_proxy: bool
    cache_ttl: int
    keep_latest_events: int
    decision_history_retention_days: int
    decision_history_max_per_domain: int
    intel_auto_update_enabled: bool
    intel_update_interval_seconds: int
    intel_http_timeout_seconds: int
    intel_max_download_bytes: int
    intel_stale_after_seconds: int
    intel_allow_http: bool
    intel_user_agent: str

    def __init__(
        self,
        env: Mapping[str, str] | None = None,
        env_files: list[Path] | None = None,
    ) -> None:
        parsed, issues = _parse_config(
            env=env,
            env_files=env_files or [],
        )

        if issues:
            raise ConfigurationParseError(issues)

        for key, value in parsed.items():
            object.__setattr__(self, key, value)

    def validate(
        self,
        mode: ValidationMode | str = ValidationMode.RUNTIME,
    ) -> None:
        """
        Raise ValueError when validation reports configuration errors.
        """

        result = validate_config(
            self,
            mode=mode,
        )

        if result.error_count:
            first = next(
                issue
                for issue in result.issues
                if issue.severity == ValidationSeverity.ERROR.value
            )
            raise ValueError(
                f"{first.setting}: {first.summary} "
                "Run 'pihole-ai config check' for details."
            )

    def validation_result(
        self,
        mode: ValidationMode | str = ValidationMode.RUNTIME,
    ) -> ConfigurationValidationResult:
        return validate_config(
            self,
            mode=mode,
        )

    def to_safe_dict(self) -> dict[str, Any]:
        """
        Return safe effective configuration values.
        """

        return {
            "project_root": str(self.project_root),
            "data_dir": str(self.data_dir),
            "log_dir": str(self.log_dir),
            "config_file": str(self.config_file),
            "events_db": str(self.events_db),
            "log_file": str(self.log_file),
            "pihole_db": str(self.pihole_db),
            "alert_log": str(self.alert_log),
            "collector": {
                "batch_size": self.collect_batch_size,
                "interval": self.collect_interval,
            },
            "engine": {
                "batch_size": self.engine_batch_size,
                "interval": self.engine_interval,
                "high_risk_threshold": self.high_risk_threshold,
                "alert_threshold": self.alert_threshold,
                "action_mode": self.action_mode,
                "cache_ttl": self.cache_ttl,
                "keep_latest_events": self.keep_latest_events,
                "decision_history_retention_days": self.decision_history_retention_days,
                "decision_history_max_per_domain": self.decision_history_max_per_domain,
            },
            "threat_intelligence": {
                "auto_update_enabled": self.intel_auto_update_enabled,
                "update_interval_seconds": self.intel_update_interval_seconds,
                "http_timeout_seconds": self.intel_http_timeout_seconds,
                "max_download_bytes": self.intel_max_download_bytes,
                "stale_after_seconds": self.intel_stale_after_seconds,
                "allow_http": self.intel_allow_http,
                "user_agent": self.intel_user_agent,
            },
            "ai": {
                "enabled": self.ai_enabled,
                "max_calls_per_minute": self.ai_max_calls_per_minute,
                "cooldown_seconds": self.ai_cooldown_seconds,
                "timeout_seconds": self.ai_timeout_seconds,
                "minimum_score": self.ai_minimum_score,
                "ollama_url": redact_url(self.ollama_url),
                "ollama_model": self.ollama_model,
            },
            "dashboard": {
                "host": self.dashboard_host,
                "port": self.dashboard_port,
                "poll_interval_ms": self.dashboard_poll_interval_ms,
                "overview_poll_interval_ms": self.dashboard_overview_poll_interval_ms,
                "metrics_poll_interval_ms": self.dashboard_metrics_poll_interval_ms,
                "tables_poll_interval_ms": self.dashboard_tables_poll_interval_ms,
                "slow_poll_interval_ms": self.dashboard_slow_poll_interval_ms,
                "dev_access_logs": self.dev_access_logs,
                "auth_enabled": self.dashboard_auth_enabled,
                "username": self.dashboard_username,
                "credentials_configured": bool(self.dashboard_password_hash.strip()),
                "secret_key_configured": bool(self.dashboard_secret_key.strip()),
                "session_lifetime_minutes": self.dashboard_session_lifetime_minutes,
                "trust_proxy": self.dashboard_trust_proxy,
            },
            "logging": {
                "level": self.log_level,
                "file": str(self.log_file),
            },
        }


def load_env_file(
    path: Path,
) -> None:
    """
    Load simple KEY=VALUE pairs without overriding existing environment.
    """

    values = read_env_file(path)

    for key, value in values.items():
        if key and key not in os.environ:
            os.environ[key] = value


def read_env_file(
    path: Path,
) -> dict[str, str]:
    """
    Read simple KEY=VALUE pairs from an env file.
    """

    try:
        exists = path.exists()
    except OSError as exc:
        if path == CONFIG_FILE:
            raise ProtectedConfigurationAccessError(path, exc) from exc
        return {}

    if not exists:
        return {}

    values: dict[str, str] = {}

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        if path == CONFIG_FILE:
            raise ProtectedConfigurationAccessError(path, exc) from exc
        return {}

    for raw_line in lines:
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")

        if key:
            values[key] = value

    return values


def load_config(
    env: Mapping[str, str] | None = None,
    env_files: list[Path] | None = None,
    validate: bool = True,
    mode: ValidationMode | str = ValidationMode.SYNTAX,
) -> Settings:
    """
    Load, parse, and optionally validate effective configuration.
    """

    config = Settings(
        env=env,
        env_files=env_files if env_files is not None else [CONFIG_FILE, PROJECT_ROOT / ".env"],
    )

    if validate:
        config.validate(mode=mode)

    return config


def load_config_with_result(
    env: Mapping[str, str] | None = None,
    env_files: list[Path] | None = None,
    mode: ValidationMode | str = ValidationMode.RUNTIME,
) -> tuple[Settings | None, ConfigurationValidationResult]:
    """
    Load configuration and return structured validation without raising.
    """

    normalized_mode = _mode(mode)

    try:
        config = load_config(
            env=env,
            env_files=env_files,
            validate=False,
        )

    except ProtectedConfigurationAccessError as exc:
        return None, ConfigurationValidationResult(
            mode=normalized_mode.value,
            issues=[exc.issue()],
        )

    except ConfigurationParseError as exc:
        return None, ConfigurationValidationResult(
            mode=normalized_mode.value,
            issues=exc.issues,
        )

    return config, validate_config(
        config,
        mode=normalized_mode,
    )


def validate_config(
    config: Settings,
    mode: ValidationMode | str = ValidationMode.RUNTIME,
) -> ConfigurationValidationResult:
    """
    Validate configuration and collect every detectable issue.
    """

    normalized_mode = _mode(mode)
    issues: list[ConfigurationIssue] = []

    _validate_pihole_db(config, normalized_mode, issues)
    _validate_events_db(config, normalized_mode, issues)
    _validate_logs(config, normalized_mode, issues)
    _validate_dashboard(config, issues)
    _validate_dashboard_auth(config, normalized_mode, issues)
    _validate_ollama(config, issues)
    _validate_numeric(config, issues)
    _validate_path_conflicts(config, issues)

    return ConfigurationValidationResult(
        mode=normalized_mode.value,
        issues=issues,
    )


class _SettingsProxy:
    """
    Backward-compatible lazy settings object.
    """

    _config: Settings | None = None

    def _get(self) -> Settings:
        if self._config is None:
            self._config = load_config(
                validate=False,
            )

        return self._config

    def reload(self) -> Settings:
        self._config = load_config(
            validate=False,
        )
        return self._config

    def __getattr__(
        self,
        name: str,
    ) -> Any:
        return getattr(
            self._get(),
            name,
        )

    def validate(
        self,
        mode: ValidationMode | str = ValidationMode.RUNTIME,
    ) -> None:
        self._get().validate(mode=mode)

    def validation_result(
        self,
        mode: ValidationMode | str = ValidationMode.RUNTIME,
    ) -> ConfigurationValidationResult:
        return self._get().validation_result(mode=mode)

    def to_safe_dict(self) -> dict[str, Any]:
        return self._get().to_safe_dict()


def redact_url(
    value: str,
) -> str:
    """
    Remove URL credentials before displaying a URL.
    """

    parts = urlsplit(value)

    if not parts.netloc or "@" not in parts.netloc:
        return value

    host = parts.hostname or ""

    if parts.port is not None:
        host = f"{host}:{parts.port}"

    return urlunsplit(
        (
            parts.scheme,
            host,
            parts.path,
            parts.query,
            parts.fragment,
        )
    )


def _parse_config(
    env: Mapping[str, str] | None = None,
    env_files: list[Path] | None = None,
) -> tuple[dict[str, Any], list[ConfigurationIssue]]:
    raw = _effective_env(
        env=env,
        env_files=env_files,
    )
    issues: list[ConfigurationIssue] = []

    def raw_value(
        *keys: str,
        default: str,
    ) -> str:
        for key in keys:
            if key in raw:
                return raw[key]
        return default

    parsed = {
        "project_root": _path(raw_value("PIHOLE_AI_PROJECT_ROOT", default=str(PROJECT_ROOT))),
        "data_dir": _path(raw_value("PIHOLE_AI_DATA_DIR", default=str(RUNTIME_DATA_DIR))),
        "log_dir": _path(raw_value("PIHOLE_AI_LOG_DIR", default=str(RUNTIME_LOG_DIR))),
        "config_file": _path(raw_value("PIHOLE_AI_CONFIG_FILE", default=str(CONFIG_FILE))),
        "events_db": _path(raw_value("EVENTS_DB_PATH", "PIHOLE_AI_EVENTS_DB", default=str(RUNTIME_EVENTS_DB))),
        "log_file": _path(raw_value("LOG_PATH", "PIHOLE_AI_LOG_FILE", default=str(RUNTIME_LOG_FILE))),
        "pihole_db": _path(raw_value("PIHOLE_AI_PIHOLE_DB", default="/etc/pihole/pihole-FTL.db")),
        "alert_log": _path(raw_value("PIHOLE_AI_ALERT_LOG", default=str(RUNTIME_ALERT_LOG))),
        "action_mode": raw_value("PIHOLE_AI_ACTION_MODE", default="dry-run").lower(),
        "ollama_url": raw_value("PIHOLE_AI_OLLAMA_URL", default="http://127.0.0.1:11434"),
        "ollama_model": raw_value("PIHOLE_AI_OLLAMA_MODEL", default="llama3.2:1b"),
        "log_level": raw_value("PIHOLE_AI_LOG_LEVEL", "LOG_LEVEL", default="INFO").upper(),
        "intel_user_agent": raw_value("PIHOLE_AI_INTEL_USER_AGENT", default="PiHole-AI threat-intel updater"),
        "dashboard_host": raw_value("PIHOLE_AI_DASHBOARD_HOST", default="0.0.0.0"),
        "dashboard_username": raw_value("PIHOLE_AI_DASHBOARD_USERNAME", default="admin"),
        "dashboard_password_hash": raw_value("PIHOLE_AI_DASHBOARD_PASSWORD_HASH", default=""),
        "dashboard_secret_key": raw_value("PIHOLE_AI_DASHBOARD_SECRET_KEY", default=""),
    }

    int_fields = {
        "collect_batch_size": ("PIHOLE_AI_COLLECT_BATCH_SIZE", "200"),
        "collect_interval": ("PIHOLE_AI_COLLECT_INTERVAL", "2"),
        "engine_batch_size": ("PIHOLE_AI_ENGINE_BATCH_SIZE", "500"),
        "engine_interval": ("PIHOLE_AI_ENGINE_INTERVAL", "5"),
        "high_risk_threshold": ("PIHOLE_AI_HIGH_RISK_THRESHOLD", "70"),
        "alert_threshold": ("PIHOLE_AI_ALERT_THRESHOLD", "50"),
        "beacon_history": ("PIHOLE_AI_BEACON_HISTORY", "100"),
        "beacon_min_events": ("PIHOLE_AI_BEACON_MIN_EVENTS", "10"),
        "beacon_repeat_threshold": ("PIHOLE_AI_BEACON_REPEAT_THRESHOLD", "3"),
        "ai_max_calls_per_minute": ("AI_MAX_CALLS_PER_MINUTE", "2"),
        "ai_cooldown_seconds": ("AI_COOLDOWN_SECONDS", "60"),
        "ai_timeout_seconds": ("AI_TIMEOUT_SECONDS", "20"),
        "ai_minimum_score": ("PIHOLE_AI_AI_MINIMUM_SCORE", "70"),
        "http_timeout": ("PIHOLE_AI_HTTP_TIMEOUT", "60"),
        "dashboard_port": ("PIHOLE_AI_DASHBOARD_PORT", "8080"),
        "dashboard_poll_interval_ms": ("PIHOLE_AI_DASHBOARD_POLL_INTERVAL_MS", "10000"),
        "dashboard_overview_poll_interval_ms": ("PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS", "5000"),
        "dashboard_metrics_poll_interval_ms": ("PIHOLE_AI_DASHBOARD_METRICS_POLL_INTERVAL_MS", "15000"),
        "dashboard_tables_poll_interval_ms": ("PIHOLE_AI_DASHBOARD_TABLES_POLL_INTERVAL_MS", "10000"),
        "dashboard_slow_poll_interval_ms": ("PIHOLE_AI_DASHBOARD_SLOW_POLL_INTERVAL_MS", "30000"),
        "dashboard_session_lifetime_minutes": ("PIHOLE_AI_DASHBOARD_SESSION_LIFETIME_MINUTES", "480"),
        "cache_ttl": ("PIHOLE_AI_CACHE_TTL", "86400"),
        "keep_latest_events": ("PIHOLE_AI_KEEP_LATEST_EVENTS", "100000"),
        "decision_history_retention_days": ("PIHOLE_AI_DECISION_HISTORY_RETENTION_DAYS", "365"),
        "decision_history_max_per_domain": ("PIHOLE_AI_DECISION_HISTORY_MAX_PER_DOMAIN", "100"),
        "intel_update_interval_seconds": ("PIHOLE_AI_INTEL_UPDATE_INTERVAL_SECONDS", "86400"),
        "intel_http_timeout_seconds": ("PIHOLE_AI_INTEL_HTTP_TIMEOUT_SECONDS", "20"),
        "intel_max_download_bytes": ("PIHOLE_AI_INTEL_MAX_DOWNLOAD_BYTES", "2000000"),
        "intel_stale_after_seconds": ("PIHOLE_AI_INTEL_STALE_AFTER_SECONDS", "172800"),
    }

    for field, (env_key, default) in int_fields.items():
        parsed[field] = _parse_int(
            setting=env_key,
            value=raw_value(env_key, default=default),
            issues=issues,
        )

    parsed["ai_enabled"] = _parse_bool(
        setting="AI_ENABLED",
        value=raw_value("PIHOLE_AI_ENABLED", "AI_ENABLED", default="true"),
        issues=issues,
    )
    parsed["debug"] = _parse_bool(
        setting="PIHOLE_AI_DEBUG",
        value=raw_value("PIHOLE_AI_DEBUG", default="false"),
        issues=issues,
    )
    parsed["dev_access_logs"] = _parse_bool(
        setting="DEV_ACCESS_LOGS",
        value=raw_value("DEV_ACCESS_LOGS", default="false"),
        issues=issues,
    )
    parsed["intel_auto_update_enabled"] = _parse_bool(
        setting="PIHOLE_AI_INTEL_AUTO_UPDATE_ENABLED",
        value=raw_value("PIHOLE_AI_INTEL_AUTO_UPDATE_ENABLED", default="false"),
        issues=issues,
    )
    parsed["intel_allow_http"] = _parse_bool(
        setting="PIHOLE_AI_INTEL_ALLOW_HTTP",
        value=raw_value("PIHOLE_AI_INTEL_ALLOW_HTTP", default="false"),
        issues=issues,
    )
    parsed["dashboard_auth_enabled"] = _parse_bool(
        setting="PIHOLE_AI_DASHBOARD_AUTH_ENABLED",
        value=raw_value("PIHOLE_AI_DASHBOARD_AUTH_ENABLED", default="true"),
        issues=issues,
    )
    parsed["dashboard_trust_proxy"] = _parse_bool(
        setting="PIHOLE_AI_DASHBOARD_TRUST_PROXY",
        value=raw_value("PIHOLE_AI_DASHBOARD_TRUST_PROXY", default="false"),
        issues=issues,
    )

    return parsed, issues


def _effective_env(
    env: Mapping[str, str] | None,
    env_files: list[Path] | None,
) -> Mapping[str, str]:
    values: dict[str, str] = {}
    paths = env_files if env_files is not None else [CONFIG_FILE, PROJECT_ROOT / ".env"]

    for path in paths:
        try:
            values.update(read_env_file(path))
        except ProtectedConfigurationAccessError:
            project_env = PROJECT_ROOT / ".env"
            if (
                path == CONFIG_FILE
                and project_env in paths
                and project_env.exists()
            ):
                continue
            raise

    values.update(dict(env if env is not None else os.environ))

    return MappingProxyType(values)


def _parse_int(
    setting: str,
    value: str,
    issues: list[ConfigurationIssue],
) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        issues.append(
            _issue(
                code=f"config.{_setting_code(setting)}.invalid_integer",
                severity=ValidationSeverity.ERROR,
                setting=setting,
                summary="Setting must be an integer.",
                remediation=f"Set {setting} to a whole number.",
            )
        )
        return 0


def _parse_bool(
    setting: str,
    value: str,
    issues: list[ConfigurationIssue],
) -> bool:
    normalized = str(value).strip().lower()

    if normalized in {"1", "true", "yes", "on"}:
        return True

    if normalized in {"0", "false", "no", "off"}:
        return False

    issues.append(
        _issue(
            code=f"config.{_setting_code(setting)}.invalid_boolean",
            severity=ValidationSeverity.ERROR,
            setting=setting,
            summary="Setting must be a boolean.",
            remediation=f"Set {setting} to true or false.",
        )
    )
    return False


def _path(
    value: str,
) -> Path:
    path = Path(value).expanduser()

    if not path.is_absolute():
        path = PROJECT_ROOT / path

    return path.resolve(strict=False)


def _mode(
    mode: ValidationMode | str,
) -> ValidationMode:
    if isinstance(mode, ValidationMode):
        return mode

    return ValidationMode(str(mode))


def _validate_pihole_db(
    config: Settings,
    mode: ValidationMode,
    issues: list[ConfigurationIssue],
) -> None:
    if not config.pihole_db.is_absolute():
        issues.append(
            _issue(
                "config.pihole_db.not_absolute",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_PIHOLE_DB",
                "Pi-hole database path must be absolute.",
                "Set PIHOLE_AI_PIHOLE_DB to the full pihole-FTL.db path.",
            )
        )

    if mode == ValidationMode.SYNTAX:
        return

    if not config.pihole_db.exists():
        issues.append(
            _issue(
                "config.pihole_db.missing",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_PIHOLE_DB",
                "Pi-hole FTL database does not exist.",
                "Set PIHOLE_AI_PIHOLE_DB to the readable Pi-hole FTL database path.",
            )
        )
        return

    if not config.pihole_db.is_file():
        issues.append(
            _issue(
                "config.pihole_db.not_file",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_PIHOLE_DB",
                "Pi-hole database path is not a regular file.",
                "Point PIHOLE_AI_PIHOLE_DB at pihole-FTL.db.",
            )
        )

    if not os.access(config.pihole_db, os.R_OK):
        issues.append(
            _issue(
                "config.pihole_db.not_readable",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_PIHOLE_DB",
                "Pi-hole database is not readable by this process.",
                "Grant read access or run PiHole-AI as a user that can read Pi-hole data.",
            )
        )


def _validate_events_db(
    config: Settings,
    mode: ValidationMode,
    issues: list[ConfigurationIssue],
) -> None:
    if not config.events_db.is_absolute():
        issues.append(
            _issue(
                "config.events_db.not_absolute",
                ValidationSeverity.ERROR,
                "EVENTS_DB_PATH",
                "Events database path must be absolute.",
                "Set EVENTS_DB_PATH to an absolute path.",
            )
        )

    try:
        events_db_exists = config.events_db.exists()
        events_db_is_dir = config.events_db.is_dir() if events_db_exists else False
    except OSError:
        events_db_exists = False
        events_db_is_dir = False

    if events_db_exists and events_db_is_dir:
        issues.append(
            _issue(
                "config.events_db.is_directory",
                ValidationSeverity.ERROR,
                "EVENTS_DB_PATH",
                "Events database path points to a directory.",
                "Set EVENTS_DB_PATH to a SQLite database file path.",
            )
        )

    parent = config.events_db.parent

    if mode == ValidationMode.SYNTAX:
        return

    if not parent.exists():
        severity = (
            ValidationSeverity.WARNING
            if mode == ValidationMode.INSTALL
            else ValidationSeverity.ERROR
        )
        issues.append(
            _issue(
                "config.events_db.parent_missing",
                severity,
                "EVENTS_DB_PATH",
                "Events database parent directory does not exist.",
                "Create the parent directory or run 'pihole-ai install'.",
            )
        )
        return

    if not parent.is_dir():
        issues.append(
            _issue(
                "config.events_db.parent_not_directory",
                ValidationSeverity.ERROR,
                "EVENTS_DB_PATH",
                "Events database parent is not a directory.",
                "Choose a database path under a real directory.",
            )
        )
        return

    if not os.access(parent, os.W_OK):
        issues.append(
            _issue(
                "config.events_db.parent_not_writable",
                ValidationSeverity.ERROR,
                "EVENTS_DB_PATH",
                "Events database parent is not writable.",
                "Grant write access to the PiHole-AI runtime user.",
            )
        )


def _validate_logs(
    config: Settings,
    mode: ValidationMode,
    issues: list[ConfigurationIssue],
) -> None:
    parent = config.log_file.parent

    try:
        log_file_exists = config.log_file.exists()
        log_file_is_dir = config.log_file.is_dir() if log_file_exists else False
    except OSError:
        log_file_exists = False
        log_file_is_dir = False

    if log_file_exists and log_file_is_dir:
        issues.append(
            _issue(
                "config.log_file.is_directory",
                ValidationSeverity.ERROR,
                "LOG_PATH",
                "Log path points to a directory.",
                "Set LOG_PATH to a file path.",
            )
        )

    if mode == ValidationMode.SYNTAX:
        return

    if not parent.exists():
        severity = (
            ValidationSeverity.WARNING
            if mode == ValidationMode.INSTALL
            else ValidationSeverity.ERROR
        )
        issues.append(
            _issue(
                "config.log_file.parent_missing",
                severity,
                "LOG_PATH",
                "Log parent directory does not exist.",
                "Create the log directory or run 'pihole-ai install'.",
            )
        )
        return

    if not os.access(parent, os.W_OK):
        issues.append(
            _issue(
                "config.log_file.parent_not_writable",
                ValidationSeverity.ERROR,
                "LOG_PATH",
                "Log parent directory is not writable.",
                "Grant write access to the PiHole-AI runtime user.",
            )
        )


def _validate_dashboard(
    config: Settings,
    issues: list[ConfigurationIssue],
) -> None:
    if not (1 <= config.dashboard_port <= 65535):
        issues.append(
            _issue(
                "config.dashboard.invalid_port",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_DASHBOARD_PORT",
                "Dashboard port must be between 1 and 65535.",
                "Set PIHOLE_AI_DASHBOARD_PORT to a valid TCP port.",
            )
        )

    try:
        socket.getaddrinfo(config.dashboard_host, None)
    except socket.gaierror:
        issues.append(
            _issue(
                "config.dashboard.invalid_host",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_DASHBOARD_HOST",
                "Dashboard bind host is malformed or cannot be interpreted.",
                "Set PIHOLE_AI_DASHBOARD_HOST to a valid hostname or IP address.",
            )
        )
        return

    if config.dashboard_host not in {"127.0.0.1", "::1", "localhost"}:
        issues.append(
            _issue(
                "config.dashboard.non_loopback_bind",
                ValidationSeverity.WARNING,
                "PIHOLE_AI_DASHBOARD_HOST",
                "Dashboard is configured to bind outside loopback.",
                "Dashboard is reachable outside loopback. Ensure authentication is enabled and firewall/network access is restricted.",
            )
        )


def _validate_dashboard_auth(
    config: Settings,
    mode: ValidationMode,
    issues: list[ConfigurationIssue],
) -> None:
    exposed = config.dashboard_host not in {"127.0.0.1", "::1", "localhost"}

    if not config.dashboard_username.strip():
        issues.append(
            _issue(
                "config.dashboard.username_missing",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_DASHBOARD_USERNAME",
                "Dashboard username must not be empty.",
                "Set PIHOLE_AI_DASHBOARD_USERNAME, usually to admin.",
            )
        )

    if not (1 <= config.dashboard_session_lifetime_minutes <= 1440):
        issues.append(
            _issue(
                "config.dashboard.session_lifetime_invalid",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_DASHBOARD_SESSION_LIFETIME_MINUTES",
                "Dashboard session lifetime must be between 1 and 1440 minutes.",
                "Set PIHOLE_AI_DASHBOARD_SESSION_LIFETIME_MINUTES to a value from 1 through 1440.",
            )
        )

    if not config.dashboard_auth_enabled:
        if exposed:
            issues.append(
                _issue(
                    "config.dashboard.auth_disabled_exposed",
                    ValidationSeverity.ERROR,
                    "PIHOLE_AI_DASHBOARD_AUTH_ENABLED",
                    "Dashboard authentication cannot be disabled on a non-loopback bind.",
                    "Enable authentication or bind the dashboard to 127.0.0.1.",
                )
            )
        else:
            issues.append(
                _issue(
                    "config.dashboard.auth_disabled_loopback",
                    ValidationSeverity.WARNING,
                    "PIHOLE_AI_DASHBOARD_AUTH_ENABLED",
                    "Dashboard authentication is disabled for loopback-only development.",
                    "Keep this only for local development.",
                )
            )
        return

    secret_severity = (
        ValidationSeverity.WARNING
        if mode == ValidationMode.INSTALL
        else ValidationSeverity.ERROR
    )
    if not _configured_secret(config.dashboard_secret_key):
        issues.append(
            _issue(
                "config.dashboard.secret_key_missing",
                secret_severity,
                "PIHOLE_AI_DASHBOARD_SECRET_KEY",
                "Dashboard secret key is missing.",
                "Run: pihole-ai dashboard auth set-password",
            )
        )

    password_severity = (
        ValidationSeverity.WARNING
        if mode == ValidationMode.INSTALL
        else ValidationSeverity.ERROR
    )
    if not _configured_password_hash(config.dashboard_password_hash):
        issues.append(
            _issue(
                "config.dashboard.password_hash_missing",
                password_severity,
                "PIHOLE_AI_DASHBOARD_PASSWORD_HASH",
                "Dashboard administrator password is not configured.",
                "Run: pihole-ai dashboard auth set-password",
            )
        )

    if config.dashboard_trust_proxy and config.dashboard_host in {"0.0.0.0", "::"}:
        issues.append(
            _issue(
                "config.dashboard.proxy_trust_unsafe",
                ValidationSeverity.WARNING,
                "PIHOLE_AI_DASHBOARD_TRUST_PROXY",
                "Proxy trust is enabled for an exposed dashboard bind.",
                "Only enable proxy trust behind a trusted local reverse proxy.",
            )
        )


def _configured_password_hash(value: str) -> bool:
    normalized = value.strip().lower()
    return bool(normalized) and normalized not in {
        "changeme",
        "change-me",
        "placeholder",
        "unset",
    }


def _configured_secret(value: str) -> bool:
    normalized = value.strip().lower()
    return len(value.strip()) >= 32 and normalized not in {
        "changeme",
        "change-me",
        "placeholder",
        "unset",
    }


def _validate_ollama(
    config: Settings,
    issues: list[ConfigurationIssue],
) -> None:
    parts = urlsplit(config.ollama_url)

    if parts.scheme not in {"http", "https"} or not parts.hostname:
        issues.append(
            _issue(
                "config.ollama.invalid_url",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_OLLAMA_URL",
                "Ollama URL must include http or https and a hostname.",
                "Set PIHOLE_AI_OLLAMA_URL to a value like http://127.0.0.1:11434.",
            )
        )

    if parts.username or parts.password:
        issues.append(
            _issue(
                "config.ollama.credentials_in_url",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_OLLAMA_URL",
                "Ollama URL must not contain embedded credentials.",
                "Remove username/password from PIHOLE_AI_OLLAMA_URL.",
                details={"url": redact_url(config.ollama_url)},
            )
        )

    if config.ai_enabled and not config.ollama_model.strip():
        issues.append(
            _issue(
                "config.ollama.empty_model",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_OLLAMA_MODEL",
                "Ollama model must not be empty when AI is enabled.",
                "Set PIHOLE_AI_OLLAMA_MODEL or disable AI with AI_ENABLED=false.",
            )
        )


def _validate_numeric(
    config: Settings,
    issues: list[ConfigurationIssue],
) -> None:
    positive = {
        "PIHOLE_AI_COLLECT_BATCH_SIZE": config.collect_batch_size,
        "PIHOLE_AI_COLLECT_INTERVAL": config.collect_interval,
        "PIHOLE_AI_ENGINE_BATCH_SIZE": config.engine_batch_size,
        "PIHOLE_AI_ENGINE_INTERVAL": config.engine_interval,
        "PIHOLE_AI_BEACON_HISTORY": config.beacon_history,
        "PIHOLE_AI_BEACON_MIN_EVENTS": config.beacon_min_events,
        "PIHOLE_AI_BEACON_REPEAT_THRESHOLD": config.beacon_repeat_threshold,
        "AI_MAX_CALLS_PER_MINUTE": config.ai_max_calls_per_minute,
        "AI_COOLDOWN_SECONDS": config.ai_cooldown_seconds,
        "AI_TIMEOUT_SECONDS": config.ai_timeout_seconds,
        "PIHOLE_AI_HTTP_TIMEOUT": config.http_timeout,
        "PIHOLE_AI_DASHBOARD_POLL_INTERVAL_MS": config.dashboard_poll_interval_ms,
        "PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS": config.dashboard_overview_poll_interval_ms,
        "PIHOLE_AI_DASHBOARD_METRICS_POLL_INTERVAL_MS": config.dashboard_metrics_poll_interval_ms,
        "PIHOLE_AI_DASHBOARD_TABLES_POLL_INTERVAL_MS": config.dashboard_tables_poll_interval_ms,
        "PIHOLE_AI_DASHBOARD_SLOW_POLL_INTERVAL_MS": config.dashboard_slow_poll_interval_ms,
        "PIHOLE_AI_DASHBOARD_SESSION_LIFETIME_MINUTES": config.dashboard_session_lifetime_minutes,
        "PIHOLE_AI_KEEP_LATEST_EVENTS": config.keep_latest_events,
        "PIHOLE_AI_DECISION_HISTORY_RETENTION_DAYS": config.decision_history_retention_days,
        "PIHOLE_AI_DECISION_HISTORY_MAX_PER_DOMAIN": config.decision_history_max_per_domain,
        "PIHOLE_AI_INTEL_UPDATE_INTERVAL_SECONDS": config.intel_update_interval_seconds,
        "PIHOLE_AI_INTEL_HTTP_TIMEOUT_SECONDS": config.intel_http_timeout_seconds,
        "PIHOLE_AI_INTEL_MAX_DOWNLOAD_BYTES": config.intel_max_download_bytes,
        "PIHOLE_AI_INTEL_STALE_AFTER_SECONDS": config.intel_stale_after_seconds,
    }

    for setting, value in positive.items():
        if value <= 0:
            issues.append(
                _issue(
                    f"config.{_setting_code(setting)}.not_positive",
                    ValidationSeverity.ERROR,
                    setting,
                    "Setting must be greater than zero.",
                    f"Set {setting} to a positive number.",
                )
            )

    for setting, value in {
        "PIHOLE_AI_HIGH_RISK_THRESHOLD": config.high_risk_threshold,
        "PIHOLE_AI_ALERT_THRESHOLD": config.alert_threshold,
        "PIHOLE_AI_AI_MINIMUM_SCORE": config.ai_minimum_score,
    }.items():
        if not (0 <= value <= 100):
            issues.append(
                _issue(
                    f"config.{_setting_code(setting)}.out_of_range",
                    ValidationSeverity.ERROR,
                    setting,
                    "Setting must be between 0 and 100.",
                    f"Set {setting} to a value from 0 through 100.",
                )
            )

    if config.cache_ttl < 0:
        issues.append(
            _issue(
                "config.pihole_ai_cache_ttl.out_of_range",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_CACHE_TTL",
                "Cache TTL cannot be negative.",
                "Set PIHOLE_AI_CACHE_TTL to zero or a positive number.",
            )
        )

    if config.action_mode not in {"off", "dry-run", "block"}:
        issues.append(
            _issue(
                "config.action_mode.invalid",
                ValidationSeverity.ERROR,
                "PIHOLE_AI_ACTION_MODE",
                "Action mode must be off, dry-run, or block.",
                "Set PIHOLE_AI_ACTION_MODE to off, dry-run, or block.",
            )
        )


def _validate_path_conflicts(
    config: Settings,
    issues: list[ConfigurationIssue],
) -> None:
    if _same_path(config.pihole_db, config.events_db):
        issues.append(
            _issue(
                "config.database_paths.conflict",
                ValidationSeverity.ERROR,
                "EVENTS_DB_PATH",
                "Pi-hole database and PiHole-AI events database point to the same path.",
                "Use separate files. PiHole-AI must never write to the Pi-hole FTL database.",
                details={
                    "pihole_db": str(config.pihole_db),
                    "events_db": str(config.events_db),
                },
            )
        )


def _same_path(
    left: Path,
    right: Path,
) -> bool:
    try:
        return left.samefile(right)
    except OSError:
        return left.resolve(strict=False) == right.resolve(strict=False)


def _issue(
    code: str,
    severity: ValidationSeverity,
    setting: str,
    summary: str,
    remediation: str,
    details: dict[str, Any] | None = None,
) -> ConfigurationIssue:
    return ConfigurationIssue(
        code=code,
        severity=severity.value,
        setting=setting,
        summary=summary,
        remediation=remediation,
        details=details,
    )


def _setting_code(
    setting: str,
) -> str:
    return setting.lower().replace("pihole_ai_", "").replace("pi_hole_ai_", "")


settings = _SettingsProxy()


def _compat(
    name: str,
) -> Any:
    return getattr(settings, name)


def __getattr__(
    name: str,
) -> Any:
    compatibility = {
        "EVENTS_DB": "events_db",
        "EVENTS_DB_PATH": "events_db",
        "PIHOLE_DB": "pihole_db",
        "ALERT_LOG": "alert_log",
        "LOG_PATH": "log_file",
        "COLLECT_BATCH_SIZE": "collect_batch_size",
        "COLLECT_INTERVAL": "collect_interval",
        "ENGINE_BATCH_SIZE": "engine_batch_size",
        "ENGINE_INTERVAL": "engine_interval",
        "HIGH_RISK_THRESHOLD": "high_risk_threshold",
        "ALERT_THRESHOLD": "alert_threshold",
        "ACTION_MODE": "action_mode",
        "BEACON_HISTORY": "beacon_history",
        "BEACON_MIN_EVENTS": "beacon_min_events",
        "BEACON_REPEAT_THRESHOLD": "beacon_repeat_threshold",
        "OLLAMA_URL": "ollama_url",
        "OLLAMA_MODEL": "ollama_model",
        "AI_ENABLED": "ai_enabled",
        "AI_MAX_CALLS_PER_MINUTE": "ai_max_calls_per_minute",
        "AI_COOLDOWN_SECONDS": "ai_cooldown_seconds",
        "AI_TIMEOUT_SECONDS": "ai_timeout_seconds",
        "AI_MINIMUM_SCORE": "ai_minimum_score",
        "KEEP_LATEST_EVENTS": "keep_latest_events",
    }

    if name in compatibility:
        return _compat(compatibility[name])

    raise AttributeError(name)
