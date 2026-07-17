"""
Internal PiHole-AI configuration schema.

The registry in this module is metadata-only.  It describes the supported
environment-backed settings without replacing the existing runtime loader.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable

from core import config as runtime_config
from core.config_validation import ConfigValidationResult
from core.config_validation import validate_boolean
from core.config_validation import validate_enum
from core.config_validation import validate_hostname_or_ip
from core.config_validation import validate_integer
from core.config_validation import validate_numeric_range
from core.config_validation import validate_ollama_model
from core.config_validation import validate_path
from core.config_validation import validate_port
from core.config_validation import validate_url


SCHEMA_VERSION = 1

COLLECTOR_SERVICE = "pihole-ai-collector.service"
ENGINE_SERVICE = "pihole-ai-engine.service"
DASHBOARD_SERVICE = "pihole-ai-dashboard.service"
INTEL_TIMER_SERVICE = "pihole-ai-intel-update.timer"
SERVICE_RESTART_ORDER = (
    COLLECTOR_SERVICE,
    ENGINE_SERVICE,
    DASHBOARD_SERVICE,
    INTEL_TIMER_SERVICE,
)


class ConfigValueType(str, Enum):
    BOOLEAN = "boolean"
    INTEGER = "integer"
    PORT = "port"
    URL = "url"
    HOST = "host"
    PATH = "path"
    ENUM = "enum"
    OLLAMA_MODEL = "ollama_model"
    STRING = "string"


class ConfigSensitivity(str, Enum):
    PUBLIC = "public"
    OPERATIONAL = "operational"
    SENSITIVE = "sensitive"
    SECRET = "secret"


class ConfigExportPolicy(str, Enum):
    NORMAL = "normal"
    SECURE = "secure"
    EXCLUDE = "exclude"


class RestartImpact(str, Enum):
    NONE = "none"
    COLLECTOR = "collector"
    ENGINE = "engine"
    DASHBOARD = "dashboard"
    INTEL_TIMER = "intel-timer"
    ALL = "all"
    INSTALL = "install"


Validator = Callable[["ConfigItem", str], ConfigValidationResult]


@dataclass(frozen=True)
class ConfigItem:
    key: str
    env_names: tuple[str, ...]
    default: str
    value_type: ConfigValueType
    description: str
    category: str
    validator: Validator
    restart_impact: RestartImpact
    sensitivity: ConfigSensitivity
    export_policy: ConfigExportPolicy
    services: tuple[str, ...] = ()
    allowed_values: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None

    @property
    def env_var(self) -> str:
        return self.env_names[0]


def _string_validator(
    item: ConfigItem,
    value: str,
) -> ConfigValidationResult:
    return ConfigValidationResult(key=item.key, value=str(value))


def _bool_validator(
    item: ConfigItem,
    value: str,
) -> ConfigValidationResult:
    return validate_boolean(item.key, value)


def _int_validator(
    item: ConfigItem,
    value: str,
) -> ConfigValidationResult:
    if item.minimum is not None or item.maximum is not None:
        return validate_numeric_range(
            item.key,
            value,
            minimum=item.minimum,
            maximum=item.maximum,
            integer=True,
        )
    return validate_integer(item.key, value)


def _port_validator(
    item: ConfigItem,
    value: str,
) -> ConfigValidationResult:
    return validate_port(item.key, value)


def _url_validator(
    item: ConfigItem,
    value: str,
) -> ConfigValidationResult:
    return validate_url(item.key, value)


def _host_validator(
    item: ConfigItem,
    value: str,
) -> ConfigValidationResult:
    return validate_hostname_or_ip(item.key, value)


def _path_validator(
    item: ConfigItem,
    value: str,
) -> ConfigValidationResult:
    return validate_path(item.key, value)


def _enum_validator(
    item: ConfigItem,
    value: str,
) -> ConfigValidationResult:
    return validate_enum(item.key, value, allowed=item.allowed_values)


def _model_validator(
    item: ConfigItem,
    value: str,
) -> ConfigValidationResult:
    return validate_ollama_model(item.key, value)


def _item(
    key: str,
    env_names: tuple[str, ...] | str,
    default: str | int | bool | Path,
    value_type: ConfigValueType,
    description: str,
    category: str,
    validator: Validator,
    restart_impact: RestartImpact,
    sensitivity: ConfigSensitivity = ConfigSensitivity.OPERATIONAL,
    export_policy: ConfigExportPolicy = ConfigExportPolicy.NORMAL,
    services: tuple[str, ...] = (),
    allowed_values: tuple[str, ...] = (),
    minimum: int | None = None,
    maximum: int | None = None,
) -> ConfigItem:
    names = (env_names,) if isinstance(env_names, str) else env_names
    if isinstance(default, bool):
        default_text = "true" if default else "false"
    else:
        default_text = str(default)
    return ConfigItem(
        key=key,
        env_names=names,
        default=default_text,
        value_type=value_type,
        description=description,
        category=category,
        validator=validator,
        restart_impact=restart_impact,
        sensitivity=sensitivity,
        export_policy=export_policy,
        services=services,
        allowed_values=allowed_values,
        minimum=minimum,
        maximum=maximum,
    )


CONFIG_SCHEMA: tuple[ConfigItem, ...] = (
    _item("project_root", "PIHOLE_AI_PROJECT_ROOT", runtime_config.PROJECT_ROOT, ConfigValueType.PATH, "Project checkout or installed source root.", "General", _path_validator, RestartImpact.INSTALL, export_policy=ConfigExportPolicy.EXCLUDE),
    _item("data_dir", "PIHOLE_AI_DATA_DIR", runtime_config.RUNTIME_DATA_DIR, ConfigValueType.PATH, "Runtime data directory.", "General", _path_validator, RestartImpact.ALL, services=(COLLECTOR_SERVICE, ENGINE_SERVICE, DASHBOARD_SERVICE)),
    _item("log_dir", "PIHOLE_AI_LOG_DIR", runtime_config.RUNTIME_LOG_DIR, ConfigValueType.PATH, "Runtime log directory.", "Logging", _path_validator, RestartImpact.ALL, services=(COLLECTOR_SERVICE, ENGINE_SERVICE, DASHBOARD_SERVICE)),
    _item("config_file", "PIHOLE_AI_CONFIG_FILE", runtime_config.CONFIG_FILE, ConfigValueType.PATH, "Managed appliance environment file.", "General", _path_validator, RestartImpact.ALL, export_policy=ConfigExportPolicy.EXCLUDE, services=(COLLECTOR_SERVICE, ENGINE_SERVICE, DASHBOARD_SERVICE)),
    _item("events_db", ("EVENTS_DB_PATH", "PIHOLE_AI_EVENTS_DB"), runtime_config.RUNTIME_EVENTS_DB, ConfigValueType.PATH, "PiHole-AI SQLite database path.", "Database", _path_validator, RestartImpact.ALL, services=(COLLECTOR_SERVICE, ENGINE_SERVICE, DASHBOARD_SERVICE)),
    _item("pihole_db", "PIHOLE_AI_PIHOLE_DB", "/etc/pihole/pihole-FTL.db", ConfigValueType.PATH, "Pi-hole FTL database path.", "Pi-hole integration", _path_validator, RestartImpact.COLLECTOR, services=(COLLECTOR_SERVICE,)),
    _item("log_file", ("LOG_PATH", "PIHOLE_AI_LOG_FILE"), runtime_config.RUNTIME_LOG_FILE, ConfigValueType.PATH, "Application log file path.", "Logging", _path_validator, RestartImpact.ALL, services=(COLLECTOR_SERVICE, ENGINE_SERVICE, DASHBOARD_SERVICE)),
    _item("alert_log", "PIHOLE_AI_ALERT_LOG", runtime_config.RUNTIME_ALERT_LOG, ConfigValueType.PATH, "Alert log file path.", "Logging", _path_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,)),
    _item("db_timeout_seconds", "PIHOLE_AI_DB_TIMEOUT_SECONDS", 30, ConfigValueType.INTEGER, "SQLite connection timeout in seconds.", "Database", _int_validator, RestartImpact.ALL, services=(COLLECTOR_SERVICE, ENGINE_SERVICE, DASHBOARD_SERVICE), minimum=1),
    _item("db_migration_timeout_seconds", "PIHOLE_AI_DB_MIGRATION_TIMEOUT_SECONDS", 60, ConfigValueType.INTEGER, "SQLite migration timeout in seconds.", "Database", _int_validator, RestartImpact.INSTALL, minimum=1),
    _item("db_busy_timeout_ms", "PIHOLE_AI_DB_BUSY_TIMEOUT_MS", 30000, ConfigValueType.INTEGER, "SQLite busy timeout in milliseconds.", "Database", _int_validator, RestartImpact.ALL, services=(COLLECTOR_SERVICE, ENGINE_SERVICE, DASHBOARD_SERVICE), minimum=1),
    _item("collect_batch_size", "PIHOLE_AI_COLLECT_BATCH_SIZE", 200, ConfigValueType.INTEGER, "Collector batch size.", "Collector", _int_validator, RestartImpact.COLLECTOR, services=(COLLECTOR_SERVICE,), minimum=1),
    _item("collect_interval", "PIHOLE_AI_COLLECT_INTERVAL", 2, ConfigValueType.INTEGER, "Collector polling interval in seconds.", "Collector", _int_validator, RestartImpact.COLLECTOR, services=(COLLECTOR_SERVICE,), minimum=1),
    _item("engine_batch_size", "PIHOLE_AI_ENGINE_BATCH_SIZE", 500, ConfigValueType.INTEGER, "Engine batch size.", "Engine and classification", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=1),
    _item("engine_interval", "PIHOLE_AI_ENGINE_INTERVAL", 5, ConfigValueType.INTEGER, "Engine polling interval in seconds.", "Engine and classification", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=1),
    _item("high_risk_threshold", "PIHOLE_AI_HIGH_RISK_THRESHOLD", 70, ConfigValueType.INTEGER, "High-risk score threshold.", "Engine and classification", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=0, maximum=100),
    _item("alert_threshold", "PIHOLE_AI_ALERT_THRESHOLD", 50, ConfigValueType.INTEGER, "Alert score threshold.", "Engine and classification", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=0, maximum=100),
    _item("action_mode", "PIHOLE_AI_ACTION_MODE", "dry-run", ConfigValueType.ENUM, "Automatic action mode.", "Engine and classification", _enum_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), allowed_values=("off", "dry-run", "block")),
    _item("beacon_history", "PIHOLE_AI_BEACON_HISTORY", 100, ConfigValueType.INTEGER, "Beacon heuristic history length.", "Engine and classification", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=1),
    _item("beacon_min_events", "PIHOLE_AI_BEACON_MIN_EVENTS", 10, ConfigValueType.INTEGER, "Beacon heuristic minimum event count.", "Engine and classification", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=1),
    _item("beacon_repeat_threshold", "PIHOLE_AI_BEACON_REPEAT_THRESHOLD", 3, ConfigValueType.INTEGER, "Beacon heuristic repeat threshold.", "Engine and classification", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=1),
    _item("cache_ttl", "PIHOLE_AI_CACHE_TTL", 86400, ConfigValueType.INTEGER, "Engine cache TTL in seconds.", "Engine and classification", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=0),
    _item("keep_latest_events", "PIHOLE_AI_KEEP_LATEST_EVENTS", 100000, ConfigValueType.INTEGER, "Number of latest events to retain during cleanup.", "Maintenance", _int_validator, RestartImpact.NONE, minimum=1),
    _item("decision_history_retention_days", "PIHOLE_AI_DECISION_HISTORY_RETENTION_DAYS", 365, ConfigValueType.INTEGER, "Decision history retention in days.", "Maintenance", _int_validator, RestartImpact.NONE, minimum=1),
    _item("decision_history_max_per_domain", "PIHOLE_AI_DECISION_HISTORY_MAX_PER_DOMAIN", 100, ConfigValueType.INTEGER, "Maximum decision history rows per domain.", "Maintenance", _int_validator, RestartImpact.NONE, minimum=1),
    _item("ai_enabled", ("PIHOLE_AI_ENABLED", "AI_ENABLED"), True, ConfigValueType.BOOLEAN, "Enable AI classifier calls.", "Ollama and AI", _bool_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,)),
    _item("ai_max_calls_per_minute", "AI_MAX_CALLS_PER_MINUTE", 2, ConfigValueType.INTEGER, "Maximum AI calls per minute.", "Ollama and AI", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=0),
    _item("ai_cooldown_seconds", "AI_COOLDOWN_SECONDS", 60, ConfigValueType.INTEGER, "Cooldown after slow or invalid AI responses.", "Ollama and AI", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=0),
    _item("ai_timeout_seconds", "AI_TIMEOUT_SECONDS", 20, ConfigValueType.INTEGER, "AI request timeout in seconds.", "Ollama and AI", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=1),
    _item("ai_minimum_score", "PIHOLE_AI_AI_MINIMUM_SCORE", 70, ConfigValueType.INTEGER, "Minimum AI score used by AI policy.", "Ollama and AI", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=0, maximum=100),
    _item("ollama_url", ("PIHOLE_AI_OLLAMA_URL", "OLLAMA_HOST"), "http://127.0.0.1:11434", ConfigValueType.URL, "Ollama API URL.", "Ollama and AI", _url_validator, RestartImpact.ENGINE, sensitivity=ConfigSensitivity.SENSITIVE, export_policy=ConfigExportPolicy.SECURE, services=(ENGINE_SERVICE,)),
    _item("ollama_model", ("PIHOLE_AI_OLLAMA_MODEL", "OLLAMA_MODEL"), "llama3.2:1b", ConfigValueType.OLLAMA_MODEL, "Ollama model name.", "Ollama and AI", _model_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,)),
    _item("http_timeout", "PIHOLE_AI_HTTP_TIMEOUT", 60, ConfigValueType.INTEGER, "Generic HTTP timeout in seconds.", "Ollama and AI", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE,), minimum=1),
    _item("intel_auto_update_enabled", "PIHOLE_AI_INTEL_AUTO_UPDATE_ENABLED", False, ConfigValueType.BOOLEAN, "Enable scheduled threat-intelligence updates.", "Threat intelligence", _bool_validator, RestartImpact.INTEL_TIMER, services=(INTEL_TIMER_SERVICE,)),
    _item("intel_update_interval_seconds", "PIHOLE_AI_INTEL_UPDATE_INTERVAL_SECONDS", 86400, ConfigValueType.INTEGER, "Threat-intelligence update interval in seconds.", "Threat intelligence", _int_validator, RestartImpact.INTEL_TIMER, services=(INTEL_TIMER_SERVICE,), minimum=60),
    _item("intel_http_timeout_seconds", "PIHOLE_AI_INTEL_HTTP_TIMEOUT_SECONDS", 20, ConfigValueType.INTEGER, "Threat-intelligence HTTP timeout in seconds.", "Threat intelligence", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE, INTEL_TIMER_SERVICE), minimum=1),
    _item("intel_max_download_bytes", "PIHOLE_AI_INTEL_MAX_DOWNLOAD_BYTES", 2000000, ConfigValueType.INTEGER, "Maximum threat-intelligence feed download size.", "Threat intelligence", _int_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE, INTEL_TIMER_SERVICE), minimum=1),
    _item("intel_stale_after_seconds", "PIHOLE_AI_INTEL_STALE_AFTER_SECONDS", 172800, ConfigValueType.INTEGER, "Threat-intelligence stale threshold in seconds.", "Threat intelligence", _int_validator, RestartImpact.NONE, minimum=60),
    _item("intel_allow_http", "PIHOLE_AI_INTEL_ALLOW_HTTP", False, ConfigValueType.BOOLEAN, "Allow insecure HTTP threat-intelligence sources.", "Threat intelligence", _bool_validator, RestartImpact.NONE),
    _item("intel_user_agent", "PIHOLE_AI_INTEL_USER_AGENT", "PiHole-AI threat-intel updater", ConfigValueType.STRING, "Threat-intelligence HTTP user agent.", "Threat intelligence", _string_validator, RestartImpact.ENGINE, services=(ENGINE_SERVICE, INTEL_TIMER_SERVICE)),
    _item("dashboard_host", "PIHOLE_AI_DASHBOARD_HOST", "0.0.0.0", ConfigValueType.HOST, "Dashboard bind host.", "Dashboard", _host_validator, RestartImpact.DASHBOARD, services=(DASHBOARD_SERVICE,)),
    _item("dashboard_port", "PIHOLE_AI_DASHBOARD_PORT", 8080, ConfigValueType.PORT, "Dashboard TCP port.", "Dashboard", _port_validator, RestartImpact.DASHBOARD, services=(DASHBOARD_SERVICE,)),
    _item("dashboard_poll_interval_ms", "PIHOLE_AI_DASHBOARD_POLL_INTERVAL_MS", 10000, ConfigValueType.INTEGER, "Default dashboard polling interval.", "Dashboard", _int_validator, RestartImpact.DASHBOARD, services=(DASHBOARD_SERVICE,), minimum=1000),
    _item("dashboard_overview_poll_interval_ms", "PIHOLE_AI_DASHBOARD_OVERVIEW_POLL_INTERVAL_MS", 5000, ConfigValueType.INTEGER, "Dashboard overview polling interval.", "Dashboard", _int_validator, RestartImpact.DASHBOARD, services=(DASHBOARD_SERVICE,), minimum=1000),
    _item("dashboard_metrics_poll_interval_ms", "PIHOLE_AI_DASHBOARD_METRICS_POLL_INTERVAL_MS", 15000, ConfigValueType.INTEGER, "Dashboard metrics polling interval.", "Dashboard", _int_validator, RestartImpact.DASHBOARD, services=(DASHBOARD_SERVICE,), minimum=1000),
    _item("dashboard_tables_poll_interval_ms", "PIHOLE_AI_DASHBOARD_TABLES_POLL_INTERVAL_MS", 10000, ConfigValueType.INTEGER, "Dashboard table polling interval.", "Dashboard", _int_validator, RestartImpact.DASHBOARD, services=(DASHBOARD_SERVICE,), minimum=1000),
    _item("dashboard_slow_poll_interval_ms", "PIHOLE_AI_DASHBOARD_SLOW_POLL_INTERVAL_MS", 30000, ConfigValueType.INTEGER, "Dashboard slow polling interval.", "Dashboard", _int_validator, RestartImpact.DASHBOARD, services=(DASHBOARD_SERVICE,), minimum=1000),
    _item("dev_access_logs", "DEV_ACCESS_LOGS", False, ConfigValueType.BOOLEAN, "Enable development access logs.", "Dashboard", _bool_validator, RestartImpact.DASHBOARD, services=(DASHBOARD_SERVICE,)),
    _item("dashboard_auth_enabled", "PIHOLE_AI_DASHBOARD_AUTH_ENABLED", True, ConfigValueType.BOOLEAN, "Enable dashboard authentication.", "Authentication", _bool_validator, RestartImpact.DASHBOARD, sensitivity=ConfigSensitivity.SENSITIVE, export_policy=ConfigExportPolicy.SECURE, services=(DASHBOARD_SERVICE,)),
    _item("dashboard_username", "PIHOLE_AI_DASHBOARD_USERNAME", "admin", ConfigValueType.STRING, "Dashboard administrator username.", "Authentication", _string_validator, RestartImpact.DASHBOARD, sensitivity=ConfigSensitivity.SENSITIVE, export_policy=ConfigExportPolicy.SECURE, services=(DASHBOARD_SERVICE,)),
    _item("dashboard_password_hash", "PIHOLE_AI_DASHBOARD_PASSWORD_HASH", "", ConfigValueType.STRING, "Dashboard password hash.", "Authentication", _string_validator, RestartImpact.DASHBOARD, sensitivity=ConfigSensitivity.SECRET, export_policy=ConfigExportPolicy.SECURE, services=(DASHBOARD_SERVICE,)),
    _item("dashboard_secret_key", "PIHOLE_AI_DASHBOARD_SECRET_KEY", "", ConfigValueType.STRING, "Dashboard session secret key.", "Authentication", _string_validator, RestartImpact.DASHBOARD, sensitivity=ConfigSensitivity.SECRET, export_policy=ConfigExportPolicy.SECURE, services=(DASHBOARD_SERVICE,)),
    _item("dashboard_session_lifetime_minutes", "PIHOLE_AI_DASHBOARD_SESSION_LIFETIME_MINUTES", 480, ConfigValueType.INTEGER, "Dashboard session lifetime in minutes.", "Authentication", _int_validator, RestartImpact.DASHBOARD, services=(DASHBOARD_SERVICE,), minimum=1, maximum=1440),
    _item("dashboard_trust_proxy", "PIHOLE_AI_DASHBOARD_TRUST_PROXY", False, ConfigValueType.BOOLEAN, "Trust reverse-proxy headers for dashboard requests.", "Dashboard", _bool_validator, RestartImpact.DASHBOARD, services=(DASHBOARD_SERVICE,)),
    _item("debug", "PIHOLE_AI_DEBUG", False, ConfigValueType.BOOLEAN, "Enable debug mode.", "Development-only", _bool_validator, RestartImpact.ALL, export_policy=ConfigExportPolicy.EXCLUDE, services=(COLLECTOR_SERVICE, ENGINE_SERVICE, DASHBOARD_SERVICE)),
    _item("log_level", ("PIHOLE_AI_LOG_LEVEL", "LOG_LEVEL"), "INFO", ConfigValueType.ENUM, "Application log level.", "Logging", _enum_validator, RestartImpact.ALL, services=(COLLECTOR_SERVICE, ENGINE_SERVICE, DASHBOARD_SERVICE), allowed_values=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")),
)


def validate_schema(
    items: Iterable[ConfigItem] = CONFIG_SCHEMA,
) -> None:
    keys: set[str] = set()
    env_names: set[str] = set()
    for item in items:
        if item.key in keys:
            raise ValueError(f"Duplicate configuration key: {item.key}")
        keys.add(item.key)
        for env_name in item.env_names:
            if env_name in env_names:
                raise ValueError(f"Duplicate configuration environment name: {env_name}")
            env_names.add(env_name)


def items_by_key(
    items: Iterable[ConfigItem] = CONFIG_SCHEMA,
) -> dict[str, ConfigItem]:
    validate_schema(items)
    return {item.key: item for item in items}


def items_by_env(
    items: Iterable[ConfigItem] = CONFIG_SCHEMA,
) -> dict[str, ConfigItem]:
    validate_schema(items)
    return {
        env_name: item
        for item in items
        for env_name in item.env_names
    }


def get_item(
    key_or_env: str,
) -> ConfigItem:
    by_key = items_by_key()
    if key_or_env in by_key:
        return by_key[key_or_env]
    by_env = items_by_env()
    if key_or_env in by_env:
        return by_env[key_or_env]
    raise KeyError(key_or_env)


def affected_services(
    changed_keys: Iterable[str],
) -> list[str]:
    by_key = items_by_key()
    services: set[str] = set()
    for key in changed_keys:
        item = by_key.get(key) or items_by_env().get(key)
        if item is None:
            continue
        services.update(item.services)
    return [
        service
        for service in SERVICE_RESTART_ORDER
        if service in services
    ]


validate_schema()
