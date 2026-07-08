"""
PiHole-AI Configuration

Centralized configuration for the entire project.

Features
--------
- Environment variable overrides
- Automatic directory creation
- Validation helpers
- Backward compatible constants
- Type-safe settings object
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


# ============================================================================
# Project Paths
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = PROJECT_ROOT / "logs"

DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# Settings
# ============================================================================

@dataclass(frozen=True)
class Settings:
    """
    Immutable application configuration.

    Values can be overridden using environment variables.
    """

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------

    project_root: Path = PROJECT_ROOT
    data_dir: Path = DATA_DIR
    log_dir: Path = LOG_DIR

    events_db: Path = Path(
        os.getenv(
            "PIHOLE_AI_EVENTS_DB",
            str(DATA_DIR / "events.db"),
        )
    )

    pihole_db: Path = Path(
        os.getenv(
            "PIHOLE_AI_PIHOLE_DB",
            "/etc/pihole/pihole-FTL.db",
        )
    )

    alert_log: Path = Path(
        os.getenv(
            "PIHOLE_AI_ALERT_LOG",
            str(DATA_DIR / "alerts.log"),
        )
    )

    # ------------------------------------------------------------------
    # Collector
    # ------------------------------------------------------------------

    collect_batch_size: int = int(
        os.getenv("PIHOLE_AI_COLLECT_BATCH_SIZE", "200")
    )

    collect_interval: int = int(
        os.getenv("PIHOLE_AI_COLLECT_INTERVAL", "2")
    )

    # ------------------------------------------------------------------
    # Engine
    # ------------------------------------------------------------------

    engine_batch_size: int = int(
        os.getenv("PIHOLE_AI_ENGINE_BATCH_SIZE", "500")
    )

    engine_interval: int = int(
        os.getenv("PIHOLE_AI_ENGINE_INTERVAL", "5")
    )

    high_risk_threshold: int = int(
        os.getenv("PIHOLE_AI_HIGH_RISK_THRESHOLD", "70")
    )

    alert_threshold: int = int(
        os.getenv("PIHOLE_AI_ALERT_THRESHOLD", "50")
    )

    action_mode: str = os.getenv(
        "PIHOLE_AI_ACTION_MODE",
        "dry-run",
    ).lower()

    # ------------------------------------------------------------------
    # Beacon Detection
    # ------------------------------------------------------------------

    beacon_history: int = int(
        os.getenv("PIHOLE_AI_BEACON_HISTORY", "100")
    )

    beacon_min_events: int = int(
        os.getenv("PIHOLE_AI_BEACON_MIN_EVENTS", "10")
    )

    beacon_repeat_threshold: int = int(
        os.getenv("PIHOLE_AI_BEACON_REPEAT_THRESHOLD", "3")
    )

    # ------------------------------------------------------------------
    # AI
    # ------------------------------------------------------------------

    ollama_url: str = os.getenv(
        "PIHOLE_AI_OLLAMA_URL",
        "http://127.0.0.1:11434",
    )

    ollama_model: str = os.getenv(
        "PIHOLE_AI_OLLAMA_MODEL",
        "llama3.2:1b",
    )

    ai_enabled: bool = (
        os.getenv("PIHOLE_AI_ENABLED", "true").lower()
        in ("1", "true", "yes", "on")
    )

    ai_minimum_score: int = int(
        os.getenv("PIHOLE_AI_AI_MINIMUM_SCORE", "70")
    )

    http_timeout: int = int(
        os.getenv("PIHOLE_AI_HTTP_TIMEOUT", "60")
    )

    debug: bool = (
        os.getenv("PIHOLE_AI_DEBUG", "false").lower()
        in ("1", "true", "yes", "on")
    )

    log_level: str = os.getenv(
        "PIHOLE_AI_LOG_LEVEL",
        "INFO",
    ).upper()

    dashboard_port: int = int(
        os.getenv("PIHOLE_AI_DASHBOARD_PORT", "8080")
    )

    cache_ttl: int = int(
        os.getenv("PIHOLE_AI_CACHE_TTL", "86400")
    )

    keep_latest_events: int = int(
        os.getenv("PIHOLE_AI_KEEP_LATEST_EVENTS", "100000")
    )

    def validate(self) -> None:
        """
        Validate configuration values.
        Raises ValueError if a setting is invalid.
        """

        if not (0 <= self.high_risk_threshold <= 100):
            raise ValueError(
                "HIGH_RISK_THRESHOLD must be between 0 and 100."
            )

        if not (0 <= self.alert_threshold <= 100):
            raise ValueError(
                "ALERT_THRESHOLD must be between 0 and 100."
            )

        if self.action_mode not in {"off", "dry-run", "block"}:
            raise ValueError(
                "ACTION_MODE must be one of: off, dry-run, block."
            )

        if not (0 <= self.ai_minimum_score <= 100):
            raise ValueError(
                "AI_MINIMUM_SCORE must be between 0 and 100."
            )

        if self.collect_interval <= 0:
            raise ValueError(
                "COLLECT_INTERVAL must be greater than zero."
            )

        if self.engine_interval <= 0:
            raise ValueError(
                "ENGINE_INTERVAL must be greater than zero."
            )

        if self.http_timeout <= 0:
            raise ValueError(
                "HTTP_TIMEOUT must be greater than zero."
            )

        if self.keep_latest_events <= 0:
            raise ValueError(
                "KEEP_LATEST_EVENTS must be greater than zero."
            )


# ============================================================================
# Singleton
# ============================================================================

settings = Settings()
settings.validate()


# ============================================================================
# Backwards Compatibility
# ============================================================================

EVENTS_DB = settings.events_db
PIHOLE_DB = settings.pihole_db
ALERT_LOG = settings.alert_log

COLLECT_BATCH_SIZE = settings.collect_batch_size
COLLECT_INTERVAL = settings.collect_interval

ENGINE_BATCH_SIZE = settings.engine_batch_size
ENGINE_INTERVAL = settings.engine_interval
HIGH_RISK_THRESHOLD = settings.high_risk_threshold
ALERT_THRESHOLD = settings.alert_threshold
ACTION_MODE = settings.action_mode

BEACON_HISTORY = settings.beacon_history
BEACON_MIN_EVENTS = settings.beacon_min_events
BEACON_REPEAT_THRESHOLD = settings.beacon_repeat_threshold

OLLAMA_URL = settings.ollama_url
OLLAMA_MODEL = settings.ollama_model

AI_ENABLED = settings.ai_enabled
AI_MINIMUM_SCORE = settings.ai_minimum_score
KEEP_LATEST_EVENTS = settings.keep_latest_events
