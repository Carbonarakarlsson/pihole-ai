"""
PiHole-AI Logger

Centralized logging for the entire project.

Features
--------
* Console logging
* Rotating log files
* Configurable log level
* Consistent formatting
* Reusable logger instances

Usage
-----

from core.logger import get_logger

logger = get_logger(__name__)

logger.info("Collector started")
logger.warning("Suspicious domain detected")
logger.error("Unable to contact Ollama")
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from core.config import settings

# ============================================================================
# Constants
# ============================================================================

LOG_FORMAT = (
    "%(asctime)s | "
    "%(levelname)-8s | "
    "%(name)s | "
    "%(message)s"
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

LOG_FILE = Path(settings.log_file)

MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB
BACKUP_COUNT = 5

_configured = False


# ============================================================================
# Logger Configuration
# ============================================================================

def configure_logging() -> None:
    """
    Configure the root logger.

    Safe to call multiple times.
    """

    global _configured

    if _configured:
        return

    formatter = logging.Formatter(
        fmt=LOG_FORMAT,
        datefmt=DATE_FORMAT,
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(settings.log_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # ------------------------------------------------------------------
    # Console Handler
    # ------------------------------------------------------------------

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)

    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            filename=LOG_FILE,
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )

        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    except OSError:
        root_logger.debug(
            "File logging disabled; cannot write %s",
            LOG_FILE,
        )

    for noisy_logger in ("httpx", "httpcore", "ollama"):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)

    _configured = True


# ============================================================================
# Public API
# ============================================================================

def get_logger(name: str) -> logging.Logger:
    """
    Return a configured logger.

    Parameters
    ----------
    name:
        Usually __name__.

    Returns
    -------
    logging.Logger
    """

    configure_logging()

    return logging.getLogger(name)
