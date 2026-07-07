"""
Application configuration.

This module centralizes all configurable paths and constants used by the
Pi-hole AI project.

Keeping configuration here prevents hardcoded values from being scattered
throughout the codebase.
"""

from pathlib import Path

# ---------------------------------------------------------------------
# Project Paths
# ---------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = PROJECT_ROOT / "logs"

DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------
# Databases
# ---------------------------------------------------------------------

EVENTS_DB = DATA_DIR / "events.db"

# Pi-hole's FTL database
PIHOLE_DB = Path("/etc/pihole/pihole-FTL.db")

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

ALERT_LOG = DATA_DIR / "alerts.log"

# ---------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------

COLLECT_BATCH_SIZE = 200

COLLECT_INTERVAL = 2

# ---------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------

ENGINE_BATCH_SIZE = 500

HIGH_RISK_THRESHOLD = 70

# ---------------------------------------------------------------------
# Beacon Detection
# ---------------------------------------------------------------------

BEACON_HISTORY = 100

BEACON_MIN_EVENTS = 10

BEACON_REPEAT_THRESHOLD = 3

# ---------------------------------------------------------------------
# AI
# ---------------------------------------------------------------------

OLLAMA_URL = "http://127.0.0.1:11434"

OLLAMA_MODEL = "llama3.2:3b"

AI_ENABLED = True

AI_MINIMUM_SCORE = 70
