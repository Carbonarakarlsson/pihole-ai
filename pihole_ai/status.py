"""
Runtime status helpers for PiHole-AI.
"""

from __future__ import annotations

from typing import Any

from core.config import settings
from core.db import database_stats, get_state


def get_ollama_health() -> dict[str, Any]:
    """
    Return Ollama health without making the CLI depend on eager imports.
    """

    try:
        from engine.ollama_client import OllamaClient

        return OllamaClient().health()

    except Exception as exc:
        return {
            "available": False,
            "host": settings.ollama_url,
            "model": settings.ollama_model,
            "latency_ms": None,
            "error": str(exc),
        }


def collect_status(
    include_ollama: bool = True,
) -> dict[str, Any]:
    """
    Collect database, collector, and optional Ollama status.
    """

    status: dict[str, Any] = {
        "database": database_stats(),
        "collector": {
            "last_query_id": get_state(
                "collector.last_query_id",
                "0",
            ),
        },
        "config": {
            "events_db": str(settings.events_db),
            "pihole_db": str(settings.pihole_db),
            "ollama_url": settings.ollama_url,
            "ollama_model": settings.ollama_model,
            "dashboard_port": settings.dashboard_port,
            "cache_ttl": settings.cache_ttl,
        },
    }

    if include_ollama:
        status["ollama"] = get_ollama_health()

    return status


def print_status(
    include_ollama: bool = True,
) -> None:
    """
    Print a human-readable status summary.
    """

    status = collect_status(
        include_ollama=include_ollama,
    )
    database = status["database"]
    collector = status["collector"]
    config = status["config"]

    print("PiHole-AI status")
    print(f"  events_db: {config['events_db']}")
    print(f"  pihole_db: {config['pihole_db']}")
    print(f"  events: {database['events']}")
    print(f"  processed: {database['processed']}")
    print(f"  domains: {database['domains']}")
    print(f"  analyses: {database['analyses']}")
    print(f"  reputations: {database.get('reputations', 0)}")
    print(f"  threat_intel: {database.get('threat_intel', 0)}")
    print(f"  collector.last_query_id: {collector['last_query_id']}")

    if include_ollama:
        ollama = status["ollama"]
        print(f"  ollama.available: {ollama['available']}")
        print(f"  ollama.host: {ollama['host']}")
        print(f"  ollama.model: {ollama['model']}")
        print(f"  ollama.latency_ms: {ollama['latency_ms']}")

        if "error" in ollama:
            print(f"  ollama.error: {ollama['error']}")
