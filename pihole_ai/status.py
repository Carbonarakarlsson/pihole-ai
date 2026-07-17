"""
Runtime status helpers for PiHole-AI.
"""

from __future__ import annotations

from typing import Any

from core.config import settings
from core.db import database_stats_readonly as database_stats
from core.db import get_state_readonly as get_state
from core.db import threat_intel_stats


def ai_metrics() -> dict[str, int]:
    """
    Return AI counters using read-only state access.
    """

    metrics = {
        "ai_calls": int(get_state("ai.calls.total", "0") or 0),
        "rate_limit_skips": int(get_state("ai.rate_limit_skips.total", "0") or 0),
        "disabled_skips": int(get_state("ai.disabled_skips.total", "0") or 0),
        "cooldown_skips": int(get_state("ai.cooldown_skips.total", "0") or 0),
        "ai_parse_errors": int(get_state("ai.parse_errors.total", "0") or 0),
        "ai_timeouts": int(get_state("ai.timeouts.total", "0") or 0),
    }
    metrics["ai_skipped"] = (
        metrics["rate_limit_skips"]
        + metrics["disabled_skips"]
        + metrics["cooldown_skips"]
        + metrics["ai_timeouts"]
    )
    return metrics


def _empty_threat_intel_stats(error: str = "") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "sources_total": 0,
        "enabled_sources": 0,
        "disabled_sources": 0,
        "failed_sources": 0,
        "stale_sources": 0,
        "active_indicators": 0,
        "generations_total": 0,
        "active_generations": 0,
        "inactive_generations": 0,
        "staging_generations": 0,
        "last_success_at": None,
        "last_attempt_at": None,
        "audit_success": 0,
        "audit_failed": 0,
        "sources_by_status": {},
        "integrity_issues": 0,
        "integrity_issue_codes": [],
    }
    if error:
        payload["error"] = error
    return payload


def threat_intel_metrics() -> dict[str, Any]:
    try:
        return threat_intel_stats(settings.events_db)
    except Exception as exc:
        return _empty_threat_intel_stats(exc.__class__.__name__)


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
        "database": database_stats(settings.events_db),
        "collector": {
            "last_query_id": get_state(
                "collector.last_query_id",
                "0",
                database_path=settings.events_db,
            ),
        },
        "ai": ai_metrics(),
        "threat_intel": threat_intel_metrics(),
        "config": {
            "events_db": str(settings.events_db),
            "pihole_db": str(settings.pihole_db),
            "ollama_url": settings.ollama_url,
            "ollama_model": settings.ollama_model,
            "ai_enabled": settings.ai_enabled,
            "ai_max_calls_per_minute": settings.ai_max_calls_per_minute,
            "ai_cooldown_seconds": settings.ai_cooldown_seconds,
            "ai_timeout_seconds": settings.ai_timeout_seconds,
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
    ai = status["ai"]
    threat_intel = status.get("threat_intel", _empty_threat_intel_stats())
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
    print(f"  threat_intel_sources: {threat_intel['sources_total']}")
    print(f"  threat_intel_enabled_sources: {threat_intel['enabled_sources']}")
    print(f"  threat_intel_active_indicators: {threat_intel['active_indicators']}")
    print(f"  threat_intel_failed_sources: {threat_intel['failed_sources']}")
    print(f"  threat_intel_stale_sources: {threat_intel['stale_sources']}")
    print(f"  collector.last_query_id: {collector['last_query_id']}")
    print("AI:")
    print(f"  enabled: {config['ai_enabled']}")
    print(f"  max_calls_per_minute: {config['ai_max_calls_per_minute']}")
    print(f"  cooldown_seconds: {config['ai_cooldown_seconds']}")
    print(f"  timeout_seconds: {config['ai_timeout_seconds']}")
    print(f"  ai_calls: {ai['ai_calls']}")
    print(f"  ai_skipped: {ai['ai_skipped']}")
    print(f"  ai_parse_errors: {ai['ai_parse_errors']}")
    print(f"  ai_timeouts: {ai['ai_timeouts']}")

    if include_ollama:
        ollama = status["ollama"]
        print(f"  ollama.available: {ollama['available']}")
        print(f"  ollama.host: {ollama['host']}")
        print(f"  ollama.model: {ollama['model']}")
        print(f"  ollama.latency_ms: {ollama['latency_ms']}")

        if "error" in ollama:
            print(f"  ollama.error: {ollama['error']}")
