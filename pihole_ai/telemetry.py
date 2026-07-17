"""
Read-only telemetry reporting helpers.
"""

from __future__ import annotations

import json
from typing import Any

from core.db import telemetry_stats_readonly


def print_telemetry_stats(
    *,
    as_json: bool = False,
) -> dict[str, Any]:
    stats = telemetry_stats_readonly()

    if as_json:
        print(json.dumps(stats, indent=2, sort_keys=True))
        return stats

    print("Pipeline telemetry:")
    print(f"  analyses_recorded: {stats['analyses_recorded']}")
    print(f"  telemetry_rows: {stats['telemetry_rows']}")
    average = stats["average_pipeline_duration_ms"]
    if average is None:
        print("  average_pipeline_duration_ms: n/a")
    else:
        print(f"  average_pipeline_duration_ms: {average:.1f}")
    print(f"  ai_invocation_rate: {stats['ai_invocation_rate']:.1%}")
    print(f"  cache_hit_rate: {stats['cache_hit_rate']:.1%}")
    print("  classifier_counts:")
    if stats["classifier_counts"]:
        for name, count in stats["classifier_counts"].items():
            print(f"    {name}: {count}")
    else:
        print("    none: 0")

    return stats

