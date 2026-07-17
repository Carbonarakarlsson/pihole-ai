"""
Confidence calibration reporting helpers.

Calibration is observational. Raw classifier confidence remains unchanged and
calibrated values are never fed back into runtime decision logic.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from core import db
from engine.telemetry import confidence_band as raw_confidence_band


BAND_BOUNDARIES = [
    ("unknown", None, None),
    ("very_low", 0.0, 0.20),
    ("low", 0.20, 0.40),
    ("medium", 0.40, 0.70),
    ("high", 0.70, 0.90),
    ("very_high", 0.90, 1.0),
]


def calibration_profile_id() -> str:
    return f"cal_{uuid.uuid4().hex}"


def reporting_confidence_band(confidence: int | float | None) -> str:
    return raw_confidence_band(confidence) or "unknown"


def _normalize_confidence(confidence: int | float | None) -> float | None:
    if confidence is None:
        return None
    value = float(confidence)
    if value > 1:
        value /= 100.0
    if value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return value


def build_calibration_profile_from_benchmark(
    run_id: str,
    *,
    name: str = "",
    classifier_source: str = "",
    model: str = "",
    prompt_version: str = "",
    bins: int = 5,
    notes: str = "",
) -> dict[str, Any]:
    run = _benchmark_run_for_calibration(run_id)
    if run is None:
        raise ValueError(f"benchmark run not found: {run_id}")
    if run["status"] != "completed":
        raise ValueError("benchmark run is not completed")
    rows = run.get("results", [])
    if classifier_source:
        rows = [row for row in rows if (row.get("classifier_source") or "") == classifier_source]
    if not rows:
        raise ValueError("benchmark run has no calibratable samples")

    profile = _profile_from_rows(
        rows,
        name=name or f"Benchmark {run_id}",
        source_type="benchmark",
        source_id=run_id,
        dataset_identifier=run.get("fixture_identifier") or "",
        classifier_source=classifier_source or None,
        model_name=model or run.get("model_name"),
        prompt_version=prompt_version or run.get("prompt_version"),
        bins=bins,
        notes=notes,
    )
    save_calibration_profile(profile)
    return profile


def build_calibration_profile_from_feedback(**_: Any) -> dict[str, Any]:
    raise ValueError("feedback-based calibration is not available without linked labeled samples")


def _benchmark_run_for_calibration(run_id: str) -> dict[str, Any] | None:
    from pihole_ai.benchmark import get_benchmark_run

    return get_benchmark_run(run_id)


def _profile_from_rows(
    rows: list[dict[str, Any]],
    *,
    name: str,
    source_type: str,
    source_id: str,
    dataset_identifier: str,
    classifier_source: str | None,
    model_name: str | None,
    prompt_version: str | None,
    bins: int,
    notes: str,
) -> dict[str, Any]:
    bin_count = max(2, min(20, int(bins or 5)))
    valid = []
    for row in rows:
        confidence = _normalize_confidence(row.get("confidence"))
        if confidence is None:
            continue
        valid.append(
            {
                "confidence": confidence,
                "correct": 1.0 if row.get("correct") else 0.0,
            }
        )
    if not valid:
        raise ValueError("benchmark run has no samples with confidence")

    bin_rows = []
    total = len(valid)
    ece = 0.0
    mce = 0.0
    brier_sum = 0.0
    for index in range(bin_count):
        lower = index / bin_count
        upper = (index + 1) / bin_count
        samples = [
            item
            for item in valid
            if item["confidence"] >= lower
            and (item["confidence"] < upper or (index == bin_count - 1 and item["confidence"] <= upper))
        ]
        if samples:
            average_confidence = sum(item["confidence"] for item in samples) / len(samples)
            observed_accuracy = sum(item["correct"] for item in samples) / len(samples)
            bin_brier = sum((item["confidence"] - item["correct"]) ** 2 for item in samples) / len(samples)
            error = abs(average_confidence - observed_accuracy)
            ece += (len(samples) / total) * error
            mce = max(mce, error)
            brier_sum += sum((item["confidence"] - item["correct"]) ** 2 for item in samples)
        else:
            average_confidence = None
            observed_accuracy = None
            bin_brier = None
        bin_rows.append(
            {
                "bin_index": index,
                "lower_bound": lower,
                "upper_bound": upper,
                "sample_count": len(samples),
                "average_confidence": average_confidence,
                "observed_accuracy": observed_accuracy,
                "brier_score": bin_brier,
            }
        )

    now = time.time()
    return {
        "profile_id": calibration_profile_id(),
        "name": name,
        "source_type": source_type,
        "source_id": source_id,
        "dataset_identifier": dataset_identifier,
        "classifier_source": classifier_source,
        "model_name": model_name,
        "prompt_version": prompt_version,
        "sample_count": total,
        "created_at": now,
        "bins": bin_rows,
        "expected_calibration_error": ece,
        "maximum_calibration_error": mce,
        "brier_score": brier_sum / total,
        "notes": notes,
        "active": False,
        "status": "reporting",
    }


def save_calibration_profile(profile: dict[str, Any]) -> None:
    with db.transaction() as conn:
        conn.execute(
            """
            INSERT INTO calibration_profiles
            (
                profile_id, name, source_type, source_id, dataset_identifier,
                classifier_source, model_name, prompt_version, sample_count,
                created_at, bins_json, expected_calibration_error,
                maximum_calibration_error, brier_score, notes, active, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile["profile_id"],
                profile["name"],
                profile["source_type"],
                profile["source_id"],
                profile.get("dataset_identifier"),
                profile.get("classifier_source"),
                profile.get("model_name"),
                profile.get("prompt_version"),
                profile["sample_count"],
                profile["created_at"],
                json.dumps(profile["bins"], sort_keys=True),
                profile.get("expected_calibration_error"),
                profile.get("maximum_calibration_error"),
                profile.get("brier_score"),
                profile.get("notes"),
                1 if profile.get("active") else 0,
                profile.get("status") or "reporting",
            ),
        )
        conn.executemany(
            """
            INSERT INTO calibration_bins
            (
                profile_id, bin_index, lower_bound, upper_bound, sample_count,
                average_confidence, observed_accuracy, brier_score, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    profile["profile_id"],
                    item["bin_index"],
                    item["lower_bound"],
                    item["upper_bound"],
                    item["sample_count"],
                    item.get("average_confidence"),
                    item.get("observed_accuracy"),
                    item.get("brier_score"),
                    profile["created_at"],
                )
                for item in profile["bins"]
            ],
        )


def list_calibration_profiles(limit: int = 50) -> list[dict[str, Any]]:
    with db.closing(db.Database.open_read_only(db._database_path())) as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM calibration_profiles
            ORDER BY active DESC, created_at DESC
            LIMIT ?
            """,
            (max(1, min(100, int(limit or 50))),),
        ).fetchall()
    return [_profile_row_to_dict(row) for row in rows]


def get_calibration_profile(profile_id: str) -> dict[str, Any] | None:
    with db.closing(db.Database.open_read_only(db._database_path())) as conn:
        row = conn.execute(
            "SELECT * FROM calibration_profiles WHERE profile_id = ?",
            (profile_id,),
        ).fetchone()
        if row is None:
            return None
        bins = conn.execute(
            """
            SELECT bin_index, lower_bound, upper_bound, sample_count,
                   average_confidence, observed_accuracy, brier_score
            FROM calibration_bins
            WHERE profile_id = ?
            ORDER BY bin_index ASC
            """,
            (profile_id,),
        ).fetchall()
    profile = _profile_row_to_dict(row)
    profile["bins"] = [dict(item) for item in bins]
    return profile


def activate_calibration_profile(profile_id: str) -> dict[str, Any]:
    profile = get_calibration_profile(profile_id)
    if profile is None:
        raise ValueError(f"calibration profile not found: {profile_id}")
    with db.transaction() as conn:
        conn.execute(
            """
            UPDATE calibration_profiles
            SET active = 0
            WHERE COALESCE(classifier_source, '') = ?
              AND COALESCE(model_name, '') = ?
              AND COALESCE(prompt_version, '') = ?
            """,
            (
                profile.get("classifier_source") or "",
                profile.get("model_name") or "",
                profile.get("prompt_version") or "",
            ),
        )
        conn.execute(
            "UPDATE calibration_profiles SET active = 1 WHERE profile_id = ?",
            (profile_id,),
        )
    profile["active"] = True
    return profile


def deactivate_calibration_profile(profile_id: str) -> dict[str, Any]:
    profile = get_calibration_profile(profile_id)
    if profile is None:
        raise ValueError(f"calibration profile not found: {profile_id}")
    with db.transaction() as conn:
        conn.execute(
            "UPDATE calibration_profiles SET active = 0 WHERE profile_id = ?",
            (profile_id,),
        )
    profile["active"] = False
    return profile


def _profile_row_to_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["active"] = bool(item.get("active"))
    try:
        item["bins"] = json.loads(item.pop("bins_json", "[]") or "[]")
    except json.JSONDecodeError:
        item["bins"] = []
        item["_degraded"] = True
    return item


def find_active_profile(
    *,
    classifier_source: str | None = None,
    model_name: str | None = None,
    prompt_version: str | None = None,
) -> dict[str, Any] | None:
    profiles = [
        item
        for item in list_calibration_profiles(limit=100)
        if item.get("active")
    ]
    for profile in profiles:
        if profile.get("classifier_source") and profile.get("classifier_source") != classifier_source:
            continue
        if profile.get("model_name") and profile.get("model_name") != model_name:
            continue
        if profile.get("prompt_version") and profile.get("prompt_version") != prompt_version:
            continue
        return get_calibration_profile(profile["profile_id"])
    return None


def calibration_for_confidence(
    confidence: int | float | None,
    *,
    classifier_source: str | None = None,
    model_name: str | None = None,
    prompt_version: str | None = None,
) -> dict[str, Any]:
    raw_band = reporting_confidence_band(confidence)
    normalized = _normalize_confidence(confidence)
    result = {
        "raw_confidence": confidence,
        "raw_confidence_band": raw_band,
        "calibrated_confidence": None,
        "calibrated_confidence_band": None,
        "profile_id": None,
        "profile_name": None,
        "profile_sample_count": None,
        "source": None,
        "observational": True,
    }
    if normalized is None:
        return result
    profile = find_active_profile(
        classifier_source=classifier_source,
        model_name=model_name,
        prompt_version=prompt_version,
    )
    if profile is None:
        return result
    for item in profile.get("bins", []):
        lower = float(item["lower_bound"])
        upper = float(item["upper_bound"])
        if normalized >= lower and (normalized < upper or upper >= 1.0 and normalized <= upper):
            observed = item.get("observed_accuracy")
            if observed is not None:
                calibrated = float(observed) * 100.0
                result.update(
                    {
                        "calibrated_confidence": calibrated,
                        "calibrated_confidence_band": reporting_confidence_band(calibrated),
                        "profile_id": profile["profile_id"],
                        "profile_name": profile["name"],
                        "profile_sample_count": profile["sample_count"],
                        "source": profile["source_type"],
                    }
                )
            return result
    return result


def reliability_metrics(
    *,
    window: str = "all",
) -> dict[str, Any]:
    cutoff = _window_cutoff(window)
    with db.closing(db.Database.open_read_only(db._database_path())) as conn:
        params: tuple[Any, ...] = (cutoff,) if cutoff is not None else ()
        run_where = "WHERE started_at >= ?" if cutoff is not None else ""
        benchmark_where = "WHERE br.created_at >= ?" if cutoff is not None else ""
        telemetry_runs = conn.execute(
            f"""
            SELECT COUNT(*) AS total,
                   AVG(duration_ms) AS avg_latency,
                   SUM(CASE WHEN cache_hit = 1 THEN 1 ELSE 0 END) AS cache_hits,
                   SUM(CASE WHEN ai_invoked = 1 THEN 1 ELSE 0 END) AS ai_invoked,
                   SUM(CASE WHEN parse_failure = 1 THEN 1 ELSE 0 END) AS parse_failures,
                   SUM(CASE WHEN timeout = 1 THEN 1 ELSE 0 END) AS timeouts
            FROM pipeline_telemetry_runs
            {run_where}
            """,
            params,
        ).fetchone()
        durations = [
            int(row["duration_ms"] or 0)
            for row in conn.execute(
                f"""
                SELECT duration_ms
                FROM pipeline_telemetry_runs
                {run_where}
                ORDER BY duration_ms ASC
                """,
                params,
            ).fetchall()
        ]
        stage_rows = conn.execute(
            f"""
            SELECT classifier_name, confidence_band, ai_model, prompt_version,
                   stop_reason, skip_reason, COUNT(*) AS count
            FROM pipeline_telemetry_stages
            {run_where}
            GROUP BY classifier_name, confidence_band, ai_model, prompt_version, stop_reason, skip_reason
            """,
            params,
        ).fetchall()
        benchmark_runs = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM benchmark_runs
            """
        ).fetchone()
        active_profiles = conn.execute(
            "SELECT COUNT(*) AS total FROM calibration_profiles WHERE active = 1"
        ).fetchone()
        profile_count = conn.execute(
            "SELECT COUNT(*) AS total FROM calibration_profiles"
        ).fetchone()
        benchmark_results = conn.execute(
            f"""
            SELECT br.confidence_band, br.correct, br.false_positive,
                   br.false_negative, br.abstained, br.classifier_source,
                   br.confidence,
                   br.predicted_action, br.expected_action
            FROM benchmark_results br
            JOIN benchmark_runs b ON b.run_id = br.run_id
            {benchmark_where}
            """,
            params,
        ).fetchall()
        telemetry_volume = conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM pipeline_telemetry_runs) AS runs,
                (SELECT COUNT(*) FROM pipeline_telemetry_stages) AS stages,
                (SELECT MIN(started_at) FROM pipeline_telemetry_runs) AS oldest,
                (SELECT COUNT(*) FROM pipeline_telemetry_runs WHERE completed_at IS NULL) AS incomplete
            """
        ).fetchone()

    total_runs = int(telemetry_runs["total"] or 0)
    raw_distribution = _count_by([row["confidence_band"] or "unknown" for row in benchmark_results])
    calibrated_distribution = _calibrated_distribution(benchmark_results)
    observed_accuracy = _accuracy_by_band(benchmark_results)
    classifier_counts: dict[str, int] = {}
    model_counts: dict[str, int] = {}
    prompt_counts: dict[str, int] = {}
    stop_reasons: dict[str, int] = {}
    skip_reasons: dict[str, int] = {}
    for row in stage_rows:
        classifier_counts[row["classifier_name"] or "unknown"] = classifier_counts.get(row["classifier_name"] or "unknown", 0) + int(row["count"])
        if row["ai_model"]:
            model_counts[row["ai_model"]] = model_counts.get(row["ai_model"], 0) + int(row["count"])
        if row["prompt_version"]:
            prompt_counts[row["prompt_version"]] = prompt_counts.get(row["prompt_version"], 0) + int(row["count"])
        if row["stop_reason"]:
            stop_reasons[row["stop_reason"]] = stop_reasons.get(row["stop_reason"], 0) + int(row["count"])
        if row["skip_reason"]:
            skip_reasons[row["skip_reason"]] = skip_reasons.get(row["skip_reason"], 0) + int(row["count"])

    return {
        "window": window,
        "summary": {
            "telemetry_coverage_rate": 1.0 if total_runs else 0.0,
            "ai_invocation_rate": _rate(telemetry_runs["ai_invoked"], total_runs),
            "cache_hit_rate": _rate(telemetry_runs["cache_hits"], total_runs),
            "average_latency_ms": float(telemetry_runs["avg_latency"]) if telemetry_runs["avg_latency"] is not None else None,
            "p95_latency_ms": _percentile(durations, 0.95),
            "benchmark_runs": int(benchmark_runs["total"] or 0),
            "active_calibration_profiles": int(active_profiles["total"] or 0),
        },
        "confidence": {
            "raw_distribution": raw_distribution,
            "calibrated_distribution": calibrated_distribution,
            "observed_accuracy_by_band": observed_accuracy,
            "expected_calibration_error": _active_metric("expected_calibration_error"),
            "brier_score": _active_metric("brier_score"),
        },
        "errors": {
            "false_positive_count": sum(1 for row in benchmark_results if row["false_positive"]),
            "false_negative_count": sum(1 for row in benchmark_results if row["false_negative"]),
            "abstention_rate": _rate(sum(1 for row in benchmark_results if row["abstained"]), len(benchmark_results)),
            "parse_failures": int(telemetry_runs["parse_failures"] or 0),
            "timeouts": int(telemetry_runs["timeouts"] or 0),
        },
        "utilization": {
            "classifier_counts": classifier_counts,
            "model_counts": model_counts,
            "prompt_version_counts": prompt_counts,
            "stop_reasons": stop_reasons,
            "skip_reasons": skip_reasons,
        },
        "diagnostics": {
            "telemetry_run_count": int(telemetry_volume["runs"] or 0),
            "telemetry_stage_count": int(telemetry_volume["stages"] or 0),
            "benchmark_row_count": len(benchmark_results),
            "calibration_profile_count": int(profile_count["total"] or 0),
            "estimated_telemetry_storage_bytes": int(telemetry_volume["runs"] or 0) * 512 + int(telemetry_volume["stages"] or 0) * 768,
            "oldest_telemetry_timestamp": telemetry_volume["oldest"],
            "incomplete_telemetry_runs": int(telemetry_volume["incomplete"] or 0),
            "stale_active_calibration_profiles": _stale_active_profiles(),
        },
        "benchmark_history": _recent_benchmark_runs(),
        "calibration_profiles": list_calibration_profiles(limit=20),
    }


def _active_metric(name: str) -> float | None:
    profiles = [item for item in list_calibration_profiles(limit=100) if item.get("active")]
    if not profiles:
        return None
    value = profiles[0].get(name)
    return float(value) if value is not None else None


def _calibrated_distribution(rows: list[Any]) -> dict[str, int]:
    profiles = [item for item in list_calibration_profiles(limit=100) if item.get("active")]
    if not profiles:
        return {}
    counts: dict[str, int] = {}
    for row in rows:
        normalized = _normalize_confidence(row["confidence"])
        if normalized is None:
            counts["unknown"] = counts.get("unknown", 0) + 1
            continue
        profile = _matching_profile_for_row(profiles, row)
        if profile is None:
            counts["unknown"] = counts.get("unknown", 0) + 1
            continue
        band = _calibrated_band_from_profile(profile, normalized)
        counts[band or "unknown"] = counts.get(band or "unknown", 0) + 1
    return counts


def _matching_profile_for_row(profiles: list[dict[str, Any]], row: Any) -> dict[str, Any] | None:
    classifier_source = row["classifier_source"]
    for profile in profiles:
        if profile.get("classifier_source") and profile.get("classifier_source") != classifier_source:
            continue
        return profile
    return None


def _calibrated_band_from_profile(profile: dict[str, Any], normalized_confidence: float) -> str | None:
    full_profile = get_calibration_profile(profile["profile_id"]) or profile
    for item in full_profile.get("bins", []):
        lower = float(item["lower_bound"])
        upper = float(item["upper_bound"])
        if normalized_confidence >= lower and (normalized_confidence < upper or upper >= 1.0 and normalized_confidence <= upper):
            observed = item.get("observed_accuracy")
            if observed is None:
                return "unknown"
            return reporting_confidence_band(float(observed) * 100.0)
    return None


def _recent_benchmark_runs() -> list[dict[str, Any]]:
    from pihole_ai.benchmark import list_benchmark_runs

    return list_benchmark_runs(limit=10)


def _stale_active_profiles() -> list[str]:
    stale = []
    for profile in [item for item in list_calibration_profiles(limit=100) if item.get("active")]:
        run = _benchmark_run_for_calibration(profile["source_id"]) if profile["source_type"] == "benchmark" else None
        if profile["source_type"] == "benchmark" and (run is None or run.get("status") != "completed"):
            stale.append(profile["profile_id"])
    return stale


def _window_cutoff(window: str) -> float | None:
    now = time.time()
    if window == "24h":
        return now - 24 * 60 * 60
    if window == "7d":
        return now - 7 * 24 * 60 * 60
    if window == "30d":
        return now - 30 * 24 * 60 * 60
    return None


def _count_by(values: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out


def _accuracy_by_band(rows: list[Any]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        band = row["confidence_band"] or "unknown"
        item = grouped.setdefault(band, {"sample_count": 0, "correct": 0, "observed_accuracy": None})
        item["sample_count"] += 1
        if row["correct"]:
            item["correct"] += 1
    for item in grouped.values():
        item["observed_accuracy"] = item["correct"] / item["sample_count"] if item["sample_count"] else None
    return grouped


def _percentile(values: list[int], fraction: float) -> int | None:
    if not values:
        return None
    index = max(0, min(len(values) - 1, int(round((len(values) - 1) * fraction))))
    return sorted(values)[index]


def _rate(numerator: Any, denominator: int) -> float:
    return float(numerator or 0) / denominator if denominator else 0.0


def print_profile(profile: dict[str, Any], *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(profile, indent=2, sort_keys=True))
        return
    print(f"{profile['profile_id']} {profile['name']} active={profile['active']}")
    print(f"  source={profile['source_type']}:{profile['source_id']} samples={profile['sample_count']}")
    print(f"  ece={_fmt(profile.get('expected_calibration_error'))} brier={_fmt(profile.get('brier_score'))}")


def print_profiles(profiles: list[dict[str, Any]], *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(profiles, indent=2, sort_keys=True))
        return
    if not profiles:
        print("No calibration profiles found.")
        return
    for profile in profiles:
        print(f"{profile['profile_id']} active={profile['active']} samples={profile['sample_count']} name={profile['name']}")


def print_reliability(metrics: dict[str, Any], *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(metrics, indent=2, sort_keys=True))
        return
    summary = metrics["summary"]
    print("Reliability:")
    print(f"  telemetry_coverage_rate: {summary['telemetry_coverage_rate']:.1%}")
    print(f"  ai_invocation_rate: {summary['ai_invocation_rate']:.1%}")
    print(f"  cache_hit_rate: {summary['cache_hit_rate']:.1%}")
    print(f"  benchmark_runs: {summary['benchmark_runs']}")
    print(f"  active_calibration_profiles: {summary['active_calibration_profiles']}")


def _fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)
