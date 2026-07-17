"""
Persistent benchmark history and regression comparison.
"""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from statistics import median
from typing import Any, Iterator

from core import db
from engine.classifiers.ai_classifier import AIClassifier
from engine.classifiers.pipeline import ClassifierPipeline
from engine.models import AnalysisRequest, DomainMetadata
from engine.telemetry import confidence_band
from pihole_ai.evaluate import BenchmarkCase, load_benchmark_cases
from pihole_ai.version import get_version


DEFAULT_TOLERANCES = {
    "max_accuracy_drop": 0.02,
    "max_f1_drop": 0.02,
    "max_false_positive_rate_increase": 0.0,
    "max_false_negative_rate_increase": 0.0,
    "max_latency_increase": 0.25,
    "max_abstention_rate_increase": 0.05,
}


def benchmark_run_id() -> str:
    return f"bench_{uuid.uuid4().hex}"


def benchmark_result_id() -> str:
    return f"bres_{uuid.uuid4().hex}"


def fixture_digest(path: str | Path) -> str:
    payload = Path(path).read_bytes()
    return hashlib.sha256(payload).hexdigest()


def run_benchmark_command(
    fixture: str | Path,
    *,
    name: str = "",
    model: str = "",
    prompt_version: str = "",
    risk_tolerance: int = 15,
    threshold: str = "",
    notes: str = "",
    persist: bool = True,
    include_ai: bool = False,
) -> dict[str, Any]:
    started_at = time.time()
    run_id = benchmark_run_id()
    fixture_path = Path(fixture)
    digest = fixture_digest(fixture_path)
    rows: list[dict[str, Any]] = []
    status = "completed"
    error_summary = ""

    try:
        cases = load_benchmark_cases(fixture_path)
        rows = _run_cases_isolated(
            cases,
            include_ai=include_ai,
            risk_tolerance=risk_tolerance,
        )
    except Exception as exc:
        cases = []
        status = "failed"
        error_summary = str(exc)

    completed_at = time.time()
    metrics = _aggregate_metrics(rows)
    run = {
        "run_id": run_id,
        "name": name,
        "fixture_identifier": str(fixture_path),
        "fixture_digest": digest,
        "started_at": started_at,
        "completed_at": completed_at,
        "status": status,
        "pihole_ai_version": get_version(),
        "git_commit": _git_commit(),
        "model_name": model or None,
        "prompt_version": prompt_version or None,
        "classifier_config_id": "default-with-ai" if include_ai else "default-deterministic",
        "threshold_config": {"threshold": threshold} if threshold else {},
        "risk_tolerance": risk_tolerance,
        "sample_count": len(cases),
        "notes": notes,
        "duration_ms": int(round((completed_at - started_at) * 1000)),
        "error_summary": error_summary or None,
        "metrics": metrics,
        "results": rows,
    }

    if persist:
        save_benchmark_run(run)

    return run


@contextmanager
def _isolated_database() -> Iterator[None]:
    previous = db.DATABASE_PATH
    with tempfile.TemporaryDirectory() as tmpdir:
        db.DATABASE_PATH = Path(tmpdir) / "benchmark.db"
        db.init_db()
        try:
            yield
        finally:
            db.DATABASE_PATH = previous


def _run_cases_isolated(
    cases: list[BenchmarkCase],
    *,
    include_ai: bool,
    risk_tolerance: int,
) -> list[dict[str, Any]]:
    with _isolated_database():
        pipeline = ClassifierPipeline()
        if not include_ai:
            pipeline.classifiers = [
                item
                for item in pipeline.classifiers
                if not isinstance(item, AIClassifier)
            ]
        return [
            _run_one_case(
                pipeline,
                case,
                risk_tolerance=risk_tolerance,
            )
            for case in cases
        ]


def _run_one_case(
    pipeline: ClassifierPipeline,
    case: BenchmarkCase,
    *,
    risk_tolerance: int,
) -> dict[str, Any]:
    started = time.monotonic()
    sample_id = case.sample_id or case.domain
    error = None
    try:
        result = pipeline.classify(
            AnalysisRequest(
                domain=case.domain,
                metadata=DomainMetadata(
                    domain=case.domain,
                    query_count=case.query_count,
                    device_count=case.device_count,
                    recent_queries=case.recent_queries,
                ),
            )
        )
    except Exception as exc:
        result = None
        error = str(exc)

    duration_ms = int(round((time.monotonic() - started) * 1000))
    expected_action = case.expected_action or _action_for(case.category, case.risk)
    if result is None:
        predicted_category = None
        predicted_action = None
        confidence = None
        source = None
        correct = False
        false_positive = False
        false_negative = expected_action == "block"
        abstained = True
    else:
        predicted_category = result.category
        predicted_action = _action_for(result.category, result.risk)
        confidence = result.confidence
        source = result.model
        risk_error = abs(result.risk - case.risk)
        correct = (
            predicted_action == expected_action
            if case.expected_action
            else result.category == case.category and risk_error <= risk_tolerance
        )
        false_positive = expected_action != "block" and predicted_action == "block"
        false_negative = expected_action == "block" and predicted_action != "block"
        abstained = predicted_action == "review" or result.category == "unknown"

    return {
        "result_id": benchmark_result_id(),
        "sample_id": sample_id,
        "domain": case.domain,
        "expected_category": case.category,
        "expected_action": expected_action,
        "predicted_category": predicted_category,
        "predicted_action": predicted_action,
        "confidence": confidence,
        "confidence_band": confidence_band(confidence),
        "classifier_source": source,
        "correct": correct,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "abstained": abstained,
        "duration_ms": duration_ms,
        "error_summary": error,
        "telemetry_run_id": None,
    }


def _action_for(category: str, risk: int) -> str:
    if category in {"malware", "phishing", "command-and-control"} or risk >= 80:
        return "block"
    if risk <= 29 or category in {"benign", "infrastructure"}:
        return "allow"
    return "review"


def _aggregate_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    if total == 0:
        return {
            "sample_count": 0,
            "accuracy": None,
            "precision": None,
            "recall": None,
            "f1": None,
            "false_positive_rate": None,
            "false_negative_rate": None,
            "abstention_rate": None,
            "error_rate": None,
            "average_latency_ms": None,
            "p50_latency_ms": None,
            "p95_latency_ms": None,
            "ai_invocation_rate": None,
            "cache_hit_rate": None,
            "category_metrics": {},
            "classifier_source_counts": {},
        }

    correct = sum(1 for row in rows if row["correct"])
    false_positive = sum(1 for row in rows if row["false_positive"])
    false_negative = sum(1 for row in rows if row["false_negative"])
    abstained = sum(1 for row in rows if row["abstained"])
    errors = sum(1 for row in rows if row["error_summary"])
    expected_blocks = sum(1 for row in rows if row["expected_action"] == "block")
    expected_non_blocks = total - expected_blocks
    predicted_blocks = sum(1 for row in rows if row["predicted_action"] == "block")
    true_positive = sum(
        1
        for row in rows
        if row["expected_action"] == "block" and row["predicted_action"] == "block"
    )
    precision = true_positive / predicted_blocks if predicted_blocks else None
    recall = true_positive / expected_blocks if expected_blocks else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall > 0
        else None
    )
    durations = [int(row["duration_ms"] or 0) for row in rows]
    classifier_counts: dict[str, int] = {}
    category_metrics: dict[str, dict[str, int]] = {}
    for row in rows:
        source = row["classifier_source"] or "unknown"
        classifier_counts[source] = classifier_counts.get(source, 0) + 1
        category = row["expected_category"] or "unknown"
        metrics = category_metrics.setdefault(category, {"total": 0, "correct": 0})
        metrics["total"] += 1
        if row["correct"]:
            metrics["correct"] += 1

    return {
        "sample_count": total,
        "accuracy": correct / total,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive / expected_non_blocks if expected_non_blocks else None,
        "false_negative_rate": false_negative / expected_blocks if expected_blocks else None,
        "abstention_rate": abstained / total,
        "error_rate": errors / total,
        "average_latency_ms": sum(durations) / total,
        "p50_latency_ms": median(durations),
        "p95_latency_ms": _percentile(durations, 0.95),
        "ai_invocation_rate": _source_rate(rows, "ai"),
        "cache_hit_rate": None,
        "category_metrics": category_metrics,
        "classifier_source_counts": classifier_counts,
    }


def _percentile(values: list[int], fraction: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def _source_rate(rows: list[dict[str, Any]], source: str) -> float:
    if not rows:
        return 0.0
    return sum(1 for row in rows if row["classifier_source"] == source) / len(rows)


def save_benchmark_run(run: dict[str, Any]) -> None:
    now = time.time()
    with db.transaction() as conn:
        conn.execute(
            """
            INSERT INTO benchmark_runs
            (
                run_id, name, fixture_identifier, fixture_digest, started_at,
                completed_at, status, pihole_ai_version, git_commit, model_name,
                prompt_version, classifier_config_id, threshold_config_json,
                risk_tolerance, sample_count, notes, duration_ms, error_summary,
                metrics_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run["run_id"],
                run["name"],
                run["fixture_identifier"],
                run["fixture_digest"],
                run["started_at"],
                run["completed_at"],
                run["status"],
                run["pihole_ai_version"],
                run["git_commit"],
                run["model_name"],
                run["prompt_version"],
                run["classifier_config_id"],
                json.dumps(run["threshold_config"], sort_keys=True),
                run["risk_tolerance"],
                run["sample_count"],
                run["notes"],
                run["duration_ms"],
                run["error_summary"],
                json.dumps(run["metrics"], sort_keys=True),
                now,
            ),
        )
        conn.executemany(
            """
            INSERT INTO benchmark_results
            (
                result_id, run_id, sample_id, domain, expected_category,
                expected_action, predicted_category, predicted_action,
                confidence, confidence_band, classifier_source, correct,
                false_positive, false_negative, abstained, duration_ms,
                error_summary, telemetry_run_id, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    row["result_id"],
                    run["run_id"],
                    row["sample_id"],
                    row["domain"],
                    row["expected_category"],
                    row["expected_action"],
                    row["predicted_category"],
                    row["predicted_action"],
                    row["confidence"],
                    row["confidence_band"],
                    row["classifier_source"],
                    1 if row["correct"] else 0,
                    1 if row["false_positive"] else 0,
                    1 if row["false_negative"] else 0,
                    1 if row["abstained"] else 0,
                    row["duration_ms"],
                    row["error_summary"],
                    row["telemetry_run_id"],
                    now,
                )
                for row in run["results"]
            ],
        )


def list_benchmark_runs(limit: int = 20) -> list[dict[str, Any]]:
    with db.closing(db.Database.open_read_only(db._database_path())) as conn:
        rows = conn.execute(
            """
            SELECT run_id, name, fixture_identifier, fixture_digest, started_at,
                   completed_at, status, sample_count, metrics_json
            FROM benchmark_runs
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (max(1, min(100, int(limit or 20))),),
        ).fetchall()
    return [_run_row_to_dict(row, include_metrics=True) for row in rows]


def get_benchmark_run(run_id: str, *, include_results: bool = True) -> dict[str, Any] | None:
    with db.closing(db.Database.open_read_only(db._database_path())) as conn:
        row = conn.execute(
            "SELECT * FROM benchmark_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        run = _run_row_to_dict(row, include_metrics=True)
        if include_results:
            run["results"] = [
                _result_row_to_dict(item)
                for item in conn.execute(
                    "SELECT * FROM benchmark_results WHERE run_id = ? ORDER BY sample_id ASC",
                    (run_id,),
                ).fetchall()
            ]
    return run


def compare_benchmark_runs(
    baseline_run_id: str,
    candidate_run_id: str,
    *,
    tolerances: dict[str, float] | None = None,
    allow_different_fixture: bool = False,
) -> dict[str, Any]:
    baseline = get_benchmark_run(baseline_run_id)
    candidate = get_benchmark_run(candidate_run_id)
    reasons: list[str] = []
    if baseline is None or candidate is None:
        return {"verdict": "invalid", "passed": False, "reasons": ["run_not_found"]}
    if baseline["status"] != "completed" or candidate["status"] != "completed":
        return {"verdict": "invalid", "passed": False, "reasons": ["run_incomplete"]}
    if baseline["fixture_digest"] != candidate["fixture_digest"] and not allow_different_fixture:
        return {
            "verdict": "invalid",
            "passed": False,
            "reasons": ["fixture_digest_mismatch"],
            "fixture_digest_mismatch": True,
            "baseline": baseline,
            "candidate": candidate,
        }

    limits = {**DEFAULT_TOLERANCES, **(tolerances or {})}
    metric_deltas = _metric_deltas(baseline["metrics"], candidate["metrics"])
    if _exceeds_limit(_drop(metric_deltas, "accuracy"), limits["max_accuracy_drop"]):
        reasons.append("accuracy_drop")
    if _exceeds_limit(_drop(metric_deltas, "f1"), limits["max_f1_drop"]):
        reasons.append("f1_drop")
    if _exceeds_limit(
        _increase(metric_deltas, "false_positive_rate"),
        limits["max_false_positive_rate_increase"],
    ):
        reasons.append("false_positive_rate_increase")
    if _exceeds_limit(
        _increase(metric_deltas, "false_negative_rate"),
        limits["max_false_negative_rate_increase"],
    ):
        reasons.append("false_negative_rate_increase")
    if _exceeds_limit(
        _latency_increase(baseline["metrics"], candidate["metrics"]),
        limits["max_latency_increase"],
    ):
        reasons.append("latency_increase")
    if _exceeds_limit(
        _increase(metric_deltas, "abstention_rate"),
        limits["max_abstention_rate_increase"],
    ):
        reasons.append("abstention_rate_increase")

    changes = _sample_changes(baseline.get("results", []), candidate.get("results", []))
    verdict = "regression" if reasons else "pass"
    return {
        "verdict": verdict,
        "passed": not reasons,
        "reasons": reasons,
        "fixture_digest_mismatch": baseline["fixture_digest"] != candidate["fixture_digest"],
        "baseline_run_id": baseline_run_id,
        "candidate_run_id": candidate_run_id,
        "baseline_metrics": baseline["metrics"],
        "candidate_metrics": candidate["metrics"],
        "metric_deltas": metric_deltas,
        "sample_changes": changes,
        "tolerances": limits,
    }


def _run_row_to_dict(row: Any, *, include_metrics: bool) -> dict[str, Any]:
    item = dict(row)
    item["metrics"] = json.loads(item.pop("metrics_json", "{}") or "{}") if include_metrics else {}
    try:
        item["threshold_config"] = json.loads(item.pop("threshold_config_json", "{}") or "{}")
    except KeyError:
        pass
    return item


def _result_row_to_dict(row: Any) -> dict[str, Any]:
    item = dict(row)
    for key in ("correct", "false_positive", "false_negative", "abstained"):
        item[key] = bool(item[key])
    return item


def _metric_deltas(base: dict[str, Any], cand: dict[str, Any]) -> dict[str, dict[str, Any]]:
    keys = sorted(set(base) | set(cand))
    out = {}
    for key in keys:
        before = base.get(key)
        after = cand.get(key)
        if isinstance(before, (int, float)) and isinstance(after, (int, float)):
            diff = after - before
            pct = diff / before if before else None
        else:
            diff = None
            pct = None
        out[key] = {"baseline": before, "candidate": after, "difference": diff, "percent_difference": pct}
    return out


def _drop(deltas: dict[str, dict[str, Any]], key: str) -> float:
    diff = deltas.get(key, {}).get("difference")
    return -diff if isinstance(diff, (int, float)) and diff < 0 else 0.0


def _increase(deltas: dict[str, dict[str, Any]], key: str) -> float:
    diff = deltas.get(key, {}).get("difference")
    return diff if isinstance(diff, (int, float)) and diff > 0 else 0.0


def _latency_increase(base: dict[str, Any], cand: dict[str, Any]) -> float:
    before = base.get("average_latency_ms")
    after = cand.get("average_latency_ms")
    if not before or not after or after <= before:
        return 0.0
    return (after - before) / before


def _exceeds_limit(value: float, limit: float) -> bool:
    return value - limit > 1e-12


def _sample_changes(base_rows: list[dict[str, Any]], cand_rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    base = {row["sample_id"]: row for row in base_rows}
    cand = {row["sample_id"]: row for row in cand_rows}
    shared = sorted(set(base) & set(cand))
    return {
        "new_false_positives": [key for key in shared if not base[key]["false_positive"] and cand[key]["false_positive"]],
        "new_false_negatives": [key for key in shared if not base[key]["false_negative"] and cand[key]["false_negative"]],
        "resolved_false_positives": [key for key in shared if base[key]["false_positive"] and not cand[key]["false_positive"]],
        "resolved_false_negatives": [key for key in shared if base[key]["false_negative"] and not cand[key]["false_negative"]],
    }


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return None
    return result.stdout.strip() or None


def print_run(run: dict[str, Any], *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(run, indent=2, sort_keys=True))
        return
    print(
        f"Benchmark {run['run_id']} status={run['status']} "
        f"samples={run['sample_count']} accuracy={_fmt(run['metrics'].get('accuracy'))}"
    )


def print_list(runs: list[dict[str, Any]], *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(runs, indent=2, sort_keys=True))
        return
    if not runs:
        print("No benchmark runs found.")
        return
    for run in runs:
        print(
            f"{run['run_id']} status={run['status']} samples={run['sample_count']} "
            f"accuracy={_fmt(run['metrics'].get('accuracy'))} name={run.get('name') or ''}"
        )


def print_comparison(comparison: dict[str, Any], *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(comparison, indent=2, sort_keys=True))
        return
    print(f"Benchmark comparison: {comparison['verdict']}")
    for reason in comparison.get("reasons", []):
        print(f"- {reason}")


def _fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.1%}"
    return str(value)
