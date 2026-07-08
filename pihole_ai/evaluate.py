"""
Model and classifier benchmarking helpers for PiHole-AI.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from engine.classifiers.ai_classifier import AIClassifier
from engine.classifiers.pipeline import ClassifierPipeline
from engine.models import AnalysisRequest, AnalysisResult, DomainMetadata


@dataclass(frozen=True)
class BenchmarkCase:
    """
    Expected classification for one domain.
    """

    domain: str
    category: str
    risk: int
    query_count: int = 0
    device_count: int = 0
    recent_queries: int = 0


@dataclass(frozen=True)
class BenchmarkRow:
    """
    Actual classifier output compared with one benchmark case.
    """

    domain: str
    expected_category: str
    actual_category: str
    expected_risk: int
    actual_risk: int
    risk_error: int
    category_match: bool
    risk_within_tolerance: bool
    model: str
    confidence: int
    reason: str


@dataclass(frozen=True)
class BenchmarkResult:
    """
    Summary and per-domain rows for a benchmark run.
    """

    total: int
    category_matches: int
    risk_matches: int
    average_risk_error: float
    rows: list[BenchmarkRow]

    @property
    def category_accuracy(self) -> float:
        if self.total == 0:
            return 0.0

        return self.category_matches / self.total

    @property
    def risk_accuracy(self) -> float:
        if self.total == 0:
            return 0.0

        return self.risk_matches / self.total


def load_benchmark_cases(
    path: str | Path,
) -> list[BenchmarkCase]:
    """
    Load benchmark cases from a JSON or CSV fixture.
    """

    fixture = Path(path)

    if fixture.suffix.lower() == ".json":
        data = json.loads(fixture.read_text(encoding="utf-8"))

        if not isinstance(data, list):
            raise ValueError(
                "Benchmark JSON must contain a list of cases."
            )

        return [
            _case_from_mapping(item)
            for item in data
        ]

    if fixture.suffix.lower() == ".csv":
        with fixture.open("r", encoding="utf-8", newline="") as handle:
            return [
                _case_from_mapping(row)
                for row in csv.DictReader(handle)
            ]

    raise ValueError(
        "Benchmark fixture must be .json or .csv."
    )


def run_benchmark(
    cases: list[BenchmarkCase],
    risk_tolerance: int = 15,
    include_ai: bool = False,
    pipeline: ClassifierPipeline | None = None,
) -> BenchmarkResult:
    """
    Evaluate classifier output against expected labels.
    """

    classifier = pipeline or ClassifierPipeline()

    if not include_ai:
        classifier.classifiers = [
            item
            for item in classifier.classifiers
            if not isinstance(item, AIClassifier)
        ]

    rows = [
        _evaluate_case(
            classifier=classifier,
            case=case,
            risk_tolerance=risk_tolerance,
        )
        for case in cases
    ]
    total_error = sum(row.risk_error for row in rows)

    return BenchmarkResult(
        total=len(rows),
        category_matches=sum(1 for row in rows if row.category_match),
        risk_matches=sum(1 for row in rows if row.risk_within_tolerance),
        average_risk_error=(total_error / len(rows)) if rows else 0.0,
        rows=rows,
    )


def print_benchmark(
    path: str | Path,
    risk_tolerance: int = 15,
    include_ai: bool = False,
    as_json: bool = False,
) -> BenchmarkResult:
    """
    Run a benchmark fixture and print a human or JSON summary.
    """

    result = run_benchmark(
        cases=load_benchmark_cases(path),
        risk_tolerance=risk_tolerance,
        include_ai=include_ai,
    )

    if as_json:
        print(json.dumps(_result_to_dict(result), indent=2))
        return result

    print(
        "Benchmark complete: "
        f"cases={result.total}, "
        f"category_accuracy={result.category_accuracy:.1%}, "
        f"risk_accuracy={result.risk_accuracy:.1%}, "
        f"avg_risk_error={result.average_risk_error:.1f}"
    )

    mismatches = [
        row
        for row in result.rows
        if not row.category_match or not row.risk_within_tolerance
    ]

    if mismatches:
        print("Mismatches:")

    for row in mismatches:
        print(
            f"- {row.domain}: expected "
            f"{row.expected_category}/{row.expected_risk}, got "
            f"{row.actual_category}/{row.actual_risk} "
            f"({row.model}, error={row.risk_error})"
        )

    return result


def _case_from_mapping(
    values: dict[str, Any],
) -> BenchmarkCase:
    """
    Convert one mapping into a benchmark case.
    """

    domain = str(values.get("domain", "")).strip().lower().rstrip(".")
    category = str(values.get("category", "")).strip()

    if not domain:
        raise ValueError(
            "Benchmark case is missing domain."
        )

    if not category:
        raise ValueError(
            f"Benchmark case for {domain} is missing category."
        )

    return BenchmarkCase(
        domain=domain,
        category=category,
        risk=int(values.get("risk", 0) or 0),
        query_count=int(values.get("query_count", 0) or 0),
        device_count=int(values.get("device_count", 0) or 0),
        recent_queries=int(values.get("recent_queries", 0) or 0),
    )


def _evaluate_case(
    classifier: ClassifierPipeline,
    case: BenchmarkCase,
    risk_tolerance: int,
) -> BenchmarkRow:
    """
    Evaluate one benchmark case.
    """

    result = _classify(
        classifier=classifier,
        case=case,
    )
    risk_error = abs(result.risk - case.risk)

    return BenchmarkRow(
        domain=case.domain,
        expected_category=case.category,
        actual_category=result.category,
        expected_risk=case.risk,
        actual_risk=result.risk,
        risk_error=risk_error,
        category_match=result.category == case.category,
        risk_within_tolerance=risk_error <= risk_tolerance,
        model=result.model,
        confidence=result.confidence,
        reason=result.reason,
    )


def _classify(
    classifier: ClassifierPipeline,
    case: BenchmarkCase,
) -> AnalysisResult:
    """
    Classify a benchmark case with fixture metadata.
    """

    request = AnalysisRequest(
        domain=case.domain,
        metadata=DomainMetadata(
            domain=case.domain,
            query_count=case.query_count,
            device_count=case.device_count,
            recent_queries=case.recent_queries,
        ),
    )

    try:
        return classifier.classify(request)

    except RuntimeError:
        return AnalysisResult(
            domain=case.domain,
            risk=50,
            confidence=0,
            category="unknown",
            reason="No deterministic classifier matched.",
            model="benchmark-fallback",
        )


def _result_to_dict(
    result: BenchmarkResult,
) -> dict[str, Any]:
    """
    Convert benchmark result to a JSON-safe mapping.
    """

    return {
        "total": result.total,
        "category_matches": result.category_matches,
        "risk_matches": result.risk_matches,
        "category_accuracy": result.category_accuracy,
        "risk_accuracy": result.risk_accuracy,
        "average_risk_error": result.average_risk_error,
        "rows": [
            {
                "domain": row.domain,
                "expected_category": row.expected_category,
                "actual_category": row.actual_category,
                "expected_risk": row.expected_risk,
                "actual_risk": row.actual_risk,
                "risk_error": row.risk_error,
                "category_match": row.category_match,
                "risk_within_tolerance": row.risk_within_tolerance,
                "model": row.model,
                "confidence": row.confidence,
                "reason": row.reason,
            }
            for row in result.rows
        ],
    }
