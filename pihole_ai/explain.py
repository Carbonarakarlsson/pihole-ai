"""
Domain explanation helpers.
"""

from __future__ import annotations

import json
import re
from typing import Any

from core.db import (
    compare_decisions,
    get_analysis,
    get_decision,
    get_decision_record,
    get_decision_evidence,
    get_domain_metadata,
    get_domain_reputation,
    get_domain_rule,
    get_pipeline_telemetry_for_domain,
    get_recent_actions,
    get_threat_intel,
    is_valid_decision_id,
    list_decision_history,
)
from engine.evidence import (
    EVIDENCE_POLICY_VERSION,
    detect_conflicts,
    evidence_sort_key,
)
from pihole_ai.calibration import calibration_for_confidence


DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,253}$")


def normalize_domain(
    domain: str,
) -> str:
    """
    Normalize a domain for lookup.
    """

    return domain.strip().lower().rstrip(".")


def is_valid_domain_query(
    domain: str,
) -> bool:
    normalized = normalize_domain(domain)
    return bool(normalized and DOMAIN_PATTERN.match(normalized))


def row_to_dict(
    row: Any,
) -> dict[str, Any] | None:
    """
    Convert a database row to a dictionary.
    """

    if row is None:
        return None

    return dict(row)


def parse_signals(
    value: str | None,
) -> list[str]:
    """
    Parse JSON-encoded signal lists.
    """

    try:
        parsed = json.loads(value or "[]")

    except json.JSONDecodeError:
        return []

    if not isinstance(parsed, list):
        return []

    return [
        str(item)
        for item in parsed
        if str(item)
    ]


def explain_domain(
    domain: str,
    action_limit: int = 10,
    decision_id: str | None = None,
) -> dict[str, Any]:
    """
    Collect all known evidence for a domain.
    """

    normalized = normalize_domain(
        domain,
    )
    if not is_valid_domain_query(normalized):
        raise ValueError("invalid domain")

    analysis = row_to_dict(
        get_analysis(normalized),
    )
    selected_decision = None
    if decision_id is not None:
        if not is_valid_decision_id(decision_id):
            raise ValueError("invalid decision id")
        selected_decision = get_decision(decision_id)
        if selected_decision is None or selected_decision.get("domain") != normalized:
            raise LookupError("decision not found")
        evidence = sorted(
            selected_decision.get("evidence", []),
            key=evidence_sort_key,
        )
        decision_record = selected_decision
    else:
        evidence = sorted(
            get_decision_evidence(normalized),
            key=evidence_sort_key,
        )
        decision_record = get_decision_record(normalized)
    reputation = row_to_dict(
        get_domain_reputation(normalized),
    )

    if reputation is not None:
        reputation["signals"] = parse_signals(
            reputation.get("signals"),
        )

    actions = [
        dict(row)
        for row in get_recent_actions(
            limit=action_limit,
            search=normalized,
        )
        if row["domain"] == normalized
    ]

    explanation = {
        "domain": normalized,
        "rule": row_to_dict(
            get_domain_rule(normalized),
        ),
        "threat_intel": row_to_dict(
            get_threat_intel(normalized),
        ),
        "reputation": reputation,
        "analysis": analysis,
        "evidence": evidence,
        "metadata": get_domain_metadata(
            normalized,
        ),
        "actions": actions,
    }
    explanation["decision"] = summarize_decision(
        explanation,
        decision_record,
    )
    explanation["decisive_evidence"] = [
        item
        for item in evidence
        if item.get("decisive")
    ]
    explanation["risk_evidence"] = [
        item
        for item in evidence
        if item.get("polarity") == "risk" and not item.get("decisive")
    ]
    explanation["safety_evidence"] = [
        item
        for item in evidence
        if item.get("polarity") == "safety" and not item.get("decisive")
    ]
    explanation["neutral_evidence"] = [
        item
        for item in evidence
        if item.get("polarity") == "neutral" and not item.get("decisive")
    ]
    explanation["classifier_trace"] = (
        decision_record.get("classifier_trace", [])
        if decision_record is not None
        else []
    )
    telemetry_decision_id = (
        decision_record.get("decision_id")
        if decision_record is not None
        else None
    )
    telemetry = _safe_telemetry_lookup(
        normalized,
        decision_id=telemetry_decision_id,
    )
    explanation["telemetry"] = telemetry
    explanation["pipeline_timeline"] = telemetry.get("pipeline_timeline", [])
    explanation["calibration"] = _safe_calibration_lookup(
        explanation["decision"],
        telemetry,
    )
    explanation["conflicts"] = (
        decision_record.get("conflicts", [])
        if decision_record is not None
        else detect_conflicts(evidence)
    )
    explanation["policy_version"] = (
        decision_record.get("policy_version", EVIDENCE_POLICY_VERSION)
        if decision_record is not None
        else EVIDENCE_POLICY_VERSION
    )
    explanation["legacy_analysis"] = (
        analysis is not None
        and decision_record is None
    )
    explanation["legacy"] = explanation["legacy_analysis"]
    if explanation["legacy"]:
        explanation["legacy_note"] = "This decision predates structured evidence storage."
    else:
        explanation["legacy_note"] = ""
    explanation["summary"] = summarize_explanation(
        explanation,
    )

    return explanation


def _safe_telemetry_lookup(
    domain: str,
    *,
    decision_id: str | None,
) -> dict[str, Any]:
    try:
        telemetry = get_pipeline_telemetry_for_domain(
            domain,
            decision_id=decision_id,
        )
    except Exception:
        telemetry = None

    if telemetry is None:
        return {
            "available": False,
            "reason": "telemetry unavailable",
            "pipeline_timeline": [],
        }

    telemetry.setdefault("available", True)
    telemetry.setdefault("pipeline_timeline", telemetry.get("stages", []))
    return telemetry


def _safe_calibration_lookup(
    decision: dict[str, Any] | None,
    telemetry: dict[str, Any],
) -> dict[str, Any]:
    if decision is None:
        return {
            "available": False,
            "observational": True,
            "reason": "no decision confidence available",
        }
    try:
        source = decision.get("source")
        ai_model = telemetry.get("ai_model") if telemetry else None
        prompt_version = telemetry.get("prompt_version") if telemetry else None
        payload = calibration_for_confidence(
            decision.get("confidence"),
            classifier_source=source,
            model_name=ai_model,
            prompt_version=prompt_version,
        )
    except Exception:
        return {
            "available": False,
            "observational": True,
            "reason": "calibration unavailable",
        }

    payload["available"] = payload.get("profile_id") is not None
    if not payload["available"]:
        payload["reason"] = "no active matching calibration profile"
    return payload


def decision_history(
    domain: str,
    limit: int = 20,
    before: float | None = None,
) -> dict[str, Any]:
    normalized = normalize_domain(domain)
    if not is_valid_domain_query(normalized):
        raise ValueError("invalid domain")
    latest = get_decision_record(normalized)
    latest_id = latest.get("decision_id") if latest else None
    history = list_decision_history(
        normalized,
        limit=limit,
        before=before,
    )
    for item in history:
        item["current"] = bool(latest_id and item.get("decision_id") == latest_id)
        item.pop("decisive_evidence_ids", None)
        item.pop("classifier_trace", None)
        item.pop("conflicts", None)
    return {
        "domain": normalized,
        "history": history,
        "limit": limit,
        "before": before,
    }


def compare_domain_decisions(
    domain: str,
    older_id: str,
    newer_id: str,
) -> dict[str, Any]:
    normalized = normalize_domain(domain)
    if not is_valid_domain_query(normalized):
        raise ValueError("invalid domain")
    if not is_valid_decision_id(older_id) or not is_valid_decision_id(newer_id):
        raise ValueError("invalid decision id")
    comparison = compare_decisions(older_id, newer_id)
    if comparison is None or comparison.get("domain") != normalized:
        raise LookupError("decision not found")
    return comparison


def summarize_decision(
    explanation: dict[str, Any],
    decision_record: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """
    Summarize the latest stored decision in a stable API shape.
    """

    analysis = explanation["analysis"]
    if analysis is None:
        return None

    if decision_record is not None:
        return {
            "decision_id": decision_record.get("decision_id"),
            "domain": decision_record["domain"],
            "verdict": decision_record["verdict"],
            "risk_score": decision_record["risk_score"],
            "confidence": decision_record["confidence"],
            "category": decision_record["category"],
            "source": decision_record["source"],
            "explanation": decision_record["explanation"],
            "decisive_evidence_ids": decision_record["decisive_evidence_ids"],
            "classifier_trace": decision_record["classifier_trace"],
            "conflicts": decision_record["conflicts"],
            "legacy": decision_record["legacy"],
            "policy_version": decision_record["policy_version"],
            "application_version": decision_record.get("application_version", ""),
            "schema_version": decision_record.get("schema_version"),
            "evidence_truncated": decision_record["evidence_truncated"],
            "created_at": decision_record["created_at"],
            "evidence_count": len(explanation["evidence"]),
        }

    evidence = explanation["evidence"]
    decisive = [
        item["evidence_id"]
        for item in evidence
        if item.get("decisive")
    ]

    return {
        "risk": analysis["risk"],
        "risk_score": analysis["risk"],
        "confidence": analysis["confidence"],
        "category": analysis["category"],
        "source": analysis["model"],
        "explanation": analysis["reason"],
        "evidence_count": len(evidence),
        "decisive_evidence_ids": decisive,
        "verdict": _verdict_for_analysis(analysis),
        "classifier_trace": [],
        "conflicts": [],
        "legacy": True,
        "policy_version": EVIDENCE_POLICY_VERSION,
        "created_at": analysis.get("analyzed_at", 0),
    }


def _verdict_for_analysis(
    analysis: dict[str, Any],
) -> str:
    risk = int(analysis.get("risk", 0) or 0)
    category = str(analysis.get("category", "unknown"))
    if risk >= 80 or category in {"malware", "phishing", "command-and-control"}:
        return "malicious"
    if risk >= 60:
        return "suspicious"
    if risk <= 29:
        return "safe"
    return "unknown"


def summarize_explanation(
    explanation: dict[str, Any],
) -> str:
    """
    Return the strongest currently known signal.
    """

    rule = explanation["rule"]

    if rule is not None:
        return f"manual {rule['decision']} rule"

    threat = explanation["threat_intel"]

    if threat is not None:
        return (
            f"threat-intel match from {threat['source']} "
            f"as {threat['category']}"
        )

    reputation = explanation["reputation"]

    if reputation is not None and reputation["score"] >= 70:
        return f"high learned reputation score {reputation['score']}"

    analysis = explanation["analysis"]

    if analysis is not None:
        evidence = explanation.get("evidence", [])
        if evidence:
            decisive = [
                item
                for item in evidence
                if item.get("decisive")
            ]
            if decisive:
                return f"decisive evidence from {decisive[0]['classifier']}"
            return (
                f"stored decision risk {analysis['risk']} "
                f"from {len(evidence)} evidence item(s)"
            )
        return (
            f"cached analysis risk {analysis['risk']} "
            f"category {analysis['category']}"
        )

    metadata = explanation["metadata"]

    if metadata["query_count"] > 0:
        return "observed locally without a strong classification"

    return "no local evidence found"


def print_explanation(
    domain: str,
    as_json: bool = False,
    history: bool = False,
    decision_id: str | None = None,
    compare: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """
    Print an explanation and return the collected data.
    """

    if history:
        payload = decision_history(domain)
        if as_json:
            print(json.dumps(payload, indent=2))
            return payload
        print(f"PiHole-AI decision history for {payload['domain']}")
        if not payload["history"]:
            print("  none")
        for item in payload["history"]:
            current = " current" if item.get("current") else ""
            print(
                "  "
                f"{item['created_at']} {item['decision_id']}{current} "
                f"verdict={item['verdict']} risk={item['risk_score']} "
                f"confidence={item['confidence']} category={item['category']} "
                f"source={item['source']} trigger={item['trigger']} "
                f"policy={item['policy_version']}"
            )
        return payload

    if compare is not None:
        payload = compare_domain_decisions(domain, compare[0], compare[1])
        if as_json:
            print(json.dumps(payload, indent=2))
            return payload
        print(f"PiHole-AI decision comparison for {payload['domain']}")
        print(f"  older: {payload['older_decision_id']}")
        print(f"  newer: {payload['newer_decision_id']}")
        print(f"  verdict_changed: {payload['verdict_changed']}")
        print(f"  risk_delta: {payload['risk_delta']:+.0f}")
        print(f"  confidence_delta: {payload['confidence_delta']:+.2f}")
        print(f"  policy_changed: {payload['policy_changed']}")
        print(f"  decisive_evidence_changed: {payload['decisive_evidence_changed']}")
        print(f"  evidence_added: {len(payload['added_evidence'])}")
        print(f"  evidence_removed: {len(payload['removed_evidence'])}")
        print(f"  evidence_changed: {len(payload['changed_evidence'])}")
        print(f"  summary: {payload['summary']}")
        return payload

    explanation = explain_domain(
        domain,
        decision_id=decision_id,
    )

    if as_json:
        print(
            json.dumps(
                explanation,
                indent=2,
            )
        )
        return explanation

    print(f"PiHole-AI explanation for {explanation['domain']}")
    print(f"  summary: {explanation['summary']}")

    decision = explanation.get("decision")
    print("  Final decision:")
    if decision is not None:
        print(
            "    "
            f"verdict={decision.get('verdict', 'unknown')} "
            f"risk={decision.get('risk_score', decision.get('risk'))}/100 "
            f"confidence={decision['confidence']} "
            f"category={decision['category']} source={decision['source']}"
        )
        print(f"    explanation: {decision['explanation']}")
    else:
        print("    none")

    _print_calibration(
        explanation.get("calibration", {}),
    )

    _print_evidence_group(
        "Decisive evidence",
        explanation.get("decisive_evidence", []),
    )
    _print_evidence_group(
        "Risk evidence",
        explanation.get("risk_evidence", []),
    )
    _print_evidence_group(
        "Safety evidence",
        explanation.get("safety_evidence", []),
    )
    _print_evidence_group(
        "Neutral evidence",
        explanation.get("neutral_evidence", []),
    )
    _print_trace(
        explanation.get("classifier_trace", []),
    )
    _print_telemetry(
        explanation.get("telemetry", {}),
    )
    _print_list("Conflicts", explanation.get("conflicts", []))
    if explanation.get("legacy"):
        print(f"  Legacy note: {explanation['legacy_note']}")

    _print_section(
        "metadata",
        explanation["metadata"],
    )

    actions = explanation["actions"]
    print("  actions:")

    if not actions:
        print("    none")

    for action in actions:
        print(
            "    "
            f"{action['action']} status={action['status']} "
            f"risk={action['risk']} source={action['source']} "
            f"reason={action['reason']}"
        )

    return explanation


def _print_section(
    name: str,
    values: dict[str, Any] | None,
) -> None:
    """
    Print one explanation section.
    """

    print(f"  {name}:")

    if values is None:
        print("    none")
        return

    for key, value in values.items():
        print(f"    {key}: {value}")


def _print_evidence(
    evidence: list[dict[str, Any]],
) -> None:
    """
    Print stored decision evidence.
    """

    print("  evidence:")

    if not evidence:
        print("    none")
        return

    for item in evidence:
        marker = " decisive" if item.get("decisive") else ""
        print(
            "    "
            f"{item['classifier']}:{item['evidence_type']}{marker} "
            f"{item['polarity']} score={item['score']} "
            f"confidence={item['confidence']:.2f} - {item['summary']}"
        )


def _print_evidence_group(
    name: str,
    evidence: list[dict[str, Any]],
) -> None:
    print(f"  {name}:")
    if not evidence:
        print("    none")
        return
    for item in evidence:
        marker = " decisive" if item.get("decisive") else ""
        print(
            "    "
            f"{item['classifier']}:{item['evidence_type']}{marker} "
            f"score={item['score']:+.0f} confidence={item['confidence']:.2f} "
            f"- {item['summary']}"
        )


def _print_trace(
    trace: list[dict[str, Any]],
) -> None:
    print("  Classifier trace:")
    if not trace:
        print("    none")
        return
    for item in trace:
        suffix = f" reason={item['reason']}" if item.get("reason") else ""
        print(
            "    "
            f"{item['classifier']} status={item['status']} "
            f"evidence={item['evidence_count']} "
            f"latency={item['latency_ms']}ms{suffix}"
        )


def _print_telemetry(
    telemetry: dict[str, Any],
) -> None:
    print("  Pipeline telemetry:")
    if not telemetry or not telemetry.get("available"):
        reason = telemetry.get("reason", "telemetry unavailable") if telemetry else "telemetry unavailable"
        print(f"    {reason}")
        return

    print(
        "    "
        f"analysis_id={telemetry.get('run_id')} "
        f"duration={_format_nullable(telemetry.get('duration_ms'), 'ms')} "
        f"cache_hit={_format_bool(telemetry.get('cache_hit'))} "
        f"final_decision={telemetry.get('final_decision_id') or 'none'}"
    )
    timeline = telemetry.get("pipeline_timeline", [])
    if not timeline:
        print("    timeline: none")
        return

    print("    timeline:")
    for item in timeline:
        details = [
            f"#{item.get('execution_order')}",
            str(item.get("classifier_name") or "unknown"),
            f"result={item.get('classifier_result') or 'none'}",
            f"confidence={_format_nullable(item.get('confidence_raw'))}",
            f"band={item.get('confidence_band') or 'none'}",
            f"duration={_format_nullable(item.get('duration_ms'), 'ms')}",
            f"skipped={_format_bool(item.get('skipped'))}",
            f"cache_hit={_format_bool(item.get('cache_hit'))}",
        ]
        if item.get("skip_reason"):
            details.append(f"skip_reason={item['skip_reason']}")
        if item.get("stop_reason"):
            details.append(f"stop_reason={item['stop_reason']}")
        if item.get("ai_considered") is not None:
            details.append(f"ai_considered={_format_bool(item.get('ai_considered'))}")
        if item.get("ai_invoked") is not None:
            details.append(f"ai_invoked={_format_bool(item.get('ai_invoked'))}")
        if item.get("ai_model"):
            details.append(f"ai_model={item['ai_model']}")
        if item.get("prompt_version"):
            details.append(f"prompt={item['prompt_version']}")
        if item.get("timeout"):
            details.append("timeout=true")
        if item.get("parse_failure"):
            details.append("parse_failure=true")
        if item.get("fallback_reason"):
            details.append(f"fallback={item['fallback_reason']}")
        print("      " + " ".join(details))


def _print_calibration(
    calibration: dict[str, Any],
) -> None:
    print("  Confidence calibration:")
    if not calibration or not calibration.get("available"):
        print(f"    {calibration.get('reason', 'calibration unavailable') if calibration else 'calibration unavailable'}")
        return
    print(
        "    "
        f"raw={_format_nullable(calibration.get('raw_confidence'))} "
        f"raw_band={calibration.get('raw_confidence_band') or 'unknown'} "
        f"calibrated={_format_nullable(calibration.get('calibrated_confidence'))} "
        f"calibrated_band={calibration.get('calibrated_confidence_band') or 'unknown'}"
    )
    print(
        "    "
        f"profile={calibration.get('profile_id')} "
        f"name={calibration.get('profile_name')} "
        f"samples={calibration.get('profile_sample_count')} "
        f"source={calibration.get('source')} observational=true"
    )


def _format_bool(
    value: Any,
) -> str:
    if value is None:
        return "unknown"
    return "true" if bool(value) else "false"


def _format_nullable(
    value: Any,
    suffix: str = "",
) -> str:
    if value is None:
        return "unknown"
    return f"{value}{suffix}"


def _print_list(
    name: str,
    values: list[str],
) -> None:
    print(f"  {name}:")
    if not values:
        print("    none")
        return
    for value in values:
        print(f"    {value}")
