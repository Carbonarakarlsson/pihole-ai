"""
Threat-intelligence import helpers.
"""

from __future__ import annotations

import re
import fcntl
import json
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

from core.config import settings
from core.db import (
    activate_existing_threat_intel_generation,
    activate_intel_generation,
    find_reusable_threat_intel_generation,
    get_threat_intel_generation,
    get_intel_source,
    get_intel_source_state,
    list_threat_intel,
    list_intel_source_status,
    list_intel_sources,
    list_intel_update_audit,
    list_managed_threat_intel_entries,
    mark_intel_update_failed,
    mark_intel_update_not_modified,
    record_intel_update_audit,
    remove_intel_source,
    save_threat_intel,
    save_intel_source,
    rollback_intel_generation,
    set_intel_source_enabled,
    update_threat_intel_source,
)
from pihole_ai.intel_feeds import (
    FeedError,
    content_sha256,
    failed_result,
    fetch_feed,
    parse_feed,
    quality_gate,
    validate_feed_url,
)
from pihole_ai.intel_models import FeedFormat, FeedSource, FeedUpdateResult


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9][a-z0-9.-]*[a-z0-9]$"
)
BLOCKLIST_IPS = {
    "0.0.0.0",
    "127.0.0.1",
    "::",
}
LOCK_PATH = Path(
    os.getenv(
        "PIHOLE_AI_INTEL_LOCK_PATH",
        "/run/pihole-ai/intel-update.lock",
    )
)
SOURCE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
POSITIVE_INT_FIELDS = {
    "refresh_interval_seconds",
    "stale_after_seconds",
    "timeout_seconds",
    "max_download_bytes",
}


def normalize_domain(
    value: str,
) -> str | None:
    """
    Normalize and validate a domain from a feed line.
    """

    domain = value.strip().lower().rstrip(".")

    if not domain:
        return None

    if domain in {"localhost", "localhost.localdomain"}:
        return None

    if "/" in domain or ":" in domain:
        return None

    if "." not in domain:
        return None

    if not DOMAIN_PATTERN.match(domain):
        return None

    return domain


def parse_hosts_domains(
    lines: Iterable[str],
) -> list[str]:
    """
    Parse domains from hosts-style or plain-domain feed lines.
    """

    domains: list[str] = []
    seen: set[str] = set()

    for line in lines:
        content = line.split("#", 1)[0].strip()

        if not content:
            continue

        parts = content.split()

        if not parts:
            continue

        candidates = parts

        if parts[0] in BLOCKLIST_IPS:
            candidates = parts[1:]

        for candidate in candidates:
            domain = normalize_domain(
                candidate,
            )

            if domain is None or domain in seen:
                continue

            seen.add(
                domain,
            )
            domains.append(
                domain,
            )

    return domains


def import_hosts_file(
    path: str,
    source: str,
    category: str = "malware",
    confidence: int = 90,
) -> int:
    """
    Import a local hosts-style threat-intel file.
    """

    lines = Path(path).read_text(
        encoding="utf-8",
    ).splitlines()
    domains = parse_hosts_domains(
        lines,
    )

    for domain in domains:
        save_threat_intel(
            domain=domain,
            source=source,
            category=category,
            confidence=confidence,
        )

    return len(domains)


@contextmanager
def intel_update_lock(path: Path = LOCK_PATH):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("intel.lock.busy") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _source_from_row(row: dict[str, Any]) -> FeedSource:
    return FeedSource(
        source_id=str(row["source_id"]),
        name=str(row["name"]),
        url=str(row["url"]),
        format=str(row["format"]),
        enabled=bool(row["enabled"]),
        category=str(row["category"]),
        confidence=int(row["confidence"]),
        refresh_interval_seconds=int(row["refresh_interval_seconds"]),
        stale_after_seconds=int(row["stale_after_seconds"]),
        timeout_seconds=int(row["timeout_seconds"]),
        max_download_bytes=int(row["max_download_bytes"]),
        expected_content_type=str(row.get("expected_content_type") or ""),
        allow_http=bool(row["allow_http"]),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
    )


def add_source(
    *,
    source_id: str,
    name: str,
    url: str,
    feed_format: str = FeedFormat.HOSTS.value,
    category: str = "malware",
    confidence: int = 90,
    enabled: bool = True,
    allow_http: bool | None = None,
) -> FeedSource:
    source_id = source_id.strip().lower()
    if not SOURCE_ID_PATTERN.match(source_id):
        raise ValueError("invalid source id")
    confidence = int(confidence)
    if confidence < 0 or confidence > 100:
        raise ValueError("confidence must be between 0 and 100")
    allow_http = settings.intel_allow_http if allow_http is None else allow_http
    validate_feed_url(url, allow_http=allow_http)
    now = time.time()
    source = FeedSource(
        source_id=source_id,
        name=name.strip() or source_id,
        url=url.strip(),
        format=feed_format,
        enabled=enabled,
        category=category,
        confidence=confidence,
        refresh_interval_seconds=settings.intel_update_interval_seconds,
        stale_after_seconds=settings.intel_stale_after_seconds,
        timeout_seconds=settings.intel_http_timeout_seconds,
        max_download_bytes=settings.intel_max_download_bytes,
        allow_http=allow_http,
        created_at=now,
        updated_at=now,
    )
    save_intel_source(source)
    return source


def update_source_config(
    source_id: str,
    changes: dict[str, Any],
) -> dict[str, Any] | None:
    source_id = source_id.strip().lower()
    if not SOURCE_ID_PATTERN.match(source_id):
        raise ValueError("invalid source id")
    if not changes:
        raise ValueError("No source changes provided.")

    normalized = dict(changes)
    if "confidence" in normalized:
        confidence = int(normalized["confidence"])
        if confidence < 0 or confidence > 100:
            raise ValueError("confidence must be between 0 and 100")
        normalized["confidence"] = confidence
    if "format" in normalized and normalized["format"] not in {
        FeedFormat.HOSTS.value,
        FeedFormat.DOMAINS.value,
        FeedFormat.TEXT.value,
    }:
        raise ValueError("invalid feed format")
    for field in POSITIVE_INT_FIELDS:
        if field in normalized:
            value = int(normalized[field])
            if value <= 0:
                raise ValueError(f"{field} must be positive")
            normalized[field] = value
    if "url" in normalized:
        allow_http = bool(normalized.get("allow_http", settings.intel_allow_http))
        current = get_intel_source(source_id)
        if current is not None and "allow_http" not in normalized:
            allow_http = bool(current["allow_http"])
        validate_feed_url(str(normalized["url"]), allow_http=allow_http)
        normalized["url"] = str(normalized["url"]).strip()
    elif "allow_http" in normalized:
        current = get_intel_source(source_id)
        if current is None:
            return None
        validate_feed_url(str(current["url"]), allow_http=bool(normalized["allow_http"]))
    if "name" in normalized:
        normalized["name"] = str(normalized["name"]).strip()
        if not normalized["name"]:
            raise ValueError("name must not be empty")
    if "category" in normalized:
        normalized["category"] = str(normalized["category"]).strip()
        if not normalized["category"]:
            raise ValueError("category must not be empty")
    if "expected_content_type" in normalized:
        normalized["expected_content_type"] = str(normalized["expected_content_type"]).strip()

    return update_threat_intel_source(source_id, normalized)


def source_status() -> list[dict[str, Any]]:
    return list_intel_source_status()


def _generation_is_valid_remote(generation: dict[str, Any] | None) -> bool:
    return bool(
        generation
        and generation.get("status") in {"active", "inactive"}
        and generation.get("activated_at") is not None
        and int(generation.get("stored_entry_count") or -1) == int(generation.get("entry_count") or 0)
    )


def _resolve_remote_generation(source_id: str, state: dict[str, Any]) -> dict[str, Any] | None:
    remote_generation_id = str(state.get("remote_generation_id") or "")
    if remote_generation_id:
        generation = get_threat_intel_generation(source_id, remote_generation_id)
        return generation if _generation_is_valid_remote(generation) else None

    content_hash = str(state.get("content_sha256") or "")
    if not content_hash:
        return None

    active_generation_id = str(state.get("active_generation") or "")
    if active_generation_id:
        active_generation = get_threat_intel_generation(source_id, active_generation_id)
        if (
            _generation_is_valid_remote(active_generation)
            and str(active_generation.get("content_sha256") or "") == content_hash
        ):
            return active_generation

    return find_reusable_threat_intel_generation(source_id, content_hash)


def update_source(
    source_id: str,
    *,
    dry_run: bool = False,
) -> FeedUpdateResult:
    row = get_intel_source(source_id)
    if row is None:
        return FeedUpdateResult(
            source_id=source_id,
            success=False,
            error_code="intel.source.not_found",
            error_summary="Feed source was not found.",
        )
    source = _source_from_row(row)
    if not source.enabled:
        return FeedUpdateResult(
            source_id=source_id,
            success=False,
            error_code="intel.source.disabled",
            error_summary="Feed source is disabled.",
        )
    state = get_intel_source_state(source_id) or {}
    started = time.time()
    try:
        fetched = fetch_feed(
            source,
            etag=str(state.get("etag") or ""),
            last_modified=str(state.get("last_modified") or ""),
            user_agent=settings.intel_user_agent,
        )
        if fetched.not_modified:
            previous = str(state.get("active_generation") or "")
            remote_generation = _resolve_remote_generation(source_id, state)
            if remote_generation is None:
                result = FeedUpdateResult(
                    source_id=source_id,
                    success=False,
                    changed=False,
                    not_modified=True,
                    downloaded_bytes=fetched.downloaded_bytes,
                    previous_generation=previous,
                    active_generation=previous,
                    current_active_generation=previous,
                    duration_ms=int((time.time() - started) * 1000),
                    trigger="http_not_modified",
                    error_code="intel.generation.remote_reference_missing",
                    error_summary="HTTP validators do not identify a reusable generation.",
                )
                if not dry_run:
                    record_intel_update_audit(result, http_status=304)
                return result
            remote_generation_id = str(remote_generation["generation_id"])
            remote_entry_count = int(remote_generation["entry_count"])
            if previous and remote_generation_id != previous:
                active = "" if dry_run else remote_generation_id
                if not dry_run:
                    try:
                        previous, active = activate_existing_threat_intel_generation(
                            source_id=source_id,
                            generation_id=remote_generation_id,
                            previous_generation_id=previous,
                            etag=fetched.etag,
                            last_modified=fetched.last_modified,
                        )
                    except ValueError as exc:
                        result = FeedUpdateResult(
                            source_id=source_id,
                            success=False,
                            changed=False,
                            not_modified=True,
                            downloaded_bytes=fetched.downloaded_bytes,
                            previous_generation=previous,
                            active_generation=previous,
                            remote_generation=remote_generation_id,
                            current_active_generation=previous,
                            duration_ms=int((time.time() - started) * 1000),
                            trigger="http_not_modified",
                            error_code="intel.generation.remote_reference_missing",
                            error_summary=str(exc),
                        )
                        record_intel_update_audit(result, http_status=304)
                        return result
                result = FeedUpdateResult(
                    source_id=source_id,
                    success=True,
                    changed=True,
                    not_modified=True,
                    reused_generation=True,
                    downloaded_bytes=fetched.downloaded_bytes,
                    accepted_entries=remote_entry_count,
                    previous_generation=previous,
                    active_generation=active,
                    remote_generation=remote_generation_id,
                    dry_run=dry_run,
                    would_activate=dry_run,
                    proposed_generation_id=remote_generation_id if dry_run else "",
                    current_active_generation=previous,
                    duration_ms=int((time.time() - started) * 1000),
                    trigger="http_not_modified",
                )
                if not dry_run:
                    record_intel_update_audit(result, http_status=304)
                return result
            result = FeedUpdateResult(
                source_id=source_id,
                success=True,
                changed=False,
                not_modified=True,
                content_unchanged=True,
                downloaded_bytes=fetched.downloaded_bytes,
                accepted_entries=remote_entry_count,
                previous_generation=previous,
                active_generation=previous,
                remote_generation=remote_generation_id,
                current_active_generation=previous,
                duration_ms=int((time.time() - started) * 1000),
                trigger="http_not_modified",
            )
            if not dry_run:
                mark_intel_update_not_modified(
                    source_id,
                    fetched.etag,
                    fetched.last_modified,
                    remote_generation_id=remote_generation_id,
                )
                record_intel_update_audit(result, http_status=304)
            return result
        parsed = parse_feed(fetched.content, source.format, source)
        warnings = quality_gate(
            parsed,
            previous_count=int(state.get("entry_count") or 0),
        )
        sha = content_sha256(fetched.content)
        previous = str(state.get("active_generation") or "")
        active_generation = get_threat_intel_generation(source_id, previous) if previous else None
        active_sha = str(active_generation.get("content_sha256") or "") if active_generation else ""
        if previous and active_sha == sha:
            result = FeedUpdateResult(
                source_id=source_id,
                success=True,
                changed=False,
                not_modified=True,
                content_unchanged=True,
                downloaded_bytes=fetched.downloaded_bytes,
                parsed_entries=parsed.parsed_entries,
                accepted_entries=len(parsed.accepted_entries),
                rejected_entries=parsed.rejected_count,
                duplicate_entries=parsed.duplicate_count,
                previous_generation=previous,
                active_generation=previous,
                remote_generation=previous,
                current_active_generation=previous,
                duration_ms=int((time.time() - started) * 1000),
                warnings=warnings + parsed.warnings,
            )
            if not dry_run:
                mark_intel_update_not_modified(
                    source_id,
                    fetched.etag,
                    fetched.last_modified,
                    remote_generation_id=previous,
                )
                record_intel_update_audit(result, http_status=fetched.status_code)
            else:
                result = FeedUpdateResult(
                    **{
                        **result.to_dict(),
                        "dry_run": True,
                    }
                )
            return result
        reusable = find_reusable_threat_intel_generation(source_id, sha)
        if reusable is not None:
            active = str(reusable["generation_id"])
            entry_count = int(reusable["entry_count"])
            if not dry_run:
                previous, active = activate_existing_threat_intel_generation(
                    source_id=source_id,
                    generation_id=active,
                    previous_generation_id=previous,
                    etag=fetched.etag,
                    last_modified=fetched.last_modified,
                )
            result = FeedUpdateResult(
                source_id=source_id,
                success=True,
                changed=True,
                reused_generation=True,
                downloaded_bytes=fetched.downloaded_bytes,
                parsed_entries=parsed.parsed_entries,
                accepted_entries=entry_count,
                rejected_entries=parsed.rejected_count,
                duplicate_entries=parsed.duplicate_count,
                previous_generation=previous,
                active_generation=active if not dry_run else "",
                remote_generation=active,
                dry_run=dry_run,
                would_activate=dry_run,
                proposed_generation_id=active if dry_run else "",
                current_active_generation=previous,
                duration_ms=int((time.time() - started) * 1000),
                warnings=warnings + parsed.warnings,
            )
            if not dry_run:
                record_intel_update_audit(result, http_status=fetched.status_code)
            return result
        generation_id = f"gen_{uuid.uuid4().hex}"
        active = "" if dry_run else generation_id
        if not dry_run:
            previous, active = activate_intel_generation(
                source_id=source_id,
                generation_id=generation_id,
                content_sha256_value=sha,
                entries=parsed.accepted_entries,
                category=source.category,
                confidence=source.confidence,
                etag=fetched.etag,
                last_modified=fetched.last_modified,
            )
        result = FeedUpdateResult(
            source_id=source_id,
            success=True,
            changed=True,
            created_generation=not dry_run,
            downloaded_bytes=fetched.downloaded_bytes,
            parsed_entries=parsed.parsed_entries,
            accepted_entries=len(parsed.accepted_entries),
            rejected_entries=parsed.rejected_count,
            duplicate_entries=parsed.duplicate_count,
            previous_generation=previous,
            active_generation=active,
            remote_generation=active,
            dry_run=dry_run,
            would_activate=dry_run,
            proposed_generation_id=generation_id if dry_run else "",
            current_active_generation=previous,
            duration_ms=int((time.time() - started) * 1000),
            warnings=warnings + parsed.warnings,
        )
        if not dry_run:
            record_intel_update_audit(result, http_status=fetched.status_code)
        return result
    except FeedError as exc:
        result = failed_result(source_id, exc.code, exc.summary, started)
        if not dry_run:
            mark_intel_update_failed(source_id, exc.code, exc.summary)
            record_intel_update_audit(result)
        return result


def update_sources(
    source_id: str | None = None,
    *,
    all_sources: bool = False,
    dry_run: bool = False,
    automatic: bool = False,
) -> list[FeedUpdateResult]:
    if automatic and not settings.intel_auto_update_enabled:
        return [
            FeedUpdateResult(
                source_id="automatic",
                success=True,
                changed=False,
                error_code="intel.auto_update.disabled",
                error_summary="Automatic threat-intelligence updates are disabled.",
                warnings=["auto_update_disabled"],
            )
        ]
    with intel_update_lock():
        if source_id:
            return [update_source(source_id, dry_run=dry_run)]
        sources = [
            row
            for row in list_intel_sources()
            if row.get("enabled")
        ]
        if not all_sources:
            sources = [
                row
                for row in sources
                if _source_due(row)
            ]
        return [
            update_source(str(row["source_id"]), dry_run=dry_run)
            for row in sources
        ]


def _source_due(row: dict[str, Any]) -> bool:
    state = get_intel_source_state(str(row["source_id"])) or {}
    last = state.get("last_attempt_at")
    if not last:
        return True
    return time.time() - float(last) >= int(row["refresh_interval_seconds"])


def rollback_source(source_id: str) -> str | None:
    generation_id = rollback_intel_generation(source_id)
    if generation_id is not None:
        record_intel_update_audit(
            FeedUpdateResult(
                source_id=source_id,
                success=True,
                changed=True,
                active_generation=generation_id,
                warnings=["rollback"],
            )
        )
    return generation_id


def get_intel_rows(
    limit: int = 100,
    search: str = "",
    source: str = "",
    category: str = "",
    generation: str = "",
) -> list[dict[str, Any]]:
    """
    Return threat-intel groups as dictionaries.
    """

    groups: list[dict[str, Any]] = []
    managed_source = get_intel_source(source) if source else None
    legacy_rows = []
    if not generation and managed_source is None:
        legacy_rows = [
            dict(row)
            for row in list_threat_intel(
                limit=limit,
                search=search,
                source=source,
                category=category,
            )
        ]
    if source and managed_source is None and not legacy_rows:
        raise ValueError(f"Unknown threat-intel source: {source}")
    legacy_by_source: dict[str, list[dict[str, Any]]] = {}
    for row in legacy_rows:
        legacy_by_source.setdefault(str(row["source"]), []).append(row)
    for source_id, entries in legacy_by_source.items():
        groups.append(
            {
                "source_type": "manual",
                "source_id": source_id,
                "generation_id": "",
                "active": True,
                "entries": entries,
            }
        )

    managed_rows = []
    if not source or managed_source is not None:
        managed_rows = [
            dict(row)
            for row in list_managed_threat_intel_entries(
                limit=limit,
                search=search,
                source_id=source if managed_source is not None else "",
                category=category,
                generation_id=generation,
            )
        ]
    managed_by_generation: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in managed_rows:
        key = (str(row["source_id"]), str(row["generation_id"]))
        managed_by_generation.setdefault(key, []).append(row)
    for (source_id, generation_id), entries in managed_by_generation.items():
        groups.append(
            {
                "source_type": "managed",
                "source_id": source_id,
                "generation_id": generation_id,
                "active": bool(entries[0].get("active")),
                "entries": entries,
            }
        )
    return groups


def print_intel(
    limit: int = 100,
    search: str = "",
    source: str = "",
    category: str = "",
    generation: str = "",
) -> int:
    """
    Print threat-intel rows and return the number printed.
    """

    try:
        rows = get_intel_rows(
            limit=limit,
            search=search,
            source=source,
            category=category,
            generation=generation,
        )
    except ValueError as exc:
        print(str(exc))
        return -1

    if not rows and source:
        print(f"No active threat-intel entries found for source {source}.")
        return 0
    if not rows:
        print("No threat-intel rows found.")
        return 0

    count = 0
    for group in rows:
        entries = group["entries"]
        if not entries:
            continue
        for row in entries:
            generation_text = (
                f" generation={group['generation_id']}"
                if group["generation_id"]
                else ""
            )
            print(
                f"{row['domain']} source={group['source_id']}"
                f"{generation_text} category={row['category']} "
                f"confidence={row['confidence']}"
            )
            count += 1

    return count
