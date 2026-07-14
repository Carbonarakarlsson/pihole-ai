"""
Threat-intelligence import helpers.
"""

from __future__ import annotations

import re
import fcntl
import json
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

from core.config import settings
from core.db import (
    activate_intel_generation,
    get_intel_source,
    get_intel_source_state,
    list_threat_intel,
    list_intel_source_status,
    list_intel_sources,
    list_intel_update_audit,
    mark_intel_update_failed,
    mark_intel_update_not_modified,
    record_intel_update_audit,
    remove_intel_source,
    save_threat_intel,
    save_intel_source,
    rollback_intel_generation,
    set_intel_source_enabled,
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
LOCK_PATH = Path("/tmp/pihole-ai-intel-update.lock")
SOURCE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


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
        confidence=max(0, min(int(confidence), 100)),
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


def source_status() -> list[dict[str, Any]]:
    return list_intel_source_status()


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
            result = FeedUpdateResult(
                source_id=source_id,
                success=True,
                changed=False,
                not_modified=True,
                downloaded_bytes=fetched.downloaded_bytes,
                previous_generation=str(state.get("active_generation") or ""),
                active_generation=str(state.get("active_generation") or ""),
                duration_ms=int((time.time() - started) * 1000),
            )
            if not dry_run:
                mark_intel_update_not_modified(source_id, fetched.etag, fetched.last_modified)
                record_intel_update_audit(result, http_status=304)
            return result
        parsed = parse_feed(fetched.content, source.format, source)
        warnings = quality_gate(
            parsed,
            previous_count=int(state.get("entry_count") or 0),
        )
        sha = content_sha256(fetched.content)
        generation_id = f"gen_{uuid.uuid4().hex}"
        previous = str(state.get("active_generation") or "")
        active = generation_id
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
            downloaded_bytes=fetched.downloaded_bytes,
            parsed_entries=parsed.parsed_entries,
            accepted_entries=len(parsed.accepted_entries),
            rejected_entries=parsed.rejected_count,
            duplicate_entries=parsed.duplicate_count,
            previous_generation=previous,
            active_generation=active,
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
) -> list[FeedUpdateResult]:
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
) -> list[dict[str, Any]]:
    """
    Return threat-intel rows as dictionaries.
    """

    return [
        dict(row)
        for row in list_threat_intel(
            limit=limit,
            search=search,
            source=source,
            category=category,
        )
    ]


def print_intel(
    limit: int = 100,
    search: str = "",
    source: str = "",
    category: str = "",
) -> int:
    """
    Print threat-intel rows and return the number printed.
    """

    rows = get_intel_rows(
        limit=limit,
        search=search,
        source=source,
        category=category,
    )

    if not rows:
        print("No threat-intel rows found.")
        return 0

    for row in rows:
        print(
            f"{row['domain']} source={row['source']} "
            f"category={row['category']} confidence={row['confidence']}"
        )

    return len(rows)
