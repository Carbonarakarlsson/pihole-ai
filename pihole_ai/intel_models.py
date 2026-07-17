"""
Typed models for managed threat-intelligence feeds.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class FeedStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    STALE = "stale"
    FAILED = "failed"
    UPDATING = "updating"
    EMPTY = "empty"
    UNKNOWN = "unknown"


class FeedFormat(str, Enum):
    HOSTS = "hosts"
    DOMAINS = "domains"
    TEXT = "text"


@dataclass(frozen=True)
class FeedSource:
    source_id: str
    name: str
    url: str
    format: str = FeedFormat.HOSTS.value
    enabled: bool = True
    category: str = "malware"
    confidence: int = 90
    refresh_interval_seconds: int = 86400
    stale_after_seconds: int = 172800
    timeout_seconds: int = 20
    max_download_bytes: int = 2_000_000
    expected_content_type: str = ""
    allow_http: bool = False
    created_at: float = 0.0
    updated_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FeedState:
    source_id: str
    status: str = FeedStatus.UNKNOWN.value
    last_attempt_at: float | None = None
    last_success_at: float | None = None
    next_update_at: float | None = None
    etag: str = ""
    last_modified: str = ""
    content_sha256: str = ""
    entry_count: int = 0
    active_generation: str = ""
    remote_generation_id: str = ""
    last_error_code: str = ""
    last_error_summary: str = ""
    consecutive_failures: int = 0
    last_http_status: int | None = None
    last_downloaded_bytes: int = 0
    last_parsed_entries: int = 0
    last_accepted_entries: int = 0
    last_rejected_entries: int = 0
    last_duplicate_entries: int = 0
    last_warnings_json: str = "[]"
    last_update_duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FeedUpdateResult:
    source_id: str
    success: bool
    changed: bool = False
    not_modified: bool = False
    content_unchanged: bool = False
    reused_generation: bool = False
    created_generation: bool = False
    downloaded_bytes: int = 0
    parsed_entries: int = 0
    accepted_entries: int = 0
    rejected_entries: int = 0
    duplicate_entries: int = 0
    previous_generation: str = ""
    active_generation: str = ""
    remote_generation: str = ""
    dry_run: bool = False
    would_activate: bool = False
    proposed_generation_id: str = ""
    current_active_generation: str = ""
    duration_ms: int = 0
    warnings: list[str] = field(default_factory=list)
    trigger: str = ""
    error_code: str = ""
    error_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ParsedFeed:
    accepted_entries: list[str]
    rejected_count: int = 0
    duplicate_count: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def parsed_entries(self) -> int:
        return len(self.accepted_entries) + self.rejected_count + self.duplicate_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted_entries": list(self.accepted_entries),
            "rejected_count": self.rejected_count,
            "duplicate_count": self.duplicate_count,
            "warnings": list(self.warnings),
            "parsed_entries": self.parsed_entries,
        }
