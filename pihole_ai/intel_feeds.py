"""
Threat-intelligence feed parsing, fetching, and quality gates.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from pihole_ai.intel_models import FeedFormat, FeedSource, FeedUpdateResult, ParsedFeed


DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


ERROR_INSECURE_URL = "intel.fetch.insecure_url"
ERROR_PRIVATE_ADDRESS = "intel.fetch.private_address"
ERROR_TOO_LARGE = "intel.fetch.too_large"
ERROR_TIMEOUT = "intel.fetch.timeout"
ERROR_HTTP_STATUS = "intel.fetch.http_status"
ERROR_CONTENT_TYPE = "intel.fetch.invalid_content_type"
ERROR_REDIRECT = "intel.fetch.redirect_policy"
ERROR_EMPTY = "intel.quality.empty"
ERROR_SHRINK = "intel.quality.excessive_shrink"
ERROR_GROWTH = "intel.quality.excessive_growth"


@dataclass(frozen=True)
class FetchResult:
    status_code: int
    content: bytes
    etag: str = ""
    last_modified: str = ""
    content_type: str = ""
    downloaded_bytes: int = 0
    not_modified: bool = False


class FeedError(RuntimeError):
    def __init__(self, code: str, summary: str) -> None:
        self.code = code
        self.summary = summary
        super().__init__(summary)


def validate_feed_url(url: str, allow_http: bool = False) -> urllib.parse.ParseResult:
    parts = urllib.parse.urlsplit(url)
    if parts.username or parts.password:
        raise FeedError(ERROR_INSECURE_URL, "Feed URLs must not include credentials.")
    if parts.scheme not in {"https", "http"} or not parts.netloc:
        raise FeedError(ERROR_INSECURE_URL, "Feed URL must be absolute HTTP(S).")
    if parts.scheme == "http" and not allow_http:
        raise FeedError(ERROR_INSECURE_URL, "Plain HTTP feeds require explicit allow_http.")
    _reject_private_host(parts.hostname or "")
    return parts


def _reject_private_host(host: str) -> None:
    try:
        addresses = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise FeedError("intel.fetch.resolve_failed", "Feed host could not be resolved.") from exc
    for family, _, _, _, sockaddr in addresses:
        address = sockaddr[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_private:
            raise FeedError(ERROR_PRIVATE_ADDRESS, "Feed host resolves to a private or local address.")


class _RedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow_http: bool, limit: int = 3) -> None:
        self.allow_http = allow_http
        self.limit = limit
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        self.count += 1
        if self.count > self.limit:
            raise FeedError(ERROR_REDIRECT, "Feed redirect limit exceeded.")
        old_scheme = urllib.parse.urlsplit(req.full_url).scheme
        new_scheme = urllib.parse.urlsplit(newurl).scheme
        if old_scheme == "https" and new_scheme == "http" and not self.allow_http:
            raise FeedError(ERROR_REDIRECT, "HTTPS feed redirected to HTTP.")
        validate_feed_url(newurl, allow_http=self.allow_http)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_feed(
    source: FeedSource,
    *,
    etag: str = "",
    last_modified: str = "",
    user_agent: str = "PiHole-AI",
) -> FetchResult:
    validate_feed_url(source.url, allow_http=source.allow_http)
    headers = {"User-Agent": user_agent}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    request = urllib.request.Request(source.url, headers=headers)
    opener = urllib.request.build_opener(
        _RedirectHandler(source.allow_http),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(
            request,
            timeout=source.timeout_seconds,
        ) as response:
            status = int(response.status)
            content_type = response.headers.get("Content-Type", "")
            if source.expected_content_type and source.expected_content_type not in content_type:
                raise FeedError(ERROR_CONTENT_TYPE, "Feed response content type did not match.")
            chunks: list[bytes] = []
            downloaded = 0
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                downloaded += len(chunk)
                if downloaded > source.max_download_bytes:
                    raise FeedError(ERROR_TOO_LARGE, "Feed download exceeded configured limit.")
                chunks.append(chunk)
            return FetchResult(
                status_code=status,
                content=b"".join(chunks),
                etag=response.headers.get("ETag", ""),
                last_modified=response.headers.get("Last-Modified", ""),
                content_type=content_type,
                downloaded_bytes=downloaded,
            )
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return FetchResult(
                status_code=304,
                content=b"",
                etag=etag,
                last_modified=last_modified,
                downloaded_bytes=0,
                not_modified=True,
            )
        raise FeedError(ERROR_HTTP_STATUS, f"Feed returned HTTP {exc.code}.") from exc
    except TimeoutError as exc:
        raise FeedError(ERROR_TIMEOUT, "Feed fetch timed out.") from exc
    except FeedError:
        raise
    except OSError as exc:
        raise FeedError("intel.fetch.failed", "Feed fetch failed.") from exc


def parse_feed(content: bytes | str, feed_format: str, source: FeedSource) -> ParsedFeed:
    text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
    lines = text.splitlines()
    if feed_format not in {FeedFormat.HOSTS.value, FeedFormat.DOMAINS.value, FeedFormat.TEXT.value}:
        return ParsedFeed([], rejected_count=len(lines), warnings=["unsupported format"])
    accepted: list[str] = []
    seen: set[str] = set()
    rejected = 0
    duplicates = 0
    for raw in lines:
        candidates = _line_candidates(raw, feed_format)
        if not candidates:
            continue
        for candidate in candidates:
            domain = _normalize_domain(candidate)
            if domain is None:
                rejected += 1
                continue
            if domain in seen:
                duplicates += 1
                continue
            seen.add(domain)
            accepted.append(domain)
    return ParsedFeed(
        accepted_entries=accepted,
        rejected_count=rejected,
        duplicate_count=duplicates,
    )


def _line_candidates(line: str, feed_format: str) -> list[str]:
    content = line.split("#", 1)[0].strip()
    if not content:
        return []
    parts = content.split()
    if feed_format == FeedFormat.HOSTS.value:
        if parts and parts[0] in {"0.0.0.0", "127.0.0.1", "::"}:
            return parts[1:]
        return parts
    return [parts[0]]


def _normalize_domain(value: str) -> str | None:
    domain = value.strip().strip(".").lower()
    if not domain or domain == "localhost":
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if DOMAIN_PATTERN.match(domain):
        return domain
    return None


def content_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def quality_gate(
    parsed: ParsedFeed,
    *,
    previous_count: int = 0,
    max_growth_factor: int = 10,
) -> list[str]:
    warnings: list[str] = []
    accepted = len(parsed.accepted_entries)
    total = accepted + parsed.rejected_count + parsed.duplicate_count
    if accepted == 0:
        raise FeedError(ERROR_EMPTY, "Feed parsed zero accepted domains.")
    if previous_count >= 100 and accepted < previous_count * 0.1:
        raise FeedError(ERROR_SHRINK, "Feed shrank by more than 90 percent.")
    if previous_count > 0 and accepted > previous_count * max_growth_factor:
        raise FeedError(ERROR_GROWTH, "Feed grew beyond configured quality gate.")
    if previous_count >= 100 and accepted < previous_count * 0.5:
        warnings.append("feed shrank by more than 50 percent")
    if total and parsed.duplicate_count / total > 0.5:
        warnings.append("more than half of parsed feed entries were duplicates")
    if total and parsed.rejected_count / total > 0.5:
        warnings.append("more than half of parsed feed entries were rejected")
    return warnings


def failed_result(source_id: str, code: str, summary: str, started: float) -> FeedUpdateResult:
    return FeedUpdateResult(
        source_id=source_id,
        success=False,
        duration_ms=int((time.time() - started) * 1000),
        error_code=code,
        error_summary=summary,
    )
