"""
Reusable configuration validation primitives.

These helpers are intentionally independent from the existing runtime
``core.config`` loader.  Epic 3.5 Phase 1A uses them for the internal
configuration-management framework without changing current application
behaviour.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ConfigValidationError:
    code: str
    key: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "key": self.key,
            "message": self.message,
        }


@dataclass(frozen=True)
class ConfigValidationResult:
    key: str
    value: Any
    errors: tuple[ConfigValidationError, ...] = ()

    @property
    def is_valid(self) -> bool:
        return not self.errors


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_MODEL_RE = re.compile(r"^[A-Za-z0-9._:/+-]+$")


def _error(
    key: str,
    code: str,
    message: str,
) -> ConfigValidationResult:
    return ConfigValidationResult(
        key=key,
        value=None,
        errors=(
            ConfigValidationError(
                code=code,
                key=key,
                message=message,
            ),
        ),
    )


def validate_boolean(
    key: str,
    value: Any,
) -> ConfigValidationResult:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return ConfigValidationResult(key=key, value=True)
    if normalized in {"0", "false", "no", "off"}:
        return ConfigValidationResult(key=key, value=False)
    return _error(key, "config.invalid_boolean", "Value must be true or false.")


def validate_integer(
    key: str,
    value: Any,
) -> ConfigValidationResult:
    try:
        return ConfigValidationResult(key=key, value=int(str(value).strip()))
    except (TypeError, ValueError):
        return _error(key, "config.invalid_integer", "Value must be an integer.")


def validate_float(
    key: str,
    value: Any,
) -> ConfigValidationResult:
    try:
        return ConfigValidationResult(key=key, value=float(str(value).strip()))
    except (TypeError, ValueError):
        return _error(key, "config.invalid_float", "Value must be a number.")


def validate_numeric_range(
    key: str,
    value: Any,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
    integer: bool = True,
) -> ConfigValidationResult:
    parsed = validate_integer(key, value) if integer else validate_float(key, value)
    if not parsed.is_valid:
        return parsed

    numeric = parsed.value
    if minimum is not None and numeric < minimum:
        return _error(
            key,
            "config.out_of_range",
            f"Value must be greater than or equal to {minimum}.",
        )
    if maximum is not None and numeric > maximum:
        return _error(
            key,
            "config.out_of_range",
            f"Value must be less than or equal to {maximum}.",
        )
    return parsed


def validate_port(
    key: str,
    value: Any,
) -> ConfigValidationResult:
    return validate_numeric_range(
        key,
        value,
        minimum=1,
        maximum=65535,
        integer=True,
    )


def validate_url(
    key: str,
    value: Any,
    *,
    schemes: Iterable[str] = ("http", "https"),
    allow_credentials: bool = False,
) -> ConfigValidationResult:
    raw = str(value).strip()
    parsed = urlsplit(raw)
    if parsed.scheme not in set(schemes) or not parsed.hostname:
        return _error(
            key,
            "config.invalid_url",
            "Value must be an HTTP or HTTPS URL with a host.",
        )
    if not allow_credentials and (parsed.username or parsed.password):
        return _error(
            key,
            "config.url_credentials_not_allowed",
            "URL credentials are not allowed.",
        )
    return ConfigValidationResult(key=key, value=raw)


def validate_hostname_or_ip(
    key: str,
    value: Any,
) -> ConfigValidationResult:
    raw = str(value).strip()
    if raw in {"0.0.0.0", "::", "localhost"}:
        return ConfigValidationResult(key=key, value=raw)
    try:
        ipaddress.ip_address(raw)
        return ConfigValidationResult(key=key, value=raw)
    except ValueError:
        pass
    if _HOSTNAME_RE.match(raw):
        return ConfigValidationResult(key=key, value=raw)
    return _error(
        key,
        "config.invalid_hostname",
        "Value must be a hostname or IP address.",
    )


def validate_path(
    key: str,
    value: Any,
    *,
    absolute: bool = True,
) -> ConfigValidationResult:
    raw = str(value).strip()
    if not raw:
        return _error(key, "config.empty_path", "Path must not be empty.")
    path = Path(raw).expanduser()
    if absolute and not path.is_absolute():
        return _error(key, "config.path_not_absolute", "Path must be absolute.")
    return ConfigValidationResult(key=key, value=path)


def validate_enum(
    key: str,
    value: Any,
    *,
    allowed: Iterable[str],
) -> ConfigValidationResult:
    normalized = str(value).strip()
    allowed_values = tuple(allowed)
    if normalized in allowed_values:
        return ConfigValidationResult(key=key, value=normalized)
    return _error(
        key,
        "config.invalid_choice",
        "Value must be one of the allowed choices.",
    )


def validate_ollama_model(
    key: str,
    value: Any,
) -> ConfigValidationResult:
    raw = str(value).strip()
    if not raw:
        return _error(key, "config.empty_model", "Model name must not be empty.")
    if any(ord(char) < 32 for char in raw) or not _MODEL_RE.match(raw):
        return _error(
            key,
            "config.invalid_model",
            "Model name contains unsupported characters.",
        )
    return ConfigValidationResult(key=key, value=raw)
