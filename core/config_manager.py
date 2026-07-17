"""
Internal configuration manager primitives for Epic 3.5.

This module does not replace the current runtime loader.  It provides schema
resolution, attribution, validation, env-file round-tripping, atomic writes,
masking, and export helpers for future CLI/dashboard surfaces.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

from core import config as runtime_config
from core.config_schema import CONFIG_SCHEMA
from core.config_schema import SCHEMA_VERSION
from core.config_schema import ConfigExportPolicy
from core.config_schema import ConfigItem
from core.config_schema import ConfigSensitivity
from core.config_schema import affected_services
from core.config_schema import get_item
from core.config_schema import items_by_key
from core.config_validation import ConfigValidationError
from core.config_validation import ConfigValidationResult


@dataclass(frozen=True)
class EnvLine:
    kind: str
    raw: str
    key: str | None = None
    value: str | None = None
    quote: str | None = None
    changed: bool = False


class EnvDocument:
    def __init__(
        self,
        lines: list[EnvLine],
        trailing_newline: bool = True,
    ) -> None:
        self.lines = lines
        self.trailing_newline = trailing_newline

    @classmethod
    def parse(
        cls,
        text: str,
    ) -> "EnvDocument":
        raw_lines = text.splitlines()
        trailing_newline = text.endswith("\n")
        lines: list[EnvLine] = []
        for raw in raw_lines:
            stripped = raw.strip()
            if not stripped:
                lines.append(EnvLine(kind="blank", raw=raw))
                continue
            if stripped.startswith("#") or "=" not in raw:
                lines.append(EnvLine(kind="comment", raw=raw))
                continue
            key, raw_value = raw.split("=", 1)
            key = key.strip()
            value_text = raw_value.strip()
            quote = None
            value = value_text
            if len(value_text) >= 2 and value_text[0] == value_text[-1] and value_text[0] in {"'", '"'}:
                quote = value_text[0]
                value = value_text[1:-1]
            lines.append(
                EnvLine(
                    kind="entry",
                    raw=raw,
                    key=key,
                    value=value,
                    quote=quote,
                )
            )
        return cls(lines=lines, trailing_newline=trailing_newline)

    @classmethod
    def from_path(
        cls,
        path: Path,
    ) -> "EnvDocument":
        try:
            return cls.parse(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls(lines=[], trailing_newline=True)

    def values(
        self,
    ) -> dict[str, str]:
        return {
            line.key: line.value or ""
            for line in self.lines
            if line.kind == "entry" and line.key is not None
        }

    def set(
        self,
        key: str,
        value: str,
    ) -> None:
        for index, line in enumerate(self.lines):
            if line.kind == "entry" and line.key == key:
                self.lines[index] = replace(
                    line,
                    value=value,
                    changed=True,
                )
                return
        self.lines.append(
            EnvLine(
                kind="entry",
                raw="",
                key=key,
                value=value,
                changed=True,
            )
        )

    def unset(
        self,
        key: str,
    ) -> None:
        self.lines = [
            line
            for line in self.lines
            if not (line.kind == "entry" and line.key == key)
        ]

    def to_text(
        self,
    ) -> str:
        rendered = [self._render_line(line) for line in self.lines]
        text = "\n".join(rendered)
        if self.trailing_newline or rendered:
            text += "\n"
        return text

    def _render_line(
        self,
        line: EnvLine,
    ) -> str:
        if line.kind != "entry":
            return line.raw
        if not line.changed:
            return line.raw
        return f"{line.key}={_serialize_env_value(line.value or '')}"


@dataclass(frozen=True)
class ResolvedConfigValue:
    key: str
    env_name: str
    raw_value: str
    value: Any
    source: str
    validation: ConfigValidationResult


@dataclass(frozen=True)
class ManagerValidationResult:
    errors: tuple[ConfigValidationError, ...]

    @property
    def is_valid(self) -> bool:
        return not self.errors


class ConfigurationManager:
    def __init__(
        self,
        *,
        env: Mapping[str, str] | None = None,
        env_files: list[Path] | None = None,
        schema: tuple[ConfigItem, ...] = CONFIG_SCHEMA,
    ) -> None:
        self.env = dict(os.environ if env is None else env)
        self.env_files = env_files if env_files is not None else [
            runtime_config.CONFIG_FILE,
            runtime_config.PROJECT_ROOT / ".env",
        ]
        self.schema = schema
        self._resolved: dict[str, ResolvedConfigValue] | None = None

    def resolve(
        self,
    ) -> dict[str, ResolvedConfigValue]:
        values: dict[str, tuple[str, str]] = {}
        for path in self.env_files:
            document = EnvDocument.from_path(path)
            for key, value in document.values().items():
                values[key] = (value, f"env_file:{path}")
        for key, value in self.env.items():
            values[key] = (str(value), "environment")

        resolved: dict[str, ResolvedConfigValue] = {}
        for item in self.schema:
            raw_value = item.default
            env_name = item.env_var
            source = "default"
            for candidate in item.env_names:
                if candidate in values:
                    raw_value, source = values[candidate]
                    env_name = candidate
                    break
            validation = item.validator(item, raw_value)
            resolved[item.key] = ResolvedConfigValue(
                key=item.key,
                env_name=env_name,
                raw_value=raw_value,
                value=validation.value,
                source=source,
                validation=validation,
            )
        self._resolved = resolved
        return dict(resolved)

    def get(
        self,
        key: str,
    ) -> Any:
        item = get_item(key)
        resolved = self._resolved or self.resolve()
        return resolved[item.key].value

    def source_of(
        self,
        key: str,
    ) -> str:
        item = get_item(key)
        resolved = self._resolved or self.resolve()
        return resolved[item.key].source

    def validate(
        self,
    ) -> ManagerValidationResult:
        resolved = self._resolved or self.resolve()
        errors = tuple(
            error
            for value in resolved.values()
            for error in value.validation.errors
        )
        return ManagerValidationResult(errors=errors)

    def export(
        self,
        *,
        include_secrets: bool = False,
    ) -> dict[str, Any]:
        resolved = self._resolved or self.resolve()
        settings: dict[str, Any] = {}
        for item in sorted(self.schema, key=lambda entry: entry.key):
            if item.export_policy == ConfigExportPolicy.EXCLUDE:
                continue
            if item.export_policy == ConfigExportPolicy.SECURE and not include_secrets:
                continue
            if item.sensitivity == ConfigSensitivity.SECRET and not include_secrets:
                continue
            value = resolved[item.key]
            settings[item.key] = _json_safe(value.value)
        return {
            "schema_version": SCHEMA_VERSION,
            "settings": settings,
        }


def mask_value(
    item: ConfigItem | str,
    value: str | None,
    *,
    reveal: bool = False,
) -> dict[str, Any]:
    config_item = get_item(item) if isinstance(item, str) else item
    configured = value is not None and str(value) != ""
    if not configured:
        return {
            "configured": False,
            "masked": False,
            "value": None,
        }
    if reveal or config_item.sensitivity in {
        ConfigSensitivity.PUBLIC,
        ConfigSensitivity.OPERATIONAL,
    }:
        return {
            "configured": True,
            "masked": False,
            "value": value,
        }
    if config_item.sensitivity == ConfigSensitivity.SECRET:
        return {
            "configured": True,
            "masked": True,
            "value": None,
        }
    return {
        "configured": True,
        "masked": True,
        "value": _partial_mask(str(value)),
    }


def write_env_file_atomic(
    path: Path,
    updates: Mapping[str, str],
    *,
    backup: bool = True,
) -> Path | None:
    document = EnvDocument.from_path(path)
    for key in sorted(updates):
        document.set(key, str(updates[key]))

    path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = path.with_suffix(path.suffix + ".bak") if backup and path.exists() else None
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(document.to_text())
            handle.flush()
            os.fsync(handle.fileno())
        if backup_path is not None:
            shutil.copy2(path, backup_path)
        os.replace(temp_path, path)
        _fsync_directory(path.parent)
        return backup_path
    except Exception:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        raise


def changed_key_impact(
    changed_keys: list[str] | tuple[str, ...] | set[str],
) -> dict[str, Any]:
    services = affected_services(changed_keys)
    return {
        "restart_required": bool(services),
        "services": services,
    }


def _serialize_env_value(
    value: str,
) -> str:
    if value == "":
        return '""'
    if any(char.isspace() for char in value) or "#" in value or '"' in value:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


def _partial_mask(
    value: str,
) -> str:
    if len(value) <= 4:
        return "****"
    if len(value) <= 8:
        return value[:1] + "****" + value[-1:]
    return value[:3] + "****" + value[-3:]


def _json_safe(
    value: Any,
) -> Any:
    if isinstance(value, Path):
        return str(value)
    return value


def _fsync_directory(
    path: Path,
) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


__all__ = [
    "ConfigurationManager",
    "EnvDocument",
    "EnvLine",
    "ManagerValidationResult",
    "ResolvedConfigValue",
    "changed_key_impact",
    "mask_value",
    "write_env_file_atomic",
]
