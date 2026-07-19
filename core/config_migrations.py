"""
Versioned configuration migrations for managed PiHole-AI env files.

The migration layer is intentionally independent from CLI output.  It reads and
transforms preserving env documents in memory, validates the final document, and
only then performs an atomic write with a migration-specific backup.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from dataclasses import replace
from pathlib import Path
from typing import Callable, Iterable

from core.config import Settings
from core.config import ValidationMode
from core.config import ValidationSeverity
from core.config import validate_config
from core.config_manager import EnvDocument
from core.config_schema import CONFIG_SCHEMA
from core.config_schema import CONFIG_SCHEMA_ENV
from core.config_schema import CONFIG_SCHEMA_VERSION
from core.config_schema import affected_services


class ConfigMigrationError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: list[dict[str, object]] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.details = details or []
        super().__init__(message)


@dataclass(frozen=True)
class ConfigVersionState:
    path: Path
    exists: bool
    empty: bool
    version: int | None
    label: str
    marker_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "exists": self.exists,
            "empty": self.empty,
            "version": self.version,
            "label": self.label,
            "marker_count": self.marker_count,
        }


@dataclass(frozen=True)
class MigrationStep:
    migration_id: str
    from_version: int
    to_version: int
    description: str
    transform: Callable[[EnvDocument, "MigrationPlan"], EnvDocument]

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.migration_id,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "description": self.description,
        }


@dataclass
class MigrationPlan:
    source_version: int | None
    target_version: int
    source_label: str
    steps: list[MigrationStep]
    renamed_keys: list[dict[str, str]] = field(default_factory=list)
    removed_keys: list[dict[str, str]] = field(default_factory=list)
    preserved_keys: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    conflicts: list[dict[str, object]] = field(default_factory=list)
    validation_errors: list[dict[str, object]] = field(default_factory=list)
    changed: bool = False
    affected_services: list[str] = field(default_factory=list)
    expected_backup_path: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "source_version": self.source_version,
            "source_label": self.source_label,
            "target_version": self.target_version,
            "steps": [step.to_dict() for step in self.steps],
            "renamed_keys": self.renamed_keys,
            "removed_keys": self.removed_keys,
            "preserved_keys": self.preserved_keys,
            "warnings": self.warnings,
            "conflicts": self.conflicts,
            "validation_errors": self.validation_errors,
            "changed": self.changed,
            "affected_services": self.affected_services,
            "expected_backup_path": self.expected_backup_path,
        }


@dataclass
class MigrationResult:
    plan: MigrationPlan
    dry_run: bool
    written: bool = False
    backup_path: str | None = None
    restart_attempted: bool = False

    def to_dict(self) -> dict[str, object]:
        payload = self.plan.to_dict()
        payload.update(
            {
                "dry_run": self.dry_run,
                "written": self.written,
                "backup_path": self.backup_path,
                "restart_attempted": self.restart_attempted,
            }
        )
        return payload


CURRENT_CONFIG_SCHEMA_VERSION = CONFIG_SCHEMA_VERSION


DEPRECATED_KEYS: dict[str, tuple[str, str]] = {
    "PIHOLE_AI_OLD_OPTION": (
        "preserve-with-warning",
        "Legacy key PIHOLE_AI_OLD_OPTION is no longer used and was preserved unchanged.",
    )
}


def detect_config_version(path: Path) -> ConfigVersionState:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ConfigVersionState(
            path=path,
            exists=False,
            empty=True,
            version=None,
            label="missing",
        )
    except UnicodeDecodeError as exc:
        raise ConfigMigrationError(
            "config.version.invalid_encoding",
            "Configuration file is not valid UTF-8.",
        ) from exc
    except OSError as exc:
        raise ConfigMigrationError(
            "config.version.unreadable",
            "Configuration file cannot be read.",
        ) from exc

    document = EnvDocument.parse(text)
    markers = [
        line
        for line in document.lines
        if line.kind == "entry" and line.key == CONFIG_SCHEMA_ENV
    ]
    if len(markers) > 1:
        raise ConfigMigrationError(
            "config.version.duplicate_marker",
            f"Duplicate {CONFIG_SCHEMA_ENV} markers found.",
        )
    if not text.strip():
        return ConfigVersionState(
            path=path,
            exists=True,
            empty=True,
            version=0,
            label="empty legacy",
            marker_count=0,
        )
    if not markers:
        return ConfigVersionState(
            path=path,
            exists=True,
            empty=False,
            version=0,
            label="legacy / unversioned",
            marker_count=0,
        )
    raw = markers[0].value or ""
    try:
        version = int(raw)
    except ValueError as exc:
        raise ConfigMigrationError(
            "config.version.malformed_marker",
            f"Malformed {CONFIG_SCHEMA_ENV} marker.",
        ) from exc
    if version < 0:
        raise ConfigMigrationError(
            "config.version.malformed_marker",
            f"Malformed {CONFIG_SCHEMA_ENV} marker.",
        )
    if version > CURRENT_CONFIG_SCHEMA_VERSION:
        raise ConfigMigrationError(
            "config.version.unsupported_future",
            (
                f"This configuration was created for schema version {version}, "
                f"but this PiHole-AI build supports up to version {CURRENT_CONFIG_SCHEMA_VERSION}."
            ),
        )
    return ConfigVersionState(
        path=path,
        exists=True,
        empty=False,
        version=version,
        label=f"schema {version}",
        marker_count=1,
    )


def validate_registry(
    steps: Iterable[MigrationStep] | None = None,
) -> None:
    seen: set[tuple[int, int]] = set()
    for step in steps or MIGRATIONS:
        edge = (step.from_version, step.to_version)
        if edge in seen:
            raise ConfigMigrationError(
                "config.migration.duplicate_edge",
                f"Duplicate configuration migration edge {step.from_version}->{step.to_version}.",
            )
        if step.to_version <= step.from_version:
            raise ConfigMigrationError(
                "config.migration.invalid_edge",
                f"Invalid configuration migration edge {step.from_version}->{step.to_version}.",
            )
        seen.add(edge)


def plan_migrations(
    source_version: int | None,
    target_version: int = CURRENT_CONFIG_SCHEMA_VERSION,
    *,
    path: Path | None = None,
    steps: Iterable[MigrationStep] | None = None,
) -> MigrationPlan:
    if target_version < 0:
        raise ConfigMigrationError("config.migration.invalid_target", "Target version must be non-negative.")
    if target_version > CURRENT_CONFIG_SCHEMA_VERSION:
        raise ConfigMigrationError(
            "config.migration.unsupported_target",
            f"Target schema version {target_version} is not supported by this PiHole-AI build.",
        )
    if source_version is None:
        return MigrationPlan(
            source_version=None,
            source_label="missing",
            target_version=target_version,
            steps=[],
            changed=False,
        )
    if source_version > target_version:
        raise ConfigMigrationError("config.migration.downgrade_rejected", "Configuration downgrades are not supported.")
    if source_version == target_version:
        return MigrationPlan(
            source_version=source_version,
            source_label=f"schema {source_version}",
            target_version=target_version,
            steps=[],
            changed=False,
        )
    registry = list(steps or MIGRATIONS)
    validate_registry(registry)
    selected: list[MigrationStep] = []
    current = source_version
    while current < target_version:
        candidates = [
            step
            for step in registry
            if step.from_version == current and step.to_version <= target_version
        ]
        if not candidates:
            raise ConfigMigrationError(
                "config.migration.missing_path",
                f"No configuration migration path from schema {source_version} to {target_version}.",
            )
        candidates.sort(key=lambda step: (step.to_version, step.migration_id))
        step = candidates[0]
        selected.append(step)
        current = step.to_version
    backup = _migration_backup_path(path, selected) if path is not None and selected else None
    return MigrationPlan(
        source_version=source_version,
        source_label="legacy / unversioned" if source_version == 0 else f"schema {source_version}",
        target_version=target_version,
        steps=selected,
        changed=bool(selected),
        expected_backup_path=str(backup) if backup else None,
    )


def migrate_configuration(
    path: Path,
    *,
    target_version: int = CURRENT_CONFIG_SCHEMA_VERSION,
    dry_run: bool = False,
) -> MigrationResult:
    state = detect_config_version(path)
    plan = plan_migrations(
        state.version,
        target_version=target_version,
        path=path,
    )
    plan.source_label = state.label
    if state.version is None or not plan.steps:
        return MigrationResult(plan=plan, dry_run=dry_run)

    document = _read_document(path)
    original_text = document.to_text()
    transformed = apply_migrations(document, plan)
    final_text = transformed.to_text()
    plan.changed = final_text != original_text
    plan.affected_services = _affected_services_for_plan(plan)

    errors = validate_migrated_document(path, transformed, plan)
    if plan.conflicts or errors:
        plan.validation_errors = errors
        raise ConfigMigrationError(
            "config.migration.validation_failed",
            "Configuration migration validation failed.",
            details=[*plan.conflicts, *errors],
        )
    if not plan.changed:
        return MigrationResult(plan=plan, dry_run=dry_run)
    if dry_run:
        return MigrationResult(plan=plan, dry_run=True)

    backup = write_migrated_document_atomic(path, transformed, plan)
    return MigrationResult(
        plan=plan,
        dry_run=False,
        written=True,
        backup_path=str(backup),
    )


def apply_migrations(
    document: EnvDocument,
    plan: MigrationPlan,
) -> EnvDocument:
    current = document
    for step in plan.steps:
        current = step.transform(current, plan)
    return current


def validate_migrated_document(
    path: Path,
    document: EnvDocument,
    plan: MigrationPlan,
) -> list[dict[str, object]]:
    errors: list[dict[str, object]] = []
    values = document.values()
    marker = values.get(CONFIG_SCHEMA_ENV)
    if marker != str(plan.target_version):
        errors.append(
            {
                "key": CONFIG_SCHEMA_ENV,
                "code": "config.migration.marker_missing",
                "message": "Migrated configuration does not contain the target schema marker.",
            }
        )

    for key in document.entry_keys():
        item = _schema_item_for_env(key)
        if item is None:
            continue
        validation = item.validator(item, values.get(key, ""))
        if not validation.is_valid:
            for error in validation.errors:
                errors.append(error.to_dict())

    try:
        config = Settings(env=values, env_files=[])
        result = validate_config(config, mode=ValidationMode.INSTALL)
    except Exception:
        return errors
    ignored_codes = {
        "config.events_db.parent_missing",
        "config.events_db.parent_not_writable",
        "config.log_file.parent_missing",
        "config.log_file.parent_not_writable",
        "config.pihole_db.missing",
        "config.pihole_db.not_readable",
        "config.dashboard.secret_key_missing",
        "config.dashboard.password_hash_missing",
    }
    for issue in result.issues:
        if issue.severity != ValidationSeverity.ERROR.value:
            continue
        if issue.code in ignored_codes:
            continue
        errors.append(
            {
                "key": issue.setting,
                "code": issue.code,
                "message": issue.summary,
            }
        )
    return sorted(errors, key=lambda item: (str(item.get("key")), str(item.get("code"))))


def write_migrated_document_atomic(
    path: Path,
    document: EnvDocument,
    plan: MigrationPlan,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = _migration_backup_path(path, plan.steps)
    temp_path: Path | None = None
    mode = path.stat().st_mode & 0o777 if path.exists() else None
    try:
        shutil.copy2(path, backup_path)
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
        if mode is not None:
            os.chmod(temp_path, mode)
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


def _read_document(path: Path) -> EnvDocument:
    try:
        return EnvDocument.parse(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise ConfigMigrationError("config.read.invalid_encoding", "Configuration file is not valid UTF-8.") from exc
    except OSError as exc:
        raise ConfigMigrationError("config.read.unreadable", "Configuration file cannot be read.") from exc


def _v0_to_v1(document: EnvDocument, plan: MigrationPlan) -> EnvDocument:
    _detect_duplicate_marker(document)
    _detect_alias_conflicts(document, plan)
    new_lines = []
    for line in document.lines:
        if line.kind != "entry" or line.key is None:
            new_lines.append(line)
            continue
        if line.key in DEPRECATED_KEYS:
            _policy, warning = DEPRECATED_KEYS[line.key]
            if warning not in plan.warnings:
                plan.warnings.append(warning)
            plan.preserved_keys.append({"key": line.key, "policy": "preserve-with-warning"})
            new_lines.append(line)
            continue
        canonical = _canonical_env_for(line.key)
        if canonical and canonical != line.key:
            plan.renamed_keys.append({"from": line.key, "to": canonical})
            new_lines.append(replace(line, key=canonical, changed=True))
            continue
        new_lines.append(line)
    migrated = EnvDocument(new_lines, trailing_newline=document.trailing_newline)
    if CONFIG_SCHEMA_ENV not in migrated.entry_keys():
        migrated.set(CONFIG_SCHEMA_ENV, str(CONFIG_SCHEMA_VERSION))
    return migrated


def _detect_duplicate_marker(document: EnvDocument) -> None:
    if document.entry_keys().count(CONFIG_SCHEMA_ENV) > 1:
        raise ConfigMigrationError(
            "config.version.duplicate_marker",
            f"Duplicate {CONFIG_SCHEMA_ENV} markers found.",
        )


def _detect_alias_conflicts(document: EnvDocument, plan: MigrationPlan) -> None:
    entries: dict[str, list[str]] = {}
    exact_counts: dict[str, int] = {}
    for key in document.entry_keys():
        exact_counts[key] = exact_counts.get(key, 0) + 1
        canonical_key = _canonical_key_for_env(key)
        if canonical_key:
            entries.setdefault(canonical_key, []).append(key)
    for key, count in exact_counts.items():
        if count > 1 and (_canonical_key_for_env(key) or key == CONFIG_SCHEMA_ENV):
            plan.conflicts.append({"key": key, "code": "config.migration.duplicate_key"})
    for canonical_key, names in entries.items():
        if len(names) > 1:
            plan.conflicts.append(
                {
                    "key": canonical_key,
                    "code": "config.migration.alias_conflict",
                    "names": sorted(names),
                }
            )
    if plan.conflicts:
        raise ConfigMigrationError(
            "config.migration.conflict",
            "Configuration contains conflicting legacy aliases.",
            details=plan.conflicts,
        )


def _schema_item_for_env(env_name: str):
    for item in CONFIG_SCHEMA:
        if env_name in item.env_names:
            return item
    return None


def _canonical_env_for(env_name: str) -> str | None:
    item = _schema_item_for_env(env_name)
    if item is None:
        return None
    return item.env_var


def _canonical_key_for_env(env_name: str) -> str | None:
    item = _schema_item_for_env(env_name)
    return item.key if item is not None else None


def _affected_services_for_plan(plan: MigrationPlan) -> list[str]:
    keys = [
        _canonical_key_for_env(item["to"])
        for item in plan.renamed_keys
        if item.get("to")
    ]
    return affected_services([key for key in keys if key])


def _migration_backup_path(path: Path | None, steps: list[MigrationStep]) -> Path | None:
    if path is None or not steps:
        return None
    suffix = "-".join(f"v{step.from_version}-to-v{step.to_version}" for step in steps)
    base = path.with_name(f"{path.name}.migration-{suffix}.bak")
    candidate = base
    index = 1
    while candidate.exists():
        candidate = path.with_name(f"{base.name}.{index}")
        index += 1
    return candidate


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


MIGRATIONS: tuple[MigrationStep, ...] = (
    MigrationStep(
        migration_id="config-v0-to-v1",
        from_version=0,
        to_version=1,
        description="Normalize legacy aliases and add the schema marker.",
        transform=_v0_to_v1,
    ),
)


validate_registry()
