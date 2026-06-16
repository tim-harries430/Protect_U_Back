from __future__ import annotations

import hashlib
import json
import os
import platform
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from safe_path import safe_resolve


SCENE_SEED_SCHEMA = "scene_seed_v0"
SURROUNDINGS_SCHEMA = "scene_surroundings_guard_v0"

FORBIDDEN_SEED_KEYS = frozenset(
    {
        "p_enter",
        "p_exit",
        "x_enter",
        "x_exit",
        "omega",
        "omega_process",
        "evidence",
        "xray_evidence",
        "autopsy",
        "autopsy_report",
        "finding",
        "findings",
        "verdict",
        "decision",
        "can_execute",
        "can_kill",
        "can_grant_permission",
        "permission_granted",
    }
)

FORBIDDEN_SEED_VALUES = frozenset(
    {
        "HASH_MUTATED",
        "SCOPE_VIOLATION",
        "ADS_STREAM_CREATED",
        "MTIME_SPOOFED",
        "HARD_LINK_ALIAS",
        "ATOMIC_SWAP_DETECTED",
        "DELETED_DURING_WINDOW",
        "CREATED_DURING_WINDOW",
    }
)


class CapabilityState(str, Enum):
    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SceneClock:
    mtime_granularity_ns: int | None = None
    ctime_granularity_ns: int | None = None
    ctime_semantics: str = "unknown"
    timezone_name: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("mtime_granularity_ns", "ctime_granularity_ns"):
            value = getattr(self, field_name)
            if value is not None and value <= 0:
                raise ValueError(f"{field_name} must be positive when provided")

    def to_dict(self) -> dict[str, Any]:
        return {
            "mtime_granularity_ns": self.mtime_granularity_ns,
            "ctime_granularity_ns": self.ctime_granularity_ns,
            "ctime_semantics": self.ctime_semantics,
            "timezone_name": self.timezone_name,
        }


@dataclass(frozen=True)
class ScenePathRules:
    case_sensitive: bool | None = None
    path_separator: str = os.sep
    resolves_symlinks: bool = True
    allows_ads: CapabilityState | str = CapabilityState.UNKNOWN
    allows_hardlinks: CapabilityState | str = CapabilityState.UNKNOWN
    allows_symlinks: CapabilityState | str = CapabilityState.UNKNOWN
    allows_junctions: CapabilityState | str = CapabilityState.UNKNOWN

    def __post_init__(self) -> None:
        for field_name in (
            "allows_ads",
            "allows_hardlinks",
            "allows_symlinks",
            "allows_junctions",
        ):
            object.__setattr__(self, field_name, _capability(getattr(self, field_name)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_sensitive": self.case_sensitive,
            "path_separator": self.path_separator,
            "resolves_symlinks": self.resolves_symlinks,
            "allows_ads": self.allows_ads.value,
            "allows_hardlinks": self.allows_hardlinks.value,
            "allows_symlinks": self.allows_symlinks.value,
            "allows_junctions": self.allows_junctions.value,
        }


@dataclass(frozen=True)
class SceneSeed:
    seed_id: str
    boundary_root: str
    allowed_temp_root: str | None = None
    platform_name: str = field(default_factory=platform.system)
    filesystem_name: str = "unknown"
    permission_mode: str = "unknown"
    clock: SceneClock = field(default_factory=SceneClock)
    path_rules: ScenePathRules = field(default_factory=ScenePathRules)
    tool_hooks: Mapping[str, Any] = field(default_factory=dict)
    environment: Mapping[str, Any] = field(default_factory=dict)
    untouched_paths: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.seed_id.strip():
            raise ValueError("seed_id is required")
        if not str(self.boundary_root).strip():
            raise ValueError("boundary_root is required")
        _assert_seed_only(self.to_dict(include_schema=False))

    @property
    def seed_hash(self) -> str:
        return "sha256:" + _sha256_json(self.to_dict(include_hash=False))

    def to_dict(self, *, include_schema: bool = True, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "seed_id": self.seed_id,
            "boundary_root": self.boundary_root,
            "allowed_temp_root": self.allowed_temp_root,
            "platform_name": self.platform_name,
            "filesystem_name": self.filesystem_name,
            "permission_mode": self.permission_mode,
            "clock": self.clock.to_dict(),
            "path_rules": self.path_rules.to_dict(),
            "tool_hooks": _plain_data(self.tool_hooks),
            "environment": _plain_data(self.environment),
            "untouched_paths": tuple(str(path) for path in self.untouched_paths),
        }
        if include_schema:
            payload = {"schema": SCENE_SEED_SCHEMA, **payload}
        if include_hash:
            payload["seed_hash"] = "sha256:" + _sha256_json(payload)
        return payload


@dataclass(frozen=True)
class SurroundingObjectState:
    path: str
    exists: bool
    object_type: str
    size: int | None
    mtime_ns: int | None
    ctime_ns: int | None
    metadata_hash: str
    content_sha256: str | None = None
    content_hash_skipped: bool = False
    content_hash_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "object_type": self.object_type,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "ctime_ns": self.ctime_ns,
            "metadata_hash": self.metadata_hash,
            "content_sha256": self.content_sha256,
            "content_hash_skipped": self.content_hash_skipped,
            "content_hash_error": self.content_hash_error,
        }


@dataclass(frozen=True)
class SurroundingsGuardFinding:
    finding_type: str
    path: str
    before: SurroundingObjectState | None = None
    after: SurroundingObjectState | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "path": self.path,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
        }


@dataclass(frozen=True)
class SurroundingsGuardReport:
    seed_id: str
    findings: tuple[SurroundingsGuardFinding, ...]

    @property
    def requires_hold(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SURROUNDINGS_SCHEMA,
            "seed_id": self.seed_id,
            "requires_hold": self.requires_hold,
            "findings": tuple(finding.to_dict() for finding in self.findings),
        }


@dataclass(frozen=True)
class SurroundingsSnapshot:
    seed_id: str
    states: Mapping[str, SurroundingObjectState]

    def compare(self, after: "SurroundingsSnapshot") -> SurroundingsGuardReport:
        findings: list[SurroundingsGuardFinding] = []
        before_keys = set(self.states)
        after_keys = set(after.states)

        for path_key in sorted(before_keys | after_keys):
            before = self.states.get(path_key)
            current = after.states.get(path_key)
            if before is None and current is not None:
                findings.append(SurroundingsGuardFinding("SURROUNDING_CREATED", path_key, after=current))
            elif before is not None and current is None:
                findings.append(SurroundingsGuardFinding("SURROUNDING_REMOVED", path_key, before=before))
            elif before is not None and current is not None and before.to_dict() != current.to_dict():
                findings.append(SurroundingsGuardFinding("SURROUNDING_CHANGED", path_key, before, current))

        return SurroundingsGuardReport(seed_id=self.seed_id, findings=tuple(findings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SURROUNDINGS_SCHEMA,
            "seed_id": self.seed_id,
            "states": {path: state.to_dict() for path, state in sorted(self.states.items())},
        }


def capture_surroundings(
    seed: SceneSeed,
    *,
    extra_paths: Sequence[str | os.PathLike[str]] = (),
    max_file_bytes: int | None = None,
) -> SurroundingsSnapshot:
    if max_file_bytes is not None and max_file_bytes < 0:
        raise ValueError("max_file_bytes must be non-negative")
    paths = tuple(seed.untouched_paths) + tuple(str(path) for path in extra_paths)
    states = {
        str(safe_resolve(path)): _surrounding_state(Path(path), max_file_bytes=max_file_bytes)
        for path in paths
    }
    return SurroundingsSnapshot(seed_id=seed.seed_id, states=states)


def build_scene_seed(
    *,
    seed_id: str,
    boundary_root: str | os.PathLike[str],
    allowed_temp_root: str | os.PathLike[str] | None = None,
    permission_mode: str = "unknown",
    tool_hooks: Mapping[str, Any] | None = None,
    environment: Mapping[str, Any] | None = None,
    untouched_paths: Sequence[str | os.PathLike[str]] = (),
) -> SceneSeed:
    root = str(Path(boundary_root).resolve(strict=False))
    temp = str(Path(allowed_temp_root).resolve(strict=False)) if allowed_temp_root is not None else None
    return SceneSeed(
        seed_id=seed_id,
        boundary_root=root,
        allowed_temp_root=temp,
        platform_name=platform.system(),
        filesystem_name=_filesystem_name(root),
        permission_mode=permission_mode,
        clock=SceneClock(ctime_semantics=_ctime_semantics()),
        path_rules=ScenePathRules(
            case_sensitive=_case_sensitive(root),
            path_separator=os.sep,
            allows_ads=CapabilityState.PRESENT if os.name == "nt" else CapabilityState.ABSENT,
            allows_hardlinks=CapabilityState.UNKNOWN,
            allows_symlinks=CapabilityState.UNKNOWN,
            allows_junctions=CapabilityState.UNKNOWN if os.name == "nt" else CapabilityState.ABSENT,
        ),
        tool_hooks=tool_hooks or {},
        environment=environment or {},
        untouched_paths=tuple(str(Path(path).resolve(strict=False)) for path in untouched_paths),
    )


def _surrounding_state(path: Path, *, max_file_bytes: int | None) -> SurroundingObjectState:
    resolved = safe_resolve(path)
    try:
        stat_result = path.lstat()
    except (OSError, ValueError):
        values = {
            "path": str(resolved),
            "exists": False,
            "object_type": "missing",
            "size": None,
            "mtime_ns": None,
            "ctime_ns": None,
        }
        return SurroundingObjectState(**values, metadata_hash="sha256:" + _sha256_json(values))

    object_type = "directory" if path.is_dir() else "file" if path.is_file() else "other"
    content_hash = None
    skipped = False
    hash_error = None
    if object_type == "file":
        # Scene replay v0 must sample every watched file's content hash.
        # max_file_bytes is retained only for API compatibility with callers.
        try:
            content_hash = "sha256:" + _sha256_file(path)
        except OSError as exc:
            hash_error = f"{exc.__class__.__name__}: {exc}"

    values = {
        "path": str(resolved),
        "exists": True,
        "object_type": object_type,
        "size": stat_result.st_size,
        "mtime_ns": stat_result.st_mtime_ns,
        "ctime_ns": stat_result.st_ctime_ns,
        "content_sha256": content_hash,
        "content_hash_skipped": skipped,
        "content_hash_error": hash_error,
    }
    return SurroundingObjectState(**values, metadata_hash="sha256:" + _sha256_json(values))


def _assert_seed_only(value: Any, path: str = "seed") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in FORBIDDEN_SEED_KEYS:
                raise ValueError(f"SceneSeed cannot contain corpse/evidence/autopsy field: {path}.{key_text}")
            _assert_seed_only(item, f"{path}.{key_text}")
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(value):
            _assert_seed_only(item, f"{path}[{index}]")
    elif isinstance(value, str) and value in FORBIDDEN_SEED_VALUES:
        raise ValueError(f"SceneSeed cannot contain autopsy finding value: {path}")


def _capability(value: CapabilityState | str) -> CapabilityState:
    if isinstance(value, CapabilityState):
        return value
    try:
        return CapabilityState(str(value))
    except ValueError as exc:
        raise ValueError(f"unknown capability state: {value!r}") from exc


def _plain_data(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _plain_data(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(_plain_data(item) for item in value)
    if isinstance(value, Path):
        return str(value)
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(_plain_data(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _ctime_semantics() -> str:
    return "metadata_change_time" if os.name == "nt" else "inode_change_time"


def _case_sensitive(root: str) -> bool | None:
    path = Path(root)
    name = path.name
    if not name:
        return None
    return Path(str(path.parent / name.upper())) != Path(str(path.parent / name.lower()))


def _filesystem_name(root: str) -> str:
    if os.name == "nt":
        return "windows"
    try:
        return os.statvfs(root).__class__.__name__
    except OSError:
        return "unknown"
