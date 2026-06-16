from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from access_equation import (
    BoundaryMetric,
    ObservationMask,
    XrayObjectState,
)
from safe_path import safe_resolve


METADATA_VECTOR_SCHEMA = "sampled_metadata_vector_v0"
METADATA_CHANGE_SEMANTICS = "sampled_metadata_delta_v0"
DEFAULT_REQUIRED_FIELDS = (
    "exists",
    "object_type",
    "raw_path",
    "resolved_path",
    "metadata_vector_hash",
    "file_id",
    "nlink",
    "mtime_ns",
    "os_ctime_ns",
)
FULL_METADATA_FIELDS = (
    "schema",
    "sample_profile",
    "exists",
    "object_type",
    "raw_path",
    "resolved_path",
    "boundary_root",
    "byte_size",
    "mode",
    "file_id",
    "inode",
    "device_id",
    "nlink",
    "symlink_target",
    "reparse_tag",
    "mtime_ns",
    "os_ctime_ns",
    "os_ctime_semantics",
)


class MetadataSampleProfile(str, Enum):
    FULL = "full"
    TIME_SLICE = "time_slice"
    IDENTITY_SLICE = "identity_slice"
    BOUNDARY_SLICE = "boundary_slice"
    ALIAS_SLICE = "alias_slice"


PROFILE_FIELDS: dict[MetadataSampleProfile, tuple[str, ...]] = {
    MetadataSampleProfile.FULL: FULL_METADATA_FIELDS,
    MetadataSampleProfile.TIME_SLICE: (
        "schema",
        "sample_profile",
        "exists",
        "object_type",
        "raw_path",
        "byte_size",
        "mtime_ns",
        "os_ctime_ns",
        "os_ctime_semantics",
    ),
    MetadataSampleProfile.IDENTITY_SLICE: (
        "schema",
        "sample_profile",
        "exists",
        "object_type",
        "raw_path",
        "file_id",
        "inode",
        "device_id",
        "nlink",
    ),
    MetadataSampleProfile.BOUNDARY_SLICE: (
        "schema",
        "sample_profile",
        "exists",
        "object_type",
        "raw_path",
        "resolved_path",
        "boundary_root",
        "symlink_target",
        "reparse_tag",
    ),
    MetadataSampleProfile.ALIAS_SLICE: (
        "schema",
        "sample_profile",
        "exists",
        "object_type",
        "raw_path",
        "file_id",
        "inode",
        "device_id",
        "nlink",
    ),
}

PROFILE_REQUIRED_FIELDS: dict[MetadataSampleProfile, tuple[str, ...]] = {
    MetadataSampleProfile.FULL: DEFAULT_REQUIRED_FIELDS,
    MetadataSampleProfile.TIME_SLICE: (
        "exists",
        "object_type",
        "raw_path",
        "byte_size",
        "metadata_vector_hash",
        "mtime_ns",
        "os_ctime_ns",
    ),
    MetadataSampleProfile.IDENTITY_SLICE: (
        "exists",
        "object_type",
        "raw_path",
        "metadata_vector_hash",
        "file_id",
        "nlink",
    ),
    MetadataSampleProfile.BOUNDARY_SLICE: (
        "exists",
        "object_type",
        "raw_path",
        "resolved_path",
        "boundary_root",
        "metadata_vector_hash",
    ),
    MetadataSampleProfile.ALIAS_SLICE: (
        "exists",
        "object_type",
        "raw_path",
        "metadata_vector_hash",
        "file_id",
        "nlink",
    ),
}


@dataclass(frozen=True)
class ObjectStateSample:
    state: XrayObjectState
    boundary: BoundaryMetric
    observation: ObservationMask
    sampled_at_ns: int
    metadata_vector_hash: str
    metadata_vector: Mapping[str, Any]
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.to_dict(),
            "boundary": self.boundary.to_dict(),
            "observation": self.observation.to_dict(),
            "sampled_at_ns": self.sampled_at_ns,
            "metadata_vector_hash": self.metadata_vector_hash,
            "metadata_vector": dict(self.metadata_vector),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class MetadataChangeToken:
    changed: bool
    token: str | None
    semantics: str
    seen_at_ns: int | None
    enter_hash: str
    exit_hash: str
    enter_sampled_at_ns: int
    exit_sampled_at_ns: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "changed": self.changed,
            "token": self.token,
            "semantics": self.semantics,
            "seen_at_ns": self.seen_at_ns,
            "enter_hash": self.enter_hash,
            "exit_hash": self.exit_hash,
            "enter_sampled_at_ns": self.enter_sampled_at_ns,
            "exit_sampled_at_ns": self.exit_sampled_at_ns,
        }


def sample_xray_object_state(
    path: str | os.PathLike[str],
    *,
    raw_ref: str | None = None,
    cwd: str | os.PathLike[str] | None = None,
    boundary_root: str | os.PathLike[str] | None = None,
    sampled_at_ns: int | None = None,
    profile: MetadataSampleProfile | str = MetadataSampleProfile.FULL,
    required_fields: tuple[str, ...] | None = None,
) -> ObjectStateSample:
    sample_profile = _sample_profile(profile)
    sampled_fields = PROFILE_FIELDS[sample_profile]
    required = required_fields or PROFILE_REQUIRED_FIELDS[sample_profile]
    raw = str(raw_ref if raw_ref is not None else path)
    candidate = _candidate_path(path, cwd=cwd)
    needs_resolved = "resolved_path" in sampled_fields or "boundary_root" in sampled_fields
    resolved = _resolve(candidate) if needs_resolved else None
    boundary_root_path = (
        _resolve(Path(boundary_root))
        if boundary_root is not None and "boundary_root" in sampled_fields
        else None
    )
    sampled_at = int(sampled_at_ns if sampled_at_ns is not None else time.time_ns())

    stat_result = _safe_lstat(candidate)
    exists = stat_result is not None
    object_type = _object_type(candidate, stat_result)
    is_redirect = object_type in ("symlink", "reparse_point")
    symlink_target = (
        _safe_readlink(candidate)
        if is_redirect and "symlink_target" in sampled_fields
        else None
    )
    reparse_tag = _reparse_tag(stat_result) if "reparse_tag" in sampled_fields else None
    os_ctime_semantics = _os_ctime_semantics()

    size = (
        stat_result.st_size
        if stat_result is not None and object_type != "directory" and "byte_size" in sampled_fields
        else None
    )
    inode = _stat_int(stat_result, "st_ino") if "inode" in sampled_fields else None
    device_id = _stat_str(stat_result, "st_dev") if "device_id" in sampled_fields else None
    nlink = _stat_int(stat_result, "st_nlink") if "nlink" in sampled_fields else None
    mtime_ns = _stat_int(stat_result, "st_mtime_ns") if "mtime_ns" in sampled_fields else None
    ctime_ns = _stat_int(stat_result, "st_ctime_ns") if "os_ctime_ns" in sampled_fields else None
    mode = oct(stat_result.st_mode) if stat_result is not None and "mode" in sampled_fields else None
    file_id = _file_id(device_id=device_id, inode=inode) if "file_id" in sampled_fields else None

    full_vector = _metadata_vector(
        sample_profile=sample_profile.value,
        exists=exists,
        object_type=object_type,
        raw_path=raw,
        resolved_path=str(resolved) if resolved is not None else None,
        boundary_root=str(boundary_root_path) if boundary_root_path else None,
        byte_size=size,
        mode=mode,
        file_id=file_id,
        inode=inode,
        device_id=device_id,
        nlink=nlink,
        symlink_target=symlink_target,
        reparse_tag=reparse_tag,
        mtime_ns=mtime_ns,
        os_ctime_ns=ctime_ns,
        os_ctime_semantics=os_ctime_semantics,
    )
    vector = _profile_vector(full_vector, sampled_fields)
    vector_hash = _sha256_canonical(vector)
    observed_fields = _observed_fields(
        {
            **vector,
            "metadata_vector_hash": vector_hash,
        }
    )
    observation = ObservationMask.from_required_fields(
        required_fields=required,
        observed_fields=observed_fields,
        blind_spots=_blind_spots(
            exists=exists,
            object_type=object_type,
            file_id=file_id,
            nlink=nlink,
            ctime_ns=ctime_ns,
            symlink_target=symlink_target,
            object_type_is_redirect=is_redirect,
            sampled_fields=sampled_fields,
        ),
        details={
            "metadata_vector_schema": METADATA_VECTOR_SCHEMA,
            "os_ctime_semantics": os_ctime_semantics,
            "sample_profile": sample_profile.value,
            "sampled_fields": sampled_fields,
            "skipped_fields": _skipped_fields(sampled_fields),
        },
    )
    boundary = _boundary_metric(
        resolved=resolved,
        boundary_root=boundary_root_path,
        nlink=nlink,
    )
    state = XrayObjectState(
        object_ref=str(resolved if resolved is not None else candidate),
        exists=exists,
        object_type=object_type,
        raw_path=raw,
        resolved_path=str(resolved) if resolved is not None else None,
        boundary_root=str(boundary_root_path) if boundary_root_path else None,
        size=size,
        metadata_sha256=vector_hash,
        file_id=file_id,
        inode=inode,
        device_id=device_id,
        nlink=nlink,
        mtime_ns=mtime_ns,
        ctime_ns=ctime_ns,
        symlink_target=symlink_target,
        reparse_tag=reparse_tag,
        mode=mode,
        details={
            "byte_size": size,
            "metadata_vector_hash": vector_hash,
            "metadata_vector_schema": METADATA_VECTOR_SCHEMA,
            "os_ctime_semantics": os_ctime_semantics,
            "sample_profile": sample_profile.value,
            "sampled_fields": sampled_fields,
            "skipped_fields": _skipped_fields(sampled_fields),
        },
    )
    return ObjectStateSample(
        state=state,
        boundary=boundary,
        observation=observation,
        sampled_at_ns=sampled_at,
        metadata_vector_hash=vector_hash,
        metadata_vector=vector,
    )


def metadata_change_token(
    enter: ObjectStateSample,
    exit: ObjectStateSample,
) -> MetadataChangeToken:
    changed = enter.metadata_vector_hash != exit.metadata_vector_hash
    token = None
    if changed:
        token = _sha256_canonical(
            {
                "semantics": METADATA_CHANGE_SEMANTICS,
                "enter_object_ref": enter.state.object_ref,
                "exit_object_ref": exit.state.object_ref,
                "enter_hash": enter.metadata_vector_hash,
                "exit_hash": exit.metadata_vector_hash,
                "enter_sampled_at_ns": enter.sampled_at_ns,
                "exit_sampled_at_ns": exit.sampled_at_ns,
            }
        )
    return MetadataChangeToken(
        changed=changed,
        token=token,
        semantics=METADATA_CHANGE_SEMANTICS,
        seen_at_ns=exit.sampled_at_ns if changed else None,
        enter_hash=enter.metadata_vector_hash,
        exit_hash=exit.metadata_vector_hash,
        enter_sampled_at_ns=enter.sampled_at_ns,
        exit_sampled_at_ns=exit.sampled_at_ns,
    )


def _candidate_path(path: str | os.PathLike[str], *, cwd: str | os.PathLike[str] | None) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute() or cwd is None:
        return candidate
    return Path(cwd).expanduser() / candidate


def _sample_profile(profile: MetadataSampleProfile | str) -> MetadataSampleProfile:
    if isinstance(profile, MetadataSampleProfile):
        return profile
    return MetadataSampleProfile(str(profile))


def _profile_vector(
    full_vector: Mapping[str, Any],
    sampled_fields: tuple[str, ...],
) -> dict[str, Any]:
    return {
        field: full_vector.get(field)
        for field in sampled_fields
        if field in full_vector
    }


def _skipped_fields(sampled_fields: tuple[str, ...]) -> tuple[str, ...]:
    sampled = set(sampled_fields)
    return tuple(field for field in FULL_METADATA_FIELDS if field not in sampled)


def _safe_lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except (OSError, ValueError):
        return None


def _resolve(path: Path) -> Path:
    try:
        expanded = path.expanduser()
    except (OSError, ValueError, RuntimeError):
        expanded = path
    return safe_resolve(expanded)


def _object_type(path: Path, stat_result: os.stat_result | None) -> str:
    if stat_result is None:
        return "missing"
    mode = stat_result.st_mode
    if stat.S_ISLNK(mode):
        return "symlink"
    # An NT reparse point (junction / mount point) lstats as a plain directory or
    # file and reports S_ISLNK false, yet it forwards to another resource. Name it
    # for what it is so no downstream check mistakes the disguise for the target.
    if _reparse_tag(stat_result) is not None:
        return "reparse_point"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    return "other"


def _reparse_tag(stat_result: os.stat_result | None) -> int | None:
    if stat_result is None:
        return None
    tag = getattr(stat_result, "st_reparse_tag", 0)
    try:
        tag = int(tag)
    except (TypeError, ValueError):
        return None
    return tag or None


def _safe_readlink(path: Path) -> str | None:
    try:
        return os.readlink(path)
    except (OSError, ValueError):
        return None


def _os_ctime_semantics() -> str:
    if os.name == "nt":
        return "windows_creation_time"
    return "unix_metadata_change_time"


def _stat_int(stat_result: os.stat_result | None, field_name: str) -> int | None:
    if stat_result is None:
        return None
    value = getattr(stat_result, field_name, None)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _stat_str(stat_result: os.stat_result | None, field_name: str) -> str | None:
    value = _stat_int(stat_result, field_name)
    return str(value) if value is not None else None


def _file_id(*, device_id: str | None, inode: int | None) -> str | None:
    if device_id is None or inode is None:
        return None
    if inode == 0:
        return None
    return f"{device_id}:{inode}"


def _metadata_vector(
    *,
    sample_profile: str,
    exists: bool,
    object_type: str,
    raw_path: str,
    resolved_path: str | None,
    boundary_root: str | None,
    byte_size: int | None,
    mode: str | None,
    file_id: str | None,
    inode: int | None,
    device_id: str | None,
    nlink: int | None,
    symlink_target: str | None,
    reparse_tag: int | None,
    mtime_ns: int | None,
    os_ctime_ns: int | None,
    os_ctime_semantics: str,
) -> dict[str, Any]:
    return {
        "schema": METADATA_VECTOR_SCHEMA,
        "sample_profile": sample_profile,
        "exists": exists,
        "object_type": object_type,
        "raw_path": raw_path,
        "resolved_path": resolved_path,
        "boundary_root": boundary_root,
        "byte_size": byte_size,
        "mode": mode,
        "file_id": file_id,
        "inode": inode,
        "device_id": device_id,
        "nlink": nlink,
        "symlink_target": symlink_target,
        "reparse_tag": reparse_tag,
        "mtime_ns": mtime_ns,
        "os_ctime_ns": os_ctime_ns,
        "os_ctime_semantics": os_ctime_semantics,
    }


def _observed_fields(values: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        key
        for key, value in values.items()
        if value is not None
    )


def _blind_spots(
    *,
    exists: bool,
    object_type: str,
    file_id: str | None,
    nlink: int | None,
    ctime_ns: int | None,
    symlink_target: str | None,
    object_type_is_redirect: bool,
    sampled_fields: tuple[str, ...],
) -> tuple[str, ...]:
    spots: list[str] = []
    sampled = set(sampled_fields)
    if not exists:
        spots.append("object_missing")
    if "file_id" in sampled and file_id is None:
        spots.append("file_id_unavailable")
    if "nlink" in sampled and nlink is None:
        spots.append("nlink_unavailable")
    if "os_ctime_ns" in sampled and ctime_ns is None:
        spots.append("os_ctime_unavailable")
    if object_type_is_redirect and "symlink_target" in sampled and symlink_target is None:
        spots.append(
            "reparse_target_unavailable"
            if object_type == "reparse_point"
            else "symlink_target_unavailable"
        )
    return tuple(spots)


def _boundary_metric(
    *,
    resolved: Path | None,
    boundary_root: Path | None,
    nlink: int | None,
) -> BoundaryMetric:
    contained: tuple[str, ...] = ()
    escaped: tuple[str, ...] = ()
    distance: dict[str, float] = {}
    if resolved is not None and boundary_root is not None:
        inside = _is_inside_boundary(resolved, boundary_root)
        if inside:
            contained = (str(resolved),)
            distance[str(resolved)] = 0.0
        else:
            escaped = (str(resolved),)
            distance[str(resolved)] = 1.0
    alias_refs = ()
    if nlink is not None and nlink > 1:
        alias_refs = (f"nlink:{nlink}:{resolved}",)
    return BoundaryMetric(
        boundary_id="filesystem_boundary_v0",
        root=str(boundary_root) if boundary_root else None,
        scope="path_boundary" if boundary_root else "unknown",
        contained_refs=contained,
        escaped_refs=escaped,
        alias_refs=alias_refs,
        distance=distance,
        details={
            "alias_detection_semantics": "nlink_gt_1_is_alias_signal_nlink_1_is_not_proof",
        },
    )


def _is_inside_boundary(path: Path, boundary_root: Path) -> bool:
    try:
        path.relative_to(boundary_root)
        return True
    except ValueError:
        return False


def _sha256_canonical(value: Any) -> str:
    canonical = json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _canonicalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonicalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(_canonicalize(item) for item in value)
    return value
