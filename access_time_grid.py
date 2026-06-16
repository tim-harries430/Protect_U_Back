from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from access_field import AccessProcessSlot, AccessProcessTerm


TIME_GRID_SCHEMA = "access_time_grid_v0"
TIME_GRID_REQUIRED_FIELDS = (
    "metadata_vector_hash",
    "mtime_ns",
    "os_ctime_ns",
    "os_ctime_semantics",
    "file_id",
    "nlink",
    "resolved_path",
)
WINDOWS_CTIME = "windows_creation_time"
UNIX_CTIME = "unix_metadata_change_time"


@dataclass(frozen=True)
class TimeGridSpec:
    enter_ts_ns: int
    exit_ts_ns: int
    step_ns: int
    required_fields: Sequence[str] = TIME_GRID_REQUIRED_FIELDS
    max_sample_drift_ns: int | None = None

    def __post_init__(self):
        enter = int(self.enter_ts_ns)
        exit_ = int(self.exit_ts_ns)
        step = int(self.step_ns)
        if step <= 0:
            raise ValueError("time grid step_ns must be positive")
        if exit_ < enter:
            raise ValueError("time grid exit_ts_ns must be >= enter_ts_ns")
        max_drift = self.max_sample_drift_ns
        if max_drift is not None and int(max_drift) < 0:
            raise ValueError("time grid max_sample_drift_ns must be non-negative")
        object.__setattr__(self, "enter_ts_ns", enter)
        object.__setattr__(self, "exit_ts_ns", exit_)
        object.__setattr__(self, "step_ns", step)
        object.__setattr__(self, "required_fields", tuple(str(field) for field in self.required_fields))
        object.__setattr__(self, "max_sample_drift_ns", None if max_drift is None else int(max_drift))

    @property
    def expected_timestamps(self) -> tuple[int, ...]:
        timestamps = [self.enter_ts_ns]
        cursor = self.enter_ts_ns + self.step_ns
        while cursor < self.exit_ts_ns:
            timestamps.append(cursor)
            cursor += self.step_ns
        if timestamps[-1] != self.exit_ts_ns:
            timestamps.append(self.exit_ts_ns)
        return tuple(timestamps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": TIME_GRID_SCHEMA,
            "enter_ts_ns": self.enter_ts_ns,
            "exit_ts_ns": self.exit_ts_ns,
            "step_ns": self.step_ns,
            "expected_timestamps": self.expected_timestamps,
            "required_fields": tuple(self.required_fields),
            "max_sample_drift_ns": self.max_sample_drift_ns,
        }


@dataclass(frozen=True)
class TimeGridCell:
    index: int
    expected_ts_ns: int
    sampled_at_ns: int | None = None
    metadata_vector_hash: str | None = None
    mtime_ns: int | None = None
    os_ctime_ns: int | None = None
    os_ctime_semantics: str | None = None
    file_id: str | None = None
    nlink: int | None = None
    resolved_path: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "index", int(self.index))
        object.__setattr__(self, "expected_ts_ns", int(self.expected_ts_ns))
        object.__setattr__(
            self,
            "sampled_at_ns",
            None if self.sampled_at_ns is None else int(self.sampled_at_ns),
        )
        object.__setattr__(self, "mtime_ns", None if self.mtime_ns is None else int(self.mtime_ns))
        object.__setattr__(
            self,
            "os_ctime_ns",
            None if self.os_ctime_ns is None else int(self.os_ctime_ns),
        )
        object.__setattr__(self, "nlink", None if self.nlink is None else int(self.nlink))
        object.__setattr__(self, "details", dict(self.details))

    @classmethod
    def from_sample(
        cls,
        *,
        index: int,
        expected_ts_ns: int,
        sample: Any,
    ) -> "TimeGridCell":
        state = getattr(sample, "state", None)
        vector = dict(getattr(sample, "metadata_vector", {}) or {})
        details = dict(getattr(state, "details", {}) or {})
        semantics = (
            vector.get("os_ctime_semantics")
            or details.get("os_ctime_semantics")
            or _sample_detail(sample, "os_ctime_semantics")
        )
        return cls(
            index=index,
            expected_ts_ns=expected_ts_ns,
            sampled_at_ns=getattr(sample, "sampled_at_ns", None),
            metadata_vector_hash=getattr(sample, "metadata_vector_hash", None)
            or vector.get("metadata_vector_hash")
            or details.get("metadata_vector_hash"),
            mtime_ns=getattr(state, "mtime_ns", None) or vector.get("mtime_ns"),
            os_ctime_ns=getattr(state, "ctime_ns", None) or vector.get("os_ctime_ns"),
            os_ctime_semantics=semantics,
            file_id=getattr(state, "file_id", None) or vector.get("file_id"),
            nlink=getattr(state, "nlink", None) or vector.get("nlink"),
            resolved_path=getattr(state, "resolved_path", None) or vector.get("resolved_path"),
            details={
                "source": "ObjectStateSample",
                "sample_profile": vector.get("sample_profile") or details.get("sample_profile"),
            },
        )

    def missing_fields(self, required_fields: Sequence[str]) -> tuple[str, ...]:
        payload = self.to_dict()
        return tuple(field for field in required_fields if payload.get(field) is None)

    def sample_drift_ns(self) -> int | None:
        if self.sampled_at_ns is None:
            return None
        return abs(self.sampled_at_ns - self.expected_ts_ns)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": TIME_GRID_SCHEMA,
            "index": self.index,
            "expected_ts_ns": self.expected_ts_ns,
            "sampled_at_ns": self.sampled_at_ns,
            "metadata_vector_hash": self.metadata_vector_hash,
            "mtime_ns": self.mtime_ns,
            "os_ctime_ns": self.os_ctime_ns,
            "os_ctime_semantics": self.os_ctime_semantics,
            "file_id": self.file_id,
            "nlink": self.nlink,
            "resolved_path": self.resolved_path,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class TimeGridTrace:
    spec: TimeGridSpec
    cells: Sequence[TimeGridCell] = field(default_factory=tuple)
    object_ref: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        spec = self.spec if isinstance(self.spec, TimeGridSpec) else TimeGridSpec(**dict(self.spec))
        cells = tuple(_coerce_cell(cell, spec) for cell in self.cells)
        seen: set[int] = set()
        for cell in cells:
            if cell.index in seen:
                raise ValueError(f"duplicate time grid cell index: {cell.index}")
            seen.add(cell.index)
        object.__setattr__(self, "spec", spec)
        object.__setattr__(self, "cells", tuple(sorted(cells, key=lambda cell: cell.index)))
        object.__setattr__(self, "details", dict(self.details))

    @classmethod
    def from_samples(
        cls,
        *,
        spec: TimeGridSpec,
        samples: Sequence[Any],
        object_ref: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> "TimeGridTrace":
        timestamps = spec.expected_timestamps
        cells = tuple(
            TimeGridCell.from_sample(index=index, expected_ts_ns=timestamps[index], sample=sample)
            for index, sample in enumerate(samples)
            if index < len(timestamps)
        )
        return cls(spec=spec, cells=cells, object_ref=object_ref, details=details or {})

    @property
    def missing_cell_indices(self) -> tuple[int, ...]:
        expected = set(range(len(self.spec.expected_timestamps)))
        present = {cell.index for cell in self.cells}
        return tuple(sorted(expected - present))

    @property
    def findings(self) -> tuple[dict[str, Any], ...]:
        findings: list[dict[str, Any]] = []
        for index in self.missing_cell_indices:
            findings.append(
                {
                    "type": "GRID_MISSING_CELL",
                    "component": "observation_grid_missing_cell_pressure",
                    "severity": 1.0,
                    "cell_index": index,
                }
            )
        for cell in self.cells:
            for field_name in cell.missing_fields(self.spec.required_fields):
                findings.append(
                    {
                        "type": "GRID_MISSING_FIELD",
                        "component": "observation_grid_missing_field_pressure",
                        "severity": 1.0,
                        "cell_index": cell.index,
                        "field": field_name,
                    }
                )
            drift = cell.sample_drift_ns()
            if (
                drift is not None
                and self.spec.max_sample_drift_ns is not None
                and drift > self.spec.max_sample_drift_ns
            ):
                findings.append(
                    {
                        "type": "GRID_SAMPLE_DRIFT",
                        "component": "temporal_sample_drift_pressure",
                        "severity": _bounded_pressure(drift, self.spec.step_ns),
                        "cell_index": cell.index,
                        "drift_ns": drift,
                    }
                )

        semantics = tuple(
            sorted({cell.os_ctime_semantics for cell in self.cells if cell.os_ctime_semantics})
        )
        if not semantics or len(semantics) > 1 or any(item not in (WINDOWS_CTIME, UNIX_CTIME) for item in semantics):
            findings.append(
                {
                    "type": "GRID_SEMANTIC_MIXED",
                    "component": "observation_semantics_mixed_pressure",
                    "severity": 1.0,
                    "semantics": semantics,
                }
            )

        for before, after in _adjacent_cells(self.cells):
            findings.extend(_cell_pair_findings(before, after))
        return tuple(findings)

    @property
    def projection_components(self) -> dict[str, float]:
        components: dict[str, float] = {}
        for finding in self.findings:
            component = str(finding["component"])
            severity = float(finding["severity"])
            components[component] = max(components.get(component, 0.0), severity)
        return components

    @property
    def requires_hold(self) -> bool:
        return any(component.startswith("observation_") for component in self.projection_components)

    def to_process_time_term(self) -> AccessProcessTerm:
        return AccessProcessTerm(
            AccessProcessSlot.TIME,
            payload=self.to_dict(),
            projection_components=self.projection_components,
            observed=not self.requires_hold,
            evidence={"time_axis": "fixed_grid"},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": TIME_GRID_SCHEMA,
            "object_ref": self.object_ref,
            "spec": self.spec.to_dict(),
            "cells": tuple(cell.to_dict() for cell in self.cells),
            "missing_cell_indices": self.missing_cell_indices,
            "findings": self.findings,
            "projection_components": dict(self.projection_components),
            "requires_hold": self.requires_hold,
            "details": dict(self.details),
        }


def build_time_grid_trace(
    *,
    spec: TimeGridSpec,
    cells: Sequence[TimeGridCell | Mapping[str, Any]],
    object_ref: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> TimeGridTrace:
    return TimeGridTrace(spec=spec, cells=tuple(cells), object_ref=object_ref, details=details or {})


def _coerce_cell(cell: TimeGridCell | Mapping[str, Any], spec: TimeGridSpec) -> TimeGridCell:
    if isinstance(cell, TimeGridCell):
        return cell
    data = dict(cell)
    if "expected_ts_ns" not in data and "index" in data:
        index = int(data["index"])
        timestamps = spec.expected_timestamps
        if 0 <= index < len(timestamps):
            data["expected_ts_ns"] = timestamps[index]
    return TimeGridCell(**data)


def _cell_pair_findings(before: TimeGridCell, after: TimeGridCell) -> tuple[dict[str, Any], ...]:
    findings: list[dict[str, Any]] = []
    if before.metadata_vector_hash and after.metadata_vector_hash and before.metadata_vector_hash != after.metadata_vector_hash:
        findings.append(_pair_finding("GRID_HASH_CHANGE", "temporal_hash_change_pressure", before, after))
    if before.file_id and after.file_id and before.file_id != after.file_id:
        findings.append(_pair_finding("GRID_IDENTITY_DRIFT", "identity_file_id_drift_pressure", before, after))
    if before.resolved_path and after.resolved_path and before.resolved_path != after.resolved_path:
        findings.append(_pair_finding("GRID_POINTER_DRIFT", "pointer_resolved_path_drift_pressure", before, after))
    if before.nlink is not None and after.nlink is not None and before.nlink != after.nlink:
        findings.append(_pair_finding("GRID_ALIAS_DRIFT", "alias_nlink_drift_pressure", before, after))
    if before.mtime_ns is not None and after.mtime_ns is not None and before.mtime_ns != after.mtime_ns:
        findings.append(_pair_finding("GRID_MTIME_DRIFT", "temporal_mtime_drift_pressure", before, after))
    if before.os_ctime_ns is not None and after.os_ctime_ns is not None and before.os_ctime_ns != after.os_ctime_ns:
        component = (
            "identity_creation_time_drift_pressure"
            if after.os_ctime_semantics == WINDOWS_CTIME
            else "temporal_ctime_drift_pressure"
        )
        findings.append(_pair_finding("GRID_CTIME_DRIFT", component, before, after))
    return tuple(findings)


def _pair_finding(
    finding_type: str,
    component: str,
    before: TimeGridCell,
    after: TimeGridCell,
) -> dict[str, Any]:
    return {
        "type": finding_type,
        "component": component,
        "severity": 1.0,
        "before_index": before.index,
        "after_index": after.index,
    }


def _adjacent_cells(cells: Sequence[TimeGridCell]) -> tuple[tuple[TimeGridCell, TimeGridCell], ...]:
    sorted_cells = tuple(sorted(cells, key=lambda cell: cell.index))
    return tuple(zip(sorted_cells, sorted_cells[1:]))


def _bounded_pressure(value: int, scale: int) -> float:
    if scale <= 0:
        return 1.0
    return min(1.0, max(0.0, float(value) / float(scale)))


def _sample_detail(sample: Any, key: str) -> Any:
    details = dict(getattr(sample, "details", {}) or {})
    return details.get(key)
