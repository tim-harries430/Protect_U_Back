from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Mapping, Sequence


FIELD_SCHEMA = "access_field_sparse_tensor_v0"
FIELD_DIMENSIONS = ("piece", "axis", "phase")
FIELD_PRESSURE_FORMULA = "field_pressure_v0=max(projection_components)"
PROCESS_VECTOR_SCHEMA = "access_process_vector_v0"
PROCESS_FORMULA = "P=A+S-T"
PROCESS_PROJECTION_FORMULA = (
    "process_projection_v0:signed_components=A+S-T;"
    "field_pressure=max(unsigned_projection_components)"
)


class AccessFieldPhase(IntEnum):
    ENTER = 0
    EXIT = 1
    ERROR = 2


class AccessFieldAxis(str, Enum):
    IDENTITY = "identity"
    BOUNDARY = "boundary"
    ALIAS = "alias"
    POINTER = "pointer"
    TIME = "time"
    RESPONSIBILITY = "responsibility"
    OBSERVATION = "observation"


class AccessProcessSlot(str, Enum):
    AGENCY = "A"
    SURFACE = "S"
    TIME = "T"


FIELD_PHASES: tuple[AccessFieldPhase, ...] = (
    AccessFieldPhase.ENTER,
    AccessFieldPhase.EXIT,
    AccessFieldPhase.ERROR,
)
FIELD_AXES: tuple[AccessFieldAxis, ...] = (
    AccessFieldAxis.IDENTITY,
    AccessFieldAxis.BOUNDARY,
    AccessFieldAxis.ALIAS,
    AccessFieldAxis.POINTER,
    AccessFieldAxis.TIME,
    AccessFieldAxis.RESPONSIBILITY,
    AccessFieldAxis.OBSERVATION,
)

RESIDUAL_AXIS_MAP: Mapping[str, AccessFieldAxis] = {
    "OBJECT_SUBSTITUTION": AccessFieldAxis.IDENTITY,
    "POINTER_REDIRECTION": AccessFieldAxis.POINTER,
    "ALIAS_WRITE": AccessFieldAxis.ALIAS,
    "CONTAINER_ESCAPE": AccessFieldAxis.BOUNDARY,
    "TEMPORAL_RACE": AccessFieldAxis.TIME,
    "RESPONSIBILITY_SWAP": AccessFieldAxis.RESPONSIBILITY,
    "OBSERVATION_BLINDNESS": AccessFieldAxis.OBSERVATION,
}

PROCESS_SLOT_SIGNS: Mapping[AccessProcessSlot, float] = {
    AccessProcessSlot.AGENCY: 1.0,
    AccessProcessSlot.SURFACE: 1.0,
    AccessProcessSlot.TIME: -1.0,
}


@dataclass(frozen=True)
class AccessFieldCoordinate:
    piece_ref: str
    axis: AccessFieldAxis | str
    phase: AccessFieldPhase | int
    value: float = 0.0
    observed: bool = True
    payload: Any = None
    projection_components: Mapping[str, float] = field(default_factory=dict)
    evidence: Mapping[str, Any] = field(default_factory=dict)
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        axis = self.axis if isinstance(self.axis, AccessFieldAxis) else AccessFieldAxis(str(self.axis))
        phase = (
            self.phase
            if isinstance(self.phase, AccessFieldPhase)
            else AccessFieldPhase(int(self.phase))
        )
        value = float(self.value)
        if not math.isfinite(value):
            raise ValueError("access field coordinate value must be finite")
        projection_components = _normalize_projection_components(self.projection_components)
        object.__setattr__(self, "piece_ref", str(self.piece_ref))
        object.__setattr__(self, "axis", axis)
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "payload", _plain_data(self.payload))
        object.__setattr__(self, "projection_components", projection_components)
        object.__setattr__(self, "evidence", dict(self.evidence))
        object.__setattr__(self, "details", dict(self.details))

    @property
    def key(self) -> tuple[str, AccessFieldAxis, AccessFieldPhase]:
        return (self.piece_ref, self.axis, self.phase)

    @property
    def field_pressure(self) -> float:
        if self.projection_components:
            return max(self.projection_components.values())
        return max(0.0, self.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": FIELD_SCHEMA,
            "piece_ref": self.piece_ref,
            "axis": self.axis.value,
            "phase": int(self.phase),
            "phase_name": self.phase.name,
            "value": self.value,
            "field_pressure_formula": FIELD_PRESSURE_FORMULA,
            "field_pressure": self.field_pressure,
            "observed": self.observed,
            "payload": self.payload,
            "projection_components": dict(self.projection_components),
            "evidence": dict(self.evidence),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class AccessFieldTensor:
    coordinates: Sequence[AccessFieldCoordinate] = field(default_factory=tuple)
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        normalized = tuple(
            coordinate
            if isinstance(coordinate, AccessFieldCoordinate)
            else AccessFieldCoordinate(**dict(coordinate))
            for coordinate in self.coordinates
        )
        seen: set[tuple[str, AccessFieldAxis, AccessFieldPhase]] = set()
        for coordinate in normalized:
            if coordinate.key in seen:
                raise ValueError(f"duplicate access field coordinate: {coordinate.key}")
            seen.add(coordinate.key)
        object.__setattr__(self, "coordinates", normalized)
        object.__setattr__(self, "details", dict(self.details))

    @property
    def piece_refs(self) -> tuple[str, ...]:
        return _unique_tuple(coordinate.piece_ref for coordinate in self.coordinates)

    @property
    def shape(self) -> tuple[int, int, int]:
        return (len(self.piece_refs), len(FIELD_AXES), len(FIELD_PHASES))

    @property
    def error_coordinates(self) -> tuple[AccessFieldCoordinate, ...]:
        return self.phase_slice(AccessFieldPhase.ERROR)

    @property
    def requires_hold(self) -> bool:
        return any(coordinate.field_pressure > 0.0 for coordinate in self.error_coordinates)

    def coordinate(
        self,
        piece_ref: str,
        axis: AccessFieldAxis | str,
        phase: AccessFieldPhase | int,
    ) -> AccessFieldCoordinate | None:
        key = coordinate_key(piece_ref, axis, phase)
        for coordinate in self.coordinates:
            if coordinate.key == key:
                return coordinate
        return None

    def phase_slice(self, phase: AccessFieldPhase | int) -> tuple[AccessFieldCoordinate, ...]:
        normalized_phase = (
            phase if isinstance(phase, AccessFieldPhase) else AccessFieldPhase(int(phase))
        )
        return tuple(
            coordinate
            for coordinate in self.coordinates
            if coordinate.phase == normalized_phase
        )

    def axis_slice(self, axis: AccessFieldAxis | str) -> tuple[AccessFieldCoordinate, ...]:
        normalized_axis = axis if isinstance(axis, AccessFieldAxis) else AccessFieldAxis(str(axis))
        return tuple(
            coordinate for coordinate in self.coordinates if coordinate.axis == normalized_axis
        )

    def delta(self, piece_ref: str, axis: AccessFieldAxis | str) -> float | None:
        enter = self.coordinate(piece_ref, axis, AccessFieldPhase.ENTER)
        exit_ = self.coordinate(piece_ref, axis, AccessFieldPhase.EXIT)
        if enter is None or exit_ is None:
            return None
        if not enter.observed or not exit_.observed:
            return None
        return exit_.value - enter.value

    def delta_vector(self, piece_ref: str) -> dict[str, float | None]:
        return {axis.value: self.delta(piece_ref, axis) for axis in FIELD_AXES}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": FIELD_SCHEMA,
            "dimensions": FIELD_DIMENSIONS,
            "shape": self.shape,
            "field_pressure_formula": FIELD_PRESSURE_FORMULA,
            "phases": {phase.name: int(phase) for phase in FIELD_PHASES},
            "axes": tuple(axis.value for axis in FIELD_AXES),
            "requires_hold": self.requires_hold,
            "coordinates": tuple(coordinate.to_dict() for coordinate in self.coordinates),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class AccessProcessTerm:
    slot: AccessProcessSlot | str
    payload: Any = None
    projection_components: Mapping[str, float] = field(default_factory=dict)
    observed: bool = True
    evidence: Mapping[str, Any] = field(default_factory=dict)
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        slot = _normalize_process_slot(self.slot)
        object.__setattr__(self, "slot", slot)
        object.__setattr__(self, "payload", _plain_data(self.payload))
        object.__setattr__(
            self,
            "projection_components",
            _normalize_projection_components(self.projection_components),
        )
        object.__setattr__(self, "evidence", dict(self.evidence))
        object.__setattr__(self, "details", dict(self.details))

    @property
    def sign(self) -> float:
        return PROCESS_SLOT_SIGNS[self.slot]

    @property
    def field_pressure(self) -> float:
        if self.projection_components:
            return max(self.projection_components.values())
        return 0.0

    @property
    def signed_components(self) -> dict[str, float]:
        return {
            component: self.sign * pressure
            for component, pressure in self.projection_components.items()
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PROCESS_VECTOR_SCHEMA,
            "slot": self.slot.value,
            "sign": self.sign,
            "payload": self.payload,
            "projection_components": dict(self.projection_components),
            "signed_components": self.signed_components,
            "field_pressure": self.field_pressure,
            "observed": self.observed,
            "evidence": dict(self.evidence),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class AccessProcessVector:
    process_ref: str
    agency: AccessProcessTerm | Mapping[str, Any] | None = None
    surface: AccessProcessTerm | Mapping[str, Any] | None = None
    time: AccessProcessTerm | Mapping[str, Any] | None = None
    phase: AccessFieldPhase | int | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        phase = (
            None
            if self.phase is None
            else self.phase
            if isinstance(self.phase, AccessFieldPhase)
            else AccessFieldPhase(int(self.phase))
        )
        object.__setattr__(self, "process_ref", str(self.process_ref))
        object.__setattr__(
            self,
            "agency",
            _coerce_process_term(self.agency, AccessProcessSlot.AGENCY),
        )
        object.__setattr__(
            self,
            "surface",
            _coerce_process_term(self.surface, AccessProcessSlot.SURFACE),
        )
        object.__setattr__(
            self,
            "time",
            _coerce_process_term(self.time, AccessProcessSlot.TIME),
        )
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "details", dict(self.details))

    @property
    def terms(self) -> tuple[AccessProcessTerm, AccessProcessTerm, AccessProcessTerm]:
        return (self.agency, self.surface, self.time)

    @property
    def payload(self) -> dict[str, Any]:
        return {term.slot.value: term.payload for term in self.terms}

    @property
    def projection_components(self) -> dict[str, float]:
        merged: dict[str, float] = {}
        for term in self.terms:
            for component, pressure in term.projection_components.items():
                merged[component] = max(merged.get(component, 0.0), pressure)
        return merged

    @property
    def signed_components(self) -> dict[str, float]:
        signed: dict[str, float] = {}
        for term in self.terms:
            for component, value in term.signed_components.items():
                signed[component] = signed.get(component, 0.0) + value
        return signed

    @property
    def field_pressure(self) -> float:
        components = self.projection_components
        if components:
            return max(components.values())
        return 0.0

    @property
    def requires_hold(self) -> bool:
        if any(not term.observed for term in self.terms):
            return True
        return any(
            _component_axis(component) == AccessFieldAxis.OBSERVATION and pressure > 0.0
            for component, pressure in self.projection_components.items()
        )

    @property
    def axis_projection_components(self) -> dict[AccessFieldAxis, dict[str, float]]:
        grouped: dict[AccessFieldAxis, dict[str, float]] = {}
        for component, pressure in self.projection_components.items():
            axis = _component_axis(component)
            grouped.setdefault(axis, {})[component] = pressure
        return grouped

    @property
    def signed_axis_values(self) -> dict[AccessFieldAxis, float]:
        grouped: dict[AccessFieldAxis, float] = {}
        for component, signed_value in self.signed_components.items():
            axis = _component_axis(component)
            grouped[axis] = grouped.get(axis, 0.0) + signed_value
        return grouped

    def to_field_tensor(
        self,
        *,
        piece_ref: str | None = None,
        phase: AccessFieldPhase | int | None = None,
    ) -> AccessFieldTensor:
        normalized_phase = (
            self.phase
            if phase is None
            else phase
            if isinstance(phase, AccessFieldPhase)
            else AccessFieldPhase(int(phase))
        )
        if normalized_phase is None:
            raise ValueError("process vector phase is required to emit field coordinates")

        axis_values = self.signed_axis_values
        axis_components = self.axis_projection_components
        axes = tuple(sorted(set(axis_values) | set(axis_components), key=lambda axis: axis.value))
        payload = self.process_payload()
        coordinates = tuple(
            AccessFieldCoordinate(
                piece_ref=piece_ref or self.process_ref,
                axis=axis,
                phase=normalized_phase,
                value=axis_values.get(axis, 0.0),
                payload=payload,
                projection_components=axis_components.get(axis, {}),
                evidence={"process_formula": PROCESS_FORMULA},
            )
            for axis in axes
        )
        return AccessFieldTensor(
            coordinates=coordinates,
            details={
                "process_ref": self.process_ref,
                "process_formula": PROCESS_FORMULA,
                "projection_formula": PROCESS_PROJECTION_FORMULA,
            },
        )

    def process_payload(self) -> dict[str, Any]:
        return {
            "schema": PROCESS_VECTOR_SCHEMA,
            "process_ref": self.process_ref,
            "formula": PROCESS_FORMULA,
            "projection_formula": PROCESS_PROJECTION_FORMULA,
            "payload": self.payload,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PROCESS_VECTOR_SCHEMA,
            "process_ref": self.process_ref,
            "formula": PROCESS_FORMULA,
            "projection_formula": PROCESS_PROJECTION_FORMULA,
            "phase": int(self.phase) if self.phase is not None else None,
            "payload": self.payload,
            "terms": tuple(term.to_dict() for term in self.terms),
            "projection_components": self.projection_components,
            "signed_components": self.signed_components,
            "signed_axis_values": {
                axis.value: value for axis, value in self.signed_axis_values.items()
            },
            "field_pressure": self.field_pressure,
            "requires_hold": self.requires_hold,
            "details": dict(self.details),
        }


def coordinate_key(
    piece_ref: str,
    axis: AccessFieldAxis | str,
    phase: AccessFieldPhase | int,
) -> tuple[str, AccessFieldAxis, AccessFieldPhase]:
    normalized_axis = axis if isinstance(axis, AccessFieldAxis) else AccessFieldAxis(str(axis))
    normalized_phase = (
        phase if isinstance(phase, AccessFieldPhase) else AccessFieldPhase(int(phase))
    )
    return (str(piece_ref), normalized_axis, normalized_phase)


def axis_from_residual_type(residual_type: str) -> AccessFieldAxis:
    return RESIDUAL_AXIS_MAP.get(str(residual_type), AccessFieldAxis.OBSERVATION)


def build_access_field_tensor(
    *,
    piece_ref: str,
    enter: Mapping[AccessFieldAxis | str, float] | None = None,
    exit: Mapping[AccessFieldAxis | str, float] | None = None,
    error: Mapping[AccessFieldAxis | str, float] | None = None,
    payloads: Mapping[tuple[AccessFieldAxis | str, AccessFieldPhase | int], Any] | None = None,
    projections: Mapping[
        tuple[AccessFieldAxis | str, AccessFieldPhase | int],
        Mapping[str, float],
    ]
    | None = None,
    details: Mapping[str, Any] | None = None,
) -> AccessFieldTensor:
    coordinates: list[AccessFieldCoordinate] = []
    normalized_payloads = _normalize_axis_phase_values(payloads or {})
    normalized_projections = _normalize_axis_phase_values(projections or {})
    for phase, values in (
        (AccessFieldPhase.ENTER, enter or {}),
        (AccessFieldPhase.EXIT, exit or {}),
        (AccessFieldPhase.ERROR, error or {}),
    ):
        for axis, value in values.items():
            key = _axis_phase_key(axis, phase)
            coordinates.append(
                AccessFieldCoordinate(
                    piece_ref=piece_ref,
                    axis=axis,
                    phase=phase,
                    value=value,
                    payload=normalized_payloads.get(key),
                    projection_components=normalized_projections.get(key, {}),
                )
            )
    return AccessFieldTensor(coordinates=tuple(coordinates), details=details or {})


def build_access_process_vector(
    *,
    process_ref: str,
    agency_payload: Any = None,
    surface_payload: Any = None,
    time_payload: Any = None,
    agency_components: Mapping[str, float] | None = None,
    surface_components: Mapping[str, float] | None = None,
    time_components: Mapping[str, float] | None = None,
    phase: AccessFieldPhase | int | None = None,
    details: Mapping[str, Any] | None = None,
) -> AccessProcessVector:
    return AccessProcessVector(
        process_ref=process_ref,
        agency=AccessProcessTerm(
            AccessProcessSlot.AGENCY,
            payload=agency_payload,
            projection_components=agency_components or {},
        ),
        surface=AccessProcessTerm(
            AccessProcessSlot.SURFACE,
            payload=surface_payload,
            projection_components=surface_components or {},
        ),
        time=AccessProcessTerm(
            AccessProcessSlot.TIME,
            payload=time_payload,
            projection_components=time_components or {},
        ),
        phase=phase,
        details=details or {},
    )


def _unique_tuple(values: Sequence[str] | Any) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        item = str(value)
        if item not in seen:
            seen.add(item)
            result.append(item)
    return tuple(result)


def _normalize_projection_components(components: Mapping[str, float]) -> dict[str, float]:
    normalized: dict[str, float] = {}
    for key, value in dict(components).items():
        pressure = float(value)
        if not math.isfinite(pressure):
            raise ValueError("access field projection component must be finite")
        if pressure < 0.0:
            raise ValueError("access field projection component must be non-negative")
        normalized[str(key)] = pressure
    return normalized


def _normalize_process_slot(slot: AccessProcessSlot | str) -> AccessProcessSlot:
    if isinstance(slot, AccessProcessSlot):
        return slot
    token = str(slot).strip().upper()
    aliases = {
        "A": AccessProcessSlot.AGENCY,
        "AGENCY": AccessProcessSlot.AGENCY,
        "ACTOR": AccessProcessSlot.AGENCY,
        "SOURCE": AccessProcessSlot.AGENCY,
        "S": AccessProcessSlot.SURFACE,
        "SURFACE": AccessProcessSlot.SURFACE,
        "CONTACT": AccessProcessSlot.SURFACE,
        "T": AccessProcessSlot.TIME,
        "TIME": AccessProcessSlot.TIME,
        "WINDOW": AccessProcessSlot.TIME,
    }
    if token not in aliases:
        raise ValueError(f"unknown access process slot: {slot}")
    return aliases[token]


def _coerce_process_term(
    value: AccessProcessTerm | Mapping[str, Any] | None,
    slot: AccessProcessSlot,
) -> AccessProcessTerm:
    if value is None:
        return AccessProcessTerm(
            slot,
            payload=None,
            projection_components={"observation_pressure": 1.0},
            observed=False,
            details={"missing_process_slot": slot.value},
        )
    if isinstance(value, AccessProcessTerm):
        if value.slot != slot:
            raise ValueError(f"process term slot mismatch: expected {slot.value}, got {value.slot.value}")
        return value
    data = dict(value)
    if any(
        key in data
        for key in ("slot", "payload", "projection_components", "observed", "evidence", "details")
    ):
        return AccessProcessTerm(
            data.get("slot", slot),
            payload=data.get("payload"),
            projection_components=data.get("projection_components", {}),
            observed=bool(data.get("observed", True)),
            evidence=data.get("evidence", {}),
            details=data.get("details", {}),
        )
    return AccessProcessTerm(slot, payload=data)


def _component_axis(component: str) -> AccessFieldAxis:
    token = str(component).lower()
    if "boundary" in token or "escape" in token or "container" in token:
        return AccessFieldAxis.BOUNDARY
    if "alias" in token or "link" in token or "nlink" in token:
        return AccessFieldAxis.ALIAS
    if "pointer" in token or "symlink" in token or "resolved_path" in token:
        return AccessFieldAxis.POINTER
    if "time" in token or "temporal" in token or "race" in token or "ctime" in token or "mtime" in token:
        return AccessFieldAxis.TIME
    if "responsibility" in token or "agency" in token or "actor" in token or "skill" in token or "tool" in token:
        return AccessFieldAxis.RESPONSIBILITY
    if "observation" in token or "blind" in token or "missing" in token or "unknown" in token:
        return AccessFieldAxis.OBSERVATION
    return AccessFieldAxis.IDENTITY


def _normalize_axis_phase_values(mapping: Mapping[tuple[AccessFieldAxis | str, AccessFieldPhase | int], Any]) -> dict[
    tuple[AccessFieldAxis, AccessFieldPhase],
    Any,
]:
    return {_axis_phase_key(axis, phase): value for (axis, phase), value in dict(mapping).items()}


def _axis_phase_key(
    axis: AccessFieldAxis | str,
    phase: AccessFieldPhase | int,
) -> tuple[AccessFieldAxis, AccessFieldPhase]:
    normalized_axis = axis if isinstance(axis, AccessFieldAxis) else AccessFieldAxis(str(axis))
    normalized_phase = (
        phase if isinstance(phase, AccessFieldPhase) else AccessFieldPhase(int(phase))
    )
    return (normalized_axis, normalized_phase)


def _plain_data(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain_data(inner) for key, inner in value.items()}
    if isinstance(value, (list, tuple)):
        return tuple(_plain_data(inner) for inner in value)
    if isinstance(value, set):
        return tuple(sorted((_plain_data(inner) for inner in value), key=repr))
    return value
