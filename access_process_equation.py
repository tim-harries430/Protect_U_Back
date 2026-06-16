from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from access_field import AccessProcessSlot, AccessProcessTerm, AccessProcessVector


PROCESS_EQUATION_SCHEMA = "access_process_equation_v0"
PROCESS_EQUATION = "omega_process = relative_drift(P_exit, P_enter, field_frame) with T_auth applied only to T"
FORBIDDEN_AUTHORITY_FIELDS = (
    "can_execute",
    "can_kill",
    "can_grant_permission",
    "permission_granted",
)


class OmegaProcessState(str, Enum):
    CONTINUOUS = "CONTINUOUS"
    RESIDUAL = "RESIDUAL"
    INCOMPLETE_HOLD = "INCOMPLETE_HOLD"


@dataclass(frozen=True)
class FieldFrameDelta:
    components: Mapping[str, float] = field(default_factory=dict)
    frame_ref: str = "field_frame_v0"
    confidence: float = 1.0
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        confidence = float(self.confidence)
        if not math.isfinite(confidence):
            raise ValueError("field frame confidence must be finite")
        object.__setattr__(self, "components", _normalize_components(self.components))
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "details", dict(self.details))

    def value(self, component: str) -> float:
        return self.components.get(str(component), 0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "frame_ref": self.frame_ref,
            "components": dict(self.components),
            "confidence": self.confidence,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class ProcessComponentDelta:
    component: str
    enter_value: float
    exit_value: float
    frame_delta: float = 0.0
    auth_delta: float = 0.0

    @property
    def actual_delta(self) -> float:
        return self.exit_value - self.enter_value

    @property
    def residual(self) -> float:
        return self.actual_delta - self.frame_delta - self.auth_delta

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "enter_value": self.enter_value,
            "exit_value": self.exit_value,
            "actual_delta": self.actual_delta,
            "frame_delta": self.frame_delta,
            "auth_delta": self.auth_delta,
            "residual": self.residual,
        }


@dataclass(frozen=True)
class OmegaProcessResult:
    piece_ref: str
    enter_process: AccessProcessVector
    exit_process: AccessProcessVector
    frame_delta: FieldFrameDelta
    a_delta: float
    s_delta: float
    t_delta: float
    t_residual: float
    residual_components: Mapping[str, float] = field(default_factory=dict)
    explained_components: Mapping[str, float] = field(default_factory=dict)
    witnesses: tuple[dict[str, Any], ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "piece_ref", str(self.piece_ref))
        object.__setattr__(self, "residual_components", _normalize_components(self.residual_components))
        object.__setattr__(self, "explained_components", _normalize_components(self.explained_components))
        object.__setattr__(self, "witnesses", tuple(dict(witness) for witness in self.witnesses))
        object.__setattr__(self, "details", dict(self.details))

    @property
    def field_pressure(self) -> float:
        if not self.residual_components:
            return 0.0
        return max(abs(value) for value in self.residual_components.values())

    @property
    def requires_hold(self) -> bool:
        return bool(self.residual_components or self.witnesses)

    @property
    def state(self) -> OmegaProcessState:
        if any(witness.get("residual_type") in {"MISSING_PROCESS_SLOT", "OBSERVATION_GAP"} for witness in self.witnesses):
            return OmegaProcessState.INCOMPLETE_HOLD
        if self.residual_components:
            return OmegaProcessState.RESIDUAL
        return OmegaProcessState.CONTINUOUS

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": PROCESS_EQUATION_SCHEMA,
            "equation": PROCESS_EQUATION,
            "state": self.state.value,
            "piece_ref": self.piece_ref,
            "enter_process": self.enter_process.to_dict(),
            "exit_process": self.exit_process.to_dict(),
            "frame_delta": self.frame_delta.to_dict(),
            "a_delta": self.a_delta,
            "s_delta": self.s_delta,
            "t_delta": self.t_delta,
            "t_residual": self.t_residual,
            "residual_components": dict(self.residual_components),
            "explained_components": dict(self.explained_components),
            "field_pressure": self.field_pressure,
            "requires_hold": self.requires_hold,
            "witnesses": self.witnesses,
            "details": dict(self.details),
        }
        _assert_no_authority_fields(payload)
        return payload


def omega_process(
    *,
    piece_ref: str,
    enter_process: AccessProcessVector,
    exit_process: AccessProcessVector,
    frame_delta: FieldFrameDelta | Mapping[str, float] | None = None,
    t_auth: float | AccessProcessTerm | Mapping[str, float] | None = None,
    tolerance: float = 1e-9,
) -> OmegaProcessResult:
    frame = frame_delta if isinstance(frame_delta, FieldFrameDelta) else FieldFrameDelta(frame_delta or {})
    auth_t = _t_auth_value(t_auth)
    explained: dict[str, float] = {}

    a_delta = _slot_delta(enter_process.agency, exit_process.agency)
    s_delta = _slot_delta(enter_process.surface, exit_process.surface)
    t_delta = _slot_delta(enter_process.time, exit_process.time)

    residuals: dict[str, float] = {}
    witnesses: list[dict[str, Any]] = []
    witnesses.extend(_observation_witnesses(piece_ref, enter_process, phase="enter"))
    witnesses.extend(_observation_witnesses(piece_ref, exit_process, phase="exit"))

    _add_residual(
        residuals,
        witnesses,
        piece_ref=piece_ref,
        component="A",
        residual=a_delta - frame.value("A"),
        tolerance=tolerance,
    )
    _add_residual(
        residuals,
        witnesses,
        piece_ref=piece_ref,
        component="S",
        residual=s_delta - frame.value("S"),
        tolerance=tolerance,
    )

    raw_t_residual = t_delta - frame.value("T")
    applied_t_auth = min(abs(raw_t_residual), auth_t) * (1.0 if raw_t_residual >= 0 else -1.0)
    t_residual = raw_t_residual - applied_t_auth
    if auth_t:
        explained["T"] = applied_t_auth
    _add_residual(
        residuals,
        witnesses,
        piece_ref=piece_ref,
        component="T",
        residual=t_residual,
        tolerance=tolerance,
        residual_type="TEMPORAL_FRAME_RESIDUAL",
    )

    if witnesses and any(witness.get("component") == "O" for witness in witnesses):
        residuals["O"] = max(residuals.get("O", 0.0), 1.0)

    return OmegaProcessResult(
        piece_ref=piece_ref,
        enter_process=enter_process,
        exit_process=exit_process,
        frame_delta=frame,
        a_delta=a_delta,
        s_delta=s_delta,
        t_delta=t_delta,
        t_residual=t_residual,
        residual_components=residuals,
        explained_components=explained,
        witnesses=tuple(witnesses),
        details={
            "piece_model": "same_piece_ref_under_changing_field_frame",
            "t_auth_scope": "T_only",
        },
    )


def _slot_delta(enter: AccessProcessTerm, exit: AccessProcessTerm) -> float:
    if not enter.observed or not exit.observed:
        return 0.0
    return _slot_value(exit) - _slot_value(enter)


def _slot_value(term: AccessProcessTerm) -> float:
    if not term.projection_components:
        return 0.0
    return max(term.projection_components.values())


def _t_auth_value(t_auth: float | AccessProcessTerm | Mapping[str, float] | None) -> float:
    if t_auth is None:
        return 0.0
    if isinstance(t_auth, AccessProcessTerm):
        if t_auth.slot != AccessProcessSlot.TIME:
            raise ValueError("t_auth must be a TIME process term")
        return abs(_slot_value(t_auth))
    if isinstance(t_auth, Mapping):
        values = _normalize_components(t_auth)
        invalid = tuple(key for key in values if not _is_t_auth_component(key))
        if invalid:
            raise ValueError(f"t_auth can only explain T components: {invalid}")
        return max((abs(value) for value in values.values()), default=0.0)
    value = float(t_auth)
    if not math.isfinite(value):
        raise ValueError("t_auth must be finite")
    return abs(value)


def _add_residual(
    residuals: dict[str, float],
    witnesses: list[dict[str, Any]],
    *,
    piece_ref: str,
    component: str,
    residual: float,
    tolerance: float,
    residual_type: str = "FRAME_DRIFT_MISMATCH",
) -> None:
    if abs(residual) <= tolerance:
        return
    residuals[component] = residual
    witnesses.append(
        {
            "piece_ref": piece_ref,
            "component": component,
            "residual_type": residual_type,
            "residual": residual,
        }
    )


def _observation_witnesses(
    piece_ref: str,
    process: AccessProcessVector,
    *,
    phase: str,
) -> tuple[dict[str, Any], ...]:
    witnesses: list[dict[str, Any]] = []
    for term in process.terms:
        missing = term.details.get("missing_process_slot")
        observation_pressure = max(
            (
                pressure
                for component, pressure in term.projection_components.items()
                if str(component).startswith("observation_") and pressure > 0.0
            ),
            default=0.0,
        )
        if term.observed and observation_pressure <= 0.0:
            continue
        details = dict(term.details)
        if observation_pressure > 0.0:
            details["observation_pressure"] = observation_pressure
        witnesses.append(
            {
                "piece_ref": piece_ref,
                "component": "O",
                "residual_type": "MISSING_PROCESS_SLOT" if missing else "OBSERVATION_GAP",
                "phase": phase,
                "details": details,
            }
        )
    return tuple(witnesses)


def _normalize_components(values: Mapping[str, float]) -> dict[str, float]:
    normalized: dict[str, float] = {}
    for key, value in dict(values).items():
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ValueError("process equation component must be finite")
        normalized[str(key)] = numeric
    return normalized


def _is_t_auth_component(component: str) -> bool:
    token = str(component).lower()
    return token == "t" or any(
        marker in token
        for marker in ("time", "temporal", "ctime", "mtime", "window")
    )


def _assert_no_authority_fields(payload: Mapping[str, Any]) -> None:
    encoded = str(payload)
    for forbidden in FORBIDDEN_AUTHORITY_FIELDS:
        if forbidden in payload or forbidden in encoded:
            raise ValueError(f"process equation payload leaked authority field: {forbidden}")
