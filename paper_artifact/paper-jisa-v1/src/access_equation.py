from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


EQUATION = "omega_access(p) = o_apply(delta_b_x + div_b_j - u_auth(p))"
P_ZERO_ADMISSION_POLICY = (
    "p_zero:no_trusted_access_process:"
    "do_not_evaluate_omega_access:"
    "route_to_access_admission_hard_reject"
)
NO_TRUSTED_ACCESS_PROCESS = "NO_TRUSTED_ACCESS_PROCESS"


class ObservationState(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNOBSERVED = "UNOBSERVED"


class AccessResidualState(str, Enum):
    CONTINUOUS = "CONTINUOUS"
    RESIDUAL = "RESIDUAL"
    EXPLAINED = "EXPLAINED"
    INCOMPLETE = "INCOMPLETE"
    UNOBSERVED = "UNOBSERVED"


class AccessEquationState(str, Enum):
    CONTINUOUS = "CONTINUOUS"
    EXPLAINED = "EXPLAINED"
    RESIDUAL = "RESIDUAL"
    INCOMPLETE_HOLD = "INCOMPLETE_HOLD"
    UNOBSERVED_HOLD = "UNOBSERVED_HOLD"
    P_ZERO_HOLD = "P_ZERO_HOLD"


@dataclass(frozen=True)
class XrayObjectState:
    object_ref: str
    exists: bool | None = None
    object_type: str = "unknown"
    raw_path: str | None = None
    resolved_path: str | None = None
    boundary_root: str | None = None
    size: int | None = None
    content_sha256: str | None = None
    metadata_sha256: str | None = None
    file_id: str | None = None
    inode: int | None = None
    device_id: str | None = None
    nlink: int | None = None
    mtime_ns: int | None = None
    ctime_ns: int | None = None
    symlink_target: str | None = None
    reparse_tag: int | None = None
    mode: str | None = None
    owner: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    @property
    def state_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "object_ref": self.object_ref,
            "exists": self.exists,
            "object_type": self.object_type,
            "raw_path": self.raw_path,
            "resolved_path": self.resolved_path,
            "boundary_root": self.boundary_root,
            "size": self.size,
            "content_sha256": self.content_sha256,
            "metadata_sha256": self.metadata_sha256,
            "file_id": self.file_id,
            "inode": self.inode,
            "device_id": self.device_id,
            "nlink": self.nlink,
            "mtime_ns": self.mtime_ns,
            "ctime_ns": self.ctime_ns,
            "symlink_target": self.symlink_target,
            "reparse_tag": self.reparse_tag,
            "mode": self.mode,
            "owner": self.owner,
            "details": dict(self.details),
        }
        if include_hash:
            payload["state_hash"] = self.state_hash
        return payload


@dataclass(frozen=True)
class AccessWindow:
    enter_ts_ns: int | None = None
    exit_ts_ns: int | None = None
    duration_ns: int | None = None
    order_token: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        duration = self.duration_ns
        if duration is None and self.enter_ts_ns is not None and self.exit_ts_ns is not None:
            duration = max(0, int(self.exit_ts_ns) - int(self.enter_ts_ns))
        object.__setattr__(self, "duration_ns", duration)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enter_ts_ns": self.enter_ts_ns,
            "exit_ts_ns": self.exit_ts_ns,
            "duration_ns": self.duration_ns,
            "order_token": self.order_token,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class AccessCurrent:
    process_id: str
    agency: Sequence[str] = field(default_factory=tuple)
    surface: Sequence[str] = field(default_factory=tuple)
    window: AccessWindow = field(default_factory=AccessWindow)
    effects: Sequence[str] = field(default_factory=tuple)
    target_refs: Sequence[str] = field(default_factory=tuple)
    source_adapter: str | None = None
    tool_name: str | None = None
    proposal_id: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        window = self.window if isinstance(self.window, AccessWindow) else AccessWindow(**dict(self.window))
        object.__setattr__(self, "window", window)
        object.__setattr__(self, "agency", _unique_tuple(self.agency))
        object.__setattr__(self, "surface", _unique_tuple(self.surface))
        object.__setattr__(self, "effects", _unique_tuple(self.effects))
        object.__setattr__(self, "target_refs", _unique_tuple(self.target_refs))

    @property
    def current_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "process_id": self.process_id,
            "agency": self.agency,
            "surface": self.surface,
            "window": self.window.to_dict(),
            "effects": self.effects,
            "target_refs": self.target_refs,
            "source_adapter": self.source_adapter,
            "tool_name": self.tool_name,
            "proposal_id": self.proposal_id,
            "details": dict(self.details),
        }
        if include_hash:
            payload["current_hash"] = self.current_hash
        return payload


@dataclass(frozen=True)
class BoundaryMetric:
    boundary_id: str = "workspace"
    root: str | None = None
    scope: str = "unknown"
    contained_refs: Sequence[str] = field(default_factory=tuple)
    escaped_refs: Sequence[str] = field(default_factory=tuple)
    alias_refs: Sequence[str] = field(default_factory=tuple)
    distance: Mapping[str, float] = field(default_factory=dict)
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "contained_refs", _unique_tuple(self.contained_refs))
        object.__setattr__(self, "escaped_refs", _unique_tuple(self.escaped_refs))
        object.__setattr__(self, "alias_refs", _unique_tuple(self.alias_refs))
        object.__setattr__(
            self,
            "distance",
            {str(key): float(value) for key, value in dict(self.distance).items()},
        )

    @property
    def has_escape(self) -> bool:
        return bool(self.escaped_refs)

    @property
    def has_alias_surface(self) -> bool:
        return bool(self.alias_refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "boundary_id": self.boundary_id,
            "root": self.root,
            "scope": self.scope,
            "contained_refs": self.contained_refs,
            "escaped_refs": self.escaped_refs,
            "alias_refs": self.alias_refs,
            "distance": dict(self.distance),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class AuthPotential:
    process_id: str
    authorized_actors: Sequence[str] = field(default_factory=tuple)
    authorized_tools: Sequence[str] = field(default_factory=tuple)
    authorized_skills: Sequence[str] = field(default_factory=tuple)
    authorized_effects: Sequence[str] = field(default_factory=tuple)
    authorized_targets: Sequence[str] = field(default_factory=tuple)
    authorized_output_paths: Sequence[str] = field(default_factory=tuple)
    authorized_delete_paths: Sequence[str] = field(default_factory=tuple)
    authorized_window: AccessWindow | None = None
    benign_side_effects: Sequence[str] = field(default_factory=tuple)
    mode: str = "process_auth_v0"
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        window = self.authorized_window
        if window is not None and not isinstance(window, AccessWindow):
            window = AccessWindow(**dict(window))
        object.__setattr__(self, "authorized_window", window)
        for field_name in (
            "authorized_actors",
            "authorized_tools",
            "authorized_skills",
            "authorized_effects",
            "authorized_targets",
            "authorized_output_paths",
            "authorized_delete_paths",
            "benign_side_effects",
        ):
            object.__setattr__(self, field_name, _unique_tuple(getattr(self, field_name)))

    @property
    def auth_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    @property
    def is_empty(self) -> bool:
        return not any(
            (
                self.authorized_actors,
                self.authorized_tools,
                self.authorized_skills,
                self.authorized_effects,
                self.authorized_targets,
                self.authorized_output_paths,
                self.authorized_delete_paths,
                self.authorized_window,
                self.benign_side_effects,
            )
        )

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "process_id": self.process_id,
            "mode": self.mode,
            "authorized_actors": self.authorized_actors,
            "authorized_tools": self.authorized_tools,
            "authorized_skills": self.authorized_skills,
            "authorized_effects": self.authorized_effects,
            "authorized_targets": self.authorized_targets,
            "authorized_output_paths": self.authorized_output_paths,
            "authorized_delete_paths": self.authorized_delete_paths,
            "authorized_window": (
                self.authorized_window.to_dict() if self.authorized_window else None
            ),
            "benign_side_effects": self.benign_side_effects,
            "details": dict(self.details),
        }
        if include_hash:
            payload["auth_hash"] = self.auth_hash
        return payload


@dataclass(frozen=True)
class ObservationMask:
    state: ObservationState
    observed_fields: Sequence[str] = field(default_factory=tuple)
    missing_fields: Sequence[str] = field(default_factory=tuple)
    blind_spots: Sequence[str] = field(default_factory=tuple)
    confidence: float = 1.0
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        state = self.state if isinstance(self.state, ObservationState) else ObservationState(self.state)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "observed_fields", _unique_tuple(self.observed_fields))
        object.__setattr__(self, "missing_fields", _unique_tuple(self.missing_fields))
        object.__setattr__(self, "blind_spots", _unique_tuple(self.blind_spots))
        object.__setattr__(self, "confidence", round(float(self.confidence), 6))

    @classmethod
    def from_required_fields(
        cls,
        *,
        required_fields: Sequence[str],
        observed_fields: Sequence[str],
        blind_spots: Sequence[str] = (),
        confidence: float = 1.0,
        details: Mapping[str, Any] | None = None,
    ) -> "ObservationMask":
        required = set(str(field) for field in required_fields)
        observed = set(str(field) for field in observed_fields)
        missing = tuple(sorted(required - observed))
        if not observed and required:
            state = ObservationState.UNOBSERVED
        elif missing or blind_spots:
            state = ObservationState.PARTIAL
        else:
            state = ObservationState.COMPLETE
        return cls(
            state=state,
            observed_fields=tuple(sorted(observed)),
            missing_fields=missing,
            blind_spots=tuple(blind_spots),
            confidence=confidence,
            details=details or {},
        )

    @property
    def requires_hold(self) -> bool:
        return self.state != ObservationState.COMPLETE or bool(self.blind_spots)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "observed_fields": self.observed_fields,
            "missing_fields": self.missing_fields,
            "blind_spots": self.blind_spots,
            "confidence": self.confidence,
            "requires_hold": self.requires_hold,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class AccessResidual:
    state: AccessResidualState
    component: str
    residual_type: str
    subject: str
    severity: float = 0.0
    explained_by: str | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        state = (
            self.state
            if isinstance(self.state, AccessResidualState)
            else AccessResidualState(self.state)
        )
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "severity", round(float(self.severity), 6))

    @property
    def residual_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    @property
    def requires_action(self) -> bool:
        if self.state == AccessResidualState.EXPLAINED:
            return False
        return self.state in {
            AccessResidualState.RESIDUAL,
            AccessResidualState.INCOMPLETE,
            AccessResidualState.UNOBSERVED,
        }

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "state": self.state.value,
            "component": self.component,
            "residual_type": self.residual_type,
            "subject": self.subject,
            "severity": self.severity,
            "explained_by": self.explained_by,
            "requires_action": self.requires_action,
            "evidence": dict(self.evidence),
            "details": dict(self.details),
        }
        if include_hash:
            payload["residual_hash"] = self.residual_hash
        return payload


@dataclass(frozen=True)
class AccessEquationTerms:
    delta_b_x: Sequence[AccessResidual] = field(default_factory=tuple)
    div_b_j: Sequence[AccessResidual] = field(default_factory=tuple)
    u_auth_explanations: Sequence[AccessResidual] = field(default_factory=tuple)
    observation_residuals: Sequence[AccessResidual] = field(default_factory=tuple)
    observation: ObservationMask = field(
        default_factory=lambda: ObservationMask(ObservationState.UNOBSERVED)
    )
    equation: str = EQUATION
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "delta_b_x", tuple(self.delta_b_x))
        object.__setattr__(self, "div_b_j", tuple(self.div_b_j))
        object.__setattr__(self, "u_auth_explanations", tuple(self.u_auth_explanations))
        object.__setattr__(self, "observation_residuals", tuple(self.observation_residuals))

    @property
    def raw_residuals(self) -> tuple[AccessResidual, ...]:
        return (*self.delta_b_x, *self.div_b_j)

    def with_auth_and_observation(
        self,
        *,
        u_auth_explanations: Sequence[AccessResidual],
        observation_residuals: Sequence[AccessResidual],
    ) -> "AccessEquationTerms":
        return AccessEquationTerms(
            delta_b_x=self.delta_b_x,
            div_b_j=self.div_b_j,
            u_auth_explanations=tuple(u_auth_explanations),
            observation_residuals=tuple(observation_residuals),
            observation=self.observation,
            equation=self.equation,
            details=self.details,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "equation": self.equation,
            "delta_b_x": tuple(residual.to_dict() for residual in self.delta_b_x),
            "div_b_j": tuple(residual.to_dict() for residual in self.div_b_j),
            "u_auth_explanations": tuple(
                residual.to_dict() for residual in self.u_auth_explanations
            ),
            "observation_residuals": tuple(
                residual.to_dict() for residual in self.observation_residuals
            ),
            "observation": self.observation.to_dict(),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class AccessEquationResult:
    state: AccessEquationState
    process_id: str
    equation_applied: bool
    terms: AccessEquationTerms
    residuals: Sequence[AccessResidual] = field(default_factory=tuple)
    explained_residuals: Sequence[AccessResidual] = field(default_factory=tuple)
    hold_reasons: Sequence[str] = field(default_factory=tuple)
    minimum_action: str = "NONE"
    equation: str = EQUATION
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        state = (
            self.state
            if isinstance(self.state, AccessEquationState)
            else AccessEquationState(self.state)
        )
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "residuals", tuple(self.residuals))
        object.__setattr__(self, "explained_residuals", tuple(self.explained_residuals))
        object.__setattr__(self, "hold_reasons", _unique_tuple(self.hold_reasons))

    @property
    def requires_hold(self) -> bool:
        return self.minimum_action == "HOLD"

    def to_dict(self) -> dict[str, Any]:
        return {
            "equation": self.equation,
            "state": self.state.value,
            "process_id": self.process_id,
            "equation_applied": self.equation_applied,
            "minimum_action": self.minimum_action,
            "requires_hold": self.requires_hold,
            "terms": self.terms.to_dict(),
            "residuals": tuple(residual.to_dict() for residual in self.residuals),
            "explained_residuals": tuple(
                residual.to_dict() for residual in self.explained_residuals
            ),
            "hold_reasons": self.hold_reasons,
            "details": dict(self.details),
        }


def no_trusted_access_process_witness(
    *,
    subject: str = "access_process",
    reason: str = "missing_trusted_access_process",
    evidence: Mapping[str, Any] | None = None,
) -> AccessResidual:
    return AccessResidual(
        state=AccessResidualState.UNOBSERVED,
        component="access_admission",
        residual_type=NO_TRUSTED_ACCESS_PROCESS,
        subject=subject,
        severity=1.0,
        evidence=evidence or {},
        details={
            "policy": P_ZERO_ADMISSION_POLICY,
            "reason": reason,
            "equation_applied": False,
            "route": "AccessAdmission",
            "minimum_action": "HOLD",
        },
    )


@dataclass(frozen=True)
class AccessEquationInput:
    process_id: str
    object_states: Sequence[XrayObjectState] = field(default_factory=tuple)
    enter_object_states: Sequence[XrayObjectState] = field(default_factory=tuple)
    exit_object_states: Sequence[XrayObjectState] = field(default_factory=tuple)
    currents: Sequence[AccessCurrent] = field(default_factory=tuple)
    boundary: BoundaryMetric = field(default_factory=BoundaryMetric)
    auth: AuthPotential | None = None
    observation: ObservationMask = field(
        default_factory=lambda: ObservationMask(ObservationState.UNOBSERVED)
    )
    metadata_change_tokens: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    equation: str = EQUATION
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "object_states", tuple(self.object_states))
        object.__setattr__(self, "enter_object_states", tuple(self.enter_object_states))
        object.__setattr__(self, "exit_object_states", tuple(self.exit_object_states))
        object.__setattr__(self, "currents", tuple(self.currents))
        object.__setattr__(
            self,
            "metadata_change_tokens",
            tuple(_mapping_from(token) for token in self.metadata_change_tokens),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "equation": self.equation,
            "process_id": self.process_id,
            "object_states": tuple(state.to_dict() for state in self.object_states),
            "enter_object_states": tuple(
                state.to_dict() for state in self.enter_object_states
            ),
            "exit_object_states": tuple(state.to_dict() for state in self.exit_object_states),
            "currents": tuple(current.to_dict() for current in self.currents),
            "boundary": self.boundary.to_dict(),
            "auth": self.auth.to_dict() if self.auth else None,
            "observation": self.observation.to_dict(),
            "metadata_change_tokens": self.metadata_change_tokens,
            "details": dict(self.details),
        }


def omega_access(access_input: AccessEquationInput) -> AccessEquationResult:
    if not _has_trusted_access_process(access_input):
        witness = no_trusted_access_process_witness(
            subject=access_input.process_id or "access_process",
            evidence={
                "current_count": len(access_input.currents),
                "process_id": access_input.process_id,
            },
        )
        terms = AccessEquationTerms(observation=access_input.observation)
        return AccessEquationResult(
            state=AccessEquationState.P_ZERO_HOLD,
            process_id=access_input.process_id,
            equation_applied=False,
            terms=terms,
            residuals=(witness,),
            hold_reasons=(NO_TRUSTED_ACCESS_PROCESS,),
            minimum_action="HOLD",
            details={
                "route": "AccessAdmission",
                "policy": P_ZERO_ADMISSION_POLICY,
            },
        )

    terms = build_access_equation_terms(access_input)
    explained, remaining = explain_residuals_with_u_auth(
        terms.raw_residuals,
        access_input.auth,
        currents=access_input.currents,
    )
    observation_residuals = _observation_residuals(access_input.observation)
    terms = terms.with_auth_and_observation(
        u_auth_explanations=explained,
        observation_residuals=observation_residuals,
    )
    return o_apply_access(
        access_input.observation,
        terms=terms,
        remaining_residuals=remaining,
        explained_residuals=explained,
        process_id=access_input.process_id,
    )


def compute_omega_access(access_input: AccessEquationInput) -> AccessEquationResult:
    return omega_access(access_input)


def build_access_equation_terms(access_input: AccessEquationInput) -> AccessEquationTerms:
    delta_b_x = (
        *_object_state_delta_residuals(
            access_input.enter_object_states,
            access_input.exit_object_states,
        ),
        *_metadata_change_residuals(access_input.metadata_change_tokens),
    )
    div_b_j = _boundary_current_residuals(access_input.boundary)
    return AccessEquationTerms(
        delta_b_x=delta_b_x,
        div_b_j=div_b_j,
        observation=access_input.observation,
        details={
            "operator": "omega_access_terms_v0",
            "delta_b_x_count": len(delta_b_x),
            "div_b_j_count": len(div_b_j),
            "auth_mode": access_input.auth.mode if access_input.auth else None,
        },
    )


def explain_residuals_with_u_auth(
    residuals: Sequence[AccessResidual],
    auth: AuthPotential | None,
    *,
    currents: Sequence[AccessCurrent] = (),
) -> tuple[tuple[AccessResidual, ...], tuple[AccessResidual, ...]]:
    if auth is None or auth.is_empty or not _auth_matches_currents(auth, currents):
        return (), tuple(residuals)

    explained: list[AccessResidual] = []
    remaining: list[AccessResidual] = []
    for residual in residuals:
        explanation = _auth_explanation_for(residual, auth)
        if explanation is None:
            remaining.append(residual)
        else:
            explained.append(explanation)
    return tuple(explained), tuple(remaining)


def o_apply_access(
    observation: ObservationMask,
    *,
    terms: AccessEquationTerms,
    remaining_residuals: Sequence[AccessResidual],
    explained_residuals: Sequence[AccessResidual],
    process_id: str,
) -> AccessEquationResult:
    final_residuals = (*remaining_residuals, *terms.observation_residuals)
    hold_reasons = _hold_reasons(final_residuals, observation)

    if observation.state == ObservationState.UNOBSERVED:
        state = AccessEquationState.UNOBSERVED_HOLD
        minimum_action = "HOLD"
    elif observation.requires_hold:
        state = AccessEquationState.INCOMPLETE_HOLD
        minimum_action = "HOLD"
    elif remaining_residuals:
        state = AccessEquationState.RESIDUAL
        minimum_action = "HOLD"
    elif explained_residuals:
        state = AccessEquationState.EXPLAINED
        minimum_action = "AUDIT_ATTACH"
    else:
        state = AccessEquationState.CONTINUOUS
        minimum_action = "NONE"

    return AccessEquationResult(
        state=state,
        process_id=process_id,
        equation_applied=True,
        terms=terms,
        residuals=final_residuals,
        explained_residuals=explained_residuals,
        hold_reasons=hold_reasons,
        minimum_action=minimum_action,
        details={
            "operator": "o_apply_access_switch_v0",
            "observation_state": observation.state.value,
            "net_residual_evaluated": observation.state == ObservationState.COMPLETE
            and not observation.requires_hold,
            "authority": "witness_only_no_execution_grant",
        },
    )


def _has_trusted_access_process(access_input: AccessEquationInput) -> bool:
    if not access_input.process_id or str(access_input.process_id).strip() in {"0", "P=0"}:
        return False
    for current in access_input.currents:
        if any(
            (
                current.agency,
                current.surface,
                current.effects,
                current.target_refs,
                current.source_adapter,
                current.tool_name,
                current.proposal_id,
            )
        ):
            return True
    return False


def _object_state_delta_residuals(
    enter_states: Sequence[XrayObjectState],
    exit_states: Sequence[XrayObjectState],
) -> tuple[AccessResidual, ...]:
    enter_map = {state.object_ref: state for state in enter_states}
    exit_map = {state.object_ref: state for state in exit_states}
    residuals: list[AccessResidual] = []
    for object_ref in sorted(set(enter_map) | set(exit_map)):
        before = enter_map.get(object_ref)
        after = exit_map.get(object_ref)
        candidate_refs = _object_candidate_refs(before, after)
        if before is None:
            residual_type = _created_deleted_residual_type(after)
            mechanism = _created_deleted_mechanism(after, "object_created_during_access")
            residuals.append(
                AccessResidual(
                    state=AccessResidualState.RESIDUAL,
                    component="delta_b_x",
                    residual_type=residual_type,
                    subject=object_ref,
                    severity=0.8,
                    evidence={
                        "after_hash": after.state_hash if after else None,
                        "candidate_refs": candidate_refs,
                    },
                    details={
                        "mechanism": mechanism,
                        "minimum_action": "HOLD",
                    },
                )
            )
            continue
        if after is None:
            residual_type = _created_deleted_residual_type(before)
            mechanism = _created_deleted_mechanism(before, "object_deleted_during_access")
            residuals.append(
                AccessResidual(
                    state=AccessResidualState.RESIDUAL,
                    component="delta_b_x",
                    residual_type=residual_type,
                    subject=object_ref,
                    severity=1.0,
                    evidence={
                        "before_hash": before.state_hash,
                        "candidate_refs": candidate_refs,
                    },
                    details={
                        "mechanism": mechanism,
                        "minimum_action": "HOLD",
                    },
                )
            )
            continue
        if before.state_hash != after.state_hash:
            residual_type, mechanism = _object_delta_residual_type(before, after)
            residuals.append(
                AccessResidual(
                    state=AccessResidualState.RESIDUAL,
                    component="delta_b_x",
                    residual_type=residual_type,
                    subject=object_ref,
                    severity=0.9,
                    evidence={
                        "before_hash": before.state_hash,
                        "after_hash": after.state_hash,
                        "before_content_sha256": before.content_sha256,
                        "after_content_sha256": after.content_sha256,
                        "before_metadata_sha256": before.metadata_sha256,
                        "after_metadata_sha256": after.metadata_sha256,
                        "candidate_refs": candidate_refs,
                        "before_object_type": before.object_type,
                        "after_object_type": after.object_type,
                        "before_raw_path": before.raw_path,
                        "after_raw_path": after.raw_path,
                        "before_resolved_path": before.resolved_path,
                        "after_resolved_path": after.resolved_path,
                        "before_symlink_target": before.symlink_target,
                        "after_symlink_target": after.symlink_target,
                        "before_skill_identity": _skill_identity(before),
                        "after_skill_identity": _skill_identity(after),
                    },
                    details={
                        "mechanism": mechanism,
                        "minimum_action": "HOLD",
                    },
                )
            )
    return tuple(residuals)


def _metadata_change_residuals(
    metadata_change_tokens: Sequence[Mapping[str, Any]],
) -> tuple[AccessResidual, ...]:
    residuals: list[AccessResidual] = []
    for index, token in enumerate(metadata_change_tokens, start=1):
        payload = _mapping_from(token)
        if payload.get("changed") is not True:
            continue
        subject = str(payload.get("subject") or payload.get("object_ref") or f"metadata_token:{index}")
        residuals.append(
            AccessResidual(
                state=AccessResidualState.RESIDUAL,
                component="delta_b_x",
                residual_type="TEMPORAL_RACE",
                subject=subject,
                severity=0.7,
                evidence=payload,
                details={
                    "mechanism": "sampled_metadata_delta",
                    "semantics": payload.get("semantics"),
                    "minimum_action": "HOLD",
                },
            )
        )
    return tuple(residuals)


def _boundary_current_residuals(boundary: BoundaryMetric) -> tuple[AccessResidual, ...]:
    residuals: list[AccessResidual] = []
    for escaped_ref in boundary.escaped_refs:
        residuals.append(
            AccessResidual(
                state=AccessResidualState.RESIDUAL,
                component="div_b_j",
                residual_type="CONTAINER_ESCAPE",
                subject=escaped_ref,
                severity=1.0,
                evidence={
                    "boundary_id": boundary.boundary_id,
                    "root": boundary.root,
                    "escaped_refs": boundary.escaped_refs,
                    "distance": dict(boundary.distance),
                },
                details={
                    "mechanism": "boundary_escape",
                    "minimum_action": "HOLD",
                },
            )
        )
    for alias_ref in boundary.alias_refs:
        residuals.append(
            AccessResidual(
                state=AccessResidualState.RESIDUAL,
                component="div_b_j",
                residual_type="ALIAS_WRITE",
                subject=alias_ref,
                severity=0.8,
                evidence={
                    "boundary_id": boundary.boundary_id,
                    "root": boundary.root,
                    "alias_refs": boundary.alias_refs,
                },
                details={
                    "mechanism": "multi_link_surface",
                    "minimum_action": "HOLD",
                    "alias_detection_semantics": boundary.details.get(
                        "alias_detection_semantics"
                    ),
                },
            )
        )
    return tuple(residuals)


def _observation_residuals(observation: ObservationMask) -> tuple[AccessResidual, ...]:
    if not observation.requires_hold:
        return ()
    residual_state = (
        AccessResidualState.UNOBSERVED
        if observation.state == ObservationState.UNOBSERVED
        else AccessResidualState.INCOMPLETE
    )
    return (
        AccessResidual(
            state=residual_state,
            component="o_apply",
            residual_type="OBSERVATION_BLINDNESS",
            subject="observation",
            severity=1.0 if residual_state == AccessResidualState.UNOBSERVED else 0.75,
            evidence={
                "observation_state": observation.state.value,
                "observed_fields": observation.observed_fields,
                "missing_fields": observation.missing_fields,
                "blind_spots": observation.blind_spots,
                "confidence": observation.confidence,
            },
            details={
                "requires_hold": True,
                "minimum_action": "HOLD",
                "mechanism": "observation_blindness",
            },
        ),
    )


def _created_deleted_residual_type(state: XrayObjectState | None) -> str:
    if state is not None and _state_has_pointer_surface(state):
        return "POINTER_REDIRECTION"
    if state is not None and _skill_identity(state):
        return "RESPONSIBILITY_SWAP"
    return "OBJECT_SUBSTITUTION"


def _created_deleted_mechanism(state: XrayObjectState | None, fallback: str) -> str:
    if state is not None and _state_has_pointer_surface(state):
        return "pointer_surface_created_or_deleted"
    if state is not None and _skill_identity(state):
        return "skill_responsibility_created_or_deleted"
    return fallback


def _object_delta_residual_type(
    before: XrayObjectState,
    after: XrayObjectState,
) -> tuple[str, str]:
    if _has_pointer_delta(before, after):
        return "POINTER_REDIRECTION", "pointer_surface_delta"
    if _skill_identity(before) != _skill_identity(after):
        return "RESPONSIBILITY_SWAP", "skill_responsibility_identity_delta"
    return "OBJECT_SUBSTITUTION", "resource_identity_delta"


# A path that redirects elsewhere: a POSIX symlink or an NT reparse point
# (junction / mount point). Both forward one name to another resource, so both
# carry a pointer surface — file type alone (a junction lstats as a directory)
# must never decide this.
_REDIRECT_OBJECT_TYPES = frozenset({"symlink", "reparse_point"})


def _has_pointer_delta(before: XrayObjectState, after: XrayObjectState) -> bool:
    if before.object_type in _REDIRECT_OBJECT_TYPES or after.object_type in _REDIRECT_OBJECT_TYPES:
        return True
    if before.symlink_target or after.symlink_target:
        return before.symlink_target != after.symlink_target
    if before.raw_path and after.raw_path and before.raw_path == after.raw_path:
        return (
            before.resolved_path is not None
            and after.resolved_path is not None
            and _path_key(before.resolved_path) != _path_key(after.resolved_path)
        )
    return False


def _state_has_pointer_surface(state: XrayObjectState) -> bool:
    return bool(state.object_type in _REDIRECT_OBJECT_TYPES or state.symlink_target)


def _skill_identity(state: XrayObjectState) -> tuple[str, ...]:
    details = dict(state.details)
    values: list[Any] = []
    for key in (
        "skill_id",
        "primary_skill_id",
        "used_skill_ids",
        "declared_skill_ids",
        "skill_manifest_sha256",
        "skill_manifest_hash",
    ):
        value = details.get(key)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set, frozenset)):
            values.extend(value)
        else:
            values.append(value)
    return _unique_tuple(values)


def _auth_matches_currents(
    auth: AuthPotential,
    currents: Sequence[AccessCurrent],
) -> bool:
    if not currents:
        return False
    if auth.process_id and not any(current.process_id == auth.process_id for current in currents):
        return False
    if auth.authorized_actors:
        actors = _current_actors(currents)
        if not _tokens_overlap(auth.authorized_actors, actors):
            return False
    if auth.authorized_tools:
        tools = _current_tools(currents)
        if not _tokens_overlap(auth.authorized_tools, tools):
            return False
    return True


def _auth_explanation_for(
    residual: AccessResidual,
    auth: AuthPotential,
) -> AccessResidual | None:
    residual_type = str(residual.residual_type)
    candidates = _candidate_refs_for_residual(residual)
    if residual_type == "OBJECT_SUBSTITUTION":
        mechanism = str(residual.details.get("mechanism") or "")
        if (
            mechanism == "object_deleted_during_access"
            and "delete" in auth.authorized_effects
            and _paths_match(candidates, auth.authorized_delete_paths)
        ):
            return _explained_residual(
                residual,
                auth,
                residual_type="AUTHORIZED_DELETE",
                explained_by="authorized_delete_path",
            )
        if (
            "write" in auth.authorized_effects
            and (
                _paths_match(candidates, auth.authorized_output_paths)
                or _paths_match(candidates, auth.authorized_targets)
            )
        ):
            explained_by = (
                "authorized_output_path"
                if _paths_match(candidates, auth.authorized_output_paths)
                else "authorized_target"
            )
            return _explained_residual(
                residual,
                auth,
                residual_type="AUTHORIZED_WRITE",
                explained_by=explained_by,
            )
    if residual_type == "TEMPORAL_RACE" and _benign_side_effect_matches(
        auth,
        ("metadata_change", "metadata_delta", "sampled_metadata_delta_v0"),
    ):
        return _explained_residual(
            residual,
            auth,
            residual_type="AUTHORIZED_METADATA_SIDE_EFFECT",
            explained_by="benign_side_effect",
        )
    return None


def _explained_residual(
    residual: AccessResidual,
    auth: AuthPotential,
    *,
    residual_type: str,
    explained_by: str,
) -> AccessResidual:
    return AccessResidual(
        state=AccessResidualState.EXPLAINED,
        component="u_auth",
        residual_type=residual_type,
        subject=residual.subject,
        severity=residual.severity,
        explained_by=explained_by,
        evidence={
            "raw_residual_hash": residual.residual_hash,
            "raw_residual_type": residual.residual_type,
            "auth_hash": auth.auth_hash,
        },
        details={
            "explained_residual_type": residual.residual_type,
            "equation_authority": "explain_only_no_execution_grant",
        },
    )


def _hold_reasons(
    residuals: Sequence[AccessResidual],
    observation: ObservationMask,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if observation.requires_hold:
        reasons.append("OBSERVATION_REQUIRES_HOLD")
    reasons.extend(str(residual.residual_type) for residual in residuals if residual.requires_action)
    return _unique_tuple(reasons)


def _object_candidate_refs(
    before: XrayObjectState | None,
    after: XrayObjectState | None,
) -> tuple[str, ...]:
    refs: list[str] = []
    for state in (before, after):
        if state is None:
            continue
        refs.extend(
            ref
            for ref in (
                state.object_ref,
                state.raw_path,
                state.resolved_path,
                state.boundary_root,
            )
            if ref
        )
    return _unique_tuple(refs)


def _candidate_refs_for_residual(residual: AccessResidual) -> tuple[str, ...]:
    refs: list[str] = [residual.subject]
    candidate_refs = residual.evidence.get("candidate_refs")
    if isinstance(candidate_refs, (list, tuple, set, frozenset)):
        refs.extend(str(value) for value in candidate_refs)
    return _unique_tuple(refs)


def _current_actors(currents: Sequence[AccessCurrent]) -> tuple[str, ...]:
    actors: list[str] = []
    for current in currents:
        if current.source_adapter:
            actors.append(current.source_adapter)
        for agency in current.agency:
            token = str(agency)
            actors.append(token.removeprefix("actor:"))
    return _unique_tuple(actors)


def _current_tools(currents: Sequence[AccessCurrent]) -> tuple[str, ...]:
    tools: list[str] = []
    for current in currents:
        if current.tool_name:
            tools.append(current.tool_name)
        for agency in current.agency:
            token = str(agency)
            if token.startswith("tool:"):
                tools.append(token.removeprefix("tool:"))
    return _unique_tuple(tools)


def _tokens_overlap(left: Sequence[str], right: Sequence[str]) -> bool:
    left_tokens = {_token_key(value) for value in left}
    right_tokens = {_token_key(value) for value in right}
    return bool(left_tokens & right_tokens)


def _paths_match(candidates: Sequence[str], authorized_paths: Sequence[str]) -> bool:
    if not candidates or not authorized_paths:
        return False
    candidate_keys = {_path_key(value) for value in candidates}
    authorized_keys = {_path_key(value) for value in authorized_paths}
    return bool(candidate_keys & authorized_keys)


def _benign_side_effect_matches(auth: AuthPotential, values: Sequence[str]) -> bool:
    allowed = {_token_key(value) for value in auth.benign_side_effects}
    return any(_token_key(value) in allowed for value in values)


def _mapping_from(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "to_dict"):
        mapped = value.to_dict()
        if isinstance(mapped, Mapping):
            return dict(mapped)
    return {"value": value}


def _token_key(value: Any) -> str:
    return str(value).strip().lower()


def _path_key(value: Any) -> str:
    text = os.path.normcase(str(value).strip()).replace("\\", "/")
    return text.rstrip("/")


def _unique_tuple(values: Sequence[Any]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value) for value in values if value is not None))


def _sha256_canonical(payload: Any) -> str:
    encoded = json.dumps(
        _canonicalize(payload),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonicalize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _canonicalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(_canonicalize(item) for item in value)
    if hasattr(value, "to_dict"):
        return _canonicalize(value.to_dict())
    return value
