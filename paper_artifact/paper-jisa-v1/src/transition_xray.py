from __future__ import annotations

import hashlib
import io
import json
import math
import os
import stat
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Sequence

from access_equation import (
    AccessCurrent,
    AccessEquationInput,
    AccessWindow,
    BoundaryMetric,
    ObservationMask,
    ObservationState,
    XrayObjectState,
    omega_access,
)
from access_field import (
    AccessFieldPhase,
    AccessProcessSlot,
    AccessProcessTerm,
    AccessProcessVector,
    build_access_process_vector,
)
from access_process_equation import FieldFrameDelta, PROCESS_EQUATION, omega_process
from access_time_grid import (
    TIME_GRID_SCHEMA,
    TimeGridCell,
    TimeGridSpec,
    TimeGridTrace,
    build_time_grid_trace,
)
from archive_container_probe import (
    ZIP_CONTAINER_MAGICS,
    ZIP_CONTAINER_SUFFIX_HINTS,
    header_is_zip_container_magic,
    sniff_zip_container,
)
from ot_gate import CommandProposal, SideEffect
from safe_path import safe_resolve


DEFAULT_MAX_HASH_BYTES = 1_000_000
DEFAULT_HBAR_PHI = 1.0
DEFAULT_FIELD_WEIGHT_TAU = 0.5
DEFAULT_FIELD_SHIFT_INVESTIGATION_THRESHOLD = 0.15
ACCESS_WITNESS_SCHEMA = "omega_access_witness_v0"
PROCESS_WITNESS_SCHEMA = "omega_process_witness_v0"
SENSITIVE_PATH_MARKERS = (
    ".env",
    ".phi",
    ".ssh",
    "audit_layer.py",
    "autopsy_report.py",
    "credential",
    "event_ledger",
    "harness_runtime_guard.py",
    "ot_gate.py",
    "secret",
    "token",
    # (v1) governance / authority surfaces -- editing these shifts the agent's
    # own rules (policy prompts, guardrails, benchmark definitions, tool
    # schemas). Declared, not heuristic: tune this list to your project layout.
    # The eye only flags the path as a protected surface; the core HOLDs.
    "system_policy",
    "system_prompt",
    "agent_policy",
    "guardrail_policy",
    "benchmark.yaml",
    "benchmark.yml",
    "tool_schema",
)

# (A5 little-brother) directory membership: any file UNDER one of these dirs is
# sensitive regardless of its filename -- closes half of the "rename within a
# secret dir evades the path-string marker" gap. Structural (path PARTS, not
# substring): `mysecrets/` does NOT match `secrets`, but `secrets/anything` does.
# Not exhaustive by design; content-bearing secrets elsewhere still need content
# inspection (the other half of A5).
SENSITIVE_DIR_NAMES = frozenset(
    {".ssh", ".gnupg", ".aws", ".kube", ".docker", "secrets", "credentials"}
)


class XrayPhase(str, Enum):
    ENTER = "enter"
    EXIT = "exit"


class MutationState(str, Enum):
    STABLE = "STABLE"
    MUTATED = "MUTATED"
    INCOMPLETE = "INCOMPLETE"
    UNOBSERVED = "UNOBSERVED"


class ContinuityState(str, Enum):
    CONTINUOUS = "CONTINUOUS"
    BROKEN = "BROKEN"
    INCOMPLETE = "INCOMPLETE"
    UNOBSERVED = "UNOBSERVED"


class MovementResidualType(str, Enum):
    OBJECT_SUBSTITUTION = "OBJECT_SUBSTITUTION"
    POINTER_REDIRECTION = "POINTER_REDIRECTION"
    ALIAS_WRITE = "ALIAS_WRITE"
    CONTAINER_ESCAPE = "CONTAINER_ESCAPE"
    TEMPORAL_RACE = "TEMPORAL_RACE"
    RESPONSIBILITY_SWAP = "RESPONSIBILITY_SWAP"
    OBSERVATION_BLINDNESS = "OBSERVATION_BLINDNESS"


@dataclass(frozen=True)
class XrayPiece:
    kind: str
    ref: str
    exists: bool | None = None
    type: str = "metadata"
    size: int | None = None
    sha256: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.ref}"

    @property
    def piece_hash(self) -> str:
        return _sha256_canonical(self._payload())

    def _payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "ref": self.ref,
            "exists": self.exists,
            "type": self.type,
            "size": self.size,
            "sha256": self.sha256,
            "details": dict(self.details),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._payload()
        payload["piece_hash"] = self.piece_hash
        return payload


@dataclass(frozen=True)
class TransitionXrayFrame:
    phase: XrayPhase
    action_id: str
    pieces: Sequence[XrayPiece]
    k_phi: Sequence[float]
    u_phi: float
    hbar_phi: float = DEFAULT_HBAR_PHI
    field_id: str = "transition_xray:v0"
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        phase = self.phase if isinstance(self.phase, XrayPhase) else XrayPhase(self.phase)
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "pieces", tuple(self.pieces))
        object.__setattr__(self, "k_phi", tuple(float(value) for value in self.k_phi))
        object.__setattr__(self, "u_phi", float(self.u_phi))
        object.__setattr__(self, "hbar_phi", float(self.hbar_phi))

    @property
    def frame_hash(self) -> str:
        return _sha256_canonical(self._payload())

    def _payload(self) -> dict[str, Any]:
        return {
            "field_id": self.field_id,
            "phase": self.phase.value,
            "action_id": self.action_id,
            "pieces": tuple(piece.to_dict() for piece in self.pieces),
            "k_phi": tuple(self.k_phi),
            "u_phi": self.u_phi,
            "hbar_phi": self.hbar_phi,
            "details": dict(self.details),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._payload()
        payload["frame_hash"] = self.frame_hash
        return payload


@dataclass(frozen=True)
class MutationFinding:
    finding_type: str
    piece_key: str
    before_hash: str | None = None
    after_hash: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "piece_key": self.piece_key,
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class MovementResidual:
    residual_type: MovementResidualType
    piece_key: str
    mechanism: str
    finding_type: str
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        residual_type = (
            self.residual_type
            if isinstance(self.residual_type, MovementResidualType)
            else MovementResidualType(self.residual_type)
        )
        object.__setattr__(self, "residual_type", residual_type)

    def to_dict(self) -> dict[str, Any]:
        return {
            "residual_type": self.residual_type.value,
            "piece_key": self.piece_key,
            "mechanism": self.mechanism,
            "finding_type": self.finding_type,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class ContinuityResidual:
    state: ContinuityState
    scalar: float
    witnesses: Sequence[MutationFinding] = field(default_factory=tuple)
    movement_residuals: Sequence[MovementResidual] = field(default_factory=tuple)
    equation: str = (
        "omega = x_exit(r(m)) typed_diff x_enter(r(m)) typed_minus d(r(m))"
    )
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        state = (
            self.state
            if isinstance(self.state, ContinuityState)
            else ContinuityState(self.state)
        )
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "scalar", round(float(self.scalar), 6))
        object.__setattr__(self, "witnesses", tuple(self.witnesses))
        object.__setattr__(self, "movement_residuals", tuple(self.movement_residuals))

    @property
    def is_zero(self) -> bool:
        return self.state == ContinuityState.CONTINUOUS and self.scalar == 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "scalar": self.scalar,
            "equation": self.equation,
            "witnesses": tuple(witness.to_dict() for witness in self.witnesses),
            "movement_residuals": tuple(
                residual.to_dict() for residual in self.movement_residuals
            ),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class TransitionXrayPair:
    enter: TransitionXrayFrame
    exit: TransitionXrayFrame
    findings: Sequence[MutationFinding]
    mutation_state: MutationState

    def __post_init__(self):
        state = (
            self.mutation_state
            if isinstance(self.mutation_state, MutationState)
            else MutationState(self.mutation_state)
        )
        object.__setattr__(self, "mutation_state", state)
        object.__setattr__(self, "findings", tuple(self.findings))

    @property
    def field_shift(self) -> float:
        return round(self.exit.u_phi - self.enter.u_phi, 6)

    @property
    def field_shift_abs(self) -> float:
        return round(abs(self.field_shift), 6)

    @property
    def field_shift_requires_review(self) -> bool:
        return self.field_shift_abs >= DEFAULT_FIELD_SHIFT_INVESTIGATION_THRESHOLD

    @property
    def continuity_state(self) -> ContinuityState:
        return _continuity_state_from_mutation(self.mutation_state)

    @property
    def continuity_residual_scalar(self) -> float:
        return _continuity_residual_scalar(self.findings)

    @property
    def continuity_residual(self) -> ContinuityResidual:
        movement_residuals = _classify_movement_residuals(self.findings)
        return ContinuityResidual(
            state=self.continuity_state,
            scalar=self.continuity_residual_scalar,
            witnesses=self.findings,
            movement_residuals=movement_residuals,
            details={
                "operator": "strict_discrete_movement_continuity_v0",
                "authorized_delta_mode": "declared_motion_observation_only_v0",
                "authority": "observe_residual_attach_only",
                "movement_residual_taxonomy": "movement_residual_operators_v1",
                "piece_count_enter": len(self.enter.pieces),
                "piece_count_exit": len(self.exit.pieces),
                "field_shift": self.field_shift,
                "field_shift_abs": self.field_shift_abs,
                "field_shift_requires_review": self.field_shift_requires_review,
            },
        )

    @property
    def pair_hash(self) -> str:
        return _sha256_canonical(
            {
                "enter_hash": self.enter.frame_hash,
                "exit_hash": self.exit.frame_hash,
                "continuity_residual": self.continuity_residual.to_dict(),
                "field_shift": self.field_shift,
                "field_shift_abs": self.field_shift_abs,
                "field_shift_requires_review": self.field_shift_requires_review,
                "mutation_state": self.mutation_state.value,
                "findings": tuple(finding.to_dict() for finding in self.findings),
            }
        )

    @property
    def autopsy_required(self) -> bool:
        """
        Report hint only.

        This is not a kill/hold signal and must not be promoted into execution
        authority. It means a later autopsy should include the X-ray pair if an
        existing authority has already produced a corpse or hold note.
        """

        return (
            self.mutation_state != MutationState.STABLE
            or self.field_shift_requires_review
        )

    def to_evidence(self) -> tuple[str, ...]:
        return (
            f"transition_xray.enter_hash:{self.enter.frame_hash}",
            f"transition_xray.exit_hash:{self.exit.frame_hash}",
            f"transition_xray.pair_hash:{self.pair_hash}",
            f"transition_xray.mutation_state:{self.mutation_state.value}",
            f"transition_xray.continuity_state:{self.continuity_state.value}",
            (
                "transition_xray.continuity_residual_scalar:"
                f"{self.continuity_residual_scalar:.6f}"
            ),
            f"transition_xray.field_shift:{self.field_shift:.6f}",
            f"transition_xray.field_shift_abs:{self.field_shift_abs:.6f}",
            (
                "transition_xray.field_shift_requires_review:"
                f"{str(self.field_shift_requires_review).lower()}"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enter": self.enter.to_dict(),
            "exit": self.exit.to_dict(),
            "findings": tuple(finding.to_dict() for finding in self.findings),
            "mutation_state": self.mutation_state.value,
            "continuity_state": self.continuity_state.value,
            "continuity_residual": self.continuity_residual.to_dict(),
            "field_shift": self.field_shift,
            "field_shift_abs": self.field_shift_abs,
            "field_shift_requires_review": self.field_shift_requires_review,
            "autopsy_required": self.autopsy_required,
            "pair_hash": self.pair_hash,
        }


def scan_transition_xray(
    proposal: CommandProposal,
    *,
    phase: XrayPhase | str,
    decision: Any = None,
    hbar_phi: float = DEFAULT_HBAR_PHI,
    max_file_bytes: int = DEFAULT_MAX_HASH_BYTES,
) -> TransitionXrayFrame:
    """
    Build a read-only, deterministic X-ray frame for the registered action.

    The frame has no authority: it cannot pass, kill, or grant permission. It
    only canonicalizes pieces and seals their hashes for later autopsy use.
    """

    pieces = [
        _proposal_piece(proposal),
        _skill_responsibility_piece(
            proposal,
            max_file_bytes=max_file_bytes,
        ),
        *(
            _path_piece(target, cwd=proposal.cwd, max_file_bytes=max_file_bytes)
            for target in proposal.target_paths
        ),
    ]
    if decision is not None:
        pieces.append(_decision_piece(decision))

    pieces = list(_annotate_pieces(pieces))
    k_phi = _k_phi(proposal, pieces=pieces, decision_present=decision is not None)
    return TransitionXrayFrame(
        phase=XrayPhase(phase),
        action_id=proposal.proposal_id,
        pieces=tuple(pieces),
        k_phi=k_phi,
        u_phi=_u_phi_from_pieces(pieces),
        hbar_phi=hbar_phi,
        details={
            "scope": "registered_action_explicit_targets_only",
            "authority": "observe_classify_hash_attach_only",
            "u_phi_mode": "piece_pressure_weighted_mean_v0",
            "field_weight_tau": DEFAULT_FIELD_WEIGHT_TAU,
            "field_shift_review_threshold": DEFAULT_FIELD_SHIFT_INVESTIGATION_THRESHOLD,
        },
    )


def compare_transition_xray(
    enter: TransitionXrayFrame,
    exit: TransitionXrayFrame,
) -> TransitionXrayPair:
    enter_map = {piece.key: piece for piece in enter.pieces}
    exit_map = {piece.key: piece for piece in exit.pieces}
    findings: list[MutationFinding] = []

    if enter.action_id != exit.action_id:
        findings.append(
            MutationFinding(
                finding_type="ACTION_ID_MISMATCH",
                piece_key="action_id",
                before_hash=enter.action_id,
                after_hash=exit.action_id,
            )
        )

    for key in sorted(set(enter_map) | set(exit_map)):
        before = enter_map.get(key)
        after = exit_map.get(key)
        if (before is not None and before.kind == "decision") or (
            after is not None and after.kind == "decision"
        ):
            continue
        if before is None:
            findings.append(
                MutationFinding(
                    finding_type="CREATED_DURING_WINDOW",
                    piece_key=key,
                    after_hash=after.piece_hash if after else None,
                    details=_finding_details(before, after),
                )
            )
            continue
        if after is None:
            findings.append(
                MutationFinding(
                    finding_type="DELETED_DURING_WINDOW",
                    piece_key=key,
                    before_hash=before.piece_hash,
                    details=_finding_details(before, after),
                )
            )
            continue
        if before.piece_hash != after.piece_hash:
            findings.append(
                MutationFinding(
                    finding_type="HASH_MUTATED",
                    piece_key=key,
                    before_hash=before.piece_hash,
                    after_hash=after.piece_hash,
                    details=_finding_details(before, after),
                )
            )

    if not enter.pieces and not exit.pieces:
        state = MutationState.UNOBSERVED
    elif any(finding.finding_type == "ACTION_ID_MISMATCH" for finding in findings):
        state = MutationState.INCOMPLETE
    elif findings:
        state = MutationState.MUTATED
    else:
        state = MutationState.STABLE

    return TransitionXrayPair(
        enter=enter,
        exit=exit,
        findings=tuple(findings),
        mutation_state=state,
    )


def build_transition_access_witness(
    pair: TransitionXrayPair,
    proposal: CommandProposal,
) -> dict[str, Any]:
    access_input = _access_input_from_transition_pair(pair, proposal)
    result = omega_access(access_input)
    payload: dict[str, Any] = {
        "schema": ACCESS_WITNESS_SCHEMA,
        "operator": "omega_access",
        "state": result.state.value,
        "process_id": result.process_id,
        "equation_applied": result.equation_applied,
        "minimum_action": result.minimum_action,
        "requires_hold": result.requires_hold,
        "residual_count": len(result.residuals),
        "explained_count": len(result.explained_residuals),
        "hold_reasons": tuple(result.hold_reasons),
        "residual_types": tuple(
            sorted({str(residual.residual_type) for residual in result.residuals})
        ),
        "residual_components": tuple(
            sorted({str(residual.component) for residual in result.residuals})
        ),
        "observation_state": access_input.observation.state.value,
        "observation_blind_spots": tuple(access_input.observation.blind_spots),
        "metadata_token_count": len(access_input.metadata_change_tokens),
        "testimony_only": True,
    }
    payload["witness_hash"] = _sha256_canonical(payload)
    return payload


def transition_access_witness_evidence(witness: Mapping[str, Any] | None) -> tuple[str, ...]:
    if not witness:
        return ()
    evidence = [
        f"omega_access.schema:{witness.get('schema')}",
        f"omega_access.state:{witness.get('state')}",
        f"omega_access.equation_applied:{str(bool(witness.get('equation_applied'))).lower()}",
        f"omega_access.minimum_action:{witness.get('minimum_action')}",
        f"omega_access.requires_hold:{str(bool(witness.get('requires_hold'))).lower()}",
        f"omega_access.residual_count:{witness.get('residual_count')}",
        f"omega_access.explained_count:{witness.get('explained_count')}",
        f"omega_access.observation_state:{witness.get('observation_state')}",
        f"omega_access.metadata_token_count:{witness.get('metadata_token_count')}",
    ]
    for reason in witness.get("hold_reasons", ()) or ():
        evidence.append(f"omega_access.hold_reason:{reason}")
    for residual_type in witness.get("residual_types", ()) or ():
        evidence.append(f"omega_access.residual_type:{residual_type}")
    for component in witness.get("residual_components", ()) or ():
        evidence.append(f"omega_access.residual_component:{component}")
    if witness.get("witness_hash"):
        evidence.append(f"omega_access.witness_hash:{witness.get('witness_hash')}")
    return tuple(str(item) for item in evidence)


def build_transition_process_witness(
    pair: TransitionXrayPair,
    proposal: CommandProposal,
    *,
    time_grid_traces: Sequence[TimeGridTrace] | None = None,
) -> dict[str, Any]:
    """Project a sealed X-ray pair into P=A+S-T and attach Omega_process evidence."""

    enter_process, exit_process, traces = _process_vectors_from_transition_pair(
        pair,
        proposal,
        time_grid_traces=time_grid_traces,
    )
    piece_ref = f"registered_action:{_sha256_text(proposal.proposal_id)}"
    result = omega_process(
        piece_ref=piece_ref,
        enter_process=enter_process,
        exit_process=exit_process,
        frame_delta=FieldFrameDelta(
            {},
            frame_ref=pair.pair_hash,
            details={
                "source": "transition_xray_pair",
                "mode": "zero_untrusted_frame_delta",
            },
        ),
        t_auth=None,
    )
    result_payload = result.to_dict()
    payload: dict[str, Any] = {
        "schema": PROCESS_WITNESS_SCHEMA,
        "operator": "omega_process",
        "equation": PROCESS_EQUATION,
        "state": result.state.value,
        "piece_ref": piece_ref,
        "requires_hold": result.requires_hold,
        "field_pressure": result.field_pressure,
        "a_delta": result.a_delta,
        "s_delta": result.s_delta,
        "t_delta": result.t_delta,
        "t_residual": result.t_residual,
        "residual_components": dict(result.residual_components),
        "explained_components": dict(result.explained_components),
        "witness_count": len(result.witnesses),
        "time_grid_trace_count": len(traces),
        "time_grid_traces": tuple(_time_grid_trace_summary(trace) for trace in traces),
        "enter_process_hash": _sha256_canonical(enter_process.to_dict()),
        "exit_process_hash": _sha256_canonical(exit_process.to_dict()),
        "result": result_payload,
        "authority": "observe_residual_attach_only",
        "testimony_only": True,
    }
    payload["witness_hash"] = _sha256_canonical(payload)
    return payload


def transition_process_witness_evidence(
    witness: Mapping[str, Any] | None,
) -> tuple[str, ...]:
    if not witness:
        return ()
    evidence = [
        f"omega_process.schema:{witness.get('schema')}",
        f"omega_process.state:{witness.get('state')}",
        f"omega_process.requires_hold:{str(bool(witness.get('requires_hold'))).lower()}",
        f"omega_process.field_pressure:{witness.get('field_pressure')}",
        f"omega_process.a_delta:{witness.get('a_delta')}",
        f"omega_process.s_delta:{witness.get('s_delta')}",
        f"omega_process.t_delta:{witness.get('t_delta')}",
        f"omega_process.t_residual:{witness.get('t_residual')}",
        f"omega_process.time_grid_trace_count:{witness.get('time_grid_trace_count')}",
    ]
    for component in sorted((witness.get("residual_components") or {}).keys()):
        evidence.append(f"omega_process.residual_component:{component}")
    if witness.get("witness_hash"):
        evidence.append(f"omega_process.witness_hash:{witness.get('witness_hash')}")
    return tuple(str(item) for item in evidence)


def _proposal_piece(proposal: CommandProposal) -> XrayPiece:
    side_effects = tuple(sorted(effect.value for effect in proposal.expected_side_effects))
    payload = {
        "proposal_id": proposal.proposal_id,
        "actor_id": proposal.actor_id,
        "source_adapter": proposal.source_adapter,
        "tool_name": proposal.tool_name,
        "action_type": proposal.action_type,
        "declared_scope": proposal.declared_scope.value,
        "target_paths": tuple(str(target) for target in proposal.target_paths),
        "expected_side_effects": side_effects,
        "command_sha256": _sha256_text(proposal.command_text),
        "command_length": len(proposal.command_text),
        "raw_payload_sha256": _sha256_canonical(proposal.raw_payload),
    }
    return XrayPiece(
        kind="registered_action",
        ref=proposal.proposal_id,
        exists=True,
        type="proposal",
        size=len(proposal.command_text),
        sha256=_sha256_canonical(payload),
        details=payload,
    )


def _skill_responsibility_piece(
    proposal: CommandProposal,
    *,
    max_file_bytes: int,
) -> XrayPiece:
    raw_payload = proposal.raw_payload
    trace = _skill_trace(raw_payload)
    trace_present = bool(trace)
    declared_ids = (
        _skill_values(raw_payload, "declared_skill_ids")
        | _skill_values(raw_payload, "declared_skill_id")
        | _skill_values(raw_payload, "skill_ids")
        | _skill_values(raw_payload, "skill_id")
    )
    used_ids = (
        _skill_values(trace, "used_skill_ids")
        | _skill_values(trace, "skill_ids")
        | _skill_values(trace, "skill_id")
        | _skill_values(raw_payload, "used_skill_ids")
    )
    required_ids = (
        _skill_values(trace, "required_skill_ids")
        | _skill_values(raw_payload, "required_skill_ids")
    )
    missing_required = tuple(sorted(required_ids - used_ids))
    manifest_hashes = _skill_mapping(trace, "manifest_hashes")
    manifest_hashes.update(_skill_mapping(raw_payload, "skill_manifest_hashes"))
    fallback_manifest_hash = _normalize_skill_token(
        trace.get("manifest_sha256") or raw_payload.get("skill_manifest_sha256")
    )
    completed_steps = (
        _skill_values(trace, "completed_step_ids")
        | _skill_values(trace, "completed_steps")
        | _skill_values(trace, "step_ids")
    )
    instruction_ids = (
        _skill_values(trace, "instruction_ids")
        | _skill_values(trace, "used_instruction_ids")
    )
    authority_claims = (
        _skill_values(trace, "authority_claims")
        | _skill_values(trace, "claims")
    )
    scan_evidence = _skill_scan_evidence(trace)
    path_refs = _skill_path_refs(raw_payload, trace)
    path_fingerprints = tuple(
        _path_fingerprint(
            path_ref,
            cwd=proposal.cwd,
            max_file_bytes=max_file_bytes,
        )
        for path_ref in path_refs
    )
    state = _skill_responsibility_state(
        trace_present=trace_present,
        declared_ids=declared_ids,
        used_ids=used_ids,
        required_ids=required_ids,
        missing_required=missing_required,
        has_skill_artifacts=bool(
            path_fingerprints or manifest_hashes or fallback_manifest_hash
        ),
    )
    payload = {
        "state": state,
        "responsibility_required": True,
        "trace_present": trace_present,
        "trace_hash": _sha256_canonical(trace) if trace_present else None,
        "declared_skill_ids": tuple(sorted(declared_ids)),
        "used_skill_ids": tuple(sorted(used_ids)),
        "required_skill_ids": tuple(sorted(required_ids)),
        "missing_required_skill_ids": missing_required,
        "completed_step_ids": tuple(sorted(completed_steps)),
        "instruction_ids": tuple(sorted(instruction_ids)),
        "authority_claims": tuple(sorted(authority_claims)),
        "scan_evidence": scan_evidence,
        "skill_manifest_hashes": manifest_hashes,
        "skill_manifest_sha256": fallback_manifest_hash or None,
        "skill_paths": path_fingerprints,
        "raw_payload_skill_keys": tuple(
            sorted(str(key) for key in raw_payload if "skill" in str(key).lower())
        ),
    }
    return XrayPiece(
        kind="skill_responsibility",
        ref="skill_responsibility",
        exists=True,
        type="responsibility_surface",
        size=len(path_fingerprints),
        sha256=_sha256_canonical(payload),
        details=payload,
    )


def _is_abs_any(raw: str) -> bool:
    # Absolute in EITHER OS convention -- a command can carry a Windows path
    # (C:\..., \\unc) under a POSIX runtime, or a /posix path under Windows.
    text = str(raw).strip().strip("'\"")
    return PureWindowsPath(text).is_absolute() or PurePosixPath(text).is_absolute()


def _lex_norm(value: str) -> str:
    return str(value).strip().strip("'\"").replace("\\", "/").rstrip("/").lower()


def _lexically_within_boundary(raw_ref: str, cwd: str) -> bool:
    # Decide the boundary on the RAW target before any cwd-join. A relative path
    # resolves under cwd (in-boundary). An absolute path is in-boundary only if
    # it is lexically under the project root -- so a Windows path under a POSIX
    # runtime is not mis-joined INTO the root and mistaken inside. (Symlink
    # escapes are a separate axis; `..` traversal is caught by protect_scan.)
    raw = str(raw_ref).strip().strip("'\"")
    if not _is_abs_any(raw):
        return True
    target = _lex_norm(raw)
    boundary = _lex_norm(cwd)
    return target == boundary or target.startswith(boundary + "/")


def _path_piece(
    target: str | Path,
    *,
    cwd: str | Path,
    max_file_bytes: int,
) -> XrayPiece:
    raw_ref = str(target)
    # (v1) Boundary decided LEXICALLY on the raw target, BEFORE any cwd-join, so
    # a Windows-absolute path under a POSIX runtime (the WSL probe) is not
    # mis-joined INTO the project root and mistaken for in-boundary. Outside the
    # root the gate has no observation authority -> exists=None makes
    # _piece_blindspot fire and the core's OBSERVATION_BLINDSPOT holds it for
    # review. Fires whether or not the external file exists; the ATTEMPT to
    # leave the boundary is the signal. A pure decoder note -- the core decides.
    if not _lexically_within_boundary(raw_ref, str(cwd)):
        # Outside the project root the gate has no observation authority. Mark a
        # blindspot the core HOLDs (exists=True + sha256=None -> _piece_blindspot
        # option 2), WITHOUT claiming "unobserved" (exists=None). exists=None
        # drives the potential field to UNKNOWN, which the transport seal reads
        # as a SUBSTITUTION and escalates to QUARANTINE -- wrong verdict and
        # wrong reason for a benign external read. We are declining to vouch for
        # an out-of-boundary referent, not reporting an object substitution.
        return XrayPiece(
            kind="target_path",
            ref=raw_ref,
            exists=True,
            type="out_of_boundary",
            sha256=None,
            details={
                "input_ref": raw_ref,
                "hash_limit_bytes": max_file_bytes,
                "boundary_root": str(cwd),
                "observation_boundary": "outside_project_root",
                "hash_status": "skipped_out_of_boundary",
            },
        )
    path = Path(target)
    if not path.is_absolute():
        path = Path(cwd) / path
    resolved = safe_resolve(path)
    base_details = {
        "input_ref": raw_ref,
        "resolved": str(resolved),
        "hash_limit_bytes": max_file_bytes,
    }

    fingerprint = _path_fingerprint(
        target,
        cwd=cwd,
        max_file_bytes=max_file_bytes,
    )
    if fingerprint["exists"] is None:
        return XrayPiece(
            kind="target_path",
            ref=raw_ref,
            exists=None,
            type=str(fingerprint.get("type", "unobserved")),
            details={**base_details, **dict(fingerprint.get("details", {}))},
        )
    if not fingerprint["exists"]:
        return XrayPiece(
            kind="target_path",
            ref=raw_ref,
            exists=False,
            type="missing",
            details=base_details,
        )
    return XrayPiece(
        kind="target_path",
        ref=raw_ref,
        exists=True,
        type=str(fingerprint["type"]),
        size=fingerprint.get("size") if isinstance(fingerprint.get("size"), int) else None,
        sha256=fingerprint.get("sha256")
        if isinstance(fingerprint.get("sha256"), str)
        else None,
        details={**base_details, **dict(fingerprint.get("details", {}))},
    )


def _path_fingerprint(
    target: str | Path,
    *,
    cwd: str | Path,
    max_file_bytes: int,
) -> dict[str, Any]:
    raw_ref = str(target)
    path = Path(target)
    if not path.is_absolute():
        path = Path(cwd) / path
    resolved = safe_resolve(path)
    raw_path = path.expanduser()
    boundary_root = safe_resolve(Path(cwd).expanduser())
    base_details = {
        "input_ref": raw_ref,
        "raw_path": str(raw_path),
        "resolved": str(resolved),
        "resolved_path": str(resolved),
        "boundary_root": str(boundary_root),
        "hash_limit_bytes": max_file_bytes,
        "os_ctime_semantics": _os_ctime_semantics(),
    }

    try:
        stat = raw_path.lstat()
    except FileNotFoundError:
        return {
            "input_ref": raw_ref,
            "resolved": str(resolved),
            "exists": False,
            "type": "missing",
            "size": None,
            "boundary_root": str(boundary_root),
            "sha256": None,
            "details": {
                **base_details,
                "physical_observation": "missing_raw_path",
            },
        }
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "input_ref": raw_ref,
            "resolved": str(resolved),
            "exists": None,
            "type": "unobserved",
            "size": None,
            "boundary_root": str(boundary_root),
            "sha256": None,
            "details": {
                **base_details,
                "observation_status": "path_stat_unavailable",
                "observation_error": type(exc).__name__,
                "observation_winerror": getattr(exc, "winerror", None),
            },
        }

    physical_details = _physical_stat_details(stat)

    if _is_symlink_mode(stat):
        try:
            link_target = os.readlink(raw_path)
        except OSError:
            link_target = "<unreadable>"
        return {
            "input_ref": raw_ref,
            "resolved": str(resolved),
            "exists": True,
            "type": "symlink",
            "size": 0,
            "boundary_root": str(boundary_root),
            "sha256": _sha256_canonical(
                {
                    "symlink_target": link_target,
                    "resolved_path": str(resolved),
                    "file_id": physical_details.get("file_id"),
                }
            ),
            **_physical_result_fields(physical_details),
            "symlink_target": link_target,
            "details": {
                **base_details,
                **physical_details,
                "symlink_target": link_target,
                "physical_observation": "raw_lstat_symlink",
            },
        }

    if _is_file_mode(stat):
        size = int(stat.st_size)
        details = {
            **base_details,
            **physical_details,
            "physical_observation": "raw_lstat_file",
        }
        if size <= max_file_bytes:
            digest = _sha256_file(raw_path)
            details["hash_status"] = "hashed" if digest is not None else "skipped_unreadable"
        else:
            digest = None
            details["hash_status"] = "skipped_size_limit"
        archive_details = _archive_entry_details(raw_path)
        if archive_details:
            details.update(archive_details)
        ads_streams = _ads_fingerprint(raw_path)
        if ads_streams:
            # T1564.004: an alternate data stream (file:stream) is invisible to the
            # MAIN-stream sha256, and its only side-effect (an mtime bump) is erased
            # by a timestomp. Folding the stream inventory into the piece moves
            # piece_hash, so adding/changing a stream surfaces as a mutation -> HOLD.
            details["ads_streams"] = ads_streams
        return {
            "input_ref": raw_ref,
            "resolved": str(resolved),
            "exists": True,
            "type": "file",
            "size": size,
            "boundary_root": str(boundary_root),
            "sha256": digest,
            **_physical_result_fields(physical_details),
            "details": details,
        }

    if _is_dir_mode(stat):
        children = []
        for child in sorted(raw_path.iterdir(), key=lambda item: item.name.lower()):
            try:
                child_stat = child.lstat()
            except OSError:
                children.append({"name": child.name, "type": "unreadable"})
                continue
            children.append(
                {
                    "name": child.name,
                    "type": _path_type(child),
                    "size": int(child_stat.st_size),
                    "file_id": _file_id_from_stat(child_stat),
                    "inode": _stat_int(child_stat, "st_ino"),
                    "nlink": _stat_int(child_stat, "st_nlink"),
                    "mtime_ns": _stat_int(child_stat, "st_mtime_ns"),
                    "ctime_ns": _stat_int(child_stat, "st_ctime_ns"),
                }
            )
        return {
            "input_ref": raw_ref,
            "resolved": str(resolved),
            "exists": True,
            "type": "directory",
            "size": len(children),
            "boundary_root": str(boundary_root),
            "sha256": _sha256_canonical(children),
            **_physical_result_fields(physical_details),
            "details": {
                **base_details,
                **physical_details,
                "directory_hash_mode": "shallow_child_manifest",
                "physical_observation": "raw_lstat_directory",
            },
        }

    return {
        "input_ref": raw_ref,
        "resolved": str(resolved),
        "exists": True,
        "type": "special",
        "size": int(stat.st_size),
        "boundary_root": str(boundary_root),
        "sha256": _sha256_canonical({"mode": stat.st_mode, "size": stat.st_size}),
        **_physical_result_fields(physical_details),
        "details": {
            **base_details,
            **physical_details,
            "physical_observation": "raw_lstat_special",
        },
    }


def _decision_piece(decision: Any) -> XrayPiece:
    if hasattr(decision, "to_dict"):
        payload = decision.to_dict()
    else:
        payload = {
            "disposition": _value(getattr(decision, "disposition", None)),
            "decision": _value(getattr(decision, "decision", None)),
            "certificate": _value(getattr(decision, "certificate", None)),
            "reason_code": getattr(decision, "reason_code", ""),
            "io_executed": bool(getattr(decision, "io_executed", False)),
            "can_execute": bool(getattr(decision, "can_execute", False)),
            "can_grant_permission": bool(getattr(decision, "can_grant_permission", False)),
        }
    payload = _canonicalize(payload)
    return XrayPiece(
        kind="decision",
        ref="decision",
        exists=True,
        type="decision",
        sha256=_sha256_canonical(payload),
        details=payload,
    )


def _skill_trace(raw_payload: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("skill_trace", "skill_context"):
        value = raw_payload.get(key)
        if isinstance(value, Mapping):
            return value
    return {}


def _skill_values(source: Mapping[str, Any], key: str) -> set[str]:
    return _coerce_skill_tokens(source.get(key))


def _skill_mapping(source: Mapping[str, Any], key: str) -> dict[str, str]:
    value = source.get(key)
    if not isinstance(value, Mapping):
        return {}
    return {
        _normalize_skill_token(item_key): _normalize_skill_token(item_value)
        for item_key, item_value in value.items()
        if _normalize_skill_token(item_key)
    }


def _skill_path_refs(
    raw_payload: Mapping[str, Any],
    trace: Mapping[str, Any],
) -> tuple[str, ...]:
    path_values = []
    for source in (raw_payload, trace):
        for key in (
            "skill_path",
            "skill_paths",
            "skill_file",
            "skill_files",
            "skill_manifest_path",
            "skill_manifest_paths",
        ):
            path_values.extend(_coerce_path_refs(source.get(key)))
    return tuple(dict.fromkeys(path_values))


def _skill_scan_evidence(trace: Mapping[str, Any]) -> dict[str, Any]:
    scans: dict[str, Any] = {}
    for key in (
        "instruction_scan",
        "skill_scan",
        "text_scan",
        "instruction_scan_passed",
        "skill_scan_passed",
        "text_scan_passed",
    ):
        if key in trace:
            scans[key] = _canonicalize(trace[key])
    return scans


def _coerce_path_refs(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, Path)):
        path = str(value).strip()
        return (path,) if path else ()
    if isinstance(value, Mapping):
        refs = []
        for item in value.values():
            refs.extend(_coerce_path_refs(item))
        return tuple(refs)
    try:
        iterator = iter(value)
    except TypeError:
        path = str(value).strip()
        return (path,) if path else ()
    refs = []
    for item in iterator:
        refs.extend(_coerce_path_refs(item))
    return tuple(refs)


def _skill_responsibility_state(
    *,
    trace_present: bool,
    declared_ids: set[str],
    used_ids: set[str],
    required_ids: set[str],
    missing_required: Sequence[str],
    has_skill_artifacts: bool,
) -> str:
    if missing_required or (required_ids and not used_ids):
        return "required_but_missing"
    if used_ids:
        return "used"
    if declared_ids:
        return "declared"
    if has_skill_artifacts:
        return "declared"
    if trace_present:
        return "trace_present_no_id"
    return "not_claimed"


def _coerce_skill_tokens(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        token = _normalize_skill_token(value)
        return {token} if token else set()
    if isinstance(value, Mapping):
        return {
            token
            for item_key, enabled in value.items()
            if enabled and (token := _normalize_skill_token(item_key))
        }
    try:
        iterator = iter(value)
    except TypeError:
        token = _normalize_skill_token(value)
        return {token} if token else set()
    return {
        token
        for item in iterator
        if (token := _normalize_skill_token(item))
    }


def _normalize_skill_token(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _annotate_pieces(pieces: Sequence[XrayPiece]) -> tuple[XrayPiece, ...]:
    return tuple(_annotate_piece(piece) for piece in pieces)


def _annotate_piece(piece: XrayPiece) -> XrayPiece:
    details = dict(piece.details)
    details["xray_tags"] = _piece_tags(piece)
    details["piece_pressure"] = round(_piece_pressure(piece), 6)
    details["pressure_model"] = "piece_pressure_v0"
    return XrayPiece(
        kind=piece.kind,
        ref=piece.ref,
        exists=piece.exists,
        type=piece.type,
        size=piece.size,
        sha256=piece.sha256,
        details=details,
    )


def _k_phi(
    proposal: CommandProposal,
    *,
    pieces: Sequence[XrayPiece],
    decision_present: bool,
) -> tuple[float, ...]:
    target_pieces = tuple(piece for piece in pieces if piece.kind == "target_path")
    target_count = len(target_pieces)
    missing_count = sum(1 for piece in target_pieces if piece.exists is False)
    hashed_count = sum(1 for piece in target_pieces if piece.sha256)
    unhashable_count = sum(
        1 for piece in target_pieces if piece.exists and piece.sha256 is None
    )
    effects = set(proposal.expected_side_effects)
    destructive = bool(
        effects
        & {
            SideEffect.DELETE,
            SideEffect.PRIVILEGE,
            SideEffect.SECRET_ACCESS,
            SideEffect.AUDIT_CHANGE,
        }
    )
    return (
        _norm_count(len(pieces), 16),
        _norm_count(target_count, 10),
        _ratio(missing_count, target_count),
        _ratio(hashed_count, target_count),
        _ratio(unhashable_count, target_count),
        _norm_count(len(effects), 8),
        1.0 if SideEffect.WRITE in effects else 0.0,
        1.0 if SideEffect.DELETE in effects else 0.0,
        1.0 if SideEffect.NETWORK in effects else 0.0,
        1.0 if destructive else 0.0,
        1.0 if decision_present else 0.0,
    )


def _u_phi_from_pieces(
    pieces: Sequence[XrayPiece],
    *,
    field_weight_tau: float = DEFAULT_FIELD_WEIGHT_TAU,
) -> float:
    scored_pieces = tuple(piece for piece in pieces if piece.kind != "decision")
    scores = tuple(_piece_pressure(piece) for piece in scored_pieces)
    if not scores:
        return 0.0
    weights = _exponential_weights(scores, tau=field_weight_tau)
    return round(sum(score * weight for score, weight in zip(scores, weights)), 6)


def _piece_tags(piece: XrayPiece) -> tuple[str, ...]:
    if piece.kind == "registered_action":
        effects = tuple(sorted(str(effect) for effect in piece.details.get("expected_side_effects", ())))
        tags = ["registered_action"]
        if piece.details.get("target_paths"):
            tags.append("has_targets")
        tags.extend(f"effect:{effect}" for effect in effects)
        if {
            SideEffect.DELETE.value,
            SideEffect.PRIVILEGE.value,
            SideEffect.SECRET_ACCESS.value,
            SideEffect.AUDIT_CHANGE.value,
        } & set(effects):
            tags.append("high_pressure_effect")
        return tuple(tags)

    if piece.kind == "target_path":
        tags = [f"type:{piece.type}"]
        tags.append("missing" if piece.exists is False else "exists")
        if piece.exists and piece.sha256:
            tags.append("hashed")
        elif piece.exists:
            tags.append("unhashed")
        if hash_unavailable(piece.details):
            tags.append(f"hash_{piece.details.get('hash_status')}")
        if _mentions_sensitive_marker(piece):
            tags.append("sensitive_marker")
        return tuple(tags)

    if piece.kind == "skill_responsibility":
        state = str(piece.details.get("state", "unknown"))
        tags = ["skill_responsibility", f"state:{state}"]
        if state == "not_claimed":
            tags.append("no_skill_claim")
        if piece.details.get("trace_present"):
            tags.append("trace_present")
        if piece.details.get("missing_required_skill_ids"):
            tags.append("missing_required_skill")
        if piece.details.get("used_skill_ids"):
            tags.append("used_skill")
        if piece.details.get("declared_skill_ids"):
            tags.append("declared_skill")
        if piece.details.get("skill_paths"):
            tags.append("skill_path_bound")
        if piece.details.get("authority_claims"):
            tags.append("authority_claim_recorded")
        if piece.details.get("scan_evidence"):
            tags.append("scan_evidence_recorded")
        return tuple(tags)

    if piece.kind == "decision":
        return ("sealed_decision",)

    return (f"kind:{piece.kind}",)


def _piece_pressure(piece: XrayPiece) -> float:
    if piece.kind == "registered_action":
        effects = set(piece.details.get("expected_side_effects", ()))
        pressure = 0.05 + 0.2 * _norm_count(len(effects), 8)
        pressure += max((_effect_pressure(effect) for effect in effects), default=0.0)
        pressure += 0.1 * _norm_count(len(piece.details.get("target_paths", ())), 10)
        return _clamp_unit(pressure)

    if piece.kind == "target_path":
        pressure = 0.05
        if piece.exists is False:
            pressure += 0.25
        pressure += {
            "file": 0.08,
            "directory": 0.16,
            "symlink": 0.28,
            "special": 0.32,
            "missing": 0.25,
        }.get(piece.type, 0.1)
        if piece.exists and not piece.sha256:
            pressure += 0.15
        if hash_unavailable(piece.details):
            pressure += 0.15
        if _mentions_sensitive_marker(piece):
            pressure += 0.2
        if piece.size is not None:
            pressure += 0.08 * _norm_count(piece.size, DEFAULT_MAX_HASH_BYTES)
        return _clamp_unit(pressure)

    if piece.kind == "skill_responsibility":
        state = str(piece.details.get("state", "unknown"))
        pressure = {
            "not_claimed": 0.06,
            "declared": 0.14,
            "used": 0.18,
            "trace_present_no_id": 0.28,
            "required_but_missing": 0.5,
        }.get(state, 0.22)
        pressure += 0.05 * _norm_count(len(piece.details.get("used_skill_ids", ())), 8)
        pressure += 0.08 * _norm_count(
            len(piece.details.get("missing_required_skill_ids", ())),
            8,
        )
        if piece.details.get("skill_paths"):
            pressure += 0.04
        if piece.details.get("authority_claims"):
            pressure += 0.08
        if piece.details.get("scan_evidence"):
            pressure += 0.04
        if any(
            not path_item.get("exists", False)
            for path_item in piece.details.get("skill_paths", ())
            if isinstance(path_item, Mapping)
        ):
            pressure += 0.08
        return _clamp_unit(pressure)

    return 0.0


def _effect_pressure(effect: str) -> float:
    return {
        SideEffect.READ.value: 0.05,
        SideEffect.WRITE.value: 0.25,
        SideEffect.DELETE.value: 0.45,
        SideEffect.ENV_CHANGE.value: 0.3,
        SideEffect.NETWORK.value: 0.3,
        SideEffect.PRIVILEGE.value: 0.45,
        SideEffect.SECRET_ACCESS.value: 0.45,
        SideEffect.AUDIT_CHANGE.value: 0.45,
    }.get(effect, 0.05)


def _exponential_weights(values: Sequence[float], *, tau: float) -> tuple[float, ...]:
    if not values:
        return ()
    safe_tau = tau if tau > 0 else DEFAULT_FIELD_WEIGHT_TAU
    scaled = tuple(value / safe_tau for value in values)
    max_scaled = max(scaled)
    raw = tuple(math.exp(value - max_scaled) for value in scaled)
    total = sum(raw)
    if total <= 0:
        return tuple(1.0 / len(values) for _ in values)
    return tuple(value / total for value in raw)


def _mentions_sensitive_marker(piece: XrayPiece) -> bool:
    haystack = " ".join(
        (
            piece.ref,
            str(piece.details.get("input_ref", "")),
            str(piece.details.get("resolved", "")),
        )
    ).lower()
    if any(marker in haystack for marker in SENSITIVE_PATH_MARKERS):
        return True
    return _under_sensitive_dir(piece)


def _under_sensitive_dir(piece: XrayPiece) -> bool:
    # A5 little-brother: flag a file by the secret DIRECTORY it lives in, by path
    # membership (parent parts), so renaming the file inside it does not evade.
    resolved = str(piece.details.get("resolved", "") or piece.ref)
    parts = [part.lower() for part in resolved.replace("\\", "/").split("/") if part]
    return any(part in SENSITIVE_DIR_NAMES for part in parts[:-1])


def _finding_details(
    before: XrayPiece | None,
    after: XrayPiece | None,
) -> dict[str, Any]:
    before_pressure = _stored_piece_pressure(before)
    after_pressure = _stored_piece_pressure(after)
    pressure_shift = None
    if before_pressure is not None and after_pressure is not None:
        pressure_shift = round(after_pressure - before_pressure, 6)
    details = {
        "before_pressure": before_pressure,
        "after_pressure": after_pressure,
        "pressure_shift": pressure_shift,
        "pressure_shift_abs": (
            round(abs(pressure_shift), 6) if pressure_shift is not None else None
        ),
        "before_tags": _stored_piece_tags(before),
        "after_tags": _stored_piece_tags(after),
    }
    time_grid = _time_grid_details(before, after)
    if time_grid is not None:
        details["time_grid"] = time_grid
    return details


def _time_grid_details(
    before: XrayPiece | None,
    after: XrayPiece | None,
) -> dict[str, Any] | None:
    trace = _time_grid_trace(before, after)
    if trace is None:
        return None
    return {
        "schema": TIME_GRID_SCHEMA,
        "object_ref": trace.object_ref,
        "requires_hold": trace.requires_hold,
        "projection_components": dict(trace.projection_components),
        "findings": trace.findings,
    }


def _time_grid_trace(
    before: XrayPiece | None,
    after: XrayPiece | None,
) -> TimeGridTrace | None:
    if (
        before is None
        or after is None
        or before.kind != "target_path"
        or after.kind != "target_path"
    ):
        return None
    spec = TimeGridSpec(enter_ts_ns=0, exit_ts_ns=1, step_ns=1)
    trace = build_time_grid_trace(
        spec=spec,
        cells=(
            _time_grid_cell_from_piece(before, index=0, expected_ts_ns=0),
            _time_grid_cell_from_piece(after, index=1, expected_ts_ns=1),
        ),
        object_ref=before.key,
        details={"source": "transition_xray_pair"},
    )
    return trace


def _time_grid_cell_from_piece(
    piece: XrayPiece,
    *,
    index: int,
    expected_ts_ns: int,
) -> TimeGridCell:
    details = piece.details if isinstance(piece.details, Mapping) else {}
    return TimeGridCell(
        index=index,
        expected_ts_ns=expected_ts_ns,
        exists=piece.exists,
        sampled_at_ns=expected_ts_ns,
        metadata_vector_hash=_piece_metadata_vector_hash(piece),
        mtime_ns=_int_or_none(details.get("mtime_ns")),
        os_ctime_ns=_int_or_none(details.get("ctime_ns")),
        os_ctime_semantics=_str_or_none(details.get("os_ctime_semantics")),
        file_id=_str_or_none(details.get("file_id")),
        nlink=_int_or_none(details.get("nlink")),
        resolved_path=_piece_resolved_path(piece),
        details={
            "piece_key": piece.key,
            "hash_status": details.get("hash_status"),
            "physical_observation": details.get("physical_observation"),
        },
    )


def _piece_metadata_vector_hash(piece: XrayPiece) -> str:
    details = piece.details if isinstance(piece.details, Mapping) else {}
    payload = {
        "exists": piece.exists,
        "type": piece.type,
        "size": piece.size,
        "sha256": piece.sha256,
        "raw_path": details.get("raw_path"),
        "resolved_path": _piece_resolved_path(piece),
        "file_id": details.get("file_id"),
        "inode": details.get("inode"),
        "device_id": details.get("device_id"),
        "nlink": details.get("nlink"),
        "mtime_ns": details.get("mtime_ns"),
        "ctime_ns": details.get("ctime_ns"),
        "os_ctime_semantics": details.get("os_ctime_semantics"),
        "mode": details.get("mode"),
        "symlink_target": details.get("symlink_target"),
    }
    return _sha256_canonical(payload)


def _process_vectors_from_transition_pair(
    pair: TransitionXrayPair,
    proposal: CommandProposal,
    *,
    time_grid_traces: Sequence[TimeGridTrace] | None = None,
) -> tuple[AccessProcessVector, AccessProcessVector, tuple[TimeGridTrace, ...]]:
    pair_traces = _process_time_grid_traces(pair)
    if time_grid_traces is None:
        traces = pair_traces
    else:
        # The live meter closes the between-endpoint gap; the canonical pair
        # still contributes bounded content/object deltas that metadata-only
        # beats may not see. Add only changed pair traces to avoid duplicating
        # a stable target.
        traces = tuple(time_grid_traces) + tuple(
            trace for trace in pair_traces if trace.projection_components
        )
    enter_time, exit_time = _process_time_terms(pair, traces)
    process_token = _sha256_text(proposal.proposal_id)
    return (
        build_access_process_vector(
            process_ref=f"process:enter:{process_token}",
            agency_term=_agency_process_term(pair.enter),
            surface_term=_surface_process_term(pair.enter),
            time_term=enter_time,
            phase=AccessFieldPhase.ENTER,
            details={
                "source": "transition_xray_frame",
                "projection": "A_plus_S_minus_T",
            },
        ),
        build_access_process_vector(
            process_ref=f"process:exit:{process_token}",
            agency_term=_agency_process_term(pair.exit),
            surface_term=_surface_process_term(pair.exit),
            time_term=exit_time,
            phase=AccessFieldPhase.EXIT,
            details={
                "source": "transition_xray_frame",
                "projection": "A_plus_S_minus_T",
            },
        ),
        traces,
    )


def _time_grid_trace_summary(trace: TimeGridTrace) -> dict[str, Any]:
    details = dict(trace.details)
    return {
        "object_ref_hash": _sha256_text(str(trace.object_ref or "")),
        "cell_count": len(trace.cells),
        "missing_cell_indices": trace.missing_cell_indices,
        "finding_types": tuple(
            str(finding.get("type")) for finding in trace.findings
        ),
        "projection_components": dict(trace.projection_components),
        "requires_hold": trace.requires_hold,
        "sampling": dict(details.get("sampling") or {}),
    }


def _agency_process_term(frame: TransitionXrayFrame) -> AccessProcessTerm:
    action_pieces = tuple(piece for piece in frame.pieces if piece.kind == "registered_action")
    responsibility_pieces = tuple(
        piece for piece in frame.pieces if piece.kind == "skill_responsibility"
    )
    observed = bool(action_pieces and responsibility_pieces) and not any(
        _piece_blindspot(piece) for piece in (*action_pieces, *responsibility_pieces)
    )
    components: dict[str, float] = {}
    if action_pieces:
        components["agency_registered_action_pressure"] = max(
            _piece_pressure(piece) for piece in action_pieces
        )
    if responsibility_pieces:
        components["agency_responsibility_pressure"] = max(
            _piece_pressure(piece) for piece in responsibility_pieces
        )
    if not observed:
        components["observation_agency_pressure"] = 1.0
    return AccessProcessTerm(
        AccessProcessSlot.AGENCY,
        payload={
            "registered_action_hashes": tuple(piece.piece_hash for piece in action_pieces),
            "responsibility_hashes": tuple(
                piece.piece_hash for piece in responsibility_pieces
            ),
            "responsibility_states": tuple(
                str(piece.details.get("state") or "unknown")
                for piece in responsibility_pieces
            ),
        },
        projection_components=components,
        observed=observed,
        evidence={"projection_source": "registered_action_and_skill_responsibility"},
        details={"phase": frame.phase.value},
    )


def _surface_process_term(frame: TransitionXrayFrame) -> AccessProcessTerm:
    action_pieces = tuple(piece for piece in frame.pieces if piece.kind == "registered_action")
    targets = _target_path_pieces(frame)
    blind_spots = tuple(piece.key for piece in targets if _piece_blindspot(piece))
    observed = bool(action_pieces) and not blind_spots
    components: dict[str, float] = {}
    if action_pieces:
        components["surface_command_pressure"] = max(
            _piece_pressure(piece) for piece in action_pieces
        )
    if targets:
        components["surface_target_pressure"] = max(
            _piece_pressure(piece) for piece in targets
        )
    if blind_spots:
        components["observation_surface_pressure"] = 1.0
    return AccessProcessTerm(
        AccessProcessSlot.SURFACE,
        payload={
            "command_surface_hashes": tuple(piece.piece_hash for piece in action_pieces),
            "targets": tuple(
                {
                    "piece_key_hash": _sha256_text(piece.key),
                    "piece_hash": piece.piece_hash,
                    "exists": piece.exists,
                    "type": piece.type,
                    "resolved_path_hash": _sha256_text(_piece_resolved_path(piece) or ""),
                }
                for piece in targets
            ),
        },
        projection_components=components,
        observed=observed,
        evidence={"projection_source": "command_and_explicit_target_surfaces"},
        details={
            "phase": frame.phase.value,
            "blind_spot_count": len(blind_spots),
        },
    )


def _process_time_grid_traces(pair: TransitionXrayPair) -> tuple[TimeGridTrace, ...]:
    enter = {piece.key: piece for piece in _target_path_pieces(pair.enter)}
    exit_ = {piece.key: piece for piece in _target_path_pieces(pair.exit)}
    traces: list[TimeGridTrace] = []
    for key in sorted(set(enter) & set(exit_)):
        before = enter[key]
        after = exit_[key]
        if before.exists is False and after.exists is False:
            continue
        trace = _time_grid_trace(before, after)
        if trace is not None:
            traces.append(trace)
    return tuple(traces)


def _process_time_terms(
    pair: TransitionXrayPair,
    traces: Sequence[TimeGridTrace],
) -> tuple[AccessProcessTerm, AccessProcessTerm]:
    trace_terms = tuple(trace.to_process_time_term() for trace in traces)
    components: dict[str, float] = {}
    for term in trace_terms:
        for component, pressure in term.projection_components.items():
            components[component] = max(components.get(component, 0.0), pressure)
    observed = all(term.observed for term in trace_terms)
    trace_payload = tuple(trace.to_dict() for trace in traces)
    common = {
        "pair_hash": pair.pair_hash,
        "trace_count": len(traces),
        "traces": trace_payload,
    }
    enter_term = AccessProcessTerm(
        AccessProcessSlot.TIME,
        payload={**common, "projection_role": "enter_baseline"},
        projection_components={component: 0.0 for component in components},
        observed=observed,
        evidence={"time_axis": "fixed_grid", "projection": "baseline"},
        details={"mode": "enter_baseline_exit_pair_trace_v0"},
    )
    exit_term = AccessProcessTerm(
        AccessProcessSlot.TIME,
        payload={**common, "projection_role": "exit_pair_trace"},
        projection_components=components,
        observed=observed,
        evidence={"time_axis": "fixed_grid", "projection": "pair_trace"},
        details={"mode": "enter_baseline_exit_pair_trace_v0"},
    )
    return enter_term, exit_term


def _access_input_from_transition_pair(
    pair: TransitionXrayPair,
    proposal: CommandProposal,
) -> AccessEquationInput:
    enter_states = tuple(
        _xray_object_state_from_piece(piece) for piece in _target_path_pieces(pair.enter)
    )
    exit_states = tuple(
        _xray_object_state_from_piece(piece) for piece in _target_path_pieces(pair.exit)
    )
    all_pieces = (*_target_path_pieces(pair.enter), *_target_path_pieces(pair.exit))
    target_refs = tuple(sorted({piece.key for piece in all_pieces}))
    current = AccessCurrent(
        process_id=proposal.proposal_id,
        agency=tuple(item for item in (proposal.actor_id,) if item),
        surface=tuple(
            item
            for item in (
                proposal.source_adapter,
                proposal.tool_name,
                proposal.action_type,
                proposal.declared_scope.value,
            )
            if item
        ),
        window=AccessWindow(
            enter_ts_ns=0,
            exit_ts_ns=1,
            order_token=pair.pair_hash,
            details={
                "enter_hash": pair.enter.frame_hash,
                "exit_hash": pair.exit.frame_hash,
            },
        ),
        effects=tuple(sorted(effect.value for effect in proposal.expected_side_effects)),
        target_refs=target_refs,
        source_adapter=proposal.source_adapter,
        tool_name=proposal.tool_name,
        proposal_id=proposal.proposal_id,
        details={
            "action_type": proposal.action_type,
            "command_sha256": _sha256_text(proposal.command_text),
        },
    )
    return AccessEquationInput(
        process_id=proposal.proposal_id,
        object_states=exit_states,
        enter_object_states=enter_states,
        exit_object_states=exit_states,
        currents=(current,),
        boundary=_boundary_metric_from_pieces(proposal, all_pieces),
        auth=None,
        observation=_observation_mask_from_pieces(all_pieces),
        metadata_change_tokens=_metadata_change_tokens(pair.findings),
        details={
            "source": "transition_xray_pair",
            "pair_hash": pair.pair_hash,
            "mutation_state": pair.mutation_state.value,
        },
    )


def _target_path_pieces(frame: TransitionXrayFrame) -> tuple[XrayPiece, ...]:
    return tuple(piece for piece in frame.pieces if piece.kind == "target_path")


def _xray_object_state_from_piece(piece: XrayPiece) -> XrayObjectState:
    details = piece.details if isinstance(piece.details, Mapping) else {}
    return XrayObjectState(
        object_ref=piece.key,
        exists=piece.exists,
        object_type=piece.type,
        raw_path=_str_or_none(details.get("raw_path") or details.get("input_ref")),
        resolved_path=_piece_resolved_path(piece),
        boundary_root=_str_or_none(details.get("boundary_root")),
        size=piece.size,
        content_sha256=piece.sha256,
        metadata_sha256=_piece_metadata_vector_hash(piece),
        file_id=_str_or_none(details.get("file_id")),
        inode=_int_or_none(details.get("inode")),
        device_id=_str_or_none(details.get("device_id")),
        nlink=_int_or_none(details.get("nlink")),
        mtime_ns=_int_or_none(details.get("mtime_ns")),
        ctime_ns=_int_or_none(details.get("ctime_ns")),
        symlink_target=_str_or_none(details.get("symlink_target")),
        mode=_str_or_none(details.get("mode")),
        details={
            "hash_status": details.get("hash_status"),
            "observation_boundary": details.get("observation_boundary"),
            "physical_observation": details.get("physical_observation"),
            "piece_pressure": details.get("piece_pressure"),
            "xray_tags": tuple(details.get("xray_tags", ()) or ()),
        },
    )


def _boundary_metric_from_pieces(
    proposal: CommandProposal,
    pieces: Sequence[XrayPiece],
) -> BoundaryMetric:
    contained: list[str] = []
    escaped: list[str] = []
    aliases: list[str] = []
    for piece in pieces:
        ref = _piece_resolved_path(piece) or piece.ref
        details = piece.details if isinstance(piece.details, Mapping) else {}
        if (
            piece.type == "out_of_boundary"
            or details.get("observation_boundary") == "outside_project_root"
        ):
            escaped.append(ref)
        else:
            contained.append(ref)
        nlink = _int_or_none(details.get("nlink"))
        if nlink is not None and nlink > 1:
            aliases.append(ref)
    return BoundaryMetric(
        boundary_id="transition_xray_project_boundary",
        root=str(proposal.cwd),
        scope=proposal.declared_scope.value,
        contained_refs=tuple(sorted(set(contained))),
        escaped_refs=tuple(sorted(set(escaped))),
        alias_refs=tuple(sorted(set(aliases))),
        details={"source": "transition_xray_pair"},
    )


def _observation_mask_from_pieces(pieces: Sequence[XrayPiece]) -> ObservationMask:
    blind_spots = tuple(sorted({piece.key for piece in pieces if _piece_blindspot(piece)}))
    observed_fields = (
        "exists",
        "metadata_vector_hash",
        "mtime_ns",
        "os_ctime_ns",
        "os_ctime_semantics",
        "file_id",
        "nlink",
        "resolved_path",
    )
    return ObservationMask(
        ObservationState.PARTIAL if blind_spots else ObservationState.COMPLETE,
        observed_fields=observed_fields,
        blind_spots=blind_spots,
        confidence=0.5 if blind_spots else 1.0,
        details={
            "source": "transition_xray_pair",
            "target_piece_count": len(tuple(pieces)),
            "missing_files_are_observed_absence": True,
        },
    )


def _metadata_change_tokens(
    findings: Sequence[MutationFinding],
) -> tuple[dict[str, Any], ...]:
    tokens: list[dict[str, Any]] = []
    for finding in findings:
        time_grid = finding.details.get("time_grid")
        if not isinstance(time_grid, Mapping):
            continue
        for item in time_grid.get("findings", ()) or ():
            if not isinstance(item, Mapping):
                continue
            tokens.append(
                {
                    "changed": True,
                    "subject": finding.piece_key,
                    "semantics": item.get("component"),
                    "time_grid_type": item.get("type"),
                    "source_finding": finding.finding_type,
                    "severity": item.get("severity"),
                }
            )
    return tuple(tokens)


def _piece_blindspot(piece: XrayPiece) -> bool:
    details = piece.details if isinstance(piece.details, Mapping) else {}
    if piece.exists is None:
        return True
    if piece.kind == "target_path" and piece.exists is True and piece.sha256 is None:
        return True
    return hash_unavailable(details)


def _piece_resolved_path(piece: XrayPiece) -> str | None:
    details = piece.details if isinstance(piece.details, Mapping) else {}
    return _str_or_none(
        details.get("resolved_path")
        or details.get("resolved")
        or details.get("input_ref")
        or piece.ref
    )


def _int_or_none(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _continuity_state_from_mutation(state: MutationState) -> ContinuityState:
    if state == MutationState.STABLE:
        return ContinuityState.CONTINUOUS
    if state == MutationState.MUTATED:
        return ContinuityState.BROKEN
    if state == MutationState.INCOMPLETE:
        return ContinuityState.INCOMPLETE
    return ContinuityState.UNOBSERVED


def _continuity_residual_scalar(findings: Sequence[MutationFinding]) -> float:
    if not findings:
        return 0.0
    return round(sum(_continuity_witness_weight(finding) for finding in findings), 6)


def _classify_movement_residuals(
    findings: Sequence[MutationFinding],
) -> tuple[MovementResidual, ...]:
    return tuple(
        residual
        for finding in findings
        if (residual := _movement_residual_from_finding(finding)) is not None
    )


def _movement_residual_from_finding(
    finding: MutationFinding,
) -> MovementResidual | None:
    details = finding.details
    before_tags = tuple(details.get("before_tags") or ())
    after_tags = tuple(details.get("after_tags") or ())
    tags = set(before_tags) | set(after_tags)
    evidence = {
        "before_tags": before_tags,
        "after_tags": after_tags,
        "before_hash": finding.before_hash,
        "after_hash": finding.after_hash,
        "pressure_shift_abs": details.get("pressure_shift_abs"),
    }

    if finding.finding_type == "ACTION_ID_MISMATCH":
        return MovementResidual(
            residual_type=MovementResidualType.OBSERVATION_BLINDNESS,
            piece_key=finding.piece_key,
            mechanism="action_identity_mismatch",
            finding_type=finding.finding_type,
            evidence=evidence,
        )

    if finding.finding_type in {"CREATED_DURING_WINDOW", "DELETED_DURING_WINDOW"}:
        return MovementResidual(
            residual_type=MovementResidualType.OBJECT_SUBSTITUTION,
            piece_key=finding.piece_key,
            mechanism=finding.finding_type.lower(),
            finding_type=finding.finding_type,
            evidence=evidence,
        )

    if "skill_responsibility" in tags or finding.piece_key.startswith(
        "skill_responsibility:"
    ):
        return MovementResidual(
            residual_type=MovementResidualType.RESPONSIBILITY_SWAP,
            piece_key=finding.piece_key,
            mechanism="skill_responsibility_identity_delta",
            finding_type=finding.finding_type,
            evidence=evidence,
        )

    if "unhashed" in tags or "hash_skipped_size_limit" in tags:
        return MovementResidual(
            residual_type=MovementResidualType.OBSERVATION_BLINDNESS,
            piece_key=finding.piece_key,
            mechanism="resource_identity_observation_incomplete",
            finding_type=finding.finding_type,
            evidence=evidence,
        )

    if any(tag == "type:symlink" for tag in tags):
        return MovementResidual(
            residual_type=MovementResidualType.POINTER_REDIRECTION,
            piece_key=finding.piece_key,
            mechanism="path_pointer_delta",
            finding_type=finding.finding_type,
            evidence=evidence,
        )

    return MovementResidual(
        residual_type=MovementResidualType.OBJECT_SUBSTITUTION,
        piece_key=finding.piece_key,
        mechanism="resource_identity_delta",
        finding_type=finding.finding_type,
        evidence=evidence,
    )


def _continuity_witness_weight(finding: MutationFinding) -> float:
    base = {
        "ACTION_ID_MISMATCH": 1.0,
        "CREATED_DURING_WINDOW": 0.75,
        "DELETED_DURING_WINDOW": 0.75,
        "HASH_MUTATED": 0.6,
    }.get(finding.finding_type, 0.5)
    details = finding.details
    tags = set(details.get("before_tags") or ()) | set(details.get("after_tags") or ())
    pressure_shift_abs = details.get("pressure_shift_abs")
    if isinstance(pressure_shift_abs, (int, float)):
        base += min(abs(float(pressure_shift_abs)), 1.0) * 0.25
    if "sensitive_marker" in tags:
        base += 0.2
    if "skill_path_bound" in tags:
        base += 0.15
    if "missing_required_skill" in tags:
        base += 0.15
    if any(str(tag).startswith("effect:delete") for tag in tags):
        base += 0.2
    return round(base, 6)


def _stored_piece_pressure(piece: XrayPiece | None) -> float | None:
    if piece is None:
        return None
    value = piece.details.get("piece_pressure")
    if isinstance(value, (int, float)):
        return round(float(value), 6)
    return round(_piece_pressure(piece), 6)


def _stored_piece_tags(piece: XrayPiece | None) -> tuple[str, ...] | None:
    if piece is None:
        return None
    value = piece.details.get("xray_tags")
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return _piece_tags(piece)


def _physical_stat_details(stat_result: os.stat_result) -> dict[str, Any]:
    inode = _stat_int(stat_result, "st_ino")
    device_id = _stat_int(stat_result, "st_dev")
    nlink = _stat_int(stat_result, "st_nlink")
    mode_int = _stat_int(stat_result, "st_mode")
    return {
        "file_id": _file_id_from_stat(stat_result),
        "inode": inode,
        "device_id": str(device_id) if device_id is not None else None,
        "nlink": nlink,
        "mtime_ns": _stat_int(stat_result, "st_mtime_ns"),
        "ctime_ns": _stat_int(stat_result, "st_ctime_ns"),
        "mode": oct(mode_int) if mode_int is not None else None,
    }


def _physical_result_fields(details: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "file_id": details.get("file_id"),
        "inode": details.get("inode"),
        "device_id": details.get("device_id"),
        "nlink": details.get("nlink"),
        "mtime_ns": details.get("mtime_ns"),
        "ctime_ns": details.get("ctime_ns"),
        "mode": details.get("mode"),
    }


def _file_id_from_stat(stat_result: os.stat_result) -> str | None:
    inode = _stat_int(stat_result, "st_ino")
    device_id = _stat_int(stat_result, "st_dev")
    if inode is None or device_id is None or inode == 0:
        return None
    return f"{device_id}:{inode}"


def _stat_int(stat_result: os.stat_result, field_name: str) -> int | None:
    value = getattr(stat_result, field_name, None)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_symlink_mode(stat_result: os.stat_result) -> bool:
    return stat.S_ISLNK(stat_result.st_mode)


def _is_file_mode(stat_result: os.stat_result) -> bool:
    return stat.S_ISREG(stat_result.st_mode)


def _is_dir_mode(stat_result: os.stat_result) -> bool:
    return stat.S_ISDIR(stat_result.st_mode)


def _os_ctime_semantics() -> str:
    if os.name == "nt":
        return "windows_creation_time"
    return "unix_metadata_change_time"


# ZIP local-file-header / central-directory / end-of-central-directory magic.
# Office docs (.docx/.xlsx/.pptx), wheels (.whl), jars (.jar), eggs, apks and
# skill packages are ALL ZIP containers, and a plain .zip can be renamed to any
# suffix. Archive recognition is anchored on these unforgeable header bytes, never
# on the producer-chosen extension -- renaming evil.zip -> evil.whl must not blind
# CONTAINER_ESCAPE. (Red-team A1: trust the physical bytes, not the name.)
_ZIP_MAGICS = ZIP_CONTAINER_MAGICS
_ARCHIVE_SUFFIX_HINTS = ZIP_CONTAINER_SUFFIX_HINTS
# Bomb / resource guards -- scanning attacker-supplied archives must terminate and
# must not be coaxed into unbounded memory by a deeply nested or hugely-expanding
# container. On any limit we report a blindspot status (HOLD), never a silent pass.
_ARCHIVE_MAX_ENTRIES = 8192
_ARCHIVE_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_ARCHIVE_MAX_RATIO = 300
_ARCHIVE_MAX_DEPTH = 3
_ARCHIVE_NESTED_MAX_BYTES = 32 * 1024 * 1024
_ARCHIVE_ENTRY_MAP_CAP = 256


def _is_zip_magic(header: bytes) -> bool:
    return header_is_zip_container_magic(header)


def _sniff_is_zip(path: Path) -> bool:
    return sniff_zip_container(path)


def _archive_probe_metadata(path: Path) -> dict[str, Any]:
    """Additive A1 audit fields: magic governs scanning; suffix is informational."""
    metadata: dict[str, Any] = {"archive_recognition_method": "zip_magic_v1"}
    suffix = path.suffix.lower()
    if suffix:
        metadata["archive_name_suffix"] = suffix
        metadata["archive_suffix_hint_match"] = suffix in _ARCHIVE_SUFFIX_HINTS
    return metadata


def _name_matches_sensitive(name: str) -> bool:
    low = name.lower()
    return any(marker in low for marker in SENSITIVE_PATH_MARKERS)


def _archive_entry_details(path: Path) -> dict[str, Any]:
    # Recognize containers by MAGIC, not suffix (A1). Non-containers are untouched.
    if not _sniff_is_zip(path):
        return {}
    budget = {"entries": _ARCHIVE_MAX_ENTRIES, "bytes": _ARCHIVE_MAX_TOTAL_BYTES, "bomb": False}
    try:
        with zipfile.ZipFile(path, "r") as archive:
            scan = _scan_zip_entries(archive, "", 0, budget)
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
        # A zip-magic file we cannot read is an observation blindspot, not a pass.
        return {
            "archive_format": "zip",
            "archive_observation_status": "archive_unreadable",
            "archive_observation_error": type(exc).__name__,
            **_archive_probe_metadata(path),
        }
    status = "archive_scanned"
    if budget["bomb"]:
        status = "archive_resource_limit"
    elif scan["truncated"]:
        status = "archive_truncated"
    return {
        "archive_format": "zip",
        "archive_entry_map": tuple(scan["entries"][:_ARCHIVE_ENTRY_MAP_CAP]),
        "archive_entry_count": scan["entry_count"],
        "archive_nested_count": scan["nested_count"],
        "archive_escape_entries": tuple(scan["escapes"]),
        "archive_sensitive_entries": tuple(scan["sensitive"]),
        "archive_observation_status": status,
        **_archive_probe_metadata(path),
    }


def _scan_zip_entries(
    archive: zipfile.ZipFile, prefix: str, depth: int, budget: dict[str, Any]
) -> dict[str, Any]:
    """Walk one archive's entries, recursing into nested archives (bounded).

    Entry names are prefixed `outer!inner!name` so an escape/sensitive hit deep in
    a nested container is still attributable. The `budget` (entry count + total
    uncompressed bytes, shared across the recursion) bounds work and flags bombs.
    """
    entries: list[dict[str, Any]] = []
    escapes: list[str] = []
    sensitive: list[str] = []
    entry_count = 0
    nested_count = 0
    truncated = False
    for info in archive.infolist():
        if budget["entries"] <= 0:
            truncated = True
            break
        budget["entries"] -= 1
        entry_count += 1
        name = info.filename
        full = prefix + name
        size = int(info.file_size)
        compress = int(info.compress_size)
        budget["bytes"] -= size
        if budget["bytes"] < 0:
            budget["bomb"] = True
        if compress > 0 and size / compress > _ARCHIVE_MAX_RATIO:
            budget["bomb"] = True
        entry_escapes = _archive_entry_escapes(name)
        entry_sensitive = _name_matches_sensitive(name)
        if entry_escapes:
            escapes.append(full)
        if entry_sensitive:
            sensitive.append(full)
        entries.append(
            {
                "name": full,
                "file_size": size,
                "compress_size": compress,
                "is_dir": info.is_dir(),
                "escapes": entry_escapes,
                "sensitive": entry_sensitive,
            }
        )
        # Recurse into a nested archive -- the same eye, one level deeper. A cheap
        # 4-byte header sniff classifies every entry; only true, size-bounded
        # nested zips are fully read and recursed.
        if info.is_dir() or depth >= _ARCHIVE_MAX_DEPTH or budget["bomb"]:
            continue
        try:
            with archive.open(info) as handle:
                head = handle.read(4)
        except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
            continue
        if not _is_zip_magic(head):
            continue
        nested_count += 1
        if not 0 < size <= _ARCHIVE_NESTED_MAX_BYTES:
            truncated = True  # nested archive too large to inspect -> blindspot
            continue
        try:
            blob = archive.read(info)
            with zipfile.ZipFile(io.BytesIO(blob), "r") as inner:
                sub = _scan_zip_entries(inner, full + "!", depth + 1, budget)
        except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
            truncated = True
            continue
        entries.extend(sub["entries"])
        escapes.extend(sub["escapes"])
        sensitive.extend(sub["sensitive"])
        entry_count += sub["entry_count"]
        nested_count += sub["nested_count"]
        truncated = truncated or sub["truncated"]
    return {
        "entries": entries,
        "escapes": escapes,
        "sensitive": sensitive,
        "entry_count": entry_count,
        "nested_count": nested_count,
        "truncated": truncated,
    }


def _ads_fingerprint(path: Path) -> tuple[tuple[str, int], ...]:
    # Enumerate Windows alternate data streams attached to a file (excluding the
    # main "::$DATA" stream). Returned as sorted (name, size) so it is deterministic
    # and serializable. Best-effort: non-Windows has no ADS; any enumeration error
    # yields () (the main-stream hash still covers ordinary content).
    if os.name != "nt":
        return ()
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.windll.kernel32

        class _StreamData(ctypes.Structure):
            _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", wintypes.WCHAR * 296)]

        find_first = k32.FindFirstStreamW
        find_first.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        find_first.restype = wintypes.HANDLE
        find_next = k32.FindNextStreamW
        find_next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        find_next.restype = wintypes.BOOL
        find_close = k32.FindClose
        find_close.argtypes = [wintypes.HANDLE]  # else the handle overflows c_int
        find_close.restype = wintypes.BOOL

        data = _StreamData()
        invalid = wintypes.HANDLE(-1).value
        handle = find_first(str(path), 0, ctypes.byref(data), 0)
        if handle == invalid:
            return ()
        streams: list[tuple[str, int]] = []
        try:
            while True:
                name = data.cStreamName
                if name and name != "::$DATA":
                    streams.append((name, int(data.StreamSize)))
                if not find_next(handle, ctypes.byref(data)):
                    break
        finally:
            try:
                find_close(handle)
            except Exception:  # noqa: BLE001 - a close failure must not discard the result
                pass
        return tuple(sorted(streams))
    except Exception:  # noqa: BLE001
        return ()


def _archive_entry_escapes(name: str) -> bool:
    if not name or name.startswith(("/", "\\")):
        return True
    if PureWindowsPath(name).drive:
        return True
    parts = PurePosixPath(name.replace("\\", "/")).parts
    return any(part == ".." for part in parts)


def _clamp_unit(value: float) -> float:
    return max(0.0, min(1.0, value))


def _path_type(path: Path) -> str:
    if path.is_symlink():
        return "symlink"
    if path.is_file():
        return "file"
    if path.is_dir():
        return "directory"
    return "special"


def _norm_count(value: int, cap: int) -> float:
    if cap <= 0:
        return 0.0
    return round(min(max(value, 0), cap) / cap, 6)


def _ratio(value: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(value / total, 6)


HASH_SKIPPED_STATUSES = frozenset(
    {"skipped_size_limit", "skipped_unreadable", "skipped_out_of_boundary"}
)


def hash_unavailable(details: Mapping[str, Any]) -> bool:
    # Single source of truth for "an existing file whose content was not hashed".
    # Every skip reason (size limit, unreadable, any future reason) is a content
    # blindspot. Add a new reason to HASH_SKIPPED_STATUSES and every consumer
    # inherits it -- no per-site clause to forget.
    return str((details or {}).get("hash_status") or "") in HASH_SKIPPED_STATUSES


def _sha256_file(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        # Content unreadable (permission denied, vanished mid-window, device error).
        # An auditor that cannot establish state must report a blindspot (2),
        # never crash into "no state". Caller maps None -> skipped_unreadable -> HOLD.
        return None
    return f"sha256:{digest.hexdigest()}"


def _sha256_text(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _sha256_canonical(value: Any) -> str:
    canonical = json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _canonicalize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _canonicalize(child) for key, child in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return tuple(_canonicalize(item) for item in value)
    if isinstance(value, set):
        return tuple(sorted(_canonicalize(item) for item in value))
    if hasattr(value, "to_dict"):
        return _canonicalize(value.to_dict())
    return value


def _value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value
