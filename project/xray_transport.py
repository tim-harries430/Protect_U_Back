from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from ot_gate import CommandProposal
from transition_xray import (
    DEFAULT_MAX_HASH_BYTES,
    TransitionXrayFrame,
    build_transition_access_witness,
    compare_transition_xray,
    scan_transition_xray,
    transition_access_witness_evidence,
)
from xray_field import XrayFieldComparison, sample_xray_potential_pair
from xray_prison import XrayPrisonBoundary, XrayPrisonCustody, admit_xray_frame, seal_xray_pair


TRANSPORT_ID = "sealed_xray_transport:v0"
TRANSPORT_AUTHORITY = "observe_seal_attach_only"


@dataclass(frozen=True)
class XrayTransportHandle:
    proposal_id: str
    boundary: XrayPrisonBoundary
    enter_frame: TransitionXrayFrame
    transport_id: str = TRANSPORT_ID
    authority: str = TRANSPORT_AUTHORITY
    sealed: bool = True
    testimony_only: bool = True

    @property
    def boundary_hash(self) -> str:
        return self.boundary.boundary_hash

    @property
    def enter_frame_hash(self) -> str:
        return self.enter_frame.frame_hash

    @property
    def enter_admission_hash(self) -> str:
        return admit_xray_frame(self.enter_frame, boundary=self.boundary).admission_hash

    @property
    def handle_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "transport_id": self.transport_id,
            "proposal_id": self.proposal_id,
            "boundary_hash": self.boundary_hash,
            "enter_frame_hash": self.enter_frame_hash,
            "enter_admission_hash": self.enter_admission_hash,
            "authority": self.authority,
            "sealed": self.sealed,
            "testimony_only": self.testimony_only,
            "route": "main_process_pre_admission",
        }
        if include_hash:
            payload["handle_hash"] = self.handle_hash
        return payload


@dataclass(frozen=True)
class XrayTransportSeal:
    proposal_id: str
    custody: XrayPrisonCustody
    field: XrayFieldComparison
    transition_evidence: Sequence[str] = field(default_factory=tuple)
    access_witness: Mapping[str, Any] = field(default_factory=dict)
    transport_id: str = TRANSPORT_ID
    authority: str = TRANSPORT_AUTHORITY
    sealed: bool = True
    testimony_only: bool = True
    # True iff every mutation finding is exactly what the proposal DECLARED it would
    # do (a write/delete changing its declared targets = the job, not a substitution).
    # Read by xray_review.seal_disguise to stop a benign write from quarantining
    # itself. Deliberately NOT serialised into to_dict/to_evidence, so transport_hash
    # is unchanged. Default False = conservative (treat as before) when uncomputed.
    expected_mutation: bool = False

    def __post_init__(self):
        object.__setattr__(
            self,
            "transition_evidence",
            tuple(str(item) for item in self.transition_evidence),
        )
        object.__setattr__(self, "access_witness", dict(self.access_witness))

    @property
    def boundary_hash(self) -> str:
        return self.custody.boundary.boundary_hash

    @property
    def pair_hash(self) -> str:
        return self.custody.pair_hash

    @property
    def mutation_state(self) -> str:
        return self.custody.mutation_state

    @property
    def continuity_state(self) -> str:
        return self.custody.continuity_state

    @property
    def witness_count(self) -> int:
        return self.custody.witness_count

    @property
    def field_state(self) -> str:
        return self.field.state.value

    @property
    def field_hash(self) -> str:
        return self.field.field_hash

    @property
    def transport_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "transport_id": self.transport_id,
            "proposal_id": self.proposal_id,
            "boundary_hash": self.boundary_hash,
            "pair_hash": self.pair_hash,
            "mutation_state": self.mutation_state,
            "continuity_state": self.continuity_state,
            "witness_count": self.witness_count,
            "field_state": self.field_state,
            "field_hash": self.field_hash,
            "authority": self.authority,
            "sealed": self.sealed,
            "testimony_only": self.testimony_only,
            "route": "main_process_observation_channel",
            "custody": self.custody.to_dict(),
            "field": self.field.to_dict(),
            "access_witness": dict(self.access_witness),
            "evidence": self.to_evidence(include_hash=False),
        }
        if include_hash:
            payload["transport_hash"] = self.transport_hash
        return payload

    def to_evidence(self, *, include_hash: bool = True) -> tuple[str, ...]:
        evidence = (
            f"xray_transport.id:{self.transport_id}",
            f"xray_transport.boundary_hash:{self.boundary_hash}",
            f"xray_transport.pair_hash:{self.pair_hash}",
            f"xray_transport.mutation_state:{self.mutation_state}",
            f"xray_transport.continuity_state:{self.continuity_state}",
            f"xray_transport.witness_count:{self.witness_count}",
            f"xray_transport.field_state:{self.field_state}",
            f"xray_transport.testimony_only:{str(self.testimony_only).lower()}",
            f"xray_transport.sealed:{str(self.sealed).lower()}",
        )
        if include_hash:
            evidence = evidence + (f"xray_transport.transport_hash:{self.transport_hash}",)
        return (
            evidence
            + tuple(self.transition_evidence)
            + transition_access_witness_evidence(self.access_witness)
            + tuple(self.custody.to_evidence())
            + tuple(self.field.to_evidence())
        )


def open_xray_transport(
    proposal: CommandProposal,
    *,
    boundary: XrayPrisonBoundary | None = None,
    max_file_bytes: int = DEFAULT_MAX_HASH_BYTES,
) -> XrayTransportHandle:
    boundary = boundary or XrayPrisonBoundary()
    return XrayTransportHandle(
        proposal_id=proposal.proposal_id,
        boundary=boundary,
        enter_frame=scan_transition_xray(
            proposal,
            phase="enter",
            max_file_bytes=max_file_bytes,
        ),
    )


# A mutating effect (write/delete) DECLARED by the proposal vouches for the
# transition's content findings: the targets changing IS the job. A delete shows up
# as HASH_MUTATED (the hash goes to a missing sentinel), not a distinct DELETED
# finding, so we do NOT match finding type to effect -- declaring ANY mutating effect
# is enough. ACTION_ID_MISMATCH (a torn observation window) is never vouched. A
# declared-READ op that mutated has no mutating effect -> unexpected -> the seal still
# quarantines. Identity swaps (pointer/alias/container-escape) ride a SEPARATE review
# axis (single_frame_disguise on the enter frame), unaffected by this.
_MUTATING_EFFECTS = frozenset({"write", "delete"})


def _mutation_is_declared(pair: Any, proposal: CommandProposal) -> bool:
    findings = tuple(getattr(pair, "findings", ()) or ())
    if not findings:
        return False
    if any(
        str(getattr(finding, "finding_type", "")) == "ACTION_ID_MISMATCH"
        for finding in findings
    ):
        return False
    declared = {
        str(getattr(effect, "value", effect)).lower()
        for effect in getattr(proposal, "expected_side_effects", ()) or ()
    }
    return bool(declared & _MUTATING_EFFECTS)


def close_xray_transport(
    handle: XrayTransportHandle,
    proposal: CommandProposal,
    *,
    max_file_bytes: int = DEFAULT_MAX_HASH_BYTES,
) -> XrayTransportSeal:
    exit_frame = scan_transition_xray(
        proposal,
        phase="exit",
        max_file_bytes=max_file_bytes,
    )
    pair = compare_transition_xray(handle.enter_frame, exit_frame)
    custody = seal_xray_pair(pair, boundary=handle.boundary)
    field = sample_xray_potential_pair(pair, boundary=handle.boundary)
    access_witness = build_transition_access_witness(pair, proposal)
    return XrayTransportSeal(
        proposal_id=handle.proposal_id,
        custody=custody,
        field=field,
        transition_evidence=pair.to_evidence(),
        access_witness=access_witness,
        expected_mutation=_mutation_is_declared(pair, proposal),
    )


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
    if isinstance(value, Mapping):
        return {str(key): _canonicalize(child) for key, child in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return tuple(_canonicalize(item) for item in value)
    if isinstance(value, set):
        return tuple(sorted(_canonicalize(item) for item in value))
    if hasattr(value, "to_dict"):
        return _canonicalize(value.to_dict())
    return value
