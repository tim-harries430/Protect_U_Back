from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from transition_xray import TransitionXrayFrame, TransitionXrayPair


PRISON_ID = "xray_observation_prison:v0"
PRISON_SCOPE = "sealed_xray_observation_space"


class XrayPrisonAuthority(str, Enum):
    OBSERVE = "observe"
    SEAL = "seal"
    COMPARE = "compare"
    ATTACH_TESTIMONY = "attach_testimony"


FORBIDDEN_AUTHORITIES = (
    "allow",
    "commit",
    "decision",
    "execute",
    "grant",
    "io_executed",
    "kill",
    "mutate_ledger",
    "mutate_registry",
    "verdict",
)


@dataclass(frozen=True)
class XrayPrisonBoundary:
    prison_id: str = PRISON_ID
    scope: str = PRISON_SCOPE
    closed: bool = True
    same_rules_for_all: bool = True
    authorities: Sequence[XrayPrisonAuthority] = field(
        default_factory=lambda: (
            XrayPrisonAuthority.OBSERVE,
            XrayPrisonAuthority.SEAL,
            XrayPrisonAuthority.COMPARE,
            XrayPrisonAuthority.ATTACH_TESTIMONY,
        )
    )

    def __post_init__(self):
        object.__setattr__(
            self,
            "authorities",
            tuple(
                authority
                if isinstance(authority, XrayPrisonAuthority)
                else XrayPrisonAuthority(authority)
                for authority in self.authorities
            ),
        )

    @property
    def boundary_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    def permits(self, authority: str | XrayPrisonAuthority) -> bool:
        try:
            normalized = (
                authority
                if isinstance(authority, XrayPrisonAuthority)
                else XrayPrisonAuthority(str(authority))
            )
        except ValueError:
            return False
        return normalized in self.authorities

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "prison_id": self.prison_id,
            "scope": self.scope,
            "closed": self.closed,
            "same_rules_for_all": self.same_rules_for_all,
            "authorities": tuple(authority.value for authority in self.authorities),
        }
        if include_hash:
            payload["boundary_hash"] = self.boundary_hash
        return payload


@dataclass(frozen=True)
class XrayPrisonAdmission:
    boundary_hash: str
    phase: str
    action_id: str
    frame_hash: str
    field_id: str
    piece_keys: Sequence[str]
    piece_count: int
    sealed: bool = True

    def __post_init__(self):
        object.__setattr__(self, "piece_keys", tuple(sorted(set(self.piece_keys))))

    @property
    def admission_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "boundary_hash": self.boundary_hash,
            "phase": self.phase,
            "action_id": self.action_id,
            "frame_hash": self.frame_hash,
            "field_id": self.field_id,
            "piece_keys": self.piece_keys,
            "piece_count": self.piece_count,
            "sealed": self.sealed,
        }
        if include_hash:
            payload["admission_hash"] = self.admission_hash
        return payload


@dataclass(frozen=True)
class XrayPrisonCustody:
    boundary: XrayPrisonBoundary
    enter: XrayPrisonAdmission
    exit: XrayPrisonAdmission
    pair_hash: str
    mutation_state: str
    continuity_state: str
    witness_count: int
    testimony_only: bool = True
    sealed: bool = True

    @property
    def custody_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    @property
    def autopsy_basis_ready(self) -> bool:
        return self.witness_count > 0 or self.continuity_state != "CONTINUOUS"

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "boundary": self.boundary.to_dict(),
            "enter": self.enter.to_dict(),
            "exit": self.exit.to_dict(),
            "pair_hash": self.pair_hash,
            "mutation_state": self.mutation_state,
            "continuity_state": self.continuity_state,
            "witness_count": self.witness_count,
            "testimony_only": self.testimony_only,
            "sealed": self.sealed,
            "autopsy_basis_ready": self.autopsy_basis_ready,
        }
        if include_hash:
            payload["custody_hash"] = self.custody_hash
        return payload

    def to_evidence(self) -> tuple[str, ...]:
        return (
            f"xray_prison.id:{self.boundary.prison_id}",
            f"xray_prison.boundary_hash:{self.boundary.boundary_hash}",
            f"xray_prison.enter_admission_hash:{self.enter.admission_hash}",
            f"xray_prison.exit_admission_hash:{self.exit.admission_hash}",
            f"xray_prison.custody_hash:{self.custody_hash}",
            f"xray_prison.testimony_only:{str(self.testimony_only).lower()}",
            f"xray_prison.autopsy_basis_ready:{str(self.autopsy_basis_ready).lower()}",
        )


def admit_xray_frame(
    frame: TransitionXrayFrame,
    *,
    boundary: XrayPrisonBoundary | None = None,
) -> XrayPrisonAdmission:
    boundary = boundary or XrayPrisonBoundary()
    return XrayPrisonAdmission(
        boundary_hash=boundary.boundary_hash,
        phase=frame.phase.value,
        action_id=frame.action_id,
        frame_hash=frame.frame_hash,
        field_id=frame.field_id,
        piece_keys=tuple(piece.key for piece in frame.pieces),
        piece_count=len(frame.pieces),
    )


def seal_xray_pair(
    pair: TransitionXrayPair,
    *,
    boundary: XrayPrisonBoundary | None = None,
) -> XrayPrisonCustody:
    boundary = boundary or XrayPrisonBoundary()
    return XrayPrisonCustody(
        boundary=boundary,
        enter=admit_xray_frame(pair.enter, boundary=boundary),
        exit=admit_xray_frame(pair.exit, boundary=boundary),
        pair_hash=pair.pair_hash,
        mutation_state=pair.mutation_state.value,
        continuity_state=pair.continuity_state.value,
        witness_count=len(pair.findings),
    )


def leaks_forbidden_authority(payload: Mapping[str, Any]) -> bool:
    return _contains_forbidden_authority(_canonicalize(payload))


def _contains_forbidden_authority(value: Any) -> bool:
    forbidden = set(FORBIDDEN_AUTHORITIES)
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized_key = str(key).lower()
            if normalized_key in forbidden:
                return True
            if _contains_forbidden_authority(child):
                return True
        return False
    if isinstance(value, (list, tuple, set)):
        return any(_contains_forbidden_authority(child) for child in value)
    if isinstance(value, str):
        return value.lower() in forbidden
    return False


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
