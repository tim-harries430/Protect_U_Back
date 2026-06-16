from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from transition_xray import TransitionXrayFrame, TransitionXrayPair, XrayPiece, hash_unavailable
from xray_prison import PRISON_ID, XrayPrisonBoundary


FIELD_ID = "u_xray_scalar_potential:v0"
FIELD_AUTHORITY = "observe_field_only"
TESTIMONY_UNKNOWN = "unknown_observed"
TESTIMONY_DISTORTED = "field_distortion_observed"
TESTIMONY_STABLE = "field_stable"
FIELD_DENYLIST_KEYS = {
    "actor_id",
    "admin",
    "admitted",
    "allow",
    "approval",
    "approved",
    "authorization",
    "authorized",
    "can_execute",
    "can_grant_permission",
    "capability_grant",
    "certificate",
    "commit",
    "decision",
    "disposition",
    "execute",
    "final_decision",
    "grant",
    "io_executed",
    "kill",
    "mutate_ledger",
    "mutate_registry",
    "permission_level",
    "privilege",
    "role",
    "root",
    "raw_payload_sha256",
    "set_actor_state",
    "trust",
    "trust_level",
    "trusted",
    "trusted_admin_override",
    "user_root",
    "verdict",
}


class XrayFieldObservation(str, Enum):
    OBSERVED = "OBSERVED"
    UNKNOWN = "UNKNOWN"


class XrayFieldState(str, Enum):
    STABLE = "STABLE"
    DISTORTED = "DISTORTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class XrayPotentialSample:
    node_key: str
    node_kind: str
    state_hash: str
    u_value: float
    contributors: Mapping[str, float] = field(default_factory=dict)
    observation: XrayFieldObservation = XrayFieldObservation.OBSERVED
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        observation = (
            self.observation
            if isinstance(self.observation, XrayFieldObservation)
            else XrayFieldObservation(self.observation)
        )
        object.__setattr__(self, "observation", observation)
        object.__setattr__(self, "u_value", round(float(self.u_value), 6))
        object.__setattr__(
            self,
            "contributors",
            {
                str(key): round(float(value), 6)
                for key, value in sorted(self.contributors.items())
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_key": self.node_key,
            "node_kind": self.node_kind,
            "state_hash": self.state_hash,
            "u_value": self.u_value,
            "contributors": dict(self.contributors),
            "observation": self.observation.value,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class XrayPotentialField:
    prison_id: str
    field_id: str
    boundary_hash: str
    envelope_id: str
    phase: str
    samples: Sequence[XrayPotentialSample]
    authority: str = FIELD_AUTHORITY
    scalar_only: bool = True
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(
            self,
            "samples",
            tuple(sorted(self.samples, key=lambda sample: sample.node_key)),
        )

    @property
    def sample_count(self) -> int:
        return len(self.samples)

    @property
    def unknown_count(self) -> int:
        return sum(
            1
            for sample in self.samples
            if sample.observation == XrayFieldObservation.UNKNOWN
        )

    @property
    def observation(self) -> XrayFieldObservation:
        if self.unknown_count or not self.samples:
            return XrayFieldObservation.UNKNOWN
        return XrayFieldObservation.OBSERVED

    @property
    def u_total(self) -> float:
        return round(sum(sample.u_value for sample in self.samples), 6)

    @property
    def u_mean(self) -> float:
        if not self.samples:
            return 0.0
        return round(self.u_total / len(self.samples), 6)

    @property
    def field_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "prison_id": self.prison_id,
            "field_id": self.field_id,
            "boundary_hash": self.boundary_hash,
            "envelope_id": self.envelope_id,
            "phase": self.phase,
            "sample_count": self.sample_count,
            "unknown_count": self.unknown_count,
            "observation": self.observation.value,
            "u_total": self.u_total,
            "u_mean": self.u_mean,
            "samples": tuple(sample.to_dict() for sample in self.samples),
            "authority": self.authority,
            "scalar_only": self.scalar_only,
            "details": dict(self.details),
        }
        if include_hash:
            payload["field_hash"] = self.field_hash
        return payload

    def to_evidence(self) -> tuple[str, ...]:
        return (
            f"xray_field.id:{self.field_id}",
            f"xray_field.envelope_id:{self.envelope_id}",
            f"xray_field.phase:{self.phase}",
            f"xray_field.observation:{self.observation.value}",
            f"xray_field.u_total:{self.u_total:.6f}",
            f"xray_field.unknown_count:{self.unknown_count}",
            f"xray_field.field_hash:{self.field_hash}",
            f"xray_field.authority:{self.authority}",
            f"xray_field.scalar_only:{str(self.scalar_only).lower()}",
        )


@dataclass(frozen=True)
class XrayFieldComparison:
    enter: XrayPotentialField
    exit: XrayPotentialField
    field_shift: float
    field_shift_abs: float
    distorted_nodes: Sequence[str]
    state: XrayFieldState
    testimony_note: str
    testimony_only: bool = True
    authority: str = FIELD_AUTHORITY

    def __post_init__(self):
        state = (
            self.state
            if isinstance(self.state, XrayFieldState)
            else XrayFieldState(self.state)
        )
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "field_shift", round(float(self.field_shift), 6))
        object.__setattr__(
            self,
            "field_shift_abs",
            round(float(self.field_shift_abs), 6),
        )
        object.__setattr__(
            self,
            "distorted_nodes",
            tuple(sorted(set(self.distorted_nodes))),
        )

    @property
    def has_distortion(self) -> bool:
        return self.state != XrayFieldState.STABLE

    @property
    def field_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "enter": self.enter.to_dict(),
            "exit": self.exit.to_dict(),
            "field_shift": self.field_shift,
            "field_shift_abs": self.field_shift_abs,
            "distorted_nodes": self.distorted_nodes,
            "state": self.state.value,
            "testimony_note": self.testimony_note,
            "testimony_only": self.testimony_only,
            "authority": self.authority,
        }
        if include_hash:
            payload["field_hash"] = self.field_hash
        return payload

    def to_evidence(self) -> tuple[str, ...]:
        return (
            f"xray_field_pair.state:{self.state.value}",
            f"xray_field_pair.field_shift:{self.field_shift:.6f}",
            f"xray_field_pair.field_shift_abs:{self.field_shift_abs:.6f}",
            f"xray_field_pair.distorted_count:{len(self.distorted_nodes)}",
            f"xray_field_pair.testimony_note:{self.testimony_note}",
            f"xray_field_pair.testimony_only:{str(self.testimony_only).lower()}",
            f"xray_field_pair.field_hash:{self.field_hash}",
        )


def sample_xray_potential_field(
    frame: TransitionXrayFrame,
    *,
    boundary: XrayPrisonBoundary | None = None,
) -> XrayPotentialField:
    boundary = boundary or XrayPrisonBoundary()
    return XrayPotentialField(
        prison_id=PRISON_ID,
        field_id=FIELD_ID,
        boundary_hash=boundary.boundary_hash,
        envelope_id=frame.action_id,
        phase=frame.phase.value,
        samples=tuple(
            _sample_from_piece(piece)
            for piece in frame.pieces
            if piece.kind != "decision"
        ),
        details={
            "source": "transition_xray_frame",
            "frame_field_id": frame.field_id,
            "principle": "scalar_potential_observation_only",
        },
    )


def compare_xray_potential_fields(
    enter: XrayPotentialField,
    exit: XrayPotentialField,
) -> XrayFieldComparison:
    distorted_nodes = _distorted_nodes(enter, exit)
    field_shift = round(exit.u_total - enter.u_total, 6)
    has_unknown = (
        enter.observation == XrayFieldObservation.UNKNOWN
        or exit.observation == XrayFieldObservation.UNKNOWN
    )
    if has_unknown:
        state = XrayFieldState.UNKNOWN
        testimony_note = TESTIMONY_UNKNOWN
    elif distorted_nodes or field_shift != 0.0:
        state = XrayFieldState.DISTORTED
        testimony_note = TESTIMONY_DISTORTED
    else:
        state = XrayFieldState.STABLE
        testimony_note = TESTIMONY_STABLE
    return XrayFieldComparison(
        enter=enter,
        exit=exit,
        field_shift=field_shift,
        field_shift_abs=abs(field_shift),
        distorted_nodes=distorted_nodes,
        state=state,
        testimony_note=testimony_note,
    )


def sample_xray_potential_pair(
    pair: TransitionXrayPair,
    *,
    boundary: XrayPrisonBoundary | None = None,
) -> XrayFieldComparison:
    boundary = boundary or XrayPrisonBoundary()
    return compare_xray_potential_fields(
        sample_xray_potential_field(pair.enter, boundary=boundary),
        sample_xray_potential_field(pair.exit, boundary=boundary),
    )


def _sample_from_piece(piece: XrayPiece) -> XrayPotentialSample:
    state_hash = _field_state_hash(piece)
    contributors = _contributors(piece, state_hash=state_hash)
    observation = (
        XrayFieldObservation.UNKNOWN
        if _piece_observation_unknown(piece)
        else XrayFieldObservation.OBSERVED
    )
    return XrayPotentialSample(
        node_key=piece.key,
        node_kind=piece.kind,
        state_hash=state_hash,
        u_value=sum(contributors.values()),
        contributors=contributors,
        observation=observation,
        details={
            "piece_type": piece.type,
            "exists": piece.exists,
            "authority": FIELD_AUTHORITY,
        },
    )


def _contributors(piece: XrayPiece, *, state_hash: str) -> dict[str, float]:
    contributors: dict[str, float] = {
        "identity_pressure": round(_hash_unit(state_hash) * 0.05, 6),
        "piece_pressure": _stored_piece_pressure(piece),
    }
    tags = set(_stored_piece_tags(piece))
    if piece.exists is False:
        contributors["missing_surface"] = 0.25
    if piece.kind == "target_path" and piece.exists is True and piece.sha256 is None:
        contributors["unobserved_content"] = 0.6
    if hash_unavailable(piece.details):
        contributors[f"hash_{piece.details.get('hash_status')}"] = 0.8
    if piece.type == "symlink" or piece.details.get("symlink_target"):
        contributors["pointer_surface"] = 0.35
    if "sensitive_marker" in tags:
        contributors["sensitive_surface"] = 0.2
    if piece.kind == "skill_responsibility":
        state = str(piece.details.get("state", "unknown"))
        if state in {"trace_present_no_id", "required_but_missing"}:
            contributors["responsibility_blindness"] = 0.7
        if piece.details.get("authority_claims"):
            contributors["authority_claim_pressure"] = 0.2
    return {
        key: round(value, 6)
        for key, value in contributors.items()
        if value != 0.0
    }


def _piece_observation_unknown(piece: XrayPiece) -> bool:
    if piece.exists is None:
        return True
    if piece.kind == "target_path" and piece.exists is True and piece.sha256 is None:
        return True
    if hash_unavailable(piece.details):
        return True
    if piece.kind == "skill_responsibility":
        return str(piece.details.get("state", "unknown")) in {
            "trace_present_no_id",
            "required_but_missing",
        }
    return False


def _field_state_hash(piece: XrayPiece) -> str:
    redacted_details = _redact_field_details(piece.details)
    payload = {
        "kind": piece.kind,
        "ref": piece.ref,
        "exists": piece.exists,
        "type": piece.type,
        "size": piece.size,
        "sha256": _field_sha256(piece, redacted_details),
        "details": redacted_details,
    }
    return _sha256_canonical(payload)


def _field_sha256(piece: XrayPiece, redacted_details: Any) -> str | None:
    if piece.kind in {"registered_action", "skill_responsibility"}:
        return _sha256_canonical(redacted_details)
    return piece.sha256


def _redact_field_details(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted = {}
        for key, child in sorted(value.items()):
            normalized = str(key).lower()
            if normalized in FIELD_DENYLIST_KEYS or _contains_denied_token(normalized):
                continue
            redacted[str(key)] = _redact_field_details(child)
        return redacted
    if isinstance(value, (list, tuple)):
        return tuple(_redact_field_details(item) for item in value)
    if isinstance(value, set):
        return tuple(sorted(_redact_field_details(item) for item in value))
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in FIELD_DENYLIST_KEYS:
            return "<redacted>"
    return value


def _contains_denied_token(value: str) -> bool:
    return any(token in value for token in ("trust", "privilege", "admin"))


def _distorted_nodes(
    enter: XrayPotentialField,
    exit: XrayPotentialField,
) -> tuple[str, ...]:
    enter_map = {sample.node_key: sample for sample in enter.samples}
    exit_map = {sample.node_key: sample for sample in exit.samples}
    distorted = []
    for key in sorted(set(enter_map) | set(exit_map)):
        before = enter_map.get(key)
        after = exit_map.get(key)
        if before is None or after is None:
            distorted.append(key)
            continue
        if before.state_hash != after.state_hash:
            distorted.append(key)
    return tuple(distorted)


def _stored_piece_pressure(piece: XrayPiece) -> float:
    value = piece.details.get("piece_pressure")
    if isinstance(value, (int, float)):
        return round(float(value), 6)
    return 0.0


def _stored_piece_tags(piece: XrayPiece) -> tuple[str, ...]:
    value = piece.details.get("xray_tags")
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return ()


def _hash_unit(value: str) -> float:
    digest = value.split(":", 1)[-1]
    try:
        number = int(digest[:12], 16)
    except ValueError:
        number = 0
    return number / float(0xFFFFFFFFFFFF)


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
