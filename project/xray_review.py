from __future__ import annotations

import dataclasses
import enum
from typing import Any, Mapping, Sequence

from ot_gate import CommandProposal
from parallel_audit import (
    EvidenceDisposition,
    EvidenceStage,
    EvidenceTestimony,
    ParallelAuditDecision,
    run_parallel_audit,
)
from transition_xray import (
    DEFAULT_MAX_HASH_BYTES,
    TransitionXrayFrame,
    XrayPiece,
    hash_unavailable,
    scan_transition_xray,
)
from xray_field import XrayFieldObservation, sample_xray_potential_field
from xray_transport import XrayTransportSeal


class DisguiseAxis(str, enum.Enum):
    POINTER = "POINTER"
    ALIAS = "ALIAS"
    CONTAINER_ESCAPE = "CONTAINER_ESCAPE"
    SENSITIVE_SURFACE = "SENSITIVE_SURFACE"
    OBSERVATION_BLINDSPOT = "OBSERVATION_BLINDSPOT"
    RESPONSIBILITY_GAP = "RESPONSIBILITY_GAP"
    SUBSTITUTION = "SUBSTITUTION"


class ReviewDisposition(str, enum.Enum):
    PASS = "PASS"
    HOLD = "HOLD"
    QUARANTINE = "QUARANTINE"


_AXIS_SEVERITY: dict[DisguiseAxis, ReviewDisposition] = {
    DisguiseAxis.POINTER: ReviewDisposition.QUARANTINE,
    DisguiseAxis.ALIAS: ReviewDisposition.QUARANTINE,
    DisguiseAxis.CONTAINER_ESCAPE: ReviewDisposition.QUARANTINE,
    DisguiseAxis.SUBSTITUTION: ReviewDisposition.QUARANTINE,
    DisguiseAxis.SENSITIVE_SURFACE: ReviewDisposition.HOLD,
    DisguiseAxis.OBSERVATION_BLINDSPOT: ReviewDisposition.HOLD,
    DisguiseAxis.RESPONSIBILITY_GAP: ReviewDisposition.HOLD,
}

_AXIS_EMIT_ORDER: tuple[DisguiseAxis, ...] = (
    DisguiseAxis.POINTER,
    DisguiseAxis.ALIAS,
    DisguiseAxis.CONTAINER_ESCAPE,
    DisguiseAxis.SENSITIVE_SURFACE,
    DisguiseAxis.OBSERVATION_BLINDSPOT,
    DisguiseAxis.RESPONSIBILITY_GAP,
    DisguiseAxis.SUBSTITUTION,
)

_REVIEW_RANK: dict[ReviewDisposition, int] = {
    ReviewDisposition.PASS: 0,
    ReviewDisposition.HOLD: 1,
    ReviewDisposition.QUARANTINE: 2,
}

_EVIDENCE_RANK: dict[EvidenceDisposition, int] = {
    EvidenceDisposition.PASS: 0,
    EvidenceDisposition.HOLD: 1,
    EvidenceDisposition.QUARANTINE: 2,
    EvidenceDisposition.KILL: 3,
    EvidenceDisposition.REJECT: 3,
}

_REVIEW_TO_EVIDENCE: dict[ReviewDisposition, EvidenceDisposition] = {
    ReviewDisposition.PASS: EvidenceDisposition.PASS,
    ReviewDisposition.HOLD: EvidenceDisposition.HOLD,
    ReviewDisposition.QUARANTINE: EvidenceDisposition.QUARANTINE,
}

_RESPONSIBILITY_GAP_STATES = frozenset({"required_but_missing", "trace_present_no_id"})


@dataclasses.dataclass(frozen=True)
class DisguiseSignal:
    axis: DisguiseAxis
    piece_key: str
    severity: ReviewDisposition
    detail: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "axis": self.axis.value,
            "piece_key": self.piece_key,
            "severity": self.severity.value,
            "detail": self.detail,
            "evidence": list(self.evidence),
        }


@dataclasses.dataclass(frozen=True)
class XrayReview:
    requires_review: bool
    disposition: ReviewDisposition
    reason_code: str
    signals: tuple[DisguiseSignal, ...] = ()

    def to_dict(self) -> dict:
        return {
            "requires_review": self.requires_review,
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "signals": [signal.to_dict() for signal in self.signals],
        }


def single_frame_disguise(frame: TransitionXrayFrame) -> tuple[DisguiseSignal, ...]:
    signals: list[DisguiseSignal] = []
    pieces = sorted(
        (piece for piece in frame.pieces if piece.kind != "decision"),
        key=lambda piece: piece.key,
    )
    for piece in pieces:
        signals.extend(_piece_signals(piece))
    return tuple(signals)


def seal_disguise(seal: XrayTransportSeal | None) -> tuple[DisguiseSignal, ...]:
    if seal is None:
        return ()
    if not _seal_suspicious(seal):
        return ()
    evidence = (
        f"continuity_state:{seal.continuity_state}",
        f"field_state:{seal.field_state}",
        f"mutation_state:{seal.mutation_state}",
        f"witness_count:{seal.witness_count}",
    )
    return (
        DisguiseSignal(
            axis=DisguiseAxis.SUBSTITUTION,
            piece_key=f"xray_transport:{seal.proposal_id}",
            severity=ReviewDisposition.QUARANTINE,
            detail="sealed transport reports non-stable mutation/continuity/field state",
            evidence=evidence,
        ),
    )


def review_from_frame(
    frame: TransitionXrayFrame,
    *,
    seal: XrayTransportSeal | None = None,
) -> XrayReview:
    signals = single_frame_disguise(frame)
    signals = signals + _field_blindspot_signals(frame, signals)
    signals = signals + seal_disguise(seal)
    return _review_from_signals(signals)


def review_proposal(
    proposal: CommandProposal,
    *,
    seal: XrayTransportSeal | None = None,
    max_file_bytes: int = DEFAULT_MAX_HASH_BYTES,
) -> XrayReview:
    frame = scan_transition_xray(
        proposal,
        phase="enter",
        max_file_bytes=max_file_bytes,
    )
    return review_from_frame(frame, seal=seal)


def escalate_decision(
    decision: ParallelAuditDecision,
    review: XrayReview,
) -> ParallelAuditDecision:
    base_rank = _EVIDENCE_RANK[decision.disposition]
    review_rank = _REVIEW_RANK[review.disposition]
    final_rank = max(base_rank, review_rank)
    if final_rank == base_rank:
        return decision

    escalated = _REVIEW_TO_EVIDENCE[review.disposition]
    if escalated == EvidenceDisposition.PASS:
        return decision

    testimony = EvidenceTestimony(
        stage=EvidenceStage.AGGREGATOR,
        disposition=escalated,
        reason_code=review.reason_code,
        detail="X-ray review escalation: single-frame disguise detected post-aggregation.",
        evidence=_review_evidence(review),
        metadata={
            "overlay": "xray_review",
            "review_disposition": review.disposition.value,
            "axes": tuple(sorted({signal.axis.value for signal in review.signals})),
        },
    )
    return dataclasses.replace(
        decision,
        disposition=escalated,
        reason_code=review.reason_code,
        primary_stage=EvidenceStage.AGGREGATOR,
        testimonies=tuple(decision.testimonies) + (testimony,),
    )


def audit_with_xray_review(
    action: Any,
    *,
    registry: Any,
    project_root: Any,
    protect_profile: Any,
    **run_kwargs: Any,
) -> ParallelAuditDecision:
    base = run_parallel_audit(
        action,
        registry=registry,
        project_root=project_root,
        protect_profile=protect_profile,
        **run_kwargs,
    )
    proposal = (
        base.evidence_bundle.proposal
        if base.evidence_bundle is not None
        else None
    )
    if proposal is not None:
        review = review_proposal(proposal, seal=base.xray_transport)
    else:
        review = _review_from_signals(seal_disguise(base.xray_transport))
    return escalate_decision(base, review)


def _piece_signals(piece: XrayPiece) -> tuple[DisguiseSignal, ...]:
    matched: dict[DisguiseAxis, DisguiseSignal] = {}
    details = piece.details if isinstance(piece.details, Mapping) else {}

    if piece.type == "symlink" or details.get("symlink_target"):
        target = details.get("symlink_target")
        matched[DisguiseAxis.POINTER] = _signal(
            DisguiseAxis.POINTER,
            piece,
            "symlink pointer bait: target path may not match observed surface",
            (f"symlink_target:{target}",) if target is not None else (),
        )

    nlink = details.get("nlink")
    if isinstance(nlink, int) and not isinstance(nlink, bool) and nlink > 1:
        matched[DisguiseAxis.ALIAS] = _signal(
            DisguiseAxis.ALIAS,
            piece,
            "hardlink alias: multiple names reference the same inode",
            (f"nlink:{nlink}",),
        )

    escapes = details.get("archive_escape_entries")
    if _non_empty_sequence(escapes):
        matched[DisguiseAxis.CONTAINER_ESCAPE] = _signal(
            DisguiseAxis.CONTAINER_ESCAPE,
            piece,
            "container escape: archive entries traverse outside extraction root",
            tuple(f"escape:{entry}" for entry in sorted(str(item) for item in escapes)),
        )

    tags = details.get("xray_tags")
    if isinstance(tags, (list, tuple)) and "sensitive_marker" in tuple(
        str(tag) for tag in tags
    ):
        matched[DisguiseAxis.SENSITIVE_SURFACE] = _signal(
            DisguiseAxis.SENSITIVE_SURFACE,
            piece,
            "sensitive surface: target references a protected marker",
            ("sensitive_marker",),
        )

    if _piece_blindspot(piece, details):
        if piece.kind == "registered_action" and details.get("effect_modellable") is False:
            blindspot_detail = (
                "observation blindspot: turing-complete payload, effect not "
                "modellable from command surface (Rice)"
            )
        else:
            blindspot_detail = (
                "observation blindspot: content or existence could not be sealed"
            )
        matched[DisguiseAxis.OBSERVATION_BLINDSPOT] = _signal(
            DisguiseAxis.OBSERVATION_BLINDSPOT,
            piece,
            blindspot_detail,
            _blindspot_evidence(piece, details),
        )

    if piece.kind == "skill_responsibility":
        state = str(details.get("state", ""))
        if state in _RESPONSIBILITY_GAP_STATES:
            matched[DisguiseAxis.RESPONSIBILITY_GAP] = _signal(
                DisguiseAxis.RESPONSIBILITY_GAP,
                piece,
                "responsibility gap: declared skill responsibility is unbound",
                (f"state:{state}",),
            )

    return tuple(matched[axis] for axis in _AXIS_EMIT_ORDER if axis in matched)


def _field_blindspot_signals(
    frame: TransitionXrayFrame,
    existing: Sequence[DisguiseSignal],
) -> tuple[DisguiseSignal, ...]:
    if any(signal.axis == DisguiseAxis.OBSERVATION_BLINDSPOT for signal in existing):
        return ()
    field = sample_xray_potential_field(frame)
    if field.observation != XrayFieldObservation.UNKNOWN:
        return ()
    return (
        DisguiseSignal(
            axis=DisguiseAxis.OBSERVATION_BLINDSPOT,
            piece_key=f"xray_field:{frame.action_id}",
            severity=ReviewDisposition.HOLD,
            detail="observation blindspot: scalar potential field reports UNKNOWN",
            evidence=(
                f"u_total:{field.u_total}",
                f"unknown_count:{field.unknown_count}",
            ),
        ),
    )


def _piece_blindspot(piece: XrayPiece, details: Mapping[str, Any]) -> bool:
    if piece.exists is None:
        return True
    if (
        piece.kind == "target_path"
        and piece.exists is True
        and piece.sha256 is None
    ):
        return True
    if hash_unavailable(details):
        return True
    # A registered action whose payload is a Turing-complete interpreter
    # invocation: bytes are hashable, effect is not. Undecidable from surface,
    # so it is a blindspot -- the box is sealed even though we can hash it.
    if piece.kind == "registered_action" and details.get("effect_modellable") is False:
        return True
    return False


def _blindspot_evidence(
    piece: XrayPiece,
    details: Mapping[str, Any],
) -> tuple[str, ...]:
    evidence: list[str] = []
    if piece.exists is None:
        evidence.append("exists:None")
    if (
        piece.kind == "target_path"
        and piece.exists is True
        and piece.sha256 is None
    ):
        evidence.append("sha256:None")
    if hash_unavailable(details):
        evidence.append(f"hash_status:{details.get('hash_status')}")
    if piece.kind == "registered_action" and details.get("effect_modellable") is False:
        evidence.append("effect_modellable:False")
        marker = details.get("opaque_executor")
        if marker:
            evidence.append(f"opaque_executor:{marker}")
    return tuple(sorted(evidence))


def _seal_suspicious(seal: XrayTransportSeal) -> bool:
    return (
        seal.mutation_state != "STABLE"
        or seal.continuity_state != "CONTINUOUS"
        or seal.witness_count > 0
        or seal.field_state != "STABLE"
    )


def _signal(
    axis: DisguiseAxis,
    piece: XrayPiece,
    detail: str,
    evidence: tuple[str, ...],
) -> DisguiseSignal:
    return DisguiseSignal(
        axis=axis,
        piece_key=piece.key,
        severity=_AXIS_SEVERITY[axis],
        detail=detail,
        evidence=tuple(evidence),
    )


def _review_from_signals(signals: Sequence[DisguiseSignal]) -> XrayReview:
    signals = tuple(signals)
    if not signals:
        return XrayReview(
            requires_review=False,
            disposition=ReviewDisposition.PASS,
            reason_code="XRAY_CLEAR",
            signals=(),
        )
    dominant = max(signals, key=lambda signal: _REVIEW_RANK[signal.severity])
    disposition = dominant.severity
    reason_code = f"XRAY_REVIEW_{dominant.axis.value}"
    return XrayReview(
        requires_review=True,
        disposition=disposition,
        reason_code=reason_code,
        signals=signals,
    )


def _review_evidence(review: XrayReview) -> tuple[str, ...]:
    evidence: list[str] = []
    for signal in review.signals:
        evidence.append(f"{signal.axis.value}:{signal.piece_key}:{signal.severity.value}")
        evidence.extend(signal.evidence)
    return tuple(evidence)


def _non_empty_sequence(value: Any) -> bool:
    if value is None or isinstance(value, (str, bytes, Mapping)):
        return False
    try:
        return len(value) > 0
    except TypeError:
        return False
