from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Optional, Sequence

from capability_wall import CapabilityDecision, CapabilityDisposition
from event_ledger import AuditEvent
from ot_gate import (
    CommandProposal,
    ExecutionDecision,
    JudgeTestimony,
    JudgeVote,
    OTGateResult,
)
from phi_registry import ActorState, PhiRegistry


class AutopsyKind(str, Enum):
    KILL = "KILL"
    BUGCHECK = "BUGCHECK"
    HOLD_NOTE = "HOLD_NOTE"


class DeathStage(str, Enum):
    IDENTITY_CHECK = "IDENTITY_CHECK"
    LAYER_INTEGRITY = "LAYER_INTEGRITY"
    CAPABILITY_BOUNDARY = "CAPABILITY_BOUNDARY"
    MOTION_AUDIT = "MOTION_AUDIT"
    COMMIT_GATE = "COMMIT_GATE"
    REGISTRY_PROTECTION = "REGISTRY_PROTECTION"
    ACTOR_STATE_ESCALATION = "ACTOR_STATE_ESCALATION"


class LayerHint(str, Enum):
    SOURCE_LAYER = "SOURCE_LAYER"
    MOTION_LAYER = "MOTION_LAYER"
    COMMIT_LAYER = "COMMIT_LAYER"
    AUTOPSY_LAYER = "AUTOPSY_LAYER"


@dataclass(frozen=True)
class AutopsyTimelineEntry:
    step: int
    stage: str
    event: str
    outcome: str
    reason_code: Optional[str] = None
    timestamp_utc: Optional[str] = None
    evidence: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "stage": self.stage,
            "event": self.event,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "timestamp_utc": self.timestamp_utc,
            "evidence": tuple(self.evidence),
        }


@dataclass(frozen=True)
class AutopsyCause:
    judge: str
    vote: str
    reason_code: str
    critical: bool
    stage: DeathStage
    layer_hint: LayerHint
    detail: str
    evidence: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "judge": self.judge,
            "vote": self.vote,
            "reason_code": self.reason_code,
            "critical": self.critical,
            "stage": self.stage.value,
            "layer_hint": self.layer_hint.value,
            "detail": self.detail,
            "evidence": tuple(self.evidence),
        }


@dataclass(frozen=True)
class AutopsyReport:
    """
    Read-only stop explanation.

    autopsy_seed is a report fingerprint, not an incident seed. It hashes the
    canonical report snapshot, including timestamp_utc, so any important report
    field change produces a different fingerprint.
    """

    report_id: str
    timestamp_utc: str
    proposal_id: str
    actor_id: str
    source_adapter: str
    tool_name: str
    action_type: str
    kind: AutopsyKind
    final_decision: str
    death_stage: DeathStage
    death_reason: str
    autopsy_seed: str
    primary_cause: AutopsyCause
    contributing_causes: Sequence[AutopsyCause]
    touched_objects: Sequence[str]
    permission_level: str
    critical: bool
    kill_votes: int
    hold_votes: int
    registry_state_before: Optional[str]
    registry_state_after: Optional[str]
    ledger_event_id: Optional[str]
    replay_trace: Sequence[str]
    timeline: Sequence[AutopsyTimelineEntry] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "timestamp_utc": self.timestamp_utc,
            "proposal_id": self.proposal_id,
            "actor_id": self.actor_id,
            "source_adapter": self.source_adapter,
            "tool_name": self.tool_name,
            "action_type": self.action_type,
            "kind": self.kind.value,
            "final_decision": self.final_decision,
            "death_stage": self.death_stage.value,
            "death_reason": self.death_reason,
            "autopsy_seed": self.autopsy_seed,
            "primary_cause": self.primary_cause.to_dict(),
            "contributing_causes": tuple(
                cause.to_dict() for cause in self.contributing_causes
            ),
            "touched_objects": tuple(self.touched_objects),
            "permission_level": self.permission_level,
            "critical": self.critical,
            "kill_votes": self.kill_votes,
            "hold_votes": self.hold_votes,
            "registry_state_before": self.registry_state_before,
            "registry_state_after": self.registry_state_after,
            "ledger_event_id": self.ledger_event_id,
            "replay_trace": tuple(self.replay_trace),
            "timeline": tuple(entry.to_dict() for entry in self.timeline),
        }


IDENTITY_REASONS = {
    "MISSING_ACTOR_ID",
    "UNKNOWN_ACTOR",
    "MISSING_PROVENANCE",
}

ACTOR_STATE_REASONS = {
    "ACTOR_FROZEN",
    "PHI_BUGCHECK_ACTIVE",
}

REGISTRY_PROTECTION_REASONS = {
    "CRITICAL_PROTECTED_PHI_WRITE",
    "CRITICAL_REGISTRY_READ",
    "PROTECTED_LEDGER_READ_REQUIRES_APPROVAL",
    "PROTECTED_PHI_READ_REQUIRES_APPROVAL",
}

MOTION_REASONS = {
    "SCOPE_MISMATCH_SIDE_EFFECT",
    "PROJECT_SCOPE_ESCAPE",
    "INTENT_PRIVILEGE_OR_SECRET_ESCAPE",
}

LAYER_INTEGRITY_REASONS = {
    "TOOL_POISONING_DETECTED",
    "REJECTED_STATE_POLLUTION",
    "LAYER_AUTHORITY_VIOLATION",
}


def build_autopsy_report(
    proposal: CommandProposal,
    result: OTGateResult,
    *,
    ledger_event: Optional[AuditEvent] = None,
    registry: Optional[PhiRegistry] = None,
    registry_state_before: Optional[ActorState | str] = None,
    timestamp_utc: Optional[str] = None,
    transition_xray: Optional[Any] = None,
) -> AutopsyReport:
    """
    Builds a deterministic explanation for a blocked proposal.

    This function is read-only. It does not execute I/O, mutate the ledger, or
    change registry state. ALLOW decisions have no corpse and therefore do not
    produce an autopsy report.
    """

    if result.io_executed:
        raise ValueError("autopsy report requires dry-run result; I/O was executed.")

    if result.decision == ExecutionDecision.ALLOW:
        raise ValueError("ALLOW decisions do not produce autopsy reports.")

    causes = tuple(_cause_from_testimony(testimony) for testimony in result.testimonies)
    primary = _select_primary_cause(result, causes)
    kind = _report_kind(result, primary)
    state_after = _registry_state_after(proposal, ledger_event, registry)
    report_id = _report_id(proposal.proposal_id, result.reason_code)
    timestamp = _normalize_timestamp_utc(timestamp_utc)
    touched_objects = tuple(str(path) for path in proposal.target_paths)
    registry_before = _state_value(registry_state_before)
    registry_after = _state_value(state_after)
    ledger_event_id = ledger_event.event_id if ledger_event is not None else None
    replay_trace = _build_replay_trace(
        proposal=proposal,
        result=result,
        primary=primary,
        ledger_event=ledger_event,
        registry_state_after=state_after,
    )
    timeline = _build_autopsy_timeline(
        proposal=proposal,
        result=result,
        primary=primary,
        causes=causes,
        ledger_event=ledger_event,
        registry_state_after=state_after,
        timestamp_utc=timestamp,
    )
    timeline = _attach_transition_xray_timeline(timeline, transition_xray)
    replay_trace = _attach_transition_xray_trace(replay_trace, transition_xray)
    contributing_causes = tuple(
        cause for cause in causes if cause.reason_code != primary.reason_code
    )
    autopsy_seed = _autopsy_seed(
        report_id=report_id,
        timestamp_utc=timestamp,
        proposal=proposal,
        kind=kind.value,
        final_decision=result.decision.value,
        death_stage=primary.stage.value,
        death_reason=primary.reason_code,
        primary_cause=primary,
        contributing_causes=contributing_causes,
        touched_objects=touched_objects,
        permission_level=result.permission_level.value,
        critical=result.critical,
        kill_votes=result.kill_votes,
        hold_votes=result.hold_votes,
        registry_state_before=registry_before,
        registry_state_after=registry_after,
        ledger_event_id=ledger_event_id,
        replay_trace=replay_trace,
        timeline=timeline,
    )

    return AutopsyReport(
        report_id=report_id,
        timestamp_utc=timestamp,
        proposal_id=proposal.proposal_id,
        actor_id=proposal.actor_id,
        source_adapter=proposal.source_adapter,
        tool_name=proposal.tool_name,
        action_type=proposal.action_type,
        kind=kind,
        final_decision=result.decision.value,
        death_stage=primary.stage,
        death_reason=primary.reason_code,
        autopsy_seed=autopsy_seed,
        primary_cause=primary,
        contributing_causes=contributing_causes,
        touched_objects=touched_objects,
        permission_level=result.permission_level.value,
        critical=result.critical,
        kill_votes=result.kill_votes,
        hold_votes=result.hold_votes,
        registry_state_before=registry_before,
        registry_state_after=registry_after,
        ledger_event_id=ledger_event_id,
        replay_trace=replay_trace,
        timeline=timeline,
    )


def build_capability_autopsy_report(
    proposal: CommandProposal,
    decision: CapabilityDecision,
    *,
    registry: Optional[PhiRegistry] = None,
    registry_state_before: Optional[ActorState | str] = None,
    timestamp_utc: Optional[str] = None,
    transition_xray: Optional[Any] = None,
) -> AutopsyReport:
    """
    Builds a deterministic explanation for a Capability Wall stop.

    Capability Wall reports are read-only. They do not execute I/O, write the
    ledger, or mutate registry state.
    """

    if decision.can_execute or decision.can_grant_permission:
        raise ValueError("capability autopsy requires a non-authority decision.")

    if decision.disposition == CapabilityDisposition.ALLOW:
        raise ValueError("CAP_PASS decisions do not produce autopsy reports.")

    kind = (
        AutopsyKind.KILL
        if decision.disposition == CapabilityDisposition.KILL
        else AutopsyKind.HOLD_NOTE
    )
    primary = AutopsyCause(
        judge="capability",
        vote=decision.disposition.value,
        reason_code=decision.reason_code,
        critical=decision.disposition == CapabilityDisposition.KILL,
        stage=DeathStage.CAPABILITY_BOUNDARY,
        layer_hint=LayerHint.COMMIT_LAYER,
        detail=_detail_for_reason(decision.reason_code),
        evidence=tuple(decision.evidence),
    )
    state_after = _registry_state_after(proposal, None, registry)
    report_id = _report_id(proposal.proposal_id, decision.reason_code)
    timestamp = _normalize_timestamp_utc(timestamp_utc)
    touched_objects = tuple(decision.rejected_targets or proposal.target_paths)
    registry_before = _state_value(registry_state_before)
    registry_after = _state_value(state_after)
    replay_trace = _build_capability_replay_trace(
        proposal=proposal,
        decision=decision,
        registry_state_after=state_after,
    )
    timeline = _build_capability_timeline(
        proposal=proposal,
        decision=decision,
        timestamp_utc=timestamp,
        registry_state_after=state_after,
    )
    timeline = _attach_transition_xray_timeline(timeline, transition_xray)
    replay_trace = _attach_transition_xray_trace(replay_trace, transition_xray)
    autopsy_seed = _autopsy_seed(
        report_id=report_id,
        timestamp_utc=timestamp,
        proposal=proposal,
        kind=kind.value,
        final_decision=decision.disposition.value,
        death_stage=DeathStage.CAPABILITY_BOUNDARY.value,
        death_reason=decision.reason_code,
        primary_cause=primary,
        contributing_causes=(),
        touched_objects=touched_objects,
        permission_level="CAPABILITY_BOUNDARY",
        critical=decision.disposition == CapabilityDisposition.KILL,
        kill_votes=1 if decision.disposition == CapabilityDisposition.KILL else 0,
        hold_votes=1 if decision.disposition == CapabilityDisposition.HOLD else 0,
        registry_state_before=registry_before,
        registry_state_after=registry_after,
        ledger_event_id=None,
        replay_trace=replay_trace,
        timeline=timeline,
    )

    return AutopsyReport(
        report_id=report_id,
        timestamp_utc=timestamp,
        proposal_id=proposal.proposal_id,
        actor_id=proposal.actor_id,
        source_adapter=proposal.source_adapter,
        tool_name=proposal.tool_name,
        action_type=proposal.action_type,
        kind=kind,
        final_decision=decision.disposition.value,
        death_stage=DeathStage.CAPABILITY_BOUNDARY,
        death_reason=decision.reason_code,
        autopsy_seed=autopsy_seed,
        primary_cause=primary,
        contributing_causes=(),
        touched_objects=touched_objects,
        permission_level="CAPABILITY_BOUNDARY",
        critical=decision.disposition == CapabilityDisposition.KILL,
        kill_votes=1 if decision.disposition == CapabilityDisposition.KILL else 0,
        hold_votes=1 if decision.disposition == CapabilityDisposition.HOLD else 0,
        registry_state_before=registry_before,
        registry_state_after=registry_after,
        ledger_event_id=None,
        replay_trace=replay_trace,
        timeline=timeline,
    )


def _cause_from_testimony(testimony: JudgeTestimony) -> AutopsyCause:
    stage = _stage_for_reason(testimony.reason_code)
    return AutopsyCause(
        judge=testimony.judge.value,
        vote=testimony.vote.value,
        reason_code=testimony.reason_code,
        critical=testimony.critical,
        stage=stage,
        layer_hint=_layer_for_stage(stage),
        detail=_detail_for_reason(testimony.reason_code),
        evidence=tuple(str(item) for item in testimony.evidence),
    )


def _select_primary_cause(
    result: OTGateResult,
    causes: Sequence[AutopsyCause],
) -> AutopsyCause:
    if not causes:
        raise ValueError("autopsy report requires at least one judge testimony.")

    hold_note = _is_hold_note(result)
    if hold_note:
        for cause in causes:
            if cause.vote == JudgeVote.HOLD.value:
                return cause

    priority_groups = (
        lambda cause: cause.critical,
        lambda cause: cause.reason_code in ACTOR_STATE_REASONS,
        lambda cause: cause.reason_code in IDENTITY_REASONS,
        lambda cause: cause.reason_code in REGISTRY_PROTECTION_REASONS,
        lambda cause: cause.vote == JudgeVote.KILL.value,
        lambda cause: cause.vote == JudgeVote.HOLD.value,
    )

    for matches in priority_groups:
        for cause in causes:
            if matches(cause):
                return cause

    return causes[0]


def _report_kind(result: OTGateResult, primary: AutopsyCause) -> AutopsyKind:
    if _is_hold_note(result):
        return AutopsyKind.HOLD_NOTE

    if (
        result.reason_code == "CRITICAL_KILL"
        and primary.reason_code == "PHI_BUGCHECK_ACTIVE"
    ):
        return AutopsyKind.BUGCHECK

    return AutopsyKind.KILL


def _is_hold_note(result: OTGateResult) -> bool:
    return (
        result.reason_code == "HOLD_FOR_USER_CONFIRMATION"
        and not result.critical
        and result.kill_votes == 0
        and result.hold_votes > 0
    )


def _stage_for_reason(reason_code: str) -> DeathStage:
    if reason_code in ACTOR_STATE_REASONS:
        return DeathStage.ACTOR_STATE_ESCALATION

    if reason_code in IDENTITY_REASONS:
        return DeathStage.IDENTITY_CHECK

    if reason_code in REGISTRY_PROTECTION_REASONS:
        return DeathStage.REGISTRY_PROTECTION

    if reason_code in LAYER_INTEGRITY_REASONS:
        return DeathStage.LAYER_INTEGRITY

    if reason_code in MOTION_REASONS:
        return DeathStage.MOTION_AUDIT

    return DeathStage.COMMIT_GATE


def _layer_for_stage(stage: DeathStage) -> LayerHint:
    if stage == DeathStage.IDENTITY_CHECK:
        return LayerHint.SOURCE_LAYER

    if stage in {
        DeathStage.LAYER_INTEGRITY,
        DeathStage.MOTION_AUDIT,
        DeathStage.ACTOR_STATE_ESCALATION,
    }:
        return LayerHint.MOTION_LAYER

    if stage in {DeathStage.COMMIT_GATE, DeathStage.REGISTRY_PROTECTION}:
        return LayerHint.COMMIT_LAYER

    return LayerHint.AUTOPSY_LAYER


def _detail_for_reason(reason_code: str) -> str:
    details = {
        "MISSING_ACTOR_ID": "proposal has no registered actor identity",
        "UNKNOWN_ACTOR": "actor is not present in Phi Registry",
        "MISSING_PROVENANCE": "proposal is missing parent event or user request provenance",
        "ACTOR_FROZEN": "actor state blocks new proposal movement",
        "PHI_BUGCHECK_ACTIVE": "actor is already in Phi bugcheck state",
        "CRITICAL_PROTECTED_PHI_WRITE": "proposal attempted to modify protected Phi store",
        "CRITICAL_REGISTRY_READ": "proposal attempted to read protected Phi registry",
        "PROTECTED_LEDGER_READ_REQUIRES_APPROVAL": "proposal attempted to read protected Phi ledger without approval",
        "PROTECTED_PHI_READ_REQUIRES_APPROVAL": "proposal attempted to read protected Phi store without approval",
        "SCOPE_MISMATCH_SIDE_EFFECT": "declared scope does not cover inferred side effects",
        "PROJECT_SCOPE_ESCAPE": "proposal tried to escape project write scope",
        "INTENT_PRIVILEGE_OR_SECRET_ESCAPE": "proposal intent includes privilege or secret escape",
        "CRITICAL_DESTRUCTIVE_COMMAND": "proposal contains destructive file-system behavior",
        "CRITICAL_PRIVILEGE_ESCALATION": "proposal contains privilege escalation behavior",
        "CRITICAL_NETWORK_EXECUTE": "proposal combines network retrieval with dynamic execution",
        "CRITICAL_SECRET_ACCESS": "proposal targets secret-bearing material",
        "CRITICAL_AUDIT_BYPASS": "proposal targets audit or permission surfaces",
        "CRITICAL_EXTERNAL_WRITE": "proposal writes outside the project boundary",
        "ENV_OR_NETWORK_REQUIRES_APPROVAL": "environment or network effect requires user approval",
        "EXTERNAL_READ_REQUIRES_APPROVAL": "external read requires user approval",
        "EMPTY_COMMAND": "proposal has no command body",
        "CAPABILITY_MANIFEST_MISSING": "actor has no capability manifest",
        "CAPABILITY_MANIFEST_INCOMPLETE": "capability manifest is missing required fields",
        "CAPABILITY_SIDE_EFFECT_UNCLEAR": "proposal side effect cannot be established",
        "CAPABILITY_PERMISSION_MUTATION_DENIED": "proposal attempts permission mutation outside manifest",
        "CAPABILITY_AUDIT_MUTATION_DENIED": "proposal attempts audit or Phi control-space mutation outside manifest",
        "CAPABILITY_SIDE_EFFECT_DENIED": "proposal side effect exceeds the actor manifest",
        "CAPABILITY_TARGET_REQUIRED": "proposal needs target paths for capability review",
        "CAPABILITY_TARGET_UNRESOLVED": "proposal target path cannot be resolved reliably",
        "CAPABILITY_PROTECTED_TARGET_DENIED": "proposal targets protected Phi control space",
        "CAPABILITY_EXTERNAL_READ_REQUIRES_CONFIRMATION": "proposal reads outside the actor path manifest",
        "CAPABILITY_PATH_DENIED": "proposal target path exceeds the actor manifest",
        "CAPABILITY_NETWORK_DOMAIN_UNCLEAR": "proposal network target domain cannot be established",
        "CAPABILITY_NETWORK_DOMAIN_DENIED": "proposal network domain exceeds the actor manifest",
    }
    return details.get(reason_code, "judge testimony blocked the proposal")


def _registry_state_after(
    proposal: CommandProposal,
    ledger_event: Optional[AuditEvent],
    registry: Optional[PhiRegistry],
) -> Optional[ActorState]:
    if ledger_event is not None:
        return ledger_event.actor_state_after

    if registry is None or not proposal.actor_id.strip():
        return None

    actor = registry.get_actor(proposal.actor_id)
    if actor is None:
        return None

    return actor.state


def _state_value(state: Optional[ActorState | str]) -> Optional[str]:
    if state is None:
        return None

    if isinstance(state, ActorState):
        return state.value

    return str(state)


def _report_id(proposal_id: str, reason_code: str) -> str:
    safe_proposal = _safe_id(proposal_id or "unknown_proposal")
    safe_reason = _safe_id(reason_code or "unknown_reason")
    return f"autopsy_{safe_proposal}_{safe_reason}"


def _safe_id(value: str) -> str:
    return "".join(char if char.isalnum() or char == "_" else "_" for char in value)


def _current_timestamp_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00",
        "Z",
    )


def _normalize_timestamp_utc(timestamp_utc: Optional[str]) -> str:
    if timestamp_utc is None:
        return _current_timestamp_utc()

    if not isinstance(timestamp_utc, str):
        raise ValueError("timestamp_utc must be a UTC ISO timestamp ending with Z.")

    value = timestamp_utc.strip()
    if not value.endswith("Z"):
        raise ValueError("timestamp_utc must be a UTC ISO timestamp ending with Z.")

    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as exc:
        raise ValueError(
            "timestamp_utc must be a parseable UTC ISO timestamp ending with Z."
        ) from exc

    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp_utc must resolve to UTC.")

    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00",
        "Z",
    )


def _autopsy_seed(
    *,
    report_id: str,
    timestamp_utc: str,
    proposal: CommandProposal,
    kind: str,
    final_decision: str,
    death_stage: str,
    death_reason: str,
    primary_cause: AutopsyCause,
    contributing_causes: Sequence[AutopsyCause],
    touched_objects: Sequence[str],
    permission_level: str,
    critical: bool,
    kill_votes: int,
    hold_votes: int,
    registry_state_before: Optional[str],
    registry_state_after: Optional[str],
    ledger_event_id: Optional[str],
    replay_trace: Sequence[str],
    timeline: Sequence[AutopsyTimelineEntry],
) -> str:
    snapshot = {
        "report_id": report_id,
        "timestamp_utc": timestamp_utc,
        "proposal_id": proposal.proposal_id,
        "actor_id": proposal.actor_id,
        "source_adapter": proposal.source_adapter,
        "tool_name": proposal.tool_name,
        "action_type": proposal.action_type,
        "kind": kind,
        "final_decision": final_decision,
        "death_stage": death_stage,
        "death_reason": death_reason,
        "primary_cause": primary_cause.to_dict(),
        "contributing_causes": tuple(
            cause.to_dict() for cause in contributing_causes
        ),
        "touched_objects": tuple(touched_objects),
        "permission_level": permission_level,
        "critical": critical,
        "kill_votes": kill_votes,
        "hold_votes": hold_votes,
        "registry_state_before": registry_state_before,
        "registry_state_after": registry_state_after,
        "ledger_event_id": ledger_event_id,
        "replay_trace": tuple(replay_trace),
        "timeline": tuple(entry.to_dict() for entry in timeline),
    }
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _attach_transition_xray_timeline(
    timeline: Sequence[AutopsyTimelineEntry],
    transition_xray: Optional[Any],
) -> Sequence[AutopsyTimelineEntry]:
    if transition_xray is None:
        return timeline

    evidence = _transition_xray_evidence(transition_xray)
    if not evidence:
        return timeline

    enter_evidence = tuple(
        item
        for item in evidence
        if "enter_hash" in item or item.endswith(f"hbar_phi:{_xray_hbar(transition_xray)}")
    )
    exit_evidence = tuple(item for item in evidence if item not in enter_evidence)
    mutation_state = _xray_mutation_state(transition_xray)
    base = list(timeline)
    final = base[-1:] if base else []
    body = base[:-1] if final else base
    expanded: list[AutopsyTimelineEntry] = []

    for entry in body:
        expanded.append(entry)
        if entry.step == 0:
            expanded.append(
                AutopsyTimelineEntry(
                    step=-1,
                    stage="TRANSITION_XRAY_ENTER",
                    event="registered action transition X-ray sealed",
                    outcome="SEALED",
                    evidence=enter_evidence,
                )
            )

    expanded.append(
        AutopsyTimelineEntry(
            step=-1,
            stage="TRANSITION_XRAY_EXIT",
            event="decision-side transition X-ray sealed",
            outcome=mutation_state,
            evidence=exit_evidence,
        )
    )
    expanded.extend(final)
    return _renumber_timeline(expanded)


def _attach_transition_xray_trace(
    replay_trace: Sequence[str],
    transition_xray: Optional[Any],
) -> Sequence[str]:
    if transition_xray is None:
        return replay_trace

    pair_hash = getattr(transition_xray, "pair_hash", None)
    mutation_state = _xray_mutation_state(transition_xray)
    additions = []
    if pair_hash:
        additions.append(f"transition_xray_pair:{pair_hash}")
    if mutation_state:
        additions.append(f"transition_xray_state:{mutation_state}")
    return tuple(replay_trace) + tuple(additions)


def _transition_xray_evidence(transition_xray: Any) -> Sequence[str]:
    if hasattr(transition_xray, "to_evidence"):
        return tuple(str(item) for item in transition_xray.to_evidence())
    if isinstance(transition_xray, dict):
        return tuple(
            f"transition_xray.{key}:{value}"
            for key, value in sorted(transition_xray.items())
        )
    return ()


def _xray_mutation_state(transition_xray: Any) -> str:
    state = getattr(transition_xray, "mutation_state", "")
    return getattr(state, "value", state) or "UNOBSERVED"


def _xray_hbar(transition_xray: Any) -> Any:
    enter = getattr(transition_xray, "enter", None)
    return getattr(enter, "hbar_phi", "")


def _renumber_timeline(
    entries: Sequence[AutopsyTimelineEntry],
) -> Sequence[AutopsyTimelineEntry]:
    return tuple(
        AutopsyTimelineEntry(
            step=index,
            stage=entry.stage,
            event=entry.event,
            outcome=entry.outcome,
            reason_code=entry.reason_code,
            timestamp_utc=entry.timestamp_utc,
            evidence=entry.evidence,
        )
        for index, entry in enumerate(entries)
    )


def _build_replay_trace(
    *,
    proposal: CommandProposal,
    result: OTGateResult,
    primary: AutopsyCause,
    ledger_event: Optional[AuditEvent],
    registry_state_after: Optional[ActorState],
) -> Sequence[str]:
    trace = [
        f"proposal:{proposal.proposal_id}",
        f"actor:{proposal.actor_id or '<missing>'}",
        f"decision:{result.decision.value}",
        f"aggregate_reason:{result.reason_code}",
        f"primary_cause:{primary.reason_code}",
        f"stage:{primary.stage.value}",
    ]

    if ledger_event is not None:
        trace.append(f"ledger_event:{ledger_event.event_id}")

    if registry_state_after is not None:
        trace.append(f"actor_state_after:{registry_state_after.value}")

    return tuple(trace)


def _build_autopsy_timeline(
    *,
    proposal: CommandProposal,
    result: OTGateResult,
    primary: AutopsyCause,
    causes: Sequence[AutopsyCause],
    ledger_event: Optional[AuditEvent],
    registry_state_after: Optional[ActorState],
    timestamp_utc: str,
) -> Sequence[AutopsyTimelineEntry]:
    testimony_summary = tuple(
        f"{cause.judge}:{cause.vote}:{cause.reason_code}" for cause in causes
    )
    final_evidence = []
    if ledger_event is not None:
        final_evidence.append(f"ledger_event:{ledger_event.event_id}")
    if registry_state_after is not None:
        final_evidence.append(f"actor_state_after:{registry_state_after.value}")

    return (
        AutopsyTimelineEntry(
            step=0,
            stage="ADAPTER_NORMALIZE",
            event="proposal captured for dry-run autopsy",
            outcome="CAPTURED",
            evidence=(
                f"proposal:{proposal.proposal_id}",
                f"actor:{proposal.actor_id or '<missing>'}",
                f"adapter:{proposal.source_adapter or '<unknown>'}",
            ),
        ),
        AutopsyTimelineEntry(
            step=1,
            stage="REGISTRY_ADMISSION",
            event="identity and provenance testimony evaluated",
            outcome="TESTIFIED",
            reason_code=result.reason_code,
            evidence=testimony_summary,
        ),
        AutopsyTimelineEntry(
            step=2,
            stage="PRIMARY_CAUSE_SELECTION",
            event="primary stop cause selected",
            outcome=primary.stage.value,
            reason_code=primary.reason_code,
            evidence=(f"judge:{primary.judge}", f"vote:{primary.vote}"),
        ),
        AutopsyTimelineEntry(
            step=3,
            stage="FINAL_DECISION",
            event="autopsy report sealed",
            outcome=result.decision.value,
            reason_code=result.reason_code,
            timestamp_utc=timestamp_utc,
            evidence=tuple(final_evidence),
        ),
    )


def _build_capability_timeline(
    *,
    proposal: CommandProposal,
    decision: CapabilityDecision,
    timestamp_utc: str,
    registry_state_after: Optional[ActorState],
) -> Sequence[AutopsyTimelineEntry]:
    final_evidence = []
    if registry_state_after is not None:
        final_evidence.append(f"actor_state_after:{registry_state_after.value}")

    return (
        AutopsyTimelineEntry(
            step=0,
            stage="ADAPTER_NORMALIZE",
            event="proposal captured for capability autopsy",
            outcome="CAPTURED",
            evidence=(
                f"proposal:{proposal.proposal_id}",
                f"actor:{proposal.actor_id or '<missing>'}",
                f"adapter:{proposal.source_adapter or '<unknown>'}",
            ),
        ),
        AutopsyTimelineEntry(
            step=1,
            stage="CAPABILITY_PRECHECK",
            event="manifest and proposal metadata evaluated",
            outcome=decision.certificate.value,
            reason_code=decision.reason_code,
            evidence=tuple(decision.evidence),
        ),
        AutopsyTimelineEntry(
            step=2,
            stage="CAPABILITY_CERTIFICATE",
            event="capability boundary certificate issued",
            outcome=decision.disposition.value,
            reason_code=decision.reason_code,
            evidence=tuple(decision.rejected_targets),
        ),
        AutopsyTimelineEntry(
            step=3,
            stage="FINAL_DECISION",
            event="autopsy report sealed",
            outcome=decision.disposition.value,
            reason_code=decision.reason_code,
            timestamp_utc=timestamp_utc,
            evidence=tuple(final_evidence),
        ),
    )


def _build_capability_replay_trace(
    *,
    proposal: CommandProposal,
    decision: CapabilityDecision,
    registry_state_after: Optional[ActorState],
) -> Sequence[str]:
    trace = [
        f"proposal:{proposal.proposal_id}",
        f"actor:{proposal.actor_id or '<missing>'}",
        f"decision:{decision.disposition.value}",
        f"certificate:{decision.certificate.value}",
        f"primary_cause:{decision.reason_code}",
        f"stage:{DeathStage.CAPABILITY_BOUNDARY.value}",
    ]

    if decision.manifest_id:
        trace.append(f"manifest:{decision.manifest_id}")

    if registry_state_after is not None:
        trace.append(f"actor_state_after:{registry_state_after.value}")

    return tuple(trace)
