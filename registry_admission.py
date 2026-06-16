from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, Sequence

from llm_channel import ChannelEnvelope, ChannelType
from phi_registry import ActorState, ActorType, PhiRegistry


class AdmissionDisposition(str, Enum):
    ADMIT = "ADMIT"
    HOLD = "HOLD"
    REJECT = "REJECT"


@dataclass(frozen=True)
class AdmissionPolicy:
    """
    Lightweight pre-channel admission policy.

    Admission checks identity and envelope structure only. It cannot execute,
    cannot grant permission, and cannot declare a proposal safe.
    """

    require_registered_agent: bool = True
    require_registered_tool: bool = False
    allow_unregistered_user: bool = True
    require_parent_for_rejected_feedback: bool = True


@dataclass(frozen=True)
class AdmissionTicket:
    envelope_id: str
    source_id: str
    channel_type: ChannelType
    disposition: AdmissionDisposition
    reason_code: str
    actor_state: Optional[ActorState] = None
    admitted: bool = False
    can_execute: bool = False
    can_grant_permission: bool = False
    evidence: Sequence[str] = ()

    def __post_init__(self):
        if isinstance(self.channel_type, str):
            object.__setattr__(self, "channel_type", ChannelType(self.channel_type))

        if isinstance(self.disposition, str):
            object.__setattr__(
                self,
                "disposition",
                AdmissionDisposition(self.disposition),
            )

        if isinstance(self.actor_state, str):
            object.__setattr__(self, "actor_state", ActorState(self.actor_state))

        object.__setattr__(self, "admitted", self.disposition == AdmissionDisposition.ADMIT)
        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "source_id": self.source_id,
            "channel_type": self.channel_type.value,
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "actor_state": self.actor_state.value if self.actor_state else None,
            "admitted": self.admitted,
            "can_execute": False,
            "can_grant_permission": False,
            "evidence": tuple(self.evidence),
        }


def issue_admission_ticket(
    envelope: ChannelEnvelope,
    registry: PhiRegistry,
    policy: AdmissionPolicy = AdmissionPolicy(),
) -> AdmissionTicket:
    structural_issue = _structural_issue(envelope)
    if structural_issue is not None:
        reason_code, evidence = structural_issue
        return _ticket(
            envelope,
            disposition=AdmissionDisposition.HOLD,
            reason_code=reason_code,
            evidence=evidence,
        )

    actor = registry.get_actor(envelope.source_id)
    if actor is not None and actor.state in {ActorState.FROZEN, ActorState.BUGCHECK}:
        return _ticket(
            envelope,
            disposition=AdmissionDisposition.REJECT,
            reason_code=f"ADMISSION_ACTOR_{actor.state.value}",
            actor_state=actor.state,
            evidence=(envelope.source_id,),
        )

    if envelope.channel_type == ChannelType.AGENT_PROPOSAL:
        if policy.require_registered_agent and actor is None:
            return _ticket(
                envelope,
                disposition=AdmissionDisposition.REJECT,
                reason_code="ADMISSION_UNKNOWN_AGENT",
                evidence=(envelope.source_id,),
            )

        if actor is not None and actor.actor_type not in {
            ActorType.AGENT,
            ActorType.MODULE,
            ActorType.SYSTEM,
        }:
            return _ticket(
                envelope,
                disposition=AdmissionDisposition.HOLD,
                reason_code="ADMISSION_SOURCE_CHANNEL_MISMATCH",
                actor_state=actor.state,
                evidence=(actor.actor_type.value, envelope.channel_type.value),
            )

    if envelope.channel_type == ChannelType.TOOL_METADATA:
        if policy.require_registered_tool and actor is None:
            return _ticket(
                envelope,
                disposition=AdmissionDisposition.HOLD,
                reason_code="ADMISSION_UNKNOWN_TOOL",
                evidence=(envelope.source_id,),
            )

        if actor is not None and actor.actor_type != ActorType.TOOL:
            return _ticket(
                envelope,
                disposition=AdmissionDisposition.HOLD,
                reason_code="ADMISSION_SOURCE_CHANNEL_MISMATCH",
                actor_state=actor.state,
                evidence=(actor.actor_type.value, envelope.channel_type.value),
            )

    if envelope.channel_type == ChannelType.REJECTED_FEEDBACK:
        if policy.require_parent_for_rejected_feedback and not envelope.parent_event_id.strip():
            return _ticket(
                envelope,
                disposition=AdmissionDisposition.HOLD,
                reason_code="ADMISSION_REJECTED_FEEDBACK_MISSING_PARENT",
                evidence=("parent_event_id",),
            )

    if envelope.channel_type == ChannelType.USER_REQUEST:
        if actor is not None and actor.actor_type not in {ActorType.USER, ActorType.SYSTEM}:
            return _ticket(
                envelope,
                disposition=AdmissionDisposition.HOLD,
                reason_code="ADMISSION_SOURCE_CHANNEL_MISMATCH",
                actor_state=actor.state,
                evidence=(actor.actor_type.value, envelope.channel_type.value),
            )

    return _ticket(
        envelope,
        disposition=AdmissionDisposition.ADMIT,
        reason_code="ADMISSION_ADMIT",
        actor_state=actor.state if actor is not None else None,
    )


def issue_admission_batch(
    envelopes: Sequence[ChannelEnvelope],
    registry: PhiRegistry,
    policy: AdmissionPolicy = AdmissionPolicy(),
) -> Sequence[AdmissionTicket]:
    return tuple(
        issue_admission_ticket(envelope, registry, policy)
        for envelope in envelopes
    )


def admitted_envelopes(
    envelopes: Sequence[ChannelEnvelope],
    tickets: Sequence[AdmissionTicket],
) -> Sequence[ChannelEnvelope]:
    if len(envelopes) != len(tickets):
        raise ValueError("envelopes and tickets must have the same length.")

    return tuple(
        envelope
        for envelope, ticket in zip(envelopes, tickets)
        if ticket.disposition == AdmissionDisposition.ADMIT
    )


def _structural_issue(envelope: ChannelEnvelope) -> Optional[tuple[str, Sequence[str]]]:
    missing = []
    if not envelope.source_id.strip():
        missing.append("source_id")

    if not envelope.branch_id.strip():
        missing.append("branch_id")

    if not envelope.envelope_id.strip() or envelope.envelope_id == "unknown_envelope":
        missing.append("envelope_id")

    if missing:
        return "ADMISSION_MISSING_ENVELOPE_FIELDS", tuple(missing)

    return None


def _ticket(
    envelope: ChannelEnvelope,
    *,
    disposition: AdmissionDisposition,
    reason_code: str,
    actor_state: Optional[ActorState] = None,
    evidence: Sequence[str] = (),
) -> AdmissionTicket:
    return AdmissionTicket(
        envelope_id=envelope.envelope_id,
        source_id=envelope.source_id,
        channel_type=envelope.channel_type,
        disposition=disposition,
        reason_code=reason_code,
        actor_state=actor_state,
        evidence=tuple(evidence),
    )
