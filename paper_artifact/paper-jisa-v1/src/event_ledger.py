from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Sequence

from ot_gate import (
    CommandProposal,
    ExecutionDecision,
    OTGateResult,
    PermissionLevel,
)
from phi_registry import ActorState, PhiRegistry


@dataclass(frozen=True)
class LedgerPolicy:
    freeze_after_kills: int = 2
    bugcheck_after_critical: int = 2

    def __post_init__(self):
        if self.freeze_after_kills <= 0:
            raise ValueError("freeze_after_kills must be positive.")

        if self.bugcheck_after_critical <= 0:
            raise ValueError("bugcheck_after_critical must be positive.")


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    parent_event_id: str
    user_request_id: str
    actor_id: str
    proposal_id: str
    command_text: str
    decision: ExecutionDecision
    reason_code: str
    permission_level: PermissionLevel
    critical: bool
    kill_votes: int
    hold_votes: int
    judge_reason_codes: Sequence[str]
    io_executed: bool
    actor_state_after: ActorState
    timestamp_utc: str


@dataclass
class ActorLedgerStats:
    actor_id: str
    total_events: int = 0
    allow_count: int = 0
    kill_count: int = 0
    critical_count: int = 0
    hold_count: int = 0
    state: ActorState = ActorState.ACTIVE
    reason_counts: Dict[str, int] = field(default_factory=dict)

    def record(self, result: OTGateResult) -> None:
        self.total_events += 1

        if result.decision == ExecutionDecision.ALLOW:
            self.allow_count += 1
        else:
            self.kill_count += 1

        if result.critical:
            self.critical_count += 1

        if result.hold_votes > 0:
            self.hold_count += 1

        self.reason_counts[result.reason_code] = (
            self.reason_counts.get(result.reason_code, 0) + 1
        )


class EventLedger:
    """
    In-memory v0 event ledger.

    It records OT Gate dry-run decisions and derives actor state. It does not
    execute commands and does not persist to disk yet.
    """

    def __init__(
        self,
        policy: LedgerPolicy | None = None,
        registry: PhiRegistry | None = None,
    ):
        self.policy = policy if policy is not None else LedgerPolicy()
        self.registry = registry
        self.events: List[AuditEvent] = []
        self.actor_stats: Dict[str, ActorLedgerStats] = {}
        self._next_event_index = 1

    def _new_event_id(self) -> str:
        event_id = f"event_{self._next_event_index:06d}"
        self._next_event_index += 1
        return event_id

    def _stats_for(self, actor_id: str) -> ActorLedgerStats:
        if not actor_id.strip():
            raise ValueError("actor_id is required for ledger records.")

        if actor_id not in self.actor_stats:
            self.actor_stats[actor_id] = ActorLedgerStats(actor_id=actor_id)

        return self.actor_stats[actor_id]

    def _derive_state(self, stats: ActorLedgerStats) -> ActorState:
        if stats.critical_count >= self.policy.bugcheck_after_critical:
            return ActorState.BUGCHECK

        if stats.kill_count >= self.policy.freeze_after_kills:
            return ActorState.FROZEN

        if stats.kill_count > 0 or stats.hold_count > 0:
            return ActorState.WARNING

        return ActorState.ACTIVE

    def record(
        self,
        proposal: CommandProposal,
        result: OTGateResult,
    ) -> AuditEvent:
        if result.io_executed:
            raise ValueError("ledger must not record executed I/O in v0.")

        if self.registry is not None:
            self.registry.require_actor(proposal.actor_id)

        stats = self._stats_for(proposal.actor_id)
        stats.record(result)
        stats.state = self._derive_state(stats)

        if self.registry is not None:
            self.registry.set_actor_state(
                proposal.actor_id,
                stats.state,
                reason_code=result.reason_code,
            )

        event = AuditEvent(
            event_id=self._new_event_id(),
            parent_event_id=proposal.parent_event_id,
            user_request_id=proposal.user_request_id,
            actor_id=proposal.actor_id,
            proposal_id=proposal.proposal_id,
            command_text=proposal.command_text,
            decision=result.decision,
            reason_code=result.reason_code,
            permission_level=result.permission_level,
            critical=result.critical,
            kill_votes=result.kill_votes,
            hold_votes=result.hold_votes,
            judge_reason_codes=tuple(
                testimony.reason_code for testimony in result.testimonies
            ),
            io_executed=result.io_executed,
            actor_state_after=stats.state,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
        )
        self.events.append(event)
        return event

    def state_for(self, actor_id: str) -> ActorState:
        stats = self.actor_stats.get(actor_id)
        if stats is None:
            return ActorState.ACTIVE
        return stats.state

    def stats_for(self, actor_id: str) -> ActorLedgerStats:
        stats = self.actor_stats.get(actor_id)
        if stats is None:
            return ActorLedgerStats(actor_id=actor_id)
        return stats

    def events_for_actor(self, actor_id: str) -> List[AuditEvent]:
        return [event for event in self.events if event.actor_id == actor_id]
