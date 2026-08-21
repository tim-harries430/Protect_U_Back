from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Sequence


class TaskGuardState(str, Enum):
    ACTIVE = "ACTIVE"
    TERMINATED = "TERMINATED"


class TaskStopSeverity(str, Enum):
    HOLD = "HOLD"
    KILL = "KILL"
    CRITICAL = "CRITICAL"


class TaskNextAction(str, Enum):
    ASK_USER = "ASK_USER"
    STOP_TASK = "STOP_TASK"


@dataclass(frozen=True)
class TaskGuardPolicy:
    """
    Lightweight per-task cutoff policy.

    v0 terminates repeated unsafe movement inside one task. It does not freeze
    adapters, mutate registry state, persist to disk, or execute I/O.
    """

    terminate_after_kills: int = 2
    terminate_after_holds: int = 3
    terminate_on_critical: bool = False

    def __post_init__(self):
        if self.terminate_after_kills <= 0:
            raise ValueError("terminate_after_kills must be positive.")

        if self.terminate_after_holds <= 0:
            raise ValueError("terminate_after_holds must be positive.")


@dataclass(frozen=True)
class TaskStopEvent:
    user_request_id: str
    branch_id: str
    actor_id: str
    stage: str
    reason_code: str
    severity: TaskStopSeverity

    def __post_init__(self):
        if isinstance(self.severity, str):
            object.__setattr__(self, "severity", TaskStopSeverity(self.severity))

        object.__setattr__(self, "user_request_id", self.user_request_id.strip())
        object.__setattr__(self, "branch_id", self.branch_id.strip())
        object.__setattr__(self, "actor_id", self.actor_id.strip())
        object.__setattr__(self, "stage", self.stage.strip())
        object.__setattr__(self, "reason_code", self.reason_code.strip())

        if not self.user_request_id:
            raise ValueError("user_request_id must be non-empty.")

        if not self.branch_id:
            raise ValueError("branch_id must be non-empty.")

        if not self.stage:
            raise ValueError("stage must be non-empty.")

        if not self.reason_code:
            raise ValueError("reason_code must be non-empty.")

    @property
    def task_key(self) -> str:
        return task_key(self.user_request_id, self.branch_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_request_id": self.user_request_id,
            "branch_id": self.branch_id,
            "actor_id": self.actor_id,
            "stage": self.stage,
            "reason_code": self.reason_code,
            "severity": self.severity.value,
            "task_key": self.task_key,
        }


@dataclass(frozen=True)
class TaskIncidentSummary:
    task_key: str
    state: TaskGuardState
    next_action: TaskNextAction
    kill_count: int
    hold_count: int
    critical_count: int
    primary_reasons: Sequence[str] = field(default_factory=tuple)
    message_to_user: str = ""
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self):
        if isinstance(self.state, str):
            object.__setattr__(self, "state", TaskGuardState(self.state))

        if isinstance(self.next_action, str):
            object.__setattr__(self, "next_action", TaskNextAction(self.next_action))

        object.__setattr__(
            self,
            "primary_reasons",
            tuple(str(reason) for reason in self.primary_reasons),
        )
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    @property
    def terminated(self) -> bool:
        return self.state == TaskGuardState.TERMINATED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_key": self.task_key,
            "state": self.state.value,
            "next_action": self.next_action.value,
            "kill_count": self.kill_count,
            "hold_count": self.hold_count,
            "critical_count": self.critical_count,
            "primary_reasons": tuple(self.primary_reasons),
            "message_to_user": self.message_to_user,
            "can_execute": False,
            "can_grant_permission": False,
        }


class TaskGuard:
    """
    In-memory v0 task cutoff guard.

    It tracks stop events per user_request_id + branch_id. Once a task is
    terminated, later proposals in that same task should not proceed to lower
    layers.
    """

    def __init__(self, policy: TaskGuardPolicy | None = None):
        self.policy = policy if policy is not None else TaskGuardPolicy()
        self._events: Dict[str, list[TaskStopEvent]] = {}
        self._states: Dict[str, TaskGuardState] = {}

    def record(self, event: TaskStopEvent) -> TaskIncidentSummary:
        events = self._events.setdefault(event.task_key, [])
        events.append(event)

        state = self._derive_state(events)
        self._states[event.task_key] = state
        return self.summary_for_key(event.task_key)

    def is_terminated(self, user_request_id: str, branch_id: str) -> bool:
        return (
            self._states.get(task_key(user_request_id, branch_id))
            == TaskGuardState.TERMINATED
        )

    def summary_for(self, user_request_id: str, branch_id: str) -> TaskIncidentSummary:
        return self.summary_for_key(task_key(user_request_id, branch_id))

    def summary_for_key(self, key: str) -> TaskIncidentSummary:
        events = tuple(self._events.get(key, ()))
        counts = _counts(events)
        state = self._states.get(key, self._derive_state(events))
        next_action = (
            TaskNextAction.STOP_TASK
            if state == TaskGuardState.TERMINATED
            else TaskNextAction.ASK_USER
        )
        return TaskIncidentSummary(
            task_key=key,
            state=state,
            next_action=next_action,
            kill_count=counts["kills"],
            hold_count=counts["holds"],
            critical_count=counts["criticals"],
            primary_reasons=_primary_reasons(events),
            message_to_user=_message_to_user(key, events, state),
        )

    def summaries(self) -> Sequence[TaskIncidentSummary]:
        return tuple(self.summary_for_key(key) for key in sorted(self._events))

    def _derive_state(self, events: Sequence[TaskStopEvent]) -> TaskGuardState:
        counts = _counts(events)
        if self.policy.terminate_on_critical and counts["criticals"] > 0:
            return TaskGuardState.TERMINATED

        if counts["kills"] >= self.policy.terminate_after_kills:
            return TaskGuardState.TERMINATED

        if counts["holds"] >= self.policy.terminate_after_holds:
            return TaskGuardState.TERMINATED

        return TaskGuardState.ACTIVE


def task_key(user_request_id: str, branch_id: str) -> str:
    user = str(user_request_id).strip() or "<missing_user_request>"
    branch = str(branch_id).strip() or "<missing_branch>"
    return f"{user}::{branch}"


def _counts(events: Sequence[TaskStopEvent]) -> Dict[str, int]:
    holds = sum(1 for event in events if event.severity == TaskStopSeverity.HOLD)
    kills = sum(
        1
        for event in events
        if event.severity in {TaskStopSeverity.KILL, TaskStopSeverity.CRITICAL}
    )
    criticals = sum(
        1 for event in events if event.severity == TaskStopSeverity.CRITICAL
    )
    return {
        "holds": holds,
        "kills": kills,
        "criticals": criticals,
    }


def _primary_reasons(events: Sequence[TaskStopEvent]) -> Sequence[str]:
    reasons = []
    for event in events:
        if event.reason_code not in reasons:
            reasons.append(event.reason_code)
    return tuple(reasons[:5])


def _message_to_user(
    key: str,
    events: Sequence[TaskStopEvent],
    state: TaskGuardState,
) -> str:
    if not events:
        return "Task is active."

    reasons = ", ".join(_primary_reasons(events))
    if state == TaskGuardState.TERMINATED:
        return (
            f"Task {key} was terminated after repeated unsafe proposals. "
            f"Primary reasons: {reasons}."
        )

    return (
        f"Task {key} has audit stops and needs user confirmation before risk "
        f"can increase. Primary reasons: {reasons}."
    )
