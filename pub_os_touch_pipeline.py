from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from adapter_wall import ActionEnvelope, AdapterActionType
from ot_gate import SideEffect
from parallel_audit import EvidenceDisposition, ParallelAuditDecision
from phi_registry import ActorType, PhiRegistry
from protect_scan import confirm_protect_scan, default_protect_scan_profile
from pub_os_authorization import (
    CapabilityLease,
    LeaseCheck,
    LeaseDecision,
    check_lease_for_touch,
    issue_lease_from_approval,
    operation_from_touch,
)
from pub_os_visibility import (
    KingdomSession,
    ObjectTouchEvent,
    ObservationSource,
    TouchKind,
    VisibilityDecision,
    VisibilityReceipt,
    action_envelope_from_touch,
    receipt_for_touch,
)
from xray_review import audit_with_xray_review


class TouchPipelineState(str, Enum):
    LEASED = "LEASED"
    HOLD = "HOLD"


@dataclass(frozen=True)
class TouchPipelineResult:
    state: TouchPipelineState | str
    reason_code: str
    event: ObjectTouchEvent
    visibility: VisibilityReceipt
    audit_decision: ParallelAuditDecision | None = None
    lease: CapabilityLease | None = None
    lease_check: LeaseCheck | None = None
    evidence: Sequence[str] = field(default_factory=tuple)
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", TouchPipelineState(self.state))
        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "reason_code": self.reason_code,
            "event": self.event.public_metadata(),
            "visibility": self.visibility.to_dict(),
            "audit": _audit_summary(self.audit_decision),
            "lease": self.lease.to_dict() if self.lease is not None else None,
            "lease_check": self.lease_check.to_dict() if self.lease_check is not None else None,
            "evidence": tuple(self.evidence),
            "can_execute": False,
            "can_grant_permission": False,
        }


def authorize_touch_for_lease(
    event: ObjectTouchEvent,
    session: KingdomSession,
    *,
    audit_fn: Callable[..., ParallelAuditDecision] | None = None,
    now_ns: int | None = None,
    ttl_ns: int = 5_000_000_000,
    root_pid: int | None = None,
    project_root: str | Path | None = None,
) -> TouchPipelineResult:
    visibility = receipt_for_touch(event, session)
    if visibility.decision != VisibilityDecision.PASS:
        return _hold(event, visibility, visibility.reason_code, visibility.evidence)

    try:
        operation = operation_from_touch(event.kind)
    except ValueError as exc:
        return _hold(event, visibility, "PUB_OS_LEASE_UNSUPPORTED_TOUCH", (str(exc),))

    root = str(Path(project_root or session.project_root).resolve(strict=False))
    action = action_envelope_from_touch(event, project_root=root)
    decision = (audit_fn or _default_audit)(action, project_root=root)
    if decision.disposition != EvidenceDisposition.PASS:
        return _hold(
            event,
            visibility,
            decision.reason_code,
            evidence=(f"audit:{decision.disposition.value}",),
            audit_decision=decision,
        )

    lease = issue_lease_from_approval(
        decision,
        session_id=session.session_id,
        actor_id=event.actor_id,
        operation=operation,
        object_ref=event.object_ref,
        pid=event.pid,
        root_pid=root_pid,
        file_id=str(event.metadata.get("file_id", "")),
        now_ns=now_ns,
        ttl_ns=ttl_ns,
    )
    lease_check = check_lease_for_touch(lease, event, now_ns=now_ns)
    if lease_check.decision != LeaseDecision.ALLOW:
        return _hold(
            event,
            visibility,
            lease_check.reason_code,
            evidence=lease_check.evidence,
            audit_decision=decision,
            lease=lease,
            lease_check=lease_check,
        )
    return TouchPipelineResult(
        TouchPipelineState.LEASED,
        "PUB_OS_TOUCH_LEASED",
        event,
        visibility,
        audit_decision=decision,
        lease=lease,
        lease_check=lease_check,
    )


def touches_from_action(
    action: ActionEnvelope,
    *,
    session_id: str,
    pid: int,
    ppid: int,
    source: str | None = None,
) -> tuple[ObjectTouchEvent, ...]:
    kind = _touch_kind_from_action(action)
    object_refs = tuple(action.target_paths) if _targeted_touch(kind) and action.target_paths else (_object_ref(action),)
    return tuple(
        ObjectTouchEvent(
            session_id=session_id,
            event_id=f"{action.action_id}:touch:{index}",
            pid=pid,
            ppid=ppid,
            actor_id=action.actor_id,
            kind=kind,
            object_ref=str(object_ref),
            process_image=action.tool_name,
            command_text=action.command_text,
            cwd=action.cwd,
            source=source or action.source_adapter,
            observation_source=ObservationSource.PROPOSAL,
            metadata={
                "source_action_id": action.action_id,
                "source_adapter": action.source_adapter,
                "tool_name": action.tool_name,
                "target_count": len(object_refs),
                "runtime_modellable": True,
            },
        )
        for index, object_ref in enumerate(object_refs, start=1)
    )


def touches_from_claude_event(
    event: Mapping[str, Any],
    *,
    session_id: str,
    pid: int,
    ppid: int,
    environ: Mapping[str, str] | None = None,
) -> tuple[ObjectTouchEvent, ...]:
    from claude_code_hooks import action_from_claude_event

    action = action_from_claude_event(event, environ=environ)
    return touches_from_action(action, session_id=session_id, pid=pid, ppid=ppid, source="cc_hook")


def touches_from_codex_shell_argv(
    argv: Sequence[str],
    *,
    session_id: str,
    pid: int,
    ppid: int,
    cwd: str | Path,
    environ: Mapping[str, str] | None = None,
) -> tuple[ObjectTouchEvent, ...]:
    from codex_bash_guard import action_from_shell_argv

    action = action_from_shell_argv(argv, cwd=str(cwd), environ=environ)
    return touches_from_action(action, session_id=session_id, pid=pid, ppid=ppid, source="cd_shell_guard")


def _default_audit(action: ActionEnvelope, *, project_root: str) -> ParallelAuditDecision:
    registry = PhiRegistry()
    registry.register_actor(action.actor_id, ActorType.AGENT)
    profile = confirm_protect_scan(default_protect_scan_profile(project_root), confirmed=True)
    return audit_with_xray_review(
        action,
        registry=registry,
        project_root=project_root,
        protect_profile=profile,
    )


def _touch_kind_from_action(action: ActionEnvelope) -> TouchKind:
    if action.action_type == AdapterActionType.FILE_READ:
        return TouchKind.FILE_READ
    if action.action_type == AdapterActionType.FILE_WRITE:
        return TouchKind.FILE_WRITE
    if action.action_type == AdapterActionType.FILE_DELETE:
        return TouchKind.FILE_DELETE
    if action.action_type == AdapterActionType.NETWORK or SideEffect.NETWORK in action.expected_side_effects:
        return TouchKind.NETWORK_CONNECT
    return TouchKind.PROCESS_EXEC


def _targeted_touch(kind: TouchKind) -> bool:
    return kind in {
        TouchKind.FILE_READ,
        TouchKind.FILE_WRITE,
        TouchKind.FILE_DELETE,
        TouchKind.FILE_RENAME,
        TouchKind.ARTIFACT_USE,
    }


def _object_ref(action: ActionEnvelope) -> str:
    if action.target_paths:
        return str(action.target_paths[0])
    if action.tool_name:
        return action.tool_name
    return action.command_text


def _hold(
    event: ObjectTouchEvent,
    visibility: VisibilityReceipt,
    reason_code: str,
    evidence: Sequence[str] = (),
    *,
    audit_decision: ParallelAuditDecision | None = None,
    lease: CapabilityLease | None = None,
    lease_check: LeaseCheck | None = None,
) -> TouchPipelineResult:
    return TouchPipelineResult(
        TouchPipelineState.HOLD,
        reason_code,
        event,
        visibility,
        audit_decision=audit_decision,
        lease=lease,
        lease_check=lease_check,
        evidence=evidence,
    )


def _audit_summary(decision: ParallelAuditDecision | None) -> dict[str, Any] | None:
    if decision is None:
        return None
    return {
        "disposition": decision.disposition.value,
        "reason_code": decision.reason_code,
        "primary_stage": decision.primary_stage.value,
        "can_execute": False,
        "can_grant_permission": False,
    }
