from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from os.path import normcase, normpath
from pathlib import Path
from typing import Any, Mapping, Sequence

from parallel_audit import EvidenceDisposition, ParallelAuditDecision
from pub_os_visibility import ObjectTouchEvent, TouchKind


DEFAULT_LEASE_TTL_NS = 5_000_000_000


class LeaseOperation(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    RENAME = "rename"
    EXECUTE = "execute"


class LeaseDecision(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"


@dataclass(frozen=True)
class CapabilityLease:
    lease_id: str
    session_id: str
    actor_id: str
    operation: LeaseOperation | str
    object_ref: str
    issued_at_ns: int
    expires_at_ns: int
    approval_hash: str
    pid: int | None = None
    root_pid: int | None = None
    file_id: str = ""
    one_shot: bool = True
    consumed: bool = False
    authority: str = "runtime_lease_only"
    can_grant_permission: bool = False

    def __post_init__(self) -> None:
        if not self.lease_id.strip():
            raise ValueError("lease_id is required")
        if not self.session_id.strip():
            raise ValueError("session_id is required")
        if not self.actor_id.strip():
            raise ValueError("actor_id is required")
        if not self.object_ref.strip():
            raise ValueError("object_ref is required")
        object.__setattr__(self, "operation", LeaseOperation(self.operation))
        object.__setattr__(self, "object_ref", _stable_object_ref(self.object_ref))
        object.__setattr__(self, "can_grant_permission", False)

    @property
    def active(self) -> bool:
        return not self.consumed

    def consume(self) -> "CapabilityLease":
        return replace(self, consumed=True) if self.one_shot else self

    def to_dict(self) -> dict[str, Any]:
        return {
            "lease_id": self.lease_id,
            "session_id": self.session_id,
            "actor_id": self.actor_id,
            "operation": self.operation.value,
            "object_ref": self.object_ref,
            "pid": self.pid,
            "root_pid": self.root_pid,
            "file_id": self.file_id,
            "issued_at_ns": self.issued_at_ns,
            "expires_at_ns": self.expires_at_ns,
            "approval_hash": self.approval_hash,
            "one_shot": self.one_shot,
            "consumed": self.consumed,
            "authority": self.authority,
            "can_grant_permission": False,
        }


@dataclass(frozen=True)
class LeaseCheck:
    decision: LeaseDecision | str
    reason_code: str
    lease_id: str = ""
    event_id: str = ""
    evidence: Sequence[str] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    can_grant_permission: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", LeaseDecision(self.decision))
        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))
        object.__setattr__(self, "metadata", dict(self.metadata))
        object.__setattr__(self, "can_grant_permission", False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "lease_id": self.lease_id,
            "event_id": self.event_id,
            "evidence": tuple(self.evidence),
            "metadata": dict(self.metadata),
            "can_grant_permission": False,
        }


def issue_lease_from_approval(
    decision: ParallelAuditDecision,
    *,
    session_id: str,
    actor_id: str,
    operation: LeaseOperation | str,
    object_ref: str,
    pid: int | None = None,
    root_pid: int | None = None,
    file_id: str = "",
    now_ns: int | None = None,
    ttl_ns: int = DEFAULT_LEASE_TTL_NS,
    one_shot: bool = True,
) -> CapabilityLease:
    if decision.disposition != EvidenceDisposition.PASS:
        raise ValueError(f"cannot issue runtime lease from non-PASS decision: {decision.disposition.value}")
    issued_at = int(now_ns if now_ns is not None else time.time_ns())
    if ttl_ns <= 0:
        raise ValueError("ttl_ns must be positive")
    approval_hash = _approval_hash(decision)
    return CapabilityLease(
        lease_id=_lease_id(session_id, actor_id, operation, object_ref, approval_hash, issued_at),
        session_id=session_id,
        actor_id=actor_id,
        operation=operation,
        object_ref=object_ref,
        pid=pid,
        root_pid=root_pid,
        file_id=file_id,
        issued_at_ns=issued_at,
        expires_at_ns=issued_at + int(ttl_ns),
        approval_hash=approval_hash,
        one_shot=one_shot,
    )


def check_lease_for_touch(
    lease: CapabilityLease | None,
    event: ObjectTouchEvent,
    *,
    now_ns: int | None = None,
) -> LeaseCheck:
    if lease is None:
        return LeaseCheck(
            LeaseDecision.HOLD,
            "LEASE_MISSING",
            event_id=event.event_id,
            evidence=(event.kind.value, event.object_ref),
        )
    checked_at = int(now_ns if now_ns is not None else time.time_ns())
    if lease.consumed:
        return _hold("LEASE_CONSUMED", lease, event)
    if checked_at > lease.expires_at_ns:
        return _hold("LEASE_EXPIRED", lease, event, (f"checked_at_ns:{checked_at}",))
    if event.session_id != lease.session_id:
        return _hold("LEASE_SESSION_MISMATCH", lease, event, (event.session_id,))
    if event.actor_id != lease.actor_id:
        return _hold("LEASE_ACTOR_MISMATCH", lease, event, (event.actor_id,))
    if lease.pid is not None and event.pid != lease.pid:
        return _hold("LEASE_PID_MISMATCH", lease, event, (f"pid:{event.pid}",))
    if lease.root_pid is not None and event.pid != lease.root_pid and event.ppid != lease.root_pid:
        return _hold("LEASE_PROCESS_TREE_MISMATCH", lease, event, (f"pid:{event.pid}", f"ppid:{event.ppid}"))
    event_operation = operation_from_touch(event.kind)
    if event_operation != lease.operation:
        return _hold("LEASE_OPERATION_MISMATCH", lease, event, (event_operation.value,))
    if not _object_matches(lease, event):
        return _hold("LEASE_OBJECT_MISMATCH", lease, event, (_stable_object_ref(event.object_ref),))
    return LeaseCheck(
        LeaseDecision.ALLOW,
        "LEASE_MATCH",
        lease_id=lease.lease_id,
        event_id=event.event_id,
        metadata={"one_shot": lease.one_shot, "expires_at_ns": lease.expires_at_ns},
    )


def consume_lease_after_match(lease: CapabilityLease, check: LeaseCheck) -> CapabilityLease:
    if check.decision != LeaseDecision.ALLOW:
        return lease
    return lease.consume()


def operation_from_touch(kind: TouchKind | str) -> LeaseOperation:
    kind = TouchKind(kind)
    if kind in {TouchKind.FILE_READ, TouchKind.ARTIFACT_USE}:
        return LeaseOperation.READ
    if kind == TouchKind.FILE_WRITE:
        return LeaseOperation.WRITE
    if kind == TouchKind.FILE_DELETE:
        return LeaseOperation.DELETE
    if kind == TouchKind.FILE_RENAME:
        return LeaseOperation.RENAME
    if kind == TouchKind.PROCESS_EXEC:
        return LeaseOperation.EXECUTE
    raise ValueError(f"no file lease operation for touch kind: {kind.value}")


def _hold(
    reason_code: str,
    lease: CapabilityLease,
    event: ObjectTouchEvent,
    evidence: Sequence[str] = (),
) -> LeaseCheck:
    return LeaseCheck(
        LeaseDecision.HOLD,
        reason_code,
        lease_id=lease.lease_id,
        event_id=event.event_id,
        evidence=tuple(evidence),
    )


def _object_matches(lease: CapabilityLease, event: ObjectTouchEvent) -> bool:
    event_file_id = str(event.metadata.get("file_id", ""))
    if lease.file_id and event_file_id:
        return lease.file_id == event_file_id
    return lease.object_ref == _stable_object_ref(event.object_ref)


def _stable_object_ref(value: str) -> str:
    text = str(value).strip()
    if not text:
        return ""
    if "://" in text:
        return text
    return normcase(normpath(str(Path(text).resolve(strict=False))))


def _approval_hash(decision: ParallelAuditDecision) -> str:
    material = "|".join(
        (
            decision.disposition.value,
            decision.reason_code,
            decision.primary_stage.value,
            ",".join(testimony.reason_code for testimony in decision.testimonies),
        )
    )
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _lease_id(
    session_id: str,
    actor_id: str,
    operation: LeaseOperation | str,
    object_ref: str,
    approval_hash: str,
    issued_at_ns: int,
) -> str:
    material = "|".join(
        (
            session_id,
            actor_id,
            str(LeaseOperation(operation).value),
            _stable_object_ref(object_ref),
            approval_hash,
            str(issued_at_ns),
        )
    )
    return "lease_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]
