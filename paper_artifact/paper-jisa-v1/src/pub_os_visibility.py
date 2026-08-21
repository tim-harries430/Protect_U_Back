from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from adapter_wall import ActionDomain, ActionEnvelope, AdapterActionType
from llm_channel import ChannelType
from opaque_executor import is_opaque_executor
from ot_gate import DeclaredScope, SideEffect


class SensorName(str, Enum):
    PROCESS = "process"
    FILESYSTEM = "filesystem"
    SCENE = "scene"
    AUDIT = "audit"
    NETWORK = "network"


class SensorStatus(str, Enum):
    READY = "READY"
    ABSENT = "ABSENT"
    DEGRADED = "DEGRADED"


class TouchKind(str, Enum):
    PROCESS_EXEC = "process_exec"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    FILE_RENAME = "file_rename"
    NETWORK_CONNECT = "network_connect"
    ARTIFACT_USE = "artifact_use"


class VisibilityDecision(str, Enum):
    PASS = "PASS"
    HOLD = "HOLD"


class ObservationState(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNOBSERVED = "UNOBSERVED"


class ObservationSource(str, Enum):
    # PROPOSAL: the touch is reconstructed from the agent's own declared action
    #   (cc hook / cd argv), through the same lexical extraction the proposal
    #   chain already uses. It is a declaration, not an eyewitness record.
    # SENSOR: the touch came from a real local sensor that observed the object
    #   being touched. v1 ships no such sensor; this value is reserved for it.
    PROPOSAL = "PROPOSAL"
    SENSOR = "SENSOR"


@dataclass(frozen=True)
class SensorState:
    name: SensorName | str
    status: SensorStatus | str
    required: bool = True
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", SensorName(self.name))
        object.__setattr__(self, "status", SensorStatus(self.status))
        object.__setattr__(self, "detail", str(self.detail))

    @property
    def ready(self) -> bool:
        return self.status == SensorStatus.READY

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "status": self.status.value,
            "required": bool(self.required),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class VisibilityReceipt:
    decision: VisibilityDecision | str
    reason_code: str
    session_id: str
    event_id: str = ""
    evidence: Sequence[str] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    payload_captured: bool = False
    llm_visible: bool = False
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", VisibilityDecision(self.decision))
        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))
        object.__setattr__(self, "metadata", _safe_metadata(self.metadata))
        object.__setattr__(self, "payload_captured", False)
        object.__setattr__(self, "llm_visible", False)
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "session_id": self.session_id,
            "event_id": self.event_id,
            "evidence": tuple(self.evidence),
            "metadata": dict(self.metadata),
            "payload_captured": False,
            "llm_visible": False,
            "can_execute": False,
            "can_grant_permission": False,
        }


@dataclass(frozen=True)
class KingdomSession:
    session_id: str
    actor_id: str
    project_root: str
    cwd: str
    sensors: Sequence[SensorState] = field(default_factory=tuple)
    network_sensor_required: bool = False

    def __post_init__(self) -> None:
        if not self.session_id.strip():
            raise ValueError("session_id is required")
        if not self.actor_id.strip():
            raise ValueError("actor_id is required")
        object.__setattr__(self, "project_root", str(Path(self.project_root).resolve(strict=False)))
        object.__setattr__(self, "cwd", str(Path(self.cwd).resolve(strict=False)))
        object.__setattr__(self, "sensors", tuple(_sensor(sensor) for sensor in self.sensors))

    def sensor(self, name: SensorName | str) -> SensorState | None:
        name = SensorName(name)
        return next((sensor for sensor in self.sensors if sensor.name == name), None)

    @property
    def network_sensor_ready(self) -> bool:
        sensor = self.sensor(SensorName.NETWORK)
        return sensor is not None and sensor.ready

    def launch_barrier(self) -> VisibilityReceipt:
        missing = [sensor for sensor in self.sensors if sensor.required and not sensor.ready]
        network = self.sensor(SensorName.NETWORK)
        if self.network_sensor_required and (network is None or not network.ready):
            missing.append(network or SensorState(SensorName.NETWORK, SensorStatus.ABSENT))
        if missing:
            return VisibilityReceipt(
                VisibilityDecision.HOLD,
                "KINGDOM_SENSOR_NOT_READY",
                self.session_id,
                evidence=tuple(f"{item.name.value}:{item.status.value}" for item in missing),
            )
        evidence = ("network:ABSENT",) if network is None or not network.ready else ()
        return VisibilityReceipt(
            VisibilityDecision.PASS,
            "KINGDOM_READY",
            self.session_id,
            evidence=evidence,
            metadata={"network_sensor": "ABSENT" if evidence else "READY"},
        )


@dataclass(frozen=True)
class ObjectTouchEvent:
    session_id: str
    event_id: str
    pid: int
    ppid: int
    actor_id: str
    kind: TouchKind | str
    object_ref: str
    process_image: str = ""
    command_text: str = ""
    cwd: str = ""
    source: str = "pub_os_proposal"
    metadata: Mapping[str, Any] = field(default_factory=dict)
    payload_captured: bool = False
    llm_visible: bool = False
    observation_source: ObservationSource | str = ObservationSource.PROPOSAL

    def __post_init__(self) -> None:
        if self.payload_captured:
            raise ValueError("PUB-OS visibility receipts must not capture payload")
        if self.llm_visible:
            raise ValueError("PUB-OS sensor logs are not LLM-visible by default")
        if not self.event_id.strip():
            raise ValueError("event_id is required")
        object.__setattr__(self, "kind", TouchKind(self.kind))
        object.__setattr__(self, "metadata", _safe_metadata(self.metadata))
        object.__setattr__(self, "payload_captured", False)
        object.__setattr__(self, "llm_visible", False)
        object.__setattr__(self, "observation_source", ObservationSource(self.observation_source))

    @property
    def command_hash(self) -> str:
        return _sha256(self.command_text) if self.command_text else ""

    def public_metadata(self) -> dict[str, Any]:
        data = {
            "pid": int(self.pid),
            "ppid": int(self.ppid),
            "process_image": self.process_image,
            "kind": self.kind.value,
            "object_ref": self.object_ref,
            "command_sha256": self.command_hash,
            "observation_source": self.observation_source.value,
            "payload_captured": False,
            "llm_visible": False,
        }
        data.update(self.metadata)
        return _safe_metadata(data)


@dataclass(frozen=True)
class SensorFeed:
    feed_id: str
    session_id: str
    action_id: str
    proposal_id: str
    sensor_states: Sequence[SensorState]
    events: Sequence[ObjectTouchEvent] = field(default_factory=tuple)
    source_adapter: str = "pub_os_visibility"
    observation_state: ObservationState | str = ObservationState.PARTIAL
    gaps: Sequence[str] = field(default_factory=tuple)
    testimony_only: bool = True
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "sensor_states", tuple(_sensor(item) for item in self.sensor_states))
        object.__setattr__(self, "events", tuple(self.events))
        object.__setattr__(self, "observation_state", ObservationState(self.observation_state))
        object.__setattr__(self, "gaps", tuple(str(item) for item in self.gaps))
        object.__setattr__(self, "testimony_only", True)
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "session_id": self.session_id,
            "action_id": self.action_id,
            "proposal_id": self.proposal_id,
            "source_adapter": self.source_adapter,
            "sensor_states": tuple(item.to_dict() for item in self.sensor_states),
            "observation_state": self.observation_state.value,
            "gaps": tuple(self.gaps),
            "events": tuple(event.public_metadata() for event in self.events),
            "testimony_only": True,
            "can_execute": False,
            "can_grant_permission": False,
        }


def default_kingdom_session(
    *,
    session_id: str,
    actor_id: str,
    project_root: str,
    cwd: str | None = None,
    network_sensor: SensorStatus | str = SensorStatus.ABSENT,
) -> KingdomSession:
    return KingdomSession(
        session_id=session_id,
        actor_id=actor_id,
        project_root=project_root,
        cwd=cwd or project_root,
        sensors=(
            SensorState(SensorName.PROCESS, SensorStatus.READY),
            SensorState(SensorName.FILESYSTEM, SensorStatus.READY),
            SensorState(SensorName.SCENE, SensorStatus.READY),
            SensorState(SensorName.AUDIT, SensorStatus.READY),
            SensorState(SensorName.NETWORK, network_sensor, required=False),
        ),
    )


def receipt_for_touch(event: ObjectTouchEvent, session: KingdomSession) -> VisibilityReceipt:
    if event.session_id != session.session_id:
        return VisibilityReceipt(
            VisibilityDecision.HOLD,
            "KINGDOM_EVENT_SESSION_MISMATCH",
            session.session_id,
            event.event_id,
            evidence=(event.session_id,),
        )
    if event.kind == TouchKind.ARTIFACT_USE or event.metadata.get("downloaded_artifact"):
        return VisibilityReceipt(
            VisibilityDecision.HOLD,
            "PUB_OS_ARTIFACT_REQUIRES_ADMISSION",
            session.session_id,
            event.event_id,
            evidence=(event.object_ref,),
            metadata=event.public_metadata(),
        )
    if event.kind == TouchKind.PROCESS_EXEC:
        opaque, evidence = is_opaque_executor(event.command_text)
        if opaque and not session.network_sensor_ready:
            return VisibilityReceipt(
                VisibilityDecision.HOLD,
                "PUB_OS_OPAQUE_EXECUTION_HOLD",
                session.session_id,
                event.event_id,
                evidence=tuple(evidence) + ("network_sensor:ABSENT",),
                metadata=event.public_metadata(),
            )
        if event.metadata.get("runtime_modellable") is not True and not session.network_sensor_ready:
            return VisibilityReceipt(
                VisibilityDecision.HOLD,
                "PUB_OS_UNKNOWN_RUNTIME_HOLD",
                session.session_id,
                event.event_id,
                evidence=("runtime_modellable:false_or_missing", "network_sensor:ABSENT"),
                metadata=event.public_metadata(),
            )
    return VisibilityReceipt(
        VisibilityDecision.PASS,
        "PUB_OS_TOUCH_OBSERVED",
        session.session_id,
        event.event_id,
        metadata=event.public_metadata(),
    )


def action_envelope_from_touch(event: ObjectTouchEvent, *, project_root: str) -> ActionEnvelope:
    action_type, effects, scope = _shape(event.kind)
    target_paths = () if event.kind == TouchKind.PROCESS_EXEC else (event.object_ref,)
    command = event.command_text or f"{event.kind.value} {event.object_ref}".strip()
    return ActionEnvelope(
        actor_id=event.actor_id,
        action_type=action_type,
        action_domain=_domain(event.kind, effects),
        channel_type=ChannelType.AGENT_PROPOSAL,
        command_text=command,
        cwd=event.cwd or project_root,
        target_paths=target_paths,
        expected_side_effects=effects,
        declared_scope=scope,
        source_adapter="pub_os_visibility",
        tool_name=event.kind.value,
        raw_payload={
            "pub_os_visibility": event.public_metadata(),
            "payload_captured": False,
            "llm_visible": False,
        },
        branch_id=event.session_id,
        action_id=event.event_id,
        parent_event_id=f"{event.session_id}:parent",
        user_request_id=f"{event.session_id}:user_request",
    )


def _shape(kind: TouchKind) -> tuple[AdapterActionType, set[SideEffect], DeclaredScope]:
    if kind in {TouchKind.FILE_READ, TouchKind.ARTIFACT_USE}:
        return AdapterActionType.FILE_READ, {SideEffect.READ}, DeclaredScope.READ_ONLY
    if kind in {TouchKind.FILE_WRITE, TouchKind.FILE_RENAME}:
        return AdapterActionType.FILE_WRITE, {SideEffect.WRITE}, DeclaredScope.PROJECT_WRITE
    if kind == TouchKind.FILE_DELETE:
        return AdapterActionType.FILE_DELETE, {SideEffect.DELETE}, DeclaredScope.PROJECT_WRITE
    if kind == TouchKind.NETWORK_CONNECT:
        return AdapterActionType.NETWORK, {SideEffect.NETWORK}, DeclaredScope.EXTERNAL_IO
    return AdapterActionType.SHELL, set(), DeclaredScope.READ_ONLY


def _domain(kind: TouchKind, effects: set[SideEffect]) -> ActionDomain:
    if kind == TouchKind.NETWORK_CONNECT or SideEffect.NETWORK in effects:
        return ActionDomain.NETWORK_OR_EXTERNAL_IO
    if kind in {
        TouchKind.FILE_READ,
        TouchKind.FILE_WRITE,
        TouchKind.FILE_DELETE,
        TouchKind.FILE_RENAME,
        TouchKind.ARTIFACT_USE,
    }:
        return ActionDomain.FILE_SYSTEM_MANAGEMENT
    return ActionDomain.GENERAL


def _sensor(value: SensorState | Mapping[str, Any]) -> SensorState:
    if isinstance(value, SensorState):
        return value
    return SensorState(**dict(value))


def _safe_metadata(values: Mapping[str, Any]) -> dict[str, Any]:
    blocked = {
        "allow",
        "body",
        "can_execute",
        "can_grant_permission",
        "content",
        "execute",
        "grant",
        "kill",
        "network_payload",
        "payload",
        "permission_granted",
        "raw_bytes",
    }
    clean: dict[str, Any] = {}
    for key, value in dict(values).items():
        if str(key).lower() in blocked:
            raise ValueError(f"sensor metadata must not include payload field: {key}")
        clean[str(key)] = value
    return clean


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
