from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Sequence, Set

from benchmark_runner import BenchmarkCase, BenchmarkResult, PhiBenchmarkRunner
from llm_channel import ChannelEnvelope, ChannelType
from ot_gate import DeclaredScope, SideEffect


class AdapterActionType(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    SHELL = "shell"
    NETWORK = "network"
    REGISTRY = "registry"


class ActionDomain(str, Enum):
    GENERAL = "GENERAL"
    FILE_SYSTEM_MANAGEMENT = "FILE_SYSTEM_MANAGEMENT"
    SYSTEM_REMEDIATION = "SYSTEM_REMEDIATION"
    SYSTEM_CONFIGURATION_SETUP = "SYSTEM_CONFIGURATION_SETUP"
    NETWORK_OR_EXTERNAL_IO = "NETWORK_OR_EXTERNAL_IO"
    SECRET_HANDLING = "SECRET_HANDLING"
    AUDIT_OR_REGISTRY_CONTROL = "AUDIT_OR_REGISTRY_CONTROL"
    TOOL_OR_PERMISSION_AUTHORIZATION = "TOOL_OR_PERMISSION_AUTHORIZATION"


class AdapterMode(str, Enum):
    DRY_RUN = "dry_run"
    EXECUTE_IF_ALLOWED = "execute_if_allowed"


class AdapterDisposition(str, Enum):
    DRY_RUN_ALLOW = "DRY_RUN_ALLOW"
    DRY_RUN_STOP = "DRY_RUN_STOP"


@dataclass(frozen=True)
class ActionEnvelope:
    """
    Normalized adapter action.

    Agent-specific adapters should translate tool calls into this shape. The
    envelope is testimony only; it cannot execute and cannot grant authority.
    """

    actor_id: str
    action_type: AdapterActionType
    command_text: str
    cwd: str
    channel_type: ChannelType | str = ChannelType.AGENT_PROPOSAL
    action_domain: ActionDomain | str = ActionDomain.GENERAL
    target_paths: Sequence[str] = field(default_factory=tuple)
    expected_side_effects: Set[SideEffect] = field(default_factory=set)
    declared_scope: DeclaredScope | str | None = None
    source_adapter: str = "generic"
    tool_name: str = ""
    raw_payload: Dict[str, Any] = field(default_factory=dict)
    branch_id: str = "adapter_branch"
    action_id: str = "adapter_action"
    parent_event_id: str = "adapter_parent"
    user_request_id: str = "adapter_user_request"

    def __post_init__(self):
        if not self.actor_id.strip():
            raise ValueError("actor_id must be non-empty.")

        if isinstance(self.action_type, str):
            object.__setattr__(self, "action_type", AdapterActionType(self.action_type))

        if isinstance(self.channel_type, str):
            object.__setattr__(self, "channel_type", ChannelType(self.channel_type))

        if not isinstance(self.action_domain, ActionDomain):
            object.__setattr__(
                self,
                "action_domain",
                _coerce_action_domain(self.action_domain),
            )

        if not self.command_text.strip():
            raise ValueError("command_text must be non-empty.")

        if not self.cwd.strip():
            raise ValueError("cwd must be non-empty.")

        if not self.branch_id.strip():
            raise ValueError("branch_id must be non-empty.")

        if not self.action_id.strip():
            raise ValueError("action_id must be non-empty.")

        if isinstance(self.declared_scope, str):
            object.__setattr__(
                self,
                "declared_scope",
                DeclaredScope(self.declared_scope),
            )

        object.__setattr__(
            self,
            "target_paths",
            tuple(str(target) for target in self.target_paths),
        )
        object.__setattr__(
            self,
            "expected_side_effects",
            {
                effect if isinstance(effect, SideEffect) else SideEffect(effect)
                for effect in self.expected_side_effects
            },
        )
        object.__setattr__(self, "raw_payload", dict(self.raw_payload))

    @property
    def can_execute(self) -> bool:
        return False

    @property
    def can_grant_permission(self) -> bool:
        return False

    def to_channel_envelope(self) -> ChannelEnvelope:
        effects = self.expected_side_effects or _default_effects(self.action_type)
        declared_scope = self.declared_scope or _default_declared_scope(self.action_type)
        return ChannelEnvelope(
            channel_type=self.channel_type,
            source_id=self.actor_id,
            content=self.command_text,
            branch_id=self.branch_id,
            envelope_id=self.action_id,
            parent_event_id=self.parent_event_id,
            user_request_id=self.user_request_id,
            metadata={
                "cwd": self.cwd,
                "declared_scope": declared_scope,
                "target_paths": tuple(self.target_paths),
                "expected_side_effects": set(effects),
                "source_adapter": self.source_adapter,
                "tool_name": self.tool_name,
                "action_type": self.action_type.value,
                "action_domain": self.action_domain.value,
                "raw_payload": dict(self.raw_payload),
                "can_execute": False,
                "can_grant_permission": False,
            },
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "action_type": self.action_type.value,
            "action_domain": self.action_domain.value,
            "channel_type": self.channel_type.value,
            "command_text": self.command_text,
            "cwd": self.cwd,
            "target_paths": tuple(self.target_paths),
            "expected_side_effects": tuple(
                effect.value for effect in self.expected_side_effects
            ),
            "declared_scope": (
                self.declared_scope.value
                if isinstance(self.declared_scope, DeclaredScope)
                else self.declared_scope
            ),
            "source_adapter": self.source_adapter,
            "tool_name": self.tool_name,
            "raw_payload_keys": tuple(sorted(str(key) for key in self.raw_payload)),
            "branch_id": self.branch_id,
            "action_id": self.action_id,
            "parent_event_id": self.parent_event_id,
            "user_request_id": self.user_request_id,
            "can_execute": False,
            "can_grant_permission": False,
        }


@dataclass(frozen=True)
class AdapterWallPolicy:
    project_root: str
    registered_actors: Sequence[str]
    mode: AdapterMode = AdapterMode.DRY_RUN

    def __post_init__(self):
        if not self.project_root.strip():
            raise ValueError("project_root must be non-empty.")

        if isinstance(self.mode, str):
            object.__setattr__(self, "mode", AdapterMode(self.mode))

        if self.mode != AdapterMode.DRY_RUN:
            raise ValueError("Adapter Wall v0 only supports dry_run mode.")

        object.__setattr__(
            self,
            "registered_actors",
            tuple(str(actor) for actor in self.registered_actors),
        )


@dataclass(frozen=True)
class AdapterWallResult:
    action: ActionEnvelope
    channel_envelope: ChannelEnvelope
    benchmark_result: BenchmarkResult
    disposition: AdapterDisposition
    stop_stage: str
    reason_code: str
    would_execute_if_enabled: bool
    io_executed: bool = False
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self):
        if isinstance(self.disposition, str):
            object.__setattr__(
                self,
                "disposition",
                AdapterDisposition(self.disposition),
            )

        object.__setattr__(self, "io_executed", False)
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    @property
    def allowed_by_phi(self) -> bool:
        return not self.benchmark_result.phi.stopped

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.to_dict(),
            "channel": self.channel_envelope.to_dict(),
            "disposition": self.disposition.value,
            "stop_stage": self.stop_stage,
            "reason_code": self.reason_code,
            "would_execute_if_enabled": self.would_execute_if_enabled,
            "io_executed": False,
            "can_execute": False,
            "can_grant_permission": False,
            "phi": self.benchmark_result.phi.to_dict(),
        }


@dataclass(frozen=True)
class AdapterBatchResult:
    actions: Sequence[ActionEnvelope]
    channel_envelopes: Sequence[ChannelEnvelope]
    benchmark_result: BenchmarkResult
    disposition: AdapterDisposition
    stop_stage: str
    reason_code: str
    would_execute_if_enabled: bool
    io_executed: bool = False
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self):
        object.__setattr__(self, "actions", tuple(self.actions))
        object.__setattr__(self, "channel_envelopes", tuple(self.channel_envelopes))
        if isinstance(self.disposition, str):
            object.__setattr__(
                self,
                "disposition",
                AdapterDisposition(self.disposition),
            )
        object.__setattr__(self, "io_executed", False)
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actions": tuple(action.to_dict() for action in self.actions),
            "channel_count": len(self.channel_envelopes),
            "disposition": self.disposition.value,
            "stop_stage": self.stop_stage,
            "reason_code": self.reason_code,
            "would_execute_if_enabled": self.would_execute_if_enabled,
            "io_executed": False,
            "can_execute": False,
            "can_grant_permission": False,
            "phi": self.benchmark_result.phi.to_dict(),
        }


@dataclass(frozen=True)
class AdapterExecutionReceipt:
    disposition: AdapterDisposition
    reason_code: str
    executed: bool = False
    io_executed: bool = False
    can_execute: bool = False
    can_grant_permission: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "executed": False,
            "io_executed": False,
            "can_execute": False,
            "can_grant_permission": False,
        }


class AdapterWall:
    """
    Dry-run adapter boundary.

    v0 normalizes external agent actions and sends them through the existing
    Phi audit chain. It never executes shell/file/network actions, even when
    Phi returns ALLOW.
    """

    def __init__(self, policy: AdapterWallPolicy):
        self.policy = policy
        self.runner = PhiBenchmarkRunner(project_root=policy.project_root)

    def review(self, action: ActionEnvelope) -> AdapterWallResult:
        channel = action.to_channel_envelope()
        benchmark_result = self._run_case(
            case_id=f"adapter:{action.action_id}",
            envelopes=(channel,),
        )
        disposition = _adapter_disposition(benchmark_result)
        return AdapterWallResult(
            action=action,
            channel_envelope=channel,
            benchmark_result=benchmark_result,
            disposition=disposition,
            stop_stage=benchmark_result.phi.stop_stage,
            reason_code=benchmark_result.phi.reason_code,
            would_execute_if_enabled=not benchmark_result.phi.stopped,
        )

    def review_batch(
        self,
        actions: Sequence[ActionEnvelope],
        *,
        case_id: str = "adapter:batch",
    ) -> AdapterBatchResult:
        actions = tuple(actions)
        if not actions:
            raise ValueError("actions must be non-empty.")

        channels = tuple(action.to_channel_envelope() for action in actions)
        benchmark_result = self._run_case(
            case_id=case_id,
            envelopes=channels,
        )
        disposition = _adapter_disposition(benchmark_result)
        return AdapterBatchResult(
            actions=actions,
            channel_envelopes=channels,
            benchmark_result=benchmark_result,
            disposition=disposition,
            stop_stage=benchmark_result.phi.stop_stage,
            reason_code=benchmark_result.phi.reason_code,
            would_execute_if_enabled=not benchmark_result.phi.stopped,
        )

    def _run_case(
        self,
        *,
        case_id: str,
        envelopes: Sequence[ChannelEnvelope],
    ) -> BenchmarkResult:
        case = BenchmarkCase(
            case_id=case_id,
            description="Adapter Wall dry-run review.",
            should_stop=False,
            envelopes=envelopes,
            registered_actors=self.policy.registered_actors,
        )
        return self.runner.run_case(case)


class DryRunExecutor:
    """
    Execution placeholder for Adapter Wall v0.

    It deliberately never executes, including when Phi allows the action.
    """

    def execute(self, result: AdapterWallResult | AdapterBatchResult) -> AdapterExecutionReceipt:
        return AdapterExecutionReceipt(
            disposition=result.disposition,
            reason_code="DRY_RUN_NO_EXECUTION",
            executed=False,
            io_executed=False,
        )


def codex_shell_action(
    *,
    actor_id: str,
    command_text: str,
    cwd: str,
    action_id: str,
    branch_id: str,
    user_request_id: str,
    parent_event_id: str = "adapter_parent",
    expected_side_effects: Set[SideEffect] | None = None,
    target_paths: Sequence[str] = (),
    action_domain: ActionDomain | str = ActionDomain.GENERAL,
) -> ActionEnvelope:
    return ActionEnvelope(
        actor_id=actor_id,
        action_type=AdapterActionType.SHELL,
        action_domain=action_domain,
        command_text=command_text,
        cwd=cwd,
        target_paths=target_paths,
        expected_side_effects=expected_side_effects or set(),
        source_adapter="codex_vscode",
        tool_name="shell",
        branch_id=branch_id,
        action_id=action_id,
        parent_event_id=parent_event_id,
        user_request_id=user_request_id,
    )


def openclaw_tool_action(
    *,
    actor_id: str,
    tool_name: str,
    command_text: str,
    cwd: str,
    action_id: str,
    branch_id: str,
    user_request_id: str,
    raw_payload: Dict[str, Any],
    action_type: AdapterActionType = AdapterActionType.SHELL,
    parent_event_id: str = "adapter_parent",
    expected_side_effects: Set[SideEffect] | None = None,
    target_paths: Sequence[str] = (),
    action_domain: ActionDomain | str = ActionDomain.GENERAL,
) -> ActionEnvelope:
    return ActionEnvelope(
        actor_id=actor_id,
        action_type=action_type,
        action_domain=action_domain,
        command_text=command_text,
        cwd=cwd,
        target_paths=target_paths,
        expected_side_effects=expected_side_effects or set(),
        source_adapter="openclaw",
        tool_name=tool_name,
        raw_payload=raw_payload,
        branch_id=branch_id,
        action_id=action_id,
        parent_event_id=parent_event_id,
        user_request_id=user_request_id,
    )


def _adapter_disposition(result: BenchmarkResult) -> AdapterDisposition:
    if result.phi.stopped:
        return AdapterDisposition.DRY_RUN_STOP
    return AdapterDisposition.DRY_RUN_ALLOW


def _default_effects(action_type: AdapterActionType) -> Set[SideEffect]:
    mapping = {
        AdapterActionType.FILE_READ: {SideEffect.READ},
        AdapterActionType.FILE_WRITE: {SideEffect.WRITE},
        AdapterActionType.FILE_DELETE: {SideEffect.DELETE},
        AdapterActionType.SHELL: {SideEffect.READ},
        AdapterActionType.NETWORK: {SideEffect.NETWORK},
        AdapterActionType.REGISTRY: {SideEffect.AUDIT_CHANGE},
    }
    return set(mapping[action_type])


def _default_declared_scope(action_type: AdapterActionType) -> DeclaredScope:
    mapping = {
        AdapterActionType.FILE_READ: DeclaredScope.READ_ONLY,
        AdapterActionType.FILE_WRITE: DeclaredScope.PROJECT_WRITE,
        AdapterActionType.FILE_DELETE: DeclaredScope.PROJECT_WRITE,
        AdapterActionType.SHELL: DeclaredScope.READ_ONLY,
        AdapterActionType.NETWORK: DeclaredScope.EXTERNAL_IO,
        AdapterActionType.REGISTRY: DeclaredScope.ADMIN,
    }
    return mapping[action_type]


def _coerce_action_domain(value: str) -> ActionDomain:
    text = str(value).strip().upper().replace("-", "_").replace(" ", "_")
    return ActionDomain(text)
