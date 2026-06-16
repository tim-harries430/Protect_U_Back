from __future__ import annotations

import shlex
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adapter_wall import ActionDomain, ActionEnvelope, AdapterActionType
from harness_adapter import normalize_harness_event
from llm_channel import ChannelType
from ot_gate import DeclaredScope, SideEffect
from parallel_audit import EvidenceDisposition, ParallelAuditDecision
from phi_registry import ActorType, PhiRegistry
from protect_scan import confirm_protect_scan, default_protect_scan_profile
from xray_review import audit_with_xray_review


BLOCKING_DISPOSITIONS = frozenset(
    {
        EvidenceDisposition.HOLD,
        EvidenceDisposition.KILL,
        EvidenceDisposition.QUARANTINE,
        EvidenceDisposition.REJECT,
    }
)


@dataclass(frozen=True)
class ShellPreflightResult:
    action: ActionEnvelope
    decision: ParallelAuditDecision
    allowed_to_call_original: bool
    io_executed: bool = False
    can_execute: bool = False
    can_grant_permission: bool = False

    @property
    def blocked(self) -> bool:
        return not self.allowed_to_call_original

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.to_dict(),
            "decision": self.decision.to_dict(),
            "allowed_to_call_original": self.allowed_to_call_original,
            "blocked": self.blocked,
            "io_executed": False,
            "can_execute": False,
            "can_grant_permission": False,
        }

    def blocked_message(self) -> str:
        decision = self.decision
        return "\n".join(
            (
                "Protect U Back blocked this harness tool call before subprocess I/O.",
                f"Final disposition: {decision.disposition.value}",
                f"Primary stage: {decision.primary_stage.value}",
                f"Reason: {decision.reason_code}",
                f"would_enter_ot={str(decision.would_enter_ot).lower()}",
                "io_executed=false",
                "can_execute=false",
                "can_grant_permission=false",
            )
        )


@dataclass(frozen=True)
class BlockedToolResult:
    output: str
    metadata: dict[str, Any]
    is_error: bool = True
    executed: bool = False
    io_executed: bool = False
    can_execute: bool = False
    can_grant_permission: bool = False

    @classmethod
    def from_preflight(cls, result: ShellPreflightResult) -> "BlockedToolResult":
        return cls(
            output=result.blocked_message(),
            metadata={
                "protect_u_back": result.to_dict(),
                "io_executed": False,
                "can_execute": False,
                "can_grant_permission": False,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "output": self.output,
            "is_error": self.is_error,
            "metadata": dict(self.metadata),
            "executed": False,
            "io_executed": False,
            "can_execute": False,
            "can_grant_permission": False,
        }


class ProtectPreflightBlocked(RuntimeError):
    def __init__(self, result: ShellPreflightResult):
        self.result = result
        super().__init__(result.blocked_message())

    def to_metadata(self) -> dict[str, Any]:
        return {
            "protect_u_back": self.result.to_dict(),
            "io_executed": False,
            "can_execute": False,
            "can_grant_permission": False,
        }


@dataclass(frozen=True)
class ProtectGate:
    """
    Inline gate for agent tool runners.

    Tool runners should call this before touching real I/O. The gate calls the
    original tool only when the audit returns PASS.
    """

    project_root: str | Path | None = None
    actor_id: str = "agent_tool_runner"
    source_adapter: str = "generic"
    tool_name: str = "tool"
    sandbox_available: bool | None = None
    sandbox_reason: str = ""
    sandbox_fallback: str = "unsandboxed_tool_requested"

    def audit_tool_call(
        self,
        tool_call: Mapping[str, Any],
        *,
        project_root: str | Path | None = None,
        source_adapter: str | None = None,
    ) -> ShellPreflightResult:
        event = dict(tool_call)
        event.setdefault("actor_id", self.actor_id)
        event.setdefault("source_adapter", source_adapter or self.source_adapter)
        event.setdefault("tool_name", self.tool_name)
        event.setdefault("channel_type", ChannelType.AGENT_PROPOSAL.value)
        event.setdefault("action_id", "protect_gate_tool_call")
        event.setdefault("branch_id", "protect_gate_branch")
        event.setdefault("parent_event_id", "protect_gate_parent")
        event.setdefault("user_request_id", "protect_gate_user_request")
        metadata = dict(event.get("metadata") or {})
        metadata["can_execute"] = False
        metadata["can_grant_permission"] = False
        event["metadata"] = metadata
        if self.sandbox_available is not None and "sandbox" not in event:
            event["sandbox"] = {
                "available": bool(self.sandbox_available),
                "reason": self.sandbox_reason or "sandbox unavailable",
                "fallback": self.sandbox_fallback,
            }
        return audit_harness_event(
            event,
            project_root=project_root or self.project_root,
            source_adapter=source_adapter or self.source_adapter,
        )

    def guard_tool_call(
        self,
        tool_call: Mapping[str, Any],
        original_tool: Callable[..., Any],
        *tool_args: Any,
        project_root: str | Path | None = None,
        source_adapter: str | None = None,
        **tool_kwargs: Any,
    ) -> Any:
        result = self.audit_tool_call(
            tool_call,
            project_root=project_root,
            source_adapter=source_adapter,
        )
        if result.decision.disposition in BLOCKING_DISPOSITIONS:
            return BlockedToolResult.from_preflight(result)
        return original_tool(*tool_args, **tool_kwargs)

    async def guard_tool_call_async(
        self,
        tool_call: Mapping[str, Any],
        original_tool: Callable[..., Awaitable[Any]],
        *tool_args: Any,
        project_root: str | Path | None = None,
        source_adapter: str | None = None,
        **tool_kwargs: Any,
    ) -> Any:
        result = self.audit_tool_call(
            tool_call,
            project_root=project_root,
            source_adapter=source_adapter,
        )
        if result.decision.disposition in BLOCKING_DISPOSITIONS:
            return BlockedToolResult.from_preflight(result)
        return await original_tool(*tool_args, **tool_kwargs)

    def guard_shell_call(
        self,
        command: str,
        original_shell: Callable[..., Any],
        *tool_args: Any,
        cwd: str | Path | None = None,
        project_root: str | Path | None = None,
        source_adapter: str | None = None,
        tool_name: str = "bash",
        **tool_kwargs: Any,
    ) -> Any:
        event = _shell_event(
            command=command,
            cwd=str(cwd or project_root or self.project_root or "."),
            actor_id=self.actor_id,
            source_adapter=source_adapter or self.source_adapter,
            tool_name=tool_name,
            action_id="protect_gate_shell_call",
            branch_id="protect_gate_shell_branch",
            parent_event_id="protect_gate_shell_parent",
            user_request_id="protect_gate_shell_user_request",
            action_type=AdapterActionType.SHELL,
            action_domain=None,
            declared_scope=None,
            expected_side_effects=(),
            target_paths=(),
            sandbox_available=self.sandbox_available,
            sandbox_reason=self.sandbox_reason,
            sandbox_fallback=self.sandbox_fallback,
            raw_payload=None,
        )
        return self.guard_tool_call(
            event,
            original_shell,
            *tool_args,
            project_root=project_root,
            source_adapter=source_adapter,
            **tool_kwargs,
        )


def audit_harness_event(
    event: Mapping[str, Any],
    *,
    project_root: str | Path | None = None,
    source_adapter: str = "generic",
) -> ShellPreflightResult:
    project_root_text = _project_root_text(
        project_root=project_root,
        cwd=_event_cwd(event),
    )
    action = normalize_harness_event(
        event,
        project_root=project_root_text,
        source_adapter=source_adapter,
    )
    registry = PhiRegistry()
    registry.register_actor(action.actor_id, ActorType.AGENT)
    profile = confirm_protect_scan(
        default_protect_scan_profile(project_root_text),
        confirmed=True,
    )
    decision = audit_with_xray_review(
        action,
        registry=registry,
        project_root=project_root_text,
        protect_profile=profile,
    )
    allowed = decision.disposition == EvidenceDisposition.PASS
    return ShellPreflightResult(
        action=action,
        decision=decision,
        allowed_to_call_original=allowed,
    )


def audit_shell_subprocess(
    command: str,
    *,
    cwd: str | Path | None = None,
    project_root: str | Path | None = None,
    actor_id: str = "openharness_bash",
    source_adapter: str = "openharness",
    tool_name: str = "bash",
    action_id: str = "openharness_shell_preflight",
    branch_id: str = "openharness_shell_branch",
    parent_event_id: str = "openharness_shell_parent",
    user_request_id: str = "openharness_shell_user_request",
    action_type: AdapterActionType | str | None = None,
    action_domain: ActionDomain | str | None = None,
    declared_scope: DeclaredScope | str | None = None,
    expected_side_effects: Sequence[SideEffect | str] = (),
    target_paths: Sequence[str | Path] = (),
    sandbox_available: bool | None = None,
    sandbox_reason: str = "",
    sandbox_fallback: str = "unsandboxed_shell_requested",
    raw_payload: Mapping[str, Any] | None = None,
) -> ShellPreflightResult:
    """
    Audit a harness shell proposal before create_shell_subprocess commits I/O.

    This function is intended to run at the start of an external harness shell
    creation path. It never executes the command and never grants authority.
    """

    project_root_text = _project_root_text(project_root=project_root, cwd=cwd)
    cwd_text = str(cwd or project_root_text)
    event = _shell_event(
        command=command,
        cwd=cwd_text,
        actor_id=actor_id,
        source_adapter=source_adapter,
        tool_name=tool_name,
        action_id=action_id,
        branch_id=branch_id,
        parent_event_id=parent_event_id,
        user_request_id=user_request_id,
        action_type=action_type,
        action_domain=action_domain,
        declared_scope=declared_scope,
        expected_side_effects=expected_side_effects,
        target_paths=target_paths,
        sandbox_available=sandbox_available,
        sandbox_reason=sandbox_reason,
        sandbox_fallback=sandbox_fallback,
        raw_payload=raw_payload,
    )
    return audit_harness_event(
        event,
        project_root=project_root_text,
        source_adapter=source_adapter,
    )


def enforce_shell_subprocess_preflight(
    command: str,
    **kwargs: Any,
) -> ShellPreflightResult:
    result = audit_shell_subprocess(command, **kwargs)
    if result.decision.disposition in BLOCKING_DISPOSITIONS:
        raise ProtectPreflightBlocked(result)
    return result


def enforce_openharness_shell_preflight(
    command: str,
    *,
    cwd: str | Path | None = None,
    settings: Any = None,
) -> ShellPreflightResult:
    sandbox_available, sandbox_reason, sandbox_fallback = _openharness_sandbox_state(settings)
    return enforce_shell_subprocess_preflight(
        command,
        cwd=cwd,
        project_root=cwd,
        actor_id="openharness_shell",
        source_adapter="openharness",
        tool_name="create_shell_subprocess",
        action_id="openharness_create_shell_subprocess",
        branch_id="openharness_shell_branch",
        user_request_id="openharness_shell_user_request",
        sandbox_available=sandbox_available,
        sandbox_reason=sandbox_reason,
        sandbox_fallback=sandbox_fallback,
    )


async def guarded_create_shell_subprocess(
    create_shell_subprocess: Callable[..., Awaitable[Any]],
    command: str,
    *,
    cwd: str | Path | None = None,
    project_root: str | Path | None = None,
    actor_id: str = "openharness_bash",
    source_adapter: str = "openharness",
    tool_name: str = "bash",
    action_id: str = "openharness_shell_preflight",
    branch_id: str = "openharness_shell_branch",
    parent_event_id: str = "openharness_shell_parent",
    user_request_id: str = "openharness_shell_user_request",
    action_type: AdapterActionType | str | None = None,
    action_domain: ActionDomain | str | None = None,
    declared_scope: DeclaredScope | str | None = None,
    expected_side_effects: Sequence[SideEffect | str] = (),
    target_paths: Sequence[str | Path] = (),
    sandbox_available: bool | None = None,
    sandbox_reason: str = "",
    sandbox_fallback: str = "unsandboxed_shell_requested",
    raw_payload: Mapping[str, Any] | None = None,
    **subprocess_kwargs: Any,
) -> Any:
    enforce_shell_subprocess_preflight(
        command,
        cwd=cwd,
        project_root=project_root,
        actor_id=actor_id,
        source_adapter=source_adapter,
        tool_name=tool_name,
        action_id=action_id,
        branch_id=branch_id,
        parent_event_id=parent_event_id,
        user_request_id=user_request_id,
        action_type=action_type,
        action_domain=action_domain,
        declared_scope=declared_scope,
        expected_side_effects=expected_side_effects,
        target_paths=target_paths,
        sandbox_available=sandbox_available,
        sandbox_reason=sandbox_reason,
        sandbox_fallback=sandbox_fallback,
        raw_payload=raw_payload,
    )
    call_kwargs = dict(subprocess_kwargs)
    if cwd is not None:
        call_kwargs["cwd"] = cwd
    return await create_shell_subprocess(command, **call_kwargs)


def _shell_event(
    *,
    command: str,
    cwd: str,
    actor_id: str,
    source_adapter: str,
    tool_name: str,
    action_id: str,
    branch_id: str,
    parent_event_id: str,
    user_request_id: str,
    action_type: AdapterActionType | str | None,
    action_domain: ActionDomain | str | None,
    declared_scope: DeclaredScope | str | None,
    expected_side_effects: Sequence[SideEffect | str],
    target_paths: Sequence[str | Path],
    sandbox_available: bool | None,
    sandbox_reason: str,
    sandbox_fallback: str,
    raw_payload: Mapping[str, Any] | None,
) -> dict[str, Any]:
    sampled_targets = tuple(str(path) for path in target_paths)
    if not sampled_targets:
        sampled_targets = _shell_command_targets(command)
    event: dict[str, Any] = {
        "source_adapter": source_adapter,
        "actor_id": actor_id,
        "tool_name": tool_name,
        "command": str(command),
        "cwd": cwd,
        "action_id": action_id,
        "branch_id": branch_id,
        "parent_event_id": parent_event_id,
        "user_request_id": user_request_id,
        "channel_type": ChannelType.AGENT_PROPOSAL.value,
        "target_paths": sampled_targets,
        "expected_side_effects": _effect_values(expected_side_effects),
        "metadata": {
            "can_execute": False,
            "can_grant_permission": False,
        },
    }
    if action_type is not None:
        event["action_type"] = _enum_value(action_type)
    if action_domain is not None:
        event["action_domain"] = _enum_value(action_domain)
        event["metadata"]["action_domain"] = _enum_value(action_domain)
    if declared_scope is not None:
        event["declared_scope"] = _enum_value(declared_scope)
        event["metadata"]["declared_scope"] = _enum_value(declared_scope)
    if sandbox_available is not None:
        event["sandbox"] = {
            "available": bool(sandbox_available),
            "reason": sandbox_reason or "sandbox unavailable",
            "fallback": sandbox_fallback,
        }
    if raw_payload:
        event["payload"] = dict(raw_payload)
    return event


def _shell_command_targets(command: str) -> tuple[str, ...]:
    try:
        tokens = shlex.split(str(command), posix=True)
    except ValueError:
        tokens = str(command).split()

    targets: list[str] = []
    skip_next = False
    for index, token in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        if not token:
            continue
        if token in {">", ">>", "1>", "1>>", "2>", "2>>"}:
            if index + 1 < len(tokens):
                targets.append(tokens[index + 1])
                skip_next = True
            continue
        if token.startswith((">", ">>", "1>", "1>>", "2>", "2>>")) and len(token) > 1:
            value = token.lstrip("0123456789>")
            if value:
                targets.append(value)
            continue
        if token.startswith("-") or token in {"|", "&&", "||", ";"}:
            continue
        if index == 0:
            continue
        if _looks_like_target_token(token):
            targets.append(token)
    return tuple(dict.fromkeys(targets))


def _looks_like_target_token(token: str) -> bool:
    lowered = token.lower()
    if lowered.startswith(("http://", "https://")):
        return True
    if "/" in token or "\\" in token:
        return True
    return Path(token).suffix != ""


def _project_root_text(
    *,
    project_root: str | Path | None,
    cwd: str | Path | None,
) -> str:
    candidate = project_root or cwd or Path.cwd()
    return str(Path(candidate).expanduser().resolve(strict=False))


def _event_cwd(event: Mapping[str, Any]) -> str | Path | None:
    value = event.get("cwd")
    if value is not None:
        return str(value)
    metadata = event.get("metadata")
    if isinstance(metadata, Mapping) and metadata.get("cwd") is not None:
        return str(metadata["cwd"])
    context = event.get("context")
    if isinstance(context, Mapping) and context.get("cwd") is not None:
        return str(context["cwd"])
    return None


def _effect_values(values: Sequence[SideEffect | str]) -> tuple[str, ...]:
    return tuple(_enum_value(value) for value in values)


def _enum_value(value: Any) -> str:
    return str(value.value) if hasattr(value, "value") else str(value)


def _openharness_sandbox_state(settings: Any) -> tuple[bool | None, str, str]:
    sandbox = getattr(settings, "sandbox", None)
    if sandbox is None:
        return None, "", "openharness_shell"

    enabled = bool(getattr(sandbox, "enabled", False))
    backend = str(getattr(sandbox, "backend", "") or "")
    if not enabled:
        return False, "sandbox unavailable", "openharness_shell"
    if backend != "docker":
        return True, "", "openharness_shell"

    try:
        from openharness.sandbox.session import get_docker_sandbox

        session = get_docker_sandbox()
    except Exception as exc:
        return False, str(exc), "host_shell_requested"

    if session is not None and getattr(session, "is_running", False):
        return True, "", "openharness_shell"
    return False, "docker sandbox session is not running", "host_shell_requested"


__all__ = (
    "BlockedToolResult",
    "ProtectGate",
    "ProtectPreflightBlocked",
    "ShellPreflightResult",
    "audit_harness_event",
    "audit_shell_subprocess",
    "enforce_openharness_shell_preflight",
    "enforce_shell_subprocess_preflight",
    "guarded_create_shell_subprocess",
)
