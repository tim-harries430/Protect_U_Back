from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


class ProfileName(str, Enum):
    CD = "cd"
    CC = "cc"
    CODEX = "cd"
    CLAUDE_CODE = "cc"


class ProfileState(str, Enum):
    SUPERVISED = "SUPERVISED"
    HOLD = "HOLD"


def normalize_profile_name(profile: ProfileName | str) -> ProfileName:
    if isinstance(profile, ProfileName):
        return ProfileName(profile.value)
    aliases = {
        "cd": ProfileName.CD,
        "codex": ProfileName.CD,
        "cc": ProfileName.CC,
        "claude_code": ProfileName.CC,
        "claude-code": ProfileName.CC,
    }
    key = str(profile).strip().lower()
    try:
        return aliases[key]
    except KeyError as exc:
        raise ValueError(f"unknown agent profile: {profile!r}") from exc


@dataclass(frozen=True)
class ProfileReceipt:
    profile: ProfileName | str
    state: ProfileState | str
    reason_code: str
    evidence: Sequence[str] = field(default_factory=tuple)
    status: Mapping[str, Any] = field(default_factory=dict)
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile", normalize_profile_name(self.profile))
        object.__setattr__(self, "state", ProfileState(self.state))
        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))
        object.__setattr__(self, "status", dict(self.status))
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    @property
    def supervised(self) -> bool:
        return self.state == ProfileState.SUPERVISED

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.value,
            "state": self.state.value,
            "reason_code": self.reason_code,
            "evidence": tuple(self.evidence),
            "status": dict(self.status),
            "can_execute": False,
            "can_grant_permission": False,
        }


@dataclass(frozen=True)
class AgentRuntimeAdmission:
    active_profile: ProfileName | str
    receipt: ProfileReceipt
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "active_profile", normalize_profile_name(self.active_profile))
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    @property
    def state(self) -> ProfileState:
        if self.receipt.profile != self.active_profile:
            return ProfileState.HOLD
        if not self.receipt.supervised:
            return ProfileState.HOLD
        return ProfileState.SUPERVISED

    @property
    def reason_code(self) -> str:
        if self.receipt.profile != self.active_profile:
            return "AGENT_RUNTIME_PROFILE_MISMATCH"
        if self.state == ProfileState.SUPERVISED:
            return "AGENT_RUNTIME_SUPERVISED"
        return self.receipt.reason_code

    @property
    def evidence(self) -> tuple[str, ...]:
        if self.receipt.profile != self.active_profile:
            return (
                f"active_profile:{self.active_profile.value}",
                f"receipt_profile:{self.receipt.profile.value}",
            )
        return tuple(self.receipt.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_profile": self.active_profile.value,
            "state": self.state.value,
            "reason_code": self.reason_code,
            "evidence": tuple(self.evidence),
            "receipt": self.receipt.to_dict(),
            "can_execute": False,
            "can_grant_permission": False,
        }


KingdomSupervision = AgentRuntimeAdmission


def check_codex_profile(
    codex_project: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
    python_bin: str = "python3",
    status_fn: Callable[..., Mapping[str, Any]] | None = None,
) -> ProfileReceipt:
    if status_fn is None:
        from codex_connector import status_codex

        status_fn = status_codex
    status = dict(status_fn(codex_project, protect_root=protect_root, python_bin=python_bin))
    gaps: list[str] = []
    if status.get("connected") is not True:
        gaps.append("cd_connector:not_connected")
    if status.get("launcher_exists") is not True:
        gaps.append("cd_launcher:missing")
    if status.get("entry_exists") is not True:
        gaps.append("cd_entry:missing")
    if status.get("boundary") != "bwrap_shell_entry_bind_mount":
        gaps.append("cd_boundary:unexpected")
    if status.get("can_grant_permission") is not False:
        gaps.append("cd_connector:authority_leak")
    if gaps:
        return ProfileReceipt(
            ProfileName.CD,
            ProfileState.HOLD,
            "CD_PROFILE_NOT_SUPERVISED",
            evidence=tuple(gaps),
            status=status,
        )
    return ProfileReceipt(
        ProfileName.CD,
        ProfileState.SUPERVISED,
        "CD_PROFILE_SUPERVISED",
        evidence=("cd:bwrap_shell_guard_connected",),
        status=status,
    )


def check_claude_code_profile(
    claude_project: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
    python_bin: str = "python3",
    status_fn: Callable[..., Mapping[str, Any]] | None = None,
) -> ProfileReceipt:
    if status_fn is None:
        from claude_code_connector import status_claude_code

        status_fn = status_claude_code
    status = dict(status_fn(claude_project, protect_root=protect_root, python_bin=python_bin))
    gaps: list[str] = []
    if status.get("connected") is not True:
        gaps.append("cc_hooks:not_connected")
    if status.get("gate_switch") != "on":
        gaps.append("cc_gate:not_armed")
    if status.get("matcher") != "*":
        gaps.append("cc_matcher:not_all_tools")
    if status.get("pretool_hook") is not True:
        gaps.append("cc_pretool:missing")
    if status.get("posttool_hook") is not True:
        gaps.append("cc_posttool:missing")
    if gaps:
        return ProfileReceipt(
            ProfileName.CC,
            ProfileState.HOLD,
            "CC_PROFILE_NOT_SUPERVISED",
            evidence=tuple(gaps),
            status=status,
        )
    return ProfileReceipt(
        ProfileName.CC,
        ProfileState.SUPERVISED,
        "CC_PROFILE_SUPERVISED",
        evidence=("cc:all_tool_hooks_armed",),
        status=status,
    )


def check_agent_runtime(
    active_profile: ProfileName | str,
    *,
    cd_project: str | Path | None = None,
    cc_project: str | Path | None = None,
    codex_project: str | Path | None = None,
    claude_project: str | Path | None = None,
    protect_root: str | Path | None = None,
    python_bin: str = "python3",
    cd_status_fn: Callable[..., Mapping[str, Any]] | None = None,
    cc_status_fn: Callable[..., Mapping[str, Any]] | None = None,
    codex_status_fn: Callable[..., Mapping[str, Any]] | None = None,
    claude_status_fn: Callable[..., Mapping[str, Any]] | None = None,
) -> AgentRuntimeAdmission:
    profile = normalize_profile_name(active_profile)
    if profile == ProfileName.CD:
        receipt = check_codex_profile(
            cd_project if cd_project is not None else codex_project,
            protect_root=protect_root,
            python_bin=python_bin,
            status_fn=cd_status_fn or codex_status_fn,
        )
    else:
        receipt = check_claude_code_profile(
            cc_project if cc_project is not None else claude_project,
            protect_root=protect_root,
            python_bin=python_bin,
            status_fn=cc_status_fn or claude_status_fn,
        )
    return AgentRuntimeAdmission(profile, receipt)


def check_kingdom_supervision(
    *,
    active_profile: ProfileName | str = ProfileName.CD,
    cd_project: str | Path | None = None,
    cc_project: str | Path | None = None,
    codex_project: str | Path | None = None,
    claude_project: str | Path | None = None,
    protect_root: str | Path | None = None,
    python_bin: str = "python3",
    cd_status_fn: Callable[..., Mapping[str, Any]] | None = None,
    cc_status_fn: Callable[..., Mapping[str, Any]] | None = None,
    codex_status_fn: Callable[..., Mapping[str, Any]] | None = None,
    claude_status_fn: Callable[..., Mapping[str, Any]] | None = None,
) -> AgentRuntimeAdmission:
    return check_agent_runtime(
        active_profile,
        cd_project=cd_project,
        cc_project=cc_project,
        codex_project=codex_project,
        claude_project=claude_project,
        protect_root=protect_root,
        python_bin=python_bin,
        cd_status_fn=cd_status_fn,
        cc_status_fn=cc_status_fn,
        codex_status_fn=codex_status_fn,
        claude_status_fn=claude_status_fn,
    )
