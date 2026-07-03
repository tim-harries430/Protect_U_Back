from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from pub_os_profiles import AgentRuntimeAdmission, ProfileName, ProfileState, check_agent_runtime, normalize_profile_name
from pub_os_visibility import KingdomSession, SensorStatus, VisibilityDecision, default_kingdom_session


CD_DENIED_FLAGS = {
    "--dangerously-bypass-approvals-and-sandbox",
    "--full-auto",
}
CD_SANDBOX_FLAGS = {"--sandbox", "-s"}
CD_APPROVAL_FLAGS = {"--approval-policy", "--ask-for-approval", "-a"}
CD_CONFIG_FLAGS = {"--config", "-c"}
CD_DENIED_SANDBOX_MODES = {
    "danger-full-access",
    "danger_full_access",
    "full",
    "none",
    "off",
    "unrestricted",
}
CD_DENIED_APPROVAL_POLICIES = {"never"}

# Positive containment contract (fail-closed). cd may only fly when BOTH of
# Codex's own open security rails are provably armed tight in the launch argv:
#   * sandbox: workspace-write or read-only (never danger-full-access / absent)
#   * approval: untrusted or on-request (pub stays the approver / has eyes)
# A blacklist only stops the bypass flags we already know; this allowlist also
# refuses an UNDECLARED or UNKNOWN value, so a future Codex flag or a silent
# config default cannot launch an uncontained agent. pub cannot reach inside
# Codex past these two rails (its hook layer is closed), so the launch clamp is
# the whole of pub's cd leverage -- it must fail closed.
CD_ALLOWED_SANDBOX_MODES = {
    "read-only",
    "read_only",
    "readonly",
    "workspace-write",
    "workspace_write",
    "workspacewrite",
}
CD_ALLOWED_APPROVAL_POLICIES = {
    "untrusted",
    "on-request",
    "on_request",
    "onrequest",
}

CC_DENIED_FLAGS = {
    "--allow-dangerously-skip-permissions",
    "--bare",
    "--dangerously-skip-permissions",
    "--safe-mode",
}
CC_DENIED_PERMISSION_MODES = {
    "bypass-permissions",
    "bypass_permissions",
    "bypasspermissions",
    "dont-ask",
    "dont_ask",
    "dontask",
    "acceptedits",
    "accept_edits",
    "accept-edits",
}


class RunnerState(str, Enum):
    READY = "READY"
    HOLD = "HOLD"
    STARTED = "STARTED"


@dataclass(frozen=True)
class AgentRunPlan:
    session: KingdomSession
    active_profile: ProfileName | str
    state: RunnerState | str
    reason_code: str
    admission: AgentRuntimeAdmission
    argv: Sequence[str] = field(default_factory=tuple)
    evidence: Sequence[str] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "active_profile", normalize_profile_name(self.active_profile))
        object.__setattr__(self, "state", RunnerState(self.state))
        object.__setattr__(self, "argv", tuple(str(item) for item in self.argv))
        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))
        object.__setattr__(self, "metadata", _safe_record(self.metadata))
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    @property
    def ready(self) -> bool:
        return self.state == RunnerState.READY

    @property
    def argv_hash(self) -> str:
        return _sha256("\0".join(self.argv)) if self.argv else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session.session_id,
            "actor_id": self.session.actor_id,
            "active_profile": self.active_profile.value,
            "state": self.state.value,
            "reason_code": self.reason_code,
            "argv_sha256": self.argv_hash,
            "argv_count": len(self.argv),
            "evidence": tuple(self.evidence),
            "metadata": dict(self.metadata),
            "admission": self.admission.to_dict(),
            "can_execute": False,
            "can_grant_permission": False,
        }


@dataclass(frozen=True)
class RunnerReceipt:
    session_id: str
    active_profile: ProfileName | str
    state: RunnerState | str
    reason_code: str
    pid: int | None = None
    root_pid: int | None = None
    evidence: Sequence[str] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "active_profile", normalize_profile_name(self.active_profile))
        object.__setattr__(self, "state", RunnerState(self.state))
        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))
        object.__setattr__(self, "metadata", _safe_record(self.metadata))
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "active_profile": self.active_profile.value,
            "state": self.state.value,
            "reason_code": self.reason_code,
            "pid": self.pid,
            "root_pid": self.root_pid,
            "evidence": tuple(self.evidence),
            "metadata": dict(self.metadata),
            "can_execute": False,
            "can_grant_permission": False,
        }


def prepare_agent_run(
    active_profile: ProfileName | str,
    *,
    project_root: str | Path,
    actor_id: str = "pub_os_agent",
    session_id: str | None = None,
    cwd: str | Path | None = None,
    agent_args: Sequence[str] = (),
    cc_command: str = "claude",
    network_sensor: SensorStatus | str = SensorStatus.ABSENT,
    session: KingdomSession | None = None,
    cd_status_fn: Callable[..., Mapping[str, Any]] | None = None,
    cc_status_fn: Callable[..., Mapping[str, Any]] | None = None,
    protect_root: str | Path | None = None,
    python_bin: str = "python3",
) -> AgentRunPlan:
    profile = normalize_profile_name(active_profile)
    run_session = session or default_kingdom_session(
        session_id=session_id or _session_id(profile, project_root),
        actor_id=actor_id,
        project_root=str(project_root),
        cwd=str(cwd or project_root),
        network_sensor=network_sensor,
    )
    admission = check_agent_runtime(
        profile,
        cd_project=project_root,
        cc_project=project_root,
        protect_root=protect_root,
        python_bin=python_bin,
        cd_status_fn=cd_status_fn,
        cc_status_fn=cc_status_fn,
        runner_attached=True,
    )
    if admission.state != ProfileState.SUPERVISED:
        return _plan_hold(run_session, profile, admission, admission.reason_code, admission.evidence)

    barrier = run_session.launch_barrier()
    if barrier.decision != VisibilityDecision.PASS:
        return _plan_hold(run_session, profile, admission, barrier.reason_code, barrier.evidence)

    argv, gap, evidence = _argv_for_profile(profile, admission, agent_args, cc_command)
    if gap:
        return _plan_hold(run_session, profile, admission, gap, evidence)

    return AgentRunPlan(
        session=run_session,
        active_profile=profile,
        state=RunnerState.READY,
        reason_code="RUNNER_READY",
        admission=admission,
        argv=argv,
        evidence=tuple(barrier.evidence) + tuple(evidence),
        metadata={
            "cwd": str(Path(run_session.cwd).resolve(strict=False)),
            "project_root": str(Path(run_session.project_root).resolve(strict=False)),
            "network_sensor": barrier.metadata.get("network_sensor", ""),
        },
    )


def start_agent_run(
    plan: AgentRunPlan,
    *,
    spawn_fn: Callable[..., Any] | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> RunnerReceipt:
    if not plan.ready:
        return RunnerReceipt(
            plan.session.session_id,
            plan.active_profile,
            RunnerState.HOLD,
            plan.reason_code,
            evidence=plan.evidence,
        )
    if spawn_fn is None:
        return RunnerReceipt(
            plan.session.session_id,
            plan.active_profile,
            RunnerState.HOLD,
            "RUNNER_EXECUTOR_REQUIRED",
            evidence=("spawn_fn:missing",),
            metadata={"argv_sha256": plan.argv_hash},
        )
    process = spawn_fn(
        tuple(plan.argv),
        cwd=plan.session.cwd,
        env=_runner_env(plan, extra_env or {}),
    )
    pid = int(getattr(process, "pid"))
    return RunnerReceipt(
        plan.session.session_id,
        plan.active_profile,
        RunnerState.STARTED,
        "RUNNER_STARTED",
        pid=pid,
        root_pid=pid,
        evidence=("root_pid:captured",),
        metadata={"argv_sha256": plan.argv_hash},
    )


def append_ledger_entry(path: str | Path, item: AgentRunPlan | RunnerReceipt | Mapping[str, Any]) -> None:
    record = item.to_dict() if hasattr(item, "to_dict") else dict(item)
    clean = _safe_record(record)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps(clean, sort_keys=True, separators=(",", ":")) + "\n")


def _plan_hold(
    session: KingdomSession,
    profile: ProfileName,
    admission: AgentRuntimeAdmission,
    reason_code: str,
    evidence: Sequence[str],
) -> AgentRunPlan:
    return AgentRunPlan(
        session=session,
        active_profile=profile,
        state=RunnerState.HOLD,
        reason_code=reason_code,
        admission=admission,
        evidence=evidence,
    )


def _argv_for_profile(
    profile: ProfileName,
    admission: AgentRuntimeAdmission,
    agent_args: Sequence[str],
    cc_command: str,
) -> tuple[tuple[str, ...], str, tuple[str, ...]]:
    args = tuple(str(item) for item in agent_args)
    if profile == ProfileName.CD:
        launch_command = str(admission.receipt.status.get("launch_command", "")).strip()
        if not launch_command:
            return (), "RUNNER_CD_LAUNCH_COMMAND_MISSING", ("cd_launch_command:missing",)
        denied = _cd_denied_argv(args)
        if denied:
            return (), denied[0], denied[1]
        gap = _cd_containment_gap(args)
        if gap:
            return (), gap[0], gap[1]
        return (launch_command,) + args, "", (
            "cd_launcher:pub_guard",
            "cd_sandbox:contained",
            "cd_approval:contained",
        )
    command = str(cc_command).strip()
    if not command:
        return (), "RUNNER_CC_COMMAND_MISSING", ("cc_command:missing",)
    denied = _cc_denied_argv(args)
    if denied:
        return (), denied[0], denied[1]
    return (command,) + args, "", ("cc_hooks:armed",)


def _cd_denied_argv(args: Sequence[str]) -> tuple[str, tuple[str, ...]] | None:
    values = tuple(str(item).strip() for item in args)
    for index, value in enumerate(values):
        lowered = value.lower()
        if lowered in CD_DENIED_FLAGS:
            return "CD_UNSUPERVISED_ARG", (f"cd_arg:{value}", "cd_native_guard:bypassed")
        sandbox = _flag_value(values, index, CD_SANDBOX_FLAGS)
        if sandbox is not None:
            if sandbox == "":
                return "CD_SANDBOX_MODE_MISSING", (f"cd_arg:{value}",)
            if _sandbox_mode_denied(sandbox):
                return "CD_UNSUPERVISED_ARG", (f"cd_sandbox:{sandbox}",)
        approval = _flag_value(values, index, CD_APPROVAL_FLAGS)
        if approval is not None:
            if approval == "":
                return "CD_APPROVAL_POLICY_MISSING", (f"cd_arg:{value}",)
            if _approval_policy_denied(approval):
                return "CD_UNSUPERVISED_ARG", (f"cd_approval:{approval}",)
        config = _flag_value(values, index, CD_CONFIG_FLAGS)
        if config is not None:
            if config == "":
                return "CD_CONFIG_MISSING", (f"cd_arg:{value}",)
            denied = _cd_denied_config(config)
            if denied:
                return "CD_UNSUPERVISED_ARG", denied
    return None


def _cc_denied_argv(args: Sequence[str]) -> tuple[str, tuple[str, ...]] | None:
    values = tuple(str(item).strip() for item in args)
    for index, value in enumerate(values):
        lowered = value.lower()
        if lowered in CC_DENIED_FLAGS:
            return "CC_UNSUPERVISED_ARG", (f"cc_arg:{value}", "cc_hooks:skipped_or_bypassed")
        if lowered.startswith("--permission-mode="):
            mode = lowered.split("=", 1)[1]
            if _permission_mode_denied(mode):
                return "CC_UNSUPERVISED_ARG", (f"cc_permission_mode:{mode}",)
        elif lowered == "--permission-mode":
            if index + 1 >= len(values):
                return "CC_PERMISSION_MODE_MISSING", ("cc_arg:--permission-mode",)
            mode = values[index + 1].lower()
            if _permission_mode_denied(mode):
                return "CC_UNSUPERVISED_ARG", (f"cc_permission_mode:{mode}",)
    return None


def _flag_value(values: Sequence[str], index: int, names: set[str]) -> str | None:
    value = values[index]
    lowered = value.lower()
    for name in names:
        if lowered == name:
            return values[index + 1].strip() if index + 1 < len(values) else ""
        if lowered.startswith(name + "="):
            return value.split("=", 1)[1].strip()
    return None


def _cd_denied_config(value: str) -> tuple[str, ...]:
    text = value.strip().strip("\"'")
    lowered = text.lower()
    if "=" not in lowered:
        return ()
    key, raw = lowered.split("=", 1)
    key = key.strip().replace("-", "_").replace(".", "_")
    raw = raw.strip().strip("\"'")
    if key in {"sandbox", "sandbox_mode"} and _sandbox_mode_denied(raw):
        return (f"cd_config:{key}={raw}",)
    if key in {"approval_policy", "ask_for_approval"} and _approval_policy_denied(raw):
        return (f"cd_config:{key}={raw}",)
    return ()


def _cd_containment_gap(args: Sequence[str]) -> tuple[str, tuple[str, ...]] | None:
    """Positive, fail-closed containment check for a cd launch.

    Returns a (reason_code, evidence) gap when Codex's sandbox or approval rail
    is not provably armed tight, else None. Runs AFTER ``_cd_denied_argv`` so a
    flag with a present-but-empty value (e.g. a bare ``--sandbox``) is already
    reported as MISSING by the blacklist; here None means "not declared at all".
    """
    values = tuple(str(item).strip() for item in args)
    sandbox = _cd_effective_value(values, CD_SANDBOX_FLAGS, {"sandbox", "sandbox_mode"})
    if sandbox is None:
        return "CD_SANDBOX_NOT_DECLARED", ("cd_sandbox:not_declared", "fail_closed")
    if _cd_norm(sandbox) not in CD_ALLOWED_SANDBOX_MODES:
        return "CD_SANDBOX_NOT_CONTAINED", (f"cd_sandbox:{sandbox}",)
    approval = _cd_effective_value(values, CD_APPROVAL_FLAGS, {"approval_policy", "ask_for_approval"})
    if approval is None:
        return "CD_APPROVAL_NOT_DECLARED", ("cd_approval:not_declared", "fail_closed")
    if _cd_norm(approval) not in CD_ALLOWED_APPROVAL_POLICIES:
        return "CD_APPROVAL_NOT_CONTAINED", (f"cd_approval:{approval}",)
    return None


def _cd_effective_value(
    values: Sequence[str],
    flags: set[str],
    config_keys: set[str],
) -> str | None:
    """Last-wins effective value for a Codex policy across direct flags and
    ``--config key=value`` overrides. None when never declared (fail closed);
    empty-string declarations are ignored (the blacklist already flags those)."""
    found: str | None = None
    for index, value in enumerate(values):
        direct = _flag_value(values, index, flags)
        if direct:
            found = direct
        config = _cd_config_pair(values, index)
        if config and config[0] in config_keys and config[1]:
            found = config[1]
    return found


def _cd_config_pair(values: Sequence[str], index: int) -> tuple[str, str] | None:
    raw = _flag_value(values, index, CD_CONFIG_FLAGS)
    if not raw:
        return None
    text = raw.strip().strip("\"'")
    if "=" not in text:
        return None
    key, value = text.split("=", 1)
    key = key.strip().lower().replace("-", "_").replace(".", "_")
    return key, value.strip().strip("\"'")


def _cd_norm(value: str) -> str:
    return value.replace(" ", "").lower()


def _sandbox_mode_denied(value: str) -> bool:
    return value.replace(" ", "").lower() in CD_DENIED_SANDBOX_MODES


def _approval_policy_denied(value: str) -> bool:
    return value.replace(" ", "").lower() in CD_DENIED_APPROVAL_POLICIES


def _permission_mode_denied(value: str) -> bool:
    return value.replace(" ", "").lower() in CC_DENIED_PERMISSION_MODES


def _runner_env(plan: AgentRunPlan, extra_env: Mapping[str, str]) -> dict[str, str]:
    return {
        **os.environ,
        **{str(key): str(value) for key, value in extra_env.items()},
        "PUB_OS_SESSION_ID": plan.session.session_id,
        "PUB_OS_ACTIVE_PROFILE": plan.active_profile.value,
        "PUB_OS_PROJECT_ROOT": plan.session.project_root,
    }


def _session_id(profile: ProfileName, project_root: str | Path) -> str:
    material = f"{profile.value}|{Path(project_root).resolve(strict=False)}|{time.time_ns()}"
    return "pubos_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def _safe_record(values: Mapping[str, Any]) -> dict[str, Any]:
    blocked = {"allow", "body", "can_execute", "can_grant_permission", "content", "execute", "grant", "kill", "payload", "raw_bytes"}
    clean: dict[str, Any] = {}
    for key, value in dict(values).items():
        name = str(key)
        if name.lower() in {"can_execute", "can_grant_permission"} and value is False:
            clean[name] = False
            continue
        if name.lower() in blocked:
            raise ValueError(f"ledger record must not include authority or payload field: {name}")
        clean[name] = value
    return clean


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
