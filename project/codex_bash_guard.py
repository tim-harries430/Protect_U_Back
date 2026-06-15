from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adapter_wall import ActionDomain, ActionEnvelope, AdapterActionType
from claude_code_hooks import _bash_targets_and_effects
from harness_adapter import infer_action_domain, infer_action_type, infer_declared_scope
from llm_channel import ChannelType
from ot_gate import DeclaredScope, SideEffect
from parallel_audit import EvidenceDisposition
from phi_registry import ActorType, PhiRegistry
from protect_scan import confirm_protect_scan, default_protect_scan_profile
from xray_review import audit_with_xray_review


SOURCE_ADAPTER = "codex_shell_guard"
DEFAULT_ACTOR_ID = "codex_cli"
LOG_FILE_NAME = "pub_codex_guard.jsonl"
BLOCKING_DISPOSITIONS = frozenset(
    {
        EvidenceDisposition.HOLD,
        EvidenceDisposition.KILL,
        EvidenceDisposition.QUARANTINE,
        EvidenceDisposition.REJECT,
    }
)

# Codex's own shell-snapshot bootstrap (and many ordinary commands) use shell
# plumbing that the shared bash heuristic in claude_code_hooks mis-reads as
# filesystem targets:
#   * `2>/dev/null`   -> phantom WRITE to target "/dev/null"
#   * `<(compgen -e)` -> phantom READ of target "(compgen"
# Those phantom paths trip CAPABILITY_PATH_DENIED and KILL a benign command.
# We neutralise the plumbing here, inside the Codex adapter, so the shared
# parser stays untouched. We do NOT go blind: a process substitution's inner
# command is re-analysed on its own, so `<(curl http://evil)` keeps its NETWORK
# effect and genuine targets are preserved.
_BENIGN_REDIRECT_SINKS = (
    "null",
    "zero",
    "full",
    "random",
    "urandom",
    "stdout",
    "stderr",
    "tty",
)
_BENIGN_SINK_REDIRECT_RE = re.compile(
    r"(?:&|[0-9]+)?[<>]{1,2}&?\s*/dev/(?:" + "|".join(_BENIGN_REDIRECT_SINKS) + r")\b"
)
_FD_REDIRECT_RE = re.compile(r"(?:^|\s)(?:[0-9]+)?[<>]{1,2}&[0-9]+\b")
_HEREDOC_MARKER_RE = re.compile(r"<<-?\s*(['\"]?)[A-Za-z_][A-Za-z0-9_]*\1")
_PROCESS_SUBSTITUTION_RE = re.compile(r"[<>]\(([^()]*)\)")
_COMMAND_SEGMENT_RE = re.compile(r"\s*(?:\|\||&&|\|)\s*|\n+")


def _is_phantom_target(target: str) -> bool:
    if target.startswith("("):
        return True
    if target.startswith("/dev/") and target.rsplit("/", 1)[-1] in _BENIGN_REDIRECT_SINKS:
        return True
    return False


def _codex_shell_targets_and_effects(
    command_text: str,
) -> tuple[tuple[str, ...], set[SideEffect]]:
    """Extract targets/effects for a Codex shell command.

    Wraps the shared ``_bash_targets_and_effects`` but neutralises shell
    plumbing first so benign redirects and process substitutions do not become
    phantom filesystem targets. The inner command of each process substitution
    is analysed separately so its real effects (e.g. network) are not lost.
    """
    audit_text = _codex_audit_command_text(command_text)
    targets: list[str] = []
    effects: set[SideEffect] = set()

    for segment in _command_segments(audit_text):
        segment_targets, segment_effects = _bash_targets_and_effects(segment)
        extra_targets, extra_effects = _codex_segment_targets_and_effects(segment)
        targets.extend(segment_targets)
        targets.extend(extra_targets)
        effects |= segment_effects
        effects |= extra_effects

    if not effects:
        effects.add(SideEffect.READ)

    targets = _drop_sed_scripts(targets, audit_text)

    return tuple(
        dict.fromkeys(target for target in targets if not _is_phantom_target(target))
    ), effects


def _codex_audit_command_text(command_text: str) -> str:
    inner_commands = tuple(
        inner.strip()
        for inner in _PROCESS_SUBSTITUTION_RE.findall(command_text)
        if inner.strip()
    )
    cleaned = _PROCESS_SUBSTITUTION_RE.sub(" ", command_text)
    cleaned = _BENIGN_SINK_REDIRECT_RE.sub(" ", cleaned)
    cleaned = _FD_REDIRECT_RE.sub(" ", cleaned)
    cleaned = _HEREDOC_MARKER_RE.sub(" ", cleaned)
    pieces = tuple(piece for piece in (cleaned.strip(), *inner_commands) if piece)
    return "\n".join(pieces) or command_text


def _command_segments(command_text: str) -> tuple[str, ...]:
    return tuple(
        segment.strip()
        for segment in _COMMAND_SEGMENT_RE.split(command_text)
        if segment.strip()
    )


def _codex_segment_targets_and_effects(
    segment: str,
) -> tuple[tuple[str, ...], set[SideEffect]]:
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        tokens = segment.split()
    if not tokens:
        return (), {SideEffect.READ}

    verb = Path(tokens[0]).name.lower()
    args = tuple(token for token in tokens[1:] if not token.startswith("-"))
    targets: list[str] = []
    effects: set[SideEffect] = {SideEffect.READ}

    if verb in {"rg", "grep"}:
        targets.extend(_reader_targets_after_pattern(args))
    elif verb in {"ls", "find", "fd"}:
        targets.extend(_codex_read_target_args(args))
    elif verb == "sed" and _sed_edits_in_place(tokens):
        effects.add(SideEffect.WRITE)
        targets.extend(_reader_targets_after_pattern(args))
    elif verb == "perl" and _perl_edits_in_place(tokens):
        effects.add(SideEffect.WRITE)
        targets.extend(_perl_edit_targets(tokens))
    elif verb.startswith("python") and _python_write_surface(segment):
        effects.add(SideEffect.WRITE)
    elif verb == "apply_patch":
        patch_targets, patch_effects = _patch_targets_and_effects(segment)
        targets.extend(patch_targets)
        effects |= patch_effects
    elif verb in {"rm", "rmdir", "unlink"}:
        effects.add(SideEffect.DELETE)
        targets.extend(_codex_path_like_args(args))

    return tuple(dict.fromkeys(targets)), effects


def _reader_targets_after_pattern(args: Sequence[str]) -> tuple[str, ...]:
    if len(args) <= 1:
        return ()
    return _codex_read_target_args(args[1:])


def _codex_read_target_args(args: Sequence[str]) -> list[str]:
    return [
        arg
        for arg in args
        if _codex_looks_like_path(arg) and arg.strip().strip("'\"") not in {".", ".."}
    ]


def _codex_path_like_args(args: Sequence[str]) -> list[str]:
    return [arg for arg in args if _codex_looks_like_path(arg)]


def _codex_looks_like_path(value: str) -> bool:
    text = value.strip().strip("'\"")
    if text in {".", ".."}:
        return True
    if text.startswith(("./", "../", "/", "~")):
        return True
    if text.startswith(".") and len(text) > 1:
        return True
    if "/" in text or "\\" in text:
        return True
    return bool(re.search(r"\.[A-Za-z0-9_]{1,16}$", text))


def _sed_edits_in_place(tokens: Sequence[str]) -> bool:
    return any(token == "-i" or token.startswith("-i") for token in tokens[1:])


def _perl_edits_in_place(tokens: Sequence[str]) -> bool:
    return any("i" in token and token.startswith("-") for token in tokens[1:])


def _perl_edit_targets(tokens: Sequence[str]) -> tuple[str, ...]:
    targets: list[str] = []
    skip_next = False
    for token in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if token in {"-e", "-E"}:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        if _codex_looks_like_path(token):
            targets.append(token)
    return tuple(dict.fromkeys(targets))


def _python_write_surface(segment: str) -> bool:
    lowered = segment.lower()
    if ".write_text(" in lowered or ".write_bytes(" in lowered:
        return True
    return bool(re.search(r"\bopen\s*\([^)]*,\s*['\"][wa+]", lowered))


def _patch_targets_and_effects(segment: str) -> tuple[tuple[str, ...], set[SideEffect]]:
    targets: list[str] = []
    effects: set[SideEffect] = {SideEffect.READ}
    for line in segment.splitlines():
        match = re.match(r"\*\*\* (?:Add|Update) File:\s+(.+)$", line.strip())
        if match:
            targets.append(match.group(1).strip())
            effects.add(SideEffect.WRITE)
            continue
        match = re.match(r"\*\*\* Delete File:\s+(.+)$", line.strip())
        if match:
            targets.append(match.group(1).strip())
            effects.add(SideEffect.DELETE)
    return tuple(dict.fromkeys(targets)), effects


def _drop_sed_scripts(targets: Sequence[str], command_text: str) -> list[str]:
    scripts = _sed_script_tokens(command_text)
    if not scripts:
        return list(targets)
    return [target for target in targets if str(target) not in scripts]


def _sed_script_tokens(command_text: str) -> set[str]:
    scripts: set[str] = set()
    for segment in _command_segments(command_text):
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            tokens = segment.split()
        if not tokens or Path(tokens[0]).name.lower() != "sed":
            continue
        args = tuple(token for token in tokens[1:] if not token.startswith("-"))
        if args:
            scripts.add(args[0])
    return scripts


@dataclass(frozen=True)
class CodexGuardDecision:
    action: ActionEnvelope
    disposition: EvidenceDisposition
    reason_code: str
    executed: bool = False
    exit_code: int | None = None

    @property
    def blocked(self) -> bool:
        return self.disposition in BLOCKING_DISPOSITIONS

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_adapter": SOURCE_ADAPTER,
            "action_id": self.action.action_id,
            "actor_id": self.action.actor_id,
            "command_text": _display_command_text(self.action),
            "audit_command_text": self.action.command_text,
            "cwd": self.action.cwd,
            "target_paths": tuple(self.action.target_paths),
            "expected_side_effects": tuple(
                sorted(effect.value for effect in self.action.expected_side_effects)
            ),
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "blocked": self.blocked,
            "executed": self.executed,
            "exit_code": self.exit_code,
            "can_execute": False,
            "can_grant_permission": False,
        }


def action_from_shell_argv(
    argv: Sequence[str],
    *,
    cwd: str,
    environ: Mapping[str, str] | None = None,
) -> ActionEnvelope:
    env = environ or os.environ
    original_command_text = _command_text_from_shell_argv(argv)
    command_text = _codex_audit_command_text(original_command_text)
    target_paths, effects = _codex_shell_targets_and_effects(original_command_text)
    action_type = infer_action_type(
        "shell",
        tool_name="shell",
        effects=set(effects),
        command_text=command_text,
    )
    declared_scope = infer_declared_scope(
        None,
        effects=set(effects),
        action_type=action_type,
    )
    action_domain = infer_action_domain(
        None,
        declared_scope=declared_scope,
        effects=set(effects),
        command_text=command_text,
        target_paths=target_paths,
        action_type=action_type,
        default=ActionDomain.GENERAL,
    )
    cid = _correlation_id(env)
    raw_payload = {
        "codex_guard": {
            "schema_version": "pub_codex_shell_guard:v0",
            "shell_argv": tuple(str(item) for item in argv),
            "original_command_text": original_command_text,
            "audit_command_text": command_text,
            "cwd": cwd,
            "sandbox": _sandbox_evidence_from_env(env),
            "approval": _approval_evidence_from_env(env),
            "policy": _policy_evidence_from_env(env),
        }
    }
    return ActionEnvelope(
        actor_id=env.get("PUB_CODEX_ACTOR_ID", DEFAULT_ACTOR_ID),
        action_type=action_type,
        action_domain=action_domain,
        channel_type=ChannelType.AGENT_PROPOSAL,
        command_text=command_text,
        cwd=cwd,
        target_paths=target_paths,
        expected_side_effects=set(effects),
        declared_scope=declared_scope,
        source_adapter=SOURCE_ADAPTER,
        tool_name="shell",
        raw_payload=raw_payload,
        branch_id=env.get("PUB_CODEX_SESSION_ID", "codex_cli_session"),
        action_id=f"codex_cli:{cid}",
        parent_event_id=env.get("PUB_CODEX_SESSION_ID", "codex_cli_parent"),
        user_request_id=env.get("PUB_CODEX_USER_REQUEST_ID", "codex_cli_user_request"),
    )


def audit_shell_argv(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> CodexGuardDecision:
    env = environ or os.environ
    actual_cwd = cwd or os.getcwd()
    action = action_from_shell_argv(argv, cwd=actual_cwd, environ=env)
    registry = PhiRegistry()
    registry.register_actor(action.actor_id, ActorType.AGENT)
    project_root = _project_root_for_action(action, env)
    profile = confirm_protect_scan(default_protect_scan_profile(project_root), confirmed=True)
    decision = audit_with_xray_review(
        action,
        registry=registry,
        project_root=project_root,
        protect_profile=profile,
    )
    return CodexGuardDecision(
        action=action,
        disposition=decision.disposition,
        reason_code=decision.reason_code,
    )


def run_guarded_shell(
    argv: Sequence[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> int:
    env = dict(environ or os.environ)
    decision = audit_shell_argv(argv, cwd=os.getcwd(), environ=env)
    _append_log(env, {"phase": "pre", **decision.to_dict()})
    if decision.blocked:
        print(
            f"PUB_CODEX_GUARD: blocked before Codex shell execution: "
            f"{decision.disposition.value} {decision.reason_code}",
            file=sys.stderr,
        )
        return 126

    invoked_shell = Path(env.get("PUB_CODEX_INVOKED_SHELL", "")).name.lower()
    real_shell = (
        env.get("PUB_CODEX_REAL_SH")
        if invoked_shell == "sh"
        else env.get("PUB_CODEX_REAL_SHELL") or env.get("PUB_CODEX_REAL_BASH")
    )
    if not real_shell:
        print("PUB_CODEX_GUARD: missing PUB_CODEX_REAL_SHELL", file=sys.stderr)
        return 127

    completed = subprocess.run([real_shell, *argv], env=env, check=False)
    _append_log(
        env,
        {
            "phase": "post",
            **CodexGuardDecision(
                action=decision.action,
                disposition=decision.disposition,
                reason_code=decision.reason_code,
                executed=True,
                exit_code=completed.returncode,
            ).to_dict(),
        },
    )
    return completed.returncode


def _command_text_from_shell_argv(argv: Sequence[str]) -> str:
    args = tuple(str(item) for item in argv)
    if len(args) >= 2 and args[0] in {"-c", "-lc", "-l", "-ic"}:
        return args[1] if args[0] in {"-c", "-lc", "-ic"} else " ".join(args)
    if len(args) >= 3 and args[0] == "-l" and args[1] == "-c":
        return args[2]
    return " ".join(args)


def _display_command_text(action: ActionEnvelope) -> str:
    codex_guard = action.raw_payload.get("codex_guard")
    if isinstance(codex_guard, Mapping):
        original = str(codex_guard.get("original_command_text", "")).strip()
        if original:
            return original
    return action.command_text


def _project_root_for_action(action: ActionEnvelope, env: Mapping[str, str]) -> str:
    return str(env.get("PUB_CODEX_PROJECT_ROOT") or action.cwd)


def _correlation_id(env: Mapping[str, str]) -> str:
    seed = env.get("PUB_CODEX_TOOL_USE_ID") or env.get("PUB_CODEX_SESSION_ID")
    if seed:
        return _safe_id(seed)
    return str(time.time_ns())


def _safe_id(value: str) -> str:
    return "".join(character if character.isalnum() or character in "-_." else "_" for character in value)[:96]


def _sandbox_evidence_from_env(env: Mapping[str, str]) -> dict[str, Any]:
    return {
        "available": _bool_env(env.get("PUB_CODEX_SANDBOX_AVAILABLE"), default=False),
        "mode": env.get("PUB_CODEX_SANDBOX_MODE", ""),
        "fallback": env.get("PUB_CODEX_SANDBOX_FALLBACK", "codex_shell_guard"),
    }


def _approval_evidence_from_env(env: Mapping[str, str]) -> dict[str, Any]:
    return {
        "policy": env.get("PUB_CODEX_APPROVAL_POLICY", ""),
        "source": "codex_exec_policy_observed",
    }


def _policy_evidence_from_env(env: Mapping[str, str]) -> dict[str, Any]:
    return {
        "exec_policy": env.get("PUB_CODEX_EXEC_POLICY", ""),
        "prefix_approval": env.get("PUB_CODEX_PREFIX_APPROVAL", ""),
    }


def _bool_env(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _append_log(env: Mapping[str, str], row: Mapping[str, Any]) -> None:
    root = Path(env.get("PUB_CODEX_LOG_DIR") or (Path.cwd() / ".pub_codex_guard"))
    root.mkdir(parents=True, exist_ok=True)
    payload = {"ts": time.time(), **dict(row)}
    with (root / LOG_FILE_NAME).open("a", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    return run_guarded_shell(tuple(argv or ()))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
