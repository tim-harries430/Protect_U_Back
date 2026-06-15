from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from adapter_wall import ActionDomain, ActionEnvelope, AdapterActionType
from harness_adapter import infer_action_domain, infer_action_type, infer_declared_scope
from llm_channel import ChannelType
from ot_gate import CommandProposal, DeclaredScope, JudgeVote, OTPolicy, SideEffect
from parallel_audit import EvidenceDisposition
from temporal_continuity import TemporalContinuityLedger, TemporalTestimony
from phi_registry import ActorType, PhiRegistry
from protect_scan import confirm_protect_scan, default_protect_scan_profile
from transition_xray import TransitionXrayFrame, XrayPhase, XrayPiece
from xray_prison import XrayPrisonAuthority, XrayPrisonBoundary
from xray_review import XrayReview, audit_with_xray_review, review_from_frame
from xray_transport import XrayTransportHandle, XrayTransportSeal, close_xray_transport, open_xray_transport


HOOK_ID = "pub_claude_code_hooks:v0"
SOURCE_ADAPTER = "claude_code_hook"
DEFAULT_ACTOR_ID = "claude_code"
STATE_DIR_NAME = "pub_xray_state"
TEMPORAL_STATE_DIR_NAME = "pub_temporal_state"
LOG_FILE_NAME = "pub_claude_hooks.jsonl"
GATE_SWITCH_FILE_NAME = "pub_gate_switch.json"
STATE_SCHEMA_VERSION = "claude_code_pub_xray_state:v0"
DEFAULT_STATE_TTL_SECONDS = 3600
SENSITIVE_TOOL_INPUT_KEYS = frozenset(
    {
        "content",
        "new_string",
        "old_string",
        "new_str",
        "old_str",
        "replacement",
        "text",
    }
)
BLOCKING_DISPOSITIONS = frozenset(
    {
        EvidenceDisposition.HOLD,
        EvidenceDisposition.KILL,
        EvidenceDisposition.QUARANTINE,
        EvidenceDisposition.REJECT,
    }
)
# Tools whose capability this hook can actually infer from shape (see
# _targets_and_effects). Anything outside this set is an UNKNOWN capability:
# the hook has no evidence of what it does, so by default-deny-on-missing-
# evidence it must be escalated to review, never silently classified as a READ.
# Adding a tool here is a deliberate, human decision that it is modellable --
# the default for the unmodelled (WebFetch, WebSearch, Task, mcp__*) is review.
RECOGNIZED_TOOLS = frozenset(
    {
        "Bash",
        "Write",
        "Edit",
        "MultiEdit",
        "NotebookEdit",
        "Read",
        "NotebookRead",
        "Glob",
        "Grep",
        "LS",
    }
)


@dataclass(frozen=True)
class ClaudeHookAdmission:
    event: Mapping[str, Any]
    action: ActionEnvelope
    proposal: CommandProposal
    handle: XrayTransportHandle
    disposition: EvidenceDisposition
    reason_code: str
    output: Mapping[str, Any] | None
    state_path: Path
    temporal_vote: str = "PASS"
    temporal_reason_code: str = "TEMPORAL_CONTINUOUS"

    @property
    def blocked(self) -> bool:
        return self.output is not None


@dataclass(frozen=True)
class ClaudeHookAutopsy:
    event: Mapping[str, Any]
    proposal: CommandProposal | None
    seal: XrayTransportSeal | None
    review: XrayReview | None
    output: Mapping[str, Any] | None
    state_path: Path
    missing_state: bool = False


def run_pretool_admission(
    raw: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> ClaudeHookAdmission:
    env = environ or os.environ
    event = _load_event(raw)
    action = action_from_claude_event(event, environ=env)
    proposal = proposal_from_action(action)
    cid = _event_correlation_id(event, action=action)

    handle = open_xray_transport(proposal)
    state_path = _state_path(cid, event, env)
    project_root = _project_root_for_action(action)
    decision = _audit_action(action)
    gate_off = _gate_switch_off(event, env)
    output = None
    if decision.disposition is EvidenceDisposition.HOLD:
        output = _pretool_hold_output(decision.reason_code)
    elif decision.disposition in BLOCKING_DISPOSITIONS:
        output = _pretool_deny_output(decision.disposition, decision.reason_code)

    # Unmodelled capability => review (never a silent allow). A spatial block
    # already decided; this only fills the gap where the gate would let an
    # unknown tool through for lack of any inferable side effect.
    if output is None and not _is_recognized_tool(action.tool_name):
        output = _pretool_review_output("UNKNOWN_CAPABILITY", action.tool_name)

    # The spatial gate above judges THIS proposal in isolation. The temporal
    # accumulator judges the SEQUENCE: a session that drifts off its stated
    # task -- read a secret between two look-alike downloads, then egress --
    # is invisible to any single-frame check. Run it always (even under a
    # block, even gated off) so the ledger remembers; it can only TIGHTEN the
    # verdict, never loosen it.
    temporal = _run_temporal(proposal, project_root, event, env)
    candidate = _temporal_output(temporal)
    if _decision_rank(candidate) > _decision_rank(output):
        output = candidate
    temporal_vote = temporal.vote.value if temporal is not None else "PASS"
    temporal_reason_code = temporal.reason_code if temporal is not None else "TEMPORAL_CONTINUOUS"

    # The operator switch only seals the exit, never the eyes: with the gate
    # off the audit above still ran and the ledger row below is still written,
    # so the trail survives a disarmed gate. Nothing is blocked or escalated.
    if gate_off:
        output = None

    _write_json(
        state_path,
        {
            "schema_version": STATE_SCHEMA_VERSION,
            "hook_id": HOOK_ID,
            "cid": cid,
            "created_at": time.time(),
            "expires_at": time.time() + _state_ttl_seconds(env),
            "blocked": output is not None,
            "proposal": proposal_to_state(proposal),
            "boundary": handle.boundary.to_dict(include_hash=False),
            "enter_frame": handle.enter_frame.to_dict(),
            "handle": handle.to_dict(),
        },
    )

    witness = _append_log(
        env,
        {
            "phase": "pretool_admission",
            "cid": cid,
            "tool_name": action.tool_name,
            "action_id": action.action_id,
            "disposition": decision.disposition.value,
            "reason_code": decision.reason_code,
            "temporal_vote": temporal_vote,
            "temporal_reason_code": temporal_reason_code,
            "gate_switch": "off" if gate_off else "on",
            "blocked": output is not None,
            "target_paths": tuple(action.target_paths),
            "expected_side_effects": tuple(
                sorted(effect.value for effect in action.expected_side_effects)
            ),
            "xray_enter_hash": handle.enter_frame_hash,
            "xray_handle_hash": handle.handle_hash,
            "state_path": str(state_path),
        },
    )
    # Fail-closed witness (PUB-OS): inside a cc cage the ONLY audit egress is the
    # out-of-cage ledger. If the witness is lost, an unrecorded action must not
    # proceed silently -- escalate to HOLD (ask). This only fires when a ledger
    # socket is configured (witness == "unavailable" requires PUB_OS_LEDGER_SOCKET),
    # so the default uncaged path is untouched. It tightens only (never downgrades
    # a deny) and defers to the operator's gate switch (no override when gate off).
    if not gate_off and witness == "unavailable":
        _witness_hold = _pretool_hold_output("PUB_OS_LEDGER_WITNESS_LOST")
        if _decision_rank(_witness_hold) > _decision_rank(output):
            output = _witness_hold
    return ClaudeHookAdmission(
        event=event,
        action=action,
        proposal=proposal,
        handle=handle,
        disposition=decision.disposition,
        reason_code=decision.reason_code,
        output=output,
        state_path=state_path,
        temporal_vote=temporal_vote,
        temporal_reason_code=temporal_reason_code,
    )


def run_posttool_autopsy(
    raw: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> ClaudeHookAutopsy:
    env = environ or os.environ
    event = _load_event(raw)
    cid = _event_correlation_id(event)
    state_path = _state_path(cid, event, env)
    # Same exit-only switch as admission: autopsy and ledger always run, the
    # additionalContext chatter is the only thing a disarmed gate suppresses.
    silenced = _gate_switch_off(event, env)
    if not state_path.exists():
        output = None if silenced else _posttool_missing_output("missing_enter_state")
        _append_log(
            env,
            {
                "phase": "posttool_autopsy",
                "cid": cid,
                "missing_state": True,
                "state_path": str(state_path),
            },
        )
        return ClaudeHookAutopsy(
            event=event,
            proposal=None,
            seal=None,
            review=None,
            output=output,
            state_path=state_path,
            missing_state=True,
        )

    state = json.loads(state_path.read_text(encoding="utf-8"))
    if _state_expired(state):
        output = None if silenced else _posttool_missing_output("expired_enter_state")
        _append_log(
            env,
            {
                "phase": "posttool_autopsy",
                "cid": cid,
                "expired_state": True,
                "state_path": str(state_path),
            },
        )
        return ClaudeHookAutopsy(
            event=event,
            proposal=None,
            seal=None,
            review=None,
            output=output,
            state_path=state_path,
            missing_state=True,
        )
    proposal = proposal_from_state(state["proposal"])
    handle = handle_from_state(state)
    seal = close_xray_transport(handle, proposal)
    review = review_from_frame(handle.enter_frame, seal=seal)
    output = None if silenced else _posttool_context_output(seal, review)

    autopsy_path = _autopsy_path(cid, env)
    _write_json(
        autopsy_path,
        {
            "hook_id": HOOK_ID,
            "cid": cid,
            "phase": "posttool_autopsy",
            "tool_name": proposal.tool_name,
            "proposal_id": proposal.proposal_id,
            "tool_response_summary": _tool_response_summary(event.get("tool_response")),
            "xray_transport": seal.to_dict(),
            "xray_review": review.to_dict(),
        },
    )
    _append_log(
        env,
        {
            "phase": "posttool_autopsy",
            "cid": cid,
            "tool_name": proposal.tool_name,
            "mutation_state": seal.mutation_state,
            "continuity_state": seal.continuity_state,
            "witness_count": seal.witness_count,
            "field_state": seal.field_state,
            "xray_review_disposition": review.disposition.value,
            "xray_review_reason_code": review.reason_code,
            "transport_hash": seal.transport_hash,
            "autopsy_path": str(autopsy_path),
        },
    )
    return ClaudeHookAutopsy(
        event=event,
        proposal=proposal,
        seal=seal,
        review=review,
        output=output,
        state_path=state_path,
    )


def action_from_claude_event(
    event: Mapping[str, Any],
    *,
    environ: Mapping[str, str] | None = None,
) -> ActionEnvelope:
    env = environ or os.environ
    tool_name = _tool_name(event)
    tool_input = _tool_input(event)
    command_text = _command_text(tool_name, tool_input)
    target_paths, effects = _targets_and_effects(tool_name, tool_input, command_text)
    if _authority_claim_present(event):
        effects.add(SideEffect.PRIVILEGE)
    action_type = infer_action_type(
        tool_name,
        tool_name=tool_name,
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
    cid = _event_correlation_id(event)
    cwd = _event_cwd(event, env)
    raw_payload = {
        "claude_hook_event": _sanitize_claude_event(event),
        "tool_input": _sanitize_tool_input(tool_input),
        "tool_input_sha256": _sha256_json(tool_input),
        "hook_id": HOOK_ID,
    }
    sandbox = _sandbox_evidence_from_env(env)
    if sandbox:
        raw_payload["sandbox"] = sandbox

    return ActionEnvelope(
        actor_id=env.get("PUB_CLAUDE_ACTOR_ID", DEFAULT_ACTOR_ID),
        action_type=action_type,
        action_domain=action_domain,
        channel_type=ChannelType.AGENT_PROPOSAL,
        command_text=command_text,
        cwd=cwd,
        target_paths=target_paths,
        expected_side_effects=set(effects),
        declared_scope=declared_scope,
        source_adapter=SOURCE_ADAPTER,
        tool_name=tool_name,
        raw_payload=raw_payload,
        branch_id=str(event.get("session_id") or "claude_code_session"),
        action_id=f"claude_code:{cid}",
        parent_event_id=str(event.get("session_id") or "claude_code_parent"),
        user_request_id=str(event.get("transcript_path") or "claude_code_user_request"),
    )


def proposal_from_action(action: ActionEnvelope) -> CommandProposal:
    return CommandProposal(
        command_text=action.command_text,
        actor_id=action.actor_id,
        cwd=action.cwd,
        declared_scope=action.declared_scope or DeclaredScope.READ_ONLY,
        target_paths=tuple(action.target_paths),
        expected_side_effects=set(action.expected_side_effects),
        parent_event_id=action.parent_event_id,
        user_request_id=action.user_request_id,
        proposal_id=action.action_id,
        source_adapter=action.source_adapter,
        tool_name=action.tool_name,
        action_type=action.action_type.value,
        raw_payload=dict(action.raw_payload),
    )


def proposal_to_state(proposal: CommandProposal) -> dict[str, Any]:
    return {
        "command_text": proposal.command_text,
        "actor_id": proposal.actor_id,
        "cwd": proposal.cwd,
        "declared_scope": proposal.declared_scope.value,
        "target_paths": tuple(proposal.target_paths),
        "expected_side_effects": tuple(
            sorted(effect.value for effect in proposal.expected_side_effects)
        ),
        "parent_event_id": proposal.parent_event_id,
        "user_request_id": proposal.user_request_id,
        "proposal_id": proposal.proposal_id,
        "source_adapter": proposal.source_adapter,
        "tool_name": proposal.tool_name,
        "action_type": proposal.action_type,
        "raw_payload": _jsonable(proposal.raw_payload),
    }


def proposal_from_state(payload: Mapping[str, Any]) -> CommandProposal:
    return CommandProposal(
        command_text=str(payload["command_text"]),
        actor_id=str(payload["actor_id"]),
        cwd=str(payload["cwd"]),
        declared_scope=DeclaredScope(str(payload["declared_scope"])),
        target_paths=tuple(str(item) for item in payload.get("target_paths", ())),
        expected_side_effects={
            SideEffect(str(item)) for item in payload.get("expected_side_effects", ())
        },
        parent_event_id=str(payload.get("parent_event_id", "")),
        user_request_id=str(payload.get("user_request_id", "")),
        proposal_id=str(payload["proposal_id"]),
        source_adapter=str(payload.get("source_adapter", SOURCE_ADAPTER)),
        tool_name=str(payload.get("tool_name", "")),
        action_type=str(payload.get("action_type", "")),
        raw_payload=dict(payload.get("raw_payload") or {}),
    )


def handle_from_state(payload: Mapping[str, Any]) -> XrayTransportHandle:
    proposal = proposal_from_state(payload["proposal"])
    boundary = boundary_from_state(payload["boundary"])
    enter_frame = frame_from_state(payload["enter_frame"])
    return XrayTransportHandle(
        proposal_id=proposal.proposal_id,
        boundary=boundary,
        enter_frame=enter_frame,
    )


def boundary_from_state(payload: Mapping[str, Any]) -> XrayPrisonBoundary:
    return XrayPrisonBoundary(
        prison_id=str(payload.get("prison_id", "xray_observation_prison:v0")),
        scope=str(payload.get("scope", "sealed_xray_observation_space")),
        closed=bool(payload.get("closed", True)),
        same_rules_for_all=bool(payload.get("same_rules_for_all", True)),
        authorities=tuple(
            XrayPrisonAuthority(str(item))
            for item in payload.get(
                "authorities",
                (
                    XrayPrisonAuthority.OBSERVE.value,
                    XrayPrisonAuthority.SEAL.value,
                    XrayPrisonAuthority.COMPARE.value,
                    XrayPrisonAuthority.ATTACH_TESTIMONY.value,
                ),
            )
        ),
    )


def frame_from_state(payload: Mapping[str, Any]) -> TransitionXrayFrame:
    pieces = tuple(piece_from_state(item) for item in payload.get("pieces", ()))
    return TransitionXrayFrame(
        phase=XrayPhase(str(payload["phase"])),
        action_id=str(payload["action_id"]),
        pieces=pieces,
        k_phi=tuple(float(item) for item in payload.get("k_phi", ())),
        u_phi=float(payload.get("u_phi", 0.0)),
        hbar_phi=float(payload.get("hbar_phi", 1.0)),
        field_id=str(payload.get("field_id", "transition_xray:v0")),
        details=dict(payload.get("details") or {}),
    )


def piece_from_state(payload: Mapping[str, Any]) -> XrayPiece:
    return XrayPiece(
        kind=str(payload["kind"]),
        ref=str(payload["ref"]),
        exists=payload.get("exists"),
        type=str(payload.get("type", "metadata")),
        size=payload.get("size"),
        sha256=payload.get("sha256"),
        details=dict(payload.get("details") or {}),
    )


def _audit_action(action: ActionEnvelope):
    registry = PhiRegistry()
    registry.register_actor(action.actor_id, ActorType.AGENT)
    project_root = _project_root_for_action(action)
    profile = confirm_protect_scan(
        default_protect_scan_profile(project_root),
        confirmed=True,
    )
    return audit_with_xray_review(
        action,
        registry=registry,
        project_root=project_root,
        protect_profile=profile,
    )


def _run_temporal(
    proposal: CommandProposal,
    project_root: str,
    event: Mapping[str, Any],
    env: Mapping[str, str],
) -> TemporalTestimony | None:
    # The accumulator is an ADDITIVE layer. If it cannot run we do not loosen
    # the spatial verdict -- we simply add no tightening. Its own state lives
    # outside the .phi surface (under .claude) so recording taint is never
    # itself an audited mutation.
    try:
        policy = OTPolicy(project_roots=(project_root,))
        ledger = TemporalContinuityLedger(_temporal_state_dir(event, env))
        return ledger.evaluate(proposal, policy)
    except Exception as exc:  # noqa: BLE001 - never let the 4th judge crash the gate
        _append_log(
            env,
            {
                "phase": "pretool_temporal_error",
                "error": f"{type(exc).__name__}: {exc}",
                "proposal_id": proposal.proposal_id,
            },
        )
        return None


def _temporal_output(temporal: TemporalTestimony | None) -> dict[str, Any] | None:
    # Map the sequence verdict onto Claude Code's permission surface. KILL is a
    # hard deny (exfil of accumulated taint, no appeal). HOLD routes to the
    # operator's native ask, same as a spatial HOLD. PASS adds nothing.
    if temporal is None:
        return None
    if temporal.vote == JudgeVote.KILL:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "Protect U Back temporal continuity denied before Claude Ask: "
                    f"KILL {temporal.reason_code}. The action is spatially clean but "
                    "the session sequence carries accumulated exposure to an exit."
                ),
            }
        }
    if temporal.vote == JudgeVote.HOLD:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": (
                    "Protect U Back held this action for operator review: "
                    f"HOLD {temporal.reason_code}. The sequence accumulated read "
                    "exposure before this exit. Allow runs it once; deny blocks it."
                ),
            }
        }
    return None


def _decision_rank(output: Mapping[str, Any] | None) -> int:
    # tighten-only ordering: deny > ask > nothing. Lets the stronger of the
    # spatial and temporal verdicts win without either loosening the other.
    if output is None:
        return 0
    decision = output.get("hookSpecificOutput", {}).get("permissionDecision")
    return {"deny": 2, "ask": 1}.get(decision, 0)


def _pretool_deny_output(
    disposition: EvidenceDisposition,
    reason_code: str,
) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "Protect U Back pretool admission denied before Claude Ask: "
                f"{disposition.value} {reason_code}"
            ),
        }
    }


def _pretool_hold_output(reason_code: str) -> dict[str, Any]:
    # HOLD is default-deny-with-appeal: the proposal is suspicious for lack of
    # evidence, not proven hostile, and the operator is the appeal court.
    # "ask" routes it to Claude Code's native allow/deny prompt instead of a
    # dead-end deny. KILL/QUARANTINE/REJECT remain hard denies with no appeal.
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                "Protect U Back held this action for operator review: "
                f"HOLD {reason_code}. Allow runs it once; deny blocks it."
            ),
        }
    }


def _is_recognized_tool(tool_name: str) -> bool:
    return str(tool_name).strip() in RECOGNIZED_TOOLS


def _pretool_review_output(reason_code: str, tool_name: str) -> dict[str, Any]:
    # "ask" forces explicit user review even under auto-approve / acceptEdits /
    # bypassPermissions modes, so an unmodelled capability can never run
    # silently. This is default-deny-with-appeal, not an outright kill: the
    # operator may approve a legitimate WebFetch / mcp__* call.
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                "Protect U Back: unmodelled capability requires review before run "
                f"({reason_code}: {tool_name}). The hook cannot infer this tool's "
                "side effects, so it is held for explicit user approval."
            ),
        }
    }


def _posttool_context_output(
    seal: XrayTransportSeal,
    review: XrayReview,
) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                "PUB_XRAY_AUTOPSY "
                f"continuity={seal.continuity_state} "
                f"mutation={seal.mutation_state} "
                f"witnesses={seal.witness_count} "
                f"field={seal.field_state} "
                f"review={review.disposition.value} "
                f"review_reason={review.reason_code} "
                f"transport_hash={seal.transport_hash}"
            ),
        }
    }


def _posttool_missing_output(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                "PUB_XRAY_AUTOPSY continuity=UNOBSERVED "
                "mutation=UNOBSERVED witnesses=0 field=UNKNOWN "
                f"reason={reason}"
            ),
        }
    }


def _targets_and_effects(
    tool_name: str,
    tool_input: Mapping[str, Any],
    command_text: str,
) -> tuple[tuple[str, ...], set[SideEffect]]:
    effects: set[SideEffect] = {SideEffect.READ}
    targets: list[str] = []
    normalized_tool = tool_name.strip()

    if normalized_tool == "Bash":
        parsed_targets, parsed_effects = _bash_targets_and_effects(command_text)
        targets.extend(parsed_targets)
        effects |= parsed_effects
    elif normalized_tool in {"Write", "Edit", "MultiEdit", "NotebookEdit"}:
        effects.add(SideEffect.WRITE)
        targets.extend(_file_path_values(tool_input))
    elif normalized_tool in {"Read", "NotebookRead"}:
        targets.extend(_file_path_values(tool_input))
    elif normalized_tool in {"Glob", "Grep", "LS"}:
        targets.extend(_file_path_values(tool_input))
    else:
        targets.extend(_file_path_values(tool_input))

    if _network_present(command_text, targets):
        effects.add(SideEffect.NETWORK)
    if _secret_present(command_text, targets):
        effects.add(SideEffect.SECRET_ACCESS)
    if _audit_surface_present(command_text, targets) and effects & {
        SideEffect.WRITE,
        SideEffect.DELETE,
        SideEffect.PRIVILEGE,
    }:
        effects.add(SideEffect.AUDIT_CHANGE)

    return tuple(dict.fromkeys(targets)), effects


def _bash_targets_and_effects(command: str) -> tuple[tuple[str, ...], set[SideEffect]]:
    effects: set[SideEffect] = {SideEffect.READ}
    targets: list[str] = []
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    skip_next = False
    command_words: list[str] = []
    for index, token in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue

        redirect = _redirect_target(token, tokens, index)
        if redirect.consumes_next:
            skip_next = True
        if redirect.target:
            targets.append(redirect.target)
            if redirect.write:
                effects.add(SideEffect.WRITE)
            continue
        if redirect.is_redirect:
            continue
        command_words.append(token)

    if not command_words:
        return tuple(dict.fromkeys(targets)), effects

    verb = Path(command_words[0]).name.lower()
    args = tuple(arg for arg in command_words[1:] if not arg.startswith("-"))
    if verb in {"touch", "mkdir", "tee"}:
        effects.add(SideEffect.WRITE)
        targets.extend(_path_like_args(args))
    elif verb in {"rm", "rmdir", "unlink"}:
        effects.add(SideEffect.DELETE)
        targets.extend(_path_like_args(args))
    elif verb in {"cp", "copy"} and args:
        effects.add(SideEffect.WRITE)
        targets.extend(_path_like_args(args))
    elif verb in {"mv", "move"} and args:
        effects.update({SideEffect.WRITE, SideEffect.DELETE})
        targets.extend(_path_like_args(args))
    elif verb in {"cat", "head", "tail", "less", "more", "grep", "sed", "awk"}:
        targets.extend(_path_like_args(args))
    elif verb in {"curl", "wget"}:
        effects.add(SideEffect.NETWORK)
        targets.extend(arg for arg in args if arg.startswith(("http://", "https://")))

    lowered = f" {command.lower()} "
    if any(token in lowered for token in (" curl ", " wget ", " http://", " https://")):
        effects.add(SideEffect.NETWORK)
    if any(token in lowered for token in (" sudo ", " runas ", " chmod 777", " chown ")):
        effects.add(SideEffect.PRIVILEGE)
    return tuple(dict.fromkeys(targets)), effects


@dataclass(frozen=True)
class _Redirect:
    is_redirect: bool = False
    consumes_next: bool = False
    target: str = ""
    write: bool = False


def _redirect_target(token: str, tokens: Sequence[str], index: int) -> _Redirect:
    if token in {">", ">>", "1>", "1>>", "2>", "2>>", "&>"}:
        if index + 1 < len(tokens) and not tokens[index + 1].startswith("&"):
            return _Redirect(True, True, tokens[index + 1], token != "<")
        return _Redirect(True, True)
    match = re.match(r"^(?:[0-9])?(>>?|<)(.+)$", token)
    if not match:
        return _Redirect(False)
    op, target = match.groups()
    if target.startswith("&"):
        return _Redirect(True)
    return _Redirect(True, False, target, op.startswith(">"))


def _path_like_args(args: Sequence[str]) -> tuple[str, ...]:
    return tuple(arg for arg in args if _looks_like_path(arg))


def _looks_like_path(value: str) -> bool:
    text = value.strip().strip("'\"")
    if not text or text.startswith("&"):
        return False
    if text in {"|", "&&", "||", ";"}:
        return False
    if text.startswith(("/", "./", "../", "~")):
        return True
    if "/" in text or "\\" in text:
        return True
    return bool(re.search(r"\.[A-Za-z0-9]{1,12}$", text))


def _file_path_values(tool_input: Mapping[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    for key in ("file_path", "path", "notebook_path", "pattern"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
    return tuple(dict.fromkeys(values))


def _network_present(command_text: str, targets: Sequence[str]) -> bool:
    haystack = " ".join((command_text, *targets)).lower()
    return any(token in haystack for token in ("http://", "https://", " curl ", " wget "))


def _secret_present(command_text: str, targets: Sequence[str]) -> bool:
    haystack = " ".join((command_text, *targets)).lower()
    return any(
        token in haystack
        for token in (".env", ".ssh", "id_rsa", "id_ed25519", "secret", "credential", "token")
    )


def _audit_surface_present(command_text: str, targets: Sequence[str]) -> bool:
    haystack = " ".join((command_text, *targets)).lower()
    return any(
        token in haystack
        for token in (
            ".phi/",
            ".phi\\",
            "ot_gate.py",
            "parallel_audit.py",
            "protect_scan.py",
            GATE_SWITCH_FILE_NAME,
        )
    )


def _authority_claim_present(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key).strip().lower()
            if key_text in {"can_execute", "can_grant_permission"} and _truthy(child):
                return True
            if key_text in {"permission_mode", "permissionmode"} and str(child).strip() in {
                "bypassPermissions",
                "bypass_permissions",
            }:
                return True
            if key_text in {"role", "authority", "permission"} and str(child).strip().lower() in {
                "admin",
                "root",
                "owner",
            }:
                return True
            if _authority_claim_present(child):
                return True
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_authority_claim_present(item) for item in value)
    return False


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {
            "true",
            "1",
            "yes",
            "y",
            "on",
            "allowed",
            "approved",
            "granted",
            "valid",
        }
    return bool(value)


def _command_text(tool_name: str, tool_input: Mapping[str, Any]) -> str:
    if tool_name == "Bash":
        return str(tool_input.get("command") or "")
    return json.dumps(_sanitize_tool_input(tool_input), sort_keys=True, ensure_ascii=False)


def _load_event(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"Claude hook payload must be JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ValueError("Claude hook payload must be a JSON object")
    return dict(value)


def _sanitize_claude_event(event: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(_jsonable(event))
    if isinstance(payload.get("tool_input"), Mapping):
        payload["tool_input"] = _sanitize_tool_input(payload["tool_input"])
    if isinstance(payload.get("toolInput"), Mapping):
        payload["toolInput"] = _sanitize_tool_input(payload["toolInput"])
    if "tool_response" in payload:
        payload["tool_response_summary"] = _tool_response_summary(payload.pop("tool_response"))
    if "toolResponse" in payload:
        payload["toolResponseSummary"] = _tool_response_summary(payload.pop("toolResponse"))
    return payload


def _sanitize_tool_input(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in tool_input.items():
        key_text = str(key)
        if key_text in SENSITIVE_TOOL_INPUT_KEYS:
            sanitized[key_text] = _text_digest_payload(value)
        elif isinstance(value, Mapping):
            sanitized[key_text] = _sanitize_tool_input(value)
        elif isinstance(value, (list, tuple)):
            sanitized[key_text] = [
                _sanitize_tool_input(item) if isinstance(item, Mapping) else _jsonable(item)
                for item in value
            ]
        else:
            sanitized[key_text] = _jsonable(value)
    return sanitized


def _tool_response_summary(value: Any) -> Any:
    if isinstance(value, Mapping):
        summary: dict[str, Any] = {
            "type": "mapping",
            "keys": tuple(sorted(str(key) for key in value)),
            "sha256": _sha256_json(value),
        }
        for key in ("stdout", "stderr", "error", "output"):
            if key in value:
                summary[f"{key}_digest"] = _text_digest_payload(value.get(key))
        for key in ("interrupted", "isImage", "noOutputExpected", "duration_ms"):
            if key in value:
                summary[key] = _jsonable(value.get(key))
        return summary
    return {
        "type": type(value).__name__,
        "sha256": _sha256_json(value),
        "length": len(str(value)) if value is not None else 0,
    }


def _text_digest_payload(value: Any) -> dict[str, Any]:
    text = "" if value is None else str(value)
    return {
        "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
        "length": len(text),
        "redacted": True,
    }


def _tool_name(event: Mapping[str, Any]) -> str:
    return str(event.get("tool_name") or event.get("toolName") or "unknown")


def _tool_input(event: Mapping[str, Any]) -> dict[str, Any]:
    value = event.get("tool_input") or event.get("toolInput") or {}
    return dict(value) if isinstance(value, Mapping) else {}


def _event_correlation_id(
    event: Mapping[str, Any],
    *,
    action: ActionEnvelope | None = None,
) -> str:
    direct = event.get("tool_use_id") or event.get("toolUseID") or event.get("tool_use_id")
    if direct:
        return str(direct)
    payload = {
        "session_id": event.get("session_id"),
        "tool_name": _tool_name(event),
        "tool_input": _tool_input(event),
        "cwd": event.get("cwd") or (action.cwd if action is not None else None),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
    return f"sha256_{digest[:24]}"


def _event_cwd(event: Mapping[str, Any], env: Mapping[str, str]) -> str:
    cwd = event.get("cwd") or env.get("CLAUDE_PROJECT_DIR") or env.get("PUB_CLAUDE_PROJECT_ROOT")
    return str(Path(str(cwd or Path.cwd())).expanduser().resolve(strict=False))


def _project_root_for_action(action: ActionEnvelope) -> str:
    return str(Path(action.cwd).expanduser().resolve(strict=False))


def _sandbox_evidence_from_env(env: Mapping[str, str]) -> dict[str, Any]:
    if "PUB_CLAUDE_SANDBOX_AVAILABLE" not in env:
        return {}
    available = env.get("PUB_CLAUDE_SANDBOX_AVAILABLE", "").strip().lower()
    return {
        "available": available not in {"0", "false", "no", "unavailable"},
        "reason": env.get("PUB_CLAUDE_SANDBOX_REASON", ""),
        "fallback": env.get("PUB_CLAUDE_SANDBOX_FALLBACK", "claude_code_tool_runtime"),
    }


def _gate_switch_off(event: Mapping[str, Any], env: Mapping[str, str]) -> bool:
    # Operator kill switch, read fresh on every hook invocation: flipping the
    # file takes effect on the next tool call, no session restart. Fail
    # closed -- a missing, unreadable, or malformed switch keeps the gate
    # armed; only a literal {"enabled": false} disarms it.
    switch_path = Path(_event_cwd(event, env)) / ".claude" / GATE_SWITCH_FILE_NAME
    try:
        payload = json.loads(switch_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(payload, Mapping) and payload.get("enabled") is False


def _gate_switch_off_from_raw(raw: str) -> bool:
    try:
        return _gate_switch_off(_load_event(raw), os.environ)
    except Exception:
        return False


def _state_path(cid: str, event: Mapping[str, Any], env: Mapping[str, str]) -> Path:
    state_dir = env.get("PUB_CLAUDE_HOOK_STATE_DIR")
    if state_dir:
        root = Path(state_dir)
    else:
        root = Path(_event_cwd(event, env)) / ".claude" / STATE_DIR_NAME
    root.mkdir(parents=True, exist_ok=True)
    safe = hashlib.sha256(cid.encode("utf-8")).hexdigest()
    return root / f"{safe}.json"


def _temporal_state_dir(event: Mapping[str, Any], env: Mapping[str, str]) -> Path:
    # Sequence-memory state. Kept OUTSIDE the protected .phi surface (under
    # .claude) so writing taint is not itself an audited mutation. Honors the
    # same explicit override knob as the xray state dir for test isolation.
    override = env.get("PUB_CLAUDE_TEMPORAL_STATE_DIR")
    if override:
        root = Path(override)
    else:
        root = Path(_event_cwd(event, env)) / ".claude" / TEMPORAL_STATE_DIR_NAME
    root.mkdir(parents=True, exist_ok=True)
    return root


def _state_ttl_seconds(env: Mapping[str, str]) -> int:
    raw = env.get("PUB_CLAUDE_STATE_TTL_SECONDS")
    if not raw:
        return DEFAULT_STATE_TTL_SECONDS
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_STATE_TTL_SECONDS


def _state_expired(state: Mapping[str, Any]) -> bool:
    expires_at = state.get("expires_at")
    if not isinstance(expires_at, (int, float)):
        return False
    return time.time() > float(expires_at)


def _log_path(env: Mapping[str, str]) -> Path:
    log_dir = env.get("PUB_CLAUDE_HOOK_LOG_DIR")
    if log_dir:
        root = Path(log_dir)
    else:
        project = Path(env.get("CLAUDE_PROJECT_DIR") or env.get("PUB_CLAUDE_PROJECT_ROOT") or Path.cwd())
        root = project / "audit_logs"
    root.mkdir(parents=True, exist_ok=True)
    return root / LOG_FILE_NAME


def _autopsy_path(cid: str, env: Mapping[str, str]) -> Path:
    root = _log_path(env).parent
    safe = hashlib.sha256(cid.encode("utf-8")).hexdigest()
    return root / f"pub_claude_posttool_autopsy_{safe}.json"


def _append_log(env: Mapping[str, str], row: Mapping[str, Any]) -> str:
    payload = {"ts": time.time(), "hook_id": HOOK_ID, **dict(row)}
    with _log_path(env).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(_jsonable(payload), ensure_ascii=False, sort_keys=True) + "\n")
    return _mirror_to_ledger(env, payload)


def _mirror_to_ledger(env: Mapping[str, str], payload: Mapping[str, Any]) -> str:
    """Out-of-cage ledger mirror (PUB-OS Task 3). Returns a witness status.

    No-op (``"not_configured"``) unless ``PUB_OS_LEDGER_SOCKET`` is set, i.e.
    running inside a cc cage whose only audit egress is the ledger socket. When
    set, the same row just written locally is delivered to the out-of-cage
    ``LedgerSupervisor`` that owns the tamper-proof, hash-chained ledger.

    This function never raises -- a transport failure must not crash the gate.
    It only REPORTS the outcome; ``run_pretool_admission`` is what acts on a lost
    witness (fail closed -> HOLD). Statuses:
      not_configured  no ledger socket -> default uncaged behaviour, no mirror
      recorded        supervisor acknowledged the row
      unavailable     supervisor unreachable / no ack  (witness lost)
      rejected        supervisor refused the row (payload/authority field)
      error           any other mirror failure
    """
    socket_path = env.get("PUB_OS_LEDGER_SOCKET")
    if not socket_path:
        return "not_configured"
    try:
        from pub_os_ledger import LedgerEventRejected, LedgerUnavailable, emit_event

        emit_event(socket_path, _jsonable(dict(payload)))
        return "recorded"
    except LedgerUnavailable:
        return "unavailable"
    except LedgerEventRejected:
        return "rejected"
    except Exception:  # noqa: BLE001 - the audit mirror must never break the gate
        return "error"


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_jsonable(payload), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _jsonable(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(child) for key, child in sorted(value.items())}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def write_hook_output(output: Mapping[str, Any] | None) -> None:
    if output is None:
        return
    sys.stdout.write(json.dumps(_jsonable(output), ensure_ascii=False, sort_keys=True) + "\n")


def main_pretool() -> int:
    raw = sys.stdin.read()
    try:
        result = run_pretool_admission(raw)
        write_hook_output(result.output)
        return 0
    except Exception as exc:
        # The switch is the operator's escape hatch even when the gate itself
        # is broken: with the gate off, a crashing hook must not fail closed.
        if _gate_switch_off_from_raw(raw):
            return 0
        write_hook_output(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        "Protect U Back pretool admission failed closed before Claude Ask: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                }
            }
        )
        return 0


def main_posttool() -> int:
    try:
        result = run_posttool_autopsy(sys.stdin.read())
        write_hook_output(result.output)
    except Exception as exc:
        try:
            _append_log(
                os.environ,
                {
                    "phase": "posttool_autopsy",
                    "error": f"{type(exc).__name__}: {exc}",
                },
            )
        except Exception:
            pass
    return 0
