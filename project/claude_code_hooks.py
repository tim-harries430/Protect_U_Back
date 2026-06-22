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
from llm_channel import ChannelType, safe_git_write
from ot_gate import (
    CommandProposal,
    DeclaredScope,
    JudgeVote,
    OTPolicy,
    SideEffect,
    delete_command_operands,
    is_scoped_single_file_delete,
)
from parallel_audit import EvidenceDisposition
from scene_continuity import SceneContinuityLedger, SceneContinuityReport
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
SCENE_STATE_DIR_NAME = "pub_scene_state"
LOG_FILE_NAME = "pub_claude_hooks.jsonl"
GATE_SWITCH_FILE_NAME = "pub_gate_switch.json"
_SHELL_SEGMENT_RE = re.compile(r"\s*(?:;|\|\||&&|\|)\s*|\n+")
_SHELL_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
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
# evidence it must be denied for missing PUB evidence, never silently classified as a READ.
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
    gate_switch_state = _gate_switch_state(event, env)
    output = None
    if decision.disposition is EvidenceDisposition.HOLD:
        output = _pretool_hold_output(decision.reason_code)
    elif decision.disposition in BLOCKING_DISPOSITIONS:
        output = _pretool_deny_output(decision.disposition, decision.reason_code)

    # ① git-write relax (pass-road load-bearing): a clean, single, safe git mutation
    # verb (add/commit/checkout/branch/stash/restore/tag/merge, no dynamic expansion,
    # no danger flag) is held ONLY by the OPAQUE wall -- git is opaque because hooks
    # run code. We downgrade ONLY when OPAQUE is the SOLE (primary) reason: anything
    # more severe (secret/destructive/external) outranks OPAQUE and stays primary, so
    # this cannot unmask it. The .git write-protection below removes the matching
    # escalation (a planted hook), so the relaxed verb cannot run agent-supplied code.
    if (
        output is not None
        and decision.reason_code == "COMMAND_SURFACE_OPAQUE_EXECUTION"
        and safe_git_write(action.command_text)
    ):
        output = None

    # ① .git executable surface is write-protected: deny any direct agent write/delete
    # into <project>/.git/. This is the precondition that makes the git-write relax
    # safe (no agent-planted hook to trigger). Tightens only; applied after the relax.
    if _git_internal_write_denied(action, project_root):
        output = _pretool_deny_output(
            EvidenceDisposition.KILL, "PROTECT_GIT_SURFACE_WRITE_DENIED"
        )

    # Unmodelled capability => hard stop. Native Claude allow/acceptEdits is not
    # a PUB court; it cannot convert missing evidence into execution authority.
    if output is None and not _is_recognized_tool(action.tool_name):
        output = _pretool_review_output("UNKNOWN_CAPABILITY", action.tool_name)

    # The spatial gate above judges THIS proposal in isolation. The temporal
    # accumulator judges the SEQUENCE: a session that drifts off its stated
    # task -- read a secret between two look-alike downloads, then egress --
    # is invisible to any single-frame check. Run it always (even under a
    # block) so the ledger remembers; it can only TIGHTEN the verdict, never
    # loosen it.
    temporal = _run_temporal(proposal, project_root, event, env)
    candidate = _temporal_output(temporal)
    if _decision_rank(candidate) > _decision_rank(output):
        output = candidate
    temporal_vote = temporal.vote.value if temporal is not None else "PASS"
    temporal_reason_code = temporal.reason_code if temporal is not None else "TEMPORAL_CONTINUOUS"

    # The surroundings judge: did an integrity anchor (pub's own modules) or the
    # project skeleton change OUT-OF-BAND since this session's previous action? A
    # side-channel / race that mutates the scene between actions is invisible to
    # every single-frame check. Real-time at PRE; additive, can only TIGHTEN.
    scene = _run_scene(proposal, project_root, event, env)
    scene_candidate = _scene_output(scene)
    if _decision_rank(scene_candidate) > _decision_rank(output):
        output = scene_candidate
    scene_vote = scene.state.value if scene is not None else "ABSENT"
    scene_reason_code = scene.reason_code if scene is not None else "SCENE_ABSENT"

    # ④b auto-restore (補位 restore arm): when the SEQUENCE judges this session
    # compromised -- temporal KILL (accumulated taint heading to an exit) or an
    # out-of-band scene tamper -- retake the ground: roll back the in-project
    # mutations this session journalled before it was caught. Fired at most once per
    # session (marker) and ONLY on these strong deny-level signals, so a healthy
    # session's work is never undone. It restores; it never loosens the verdict.
    session_id = str(event.get("session_id") or "")
    session_compromised = (
        temporal is not None and temporal.vote == JudgeVote.KILL
    ) or (scene is not None and getattr(scene, "requires_hold", False))
    if session_compromised and session_id:
        restore_marker = (
            _log_path(env).parent
            / f"pub_session_restored_{hashlib.sha256(session_id.encode('utf-8')).hexdigest()}.marker"
        )
        if not restore_marker.exists():
            restore_summary = restore_session_backfill(session_id, env)
            _append_log(
                env,
                {
                    "phase": "session_backfill_restore",
                    "session_id": session_id,
                    "trigger": (
                        "temporal_kill"
                        if (temporal is not None and temporal.vote == JudgeVote.KILL)
                        else "scene_out_of_band"
                    ),
                    "restored": restore_summary.get("restored", 0),
                    "manifests": restore_summary.get("manifests", 0),
                },
            )
            try:
                restore_marker.write_text("1", encoding="utf-8")
            except OSError:
                pass

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
            "scene_vote": scene_vote,
            "scene_reason_code": scene_reason_code,
            "gate_switch": gate_switch_state,
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
    # proceed silently -- escalate to a hard HOLD denial. This only fires when a ledger
    # socket is configured (witness == "unavailable" requires PUB_OS_LEDGER_SOCKET),
    # so the default uncaged path is untouched. It tightens only (never downgrades
    # a deny). No runtime switch can relax this: a lost out-of-cage witness is
    # a missing-evidence condition, so it must HOLD or keep the stronger block.
    if witness == "unavailable":
        _witness_hold = _pretool_hold_output("PUB_OS_LEDGER_WITNESS_LOST")
        if _decision_rank(_witness_hold) > _decision_rank(output):
            output = _witness_hold

    # Trust-but-record: if this proposal is FINALLY allowed (output is None) and it
    # is an in-project single-file destructive op permitted under the reversible-
    # delete grant, leave a forensic note the FIRST time per session, where autopsy
    # reports land -- so a permitted destructive action is never fully invisible.
    # Backfill (補位): before an allowed mutation lands, snapshot its in-project
    # pre-image so the ground can be retaken. Additive on WRITE; a destructive op
    # whose pre-image cannot be captured is un-backfillable and flips to HOLD. The
    # RESTORE arm stays manual (restore_from_backfill_journal) until X-ray de-noise
    # gives a high-confidence flag -- auto-restore on today's over-fired QUARANTINE
    # would undo legitimate work.
    if output is None:
        backfill = _journal_reversible_targets(env, cid, action, proposal, project_root)
        if backfill.held:
            output = _pretool_hold_output("PUB_BACKFILL_JOURNAL_FAILED")
        elif backfill.entries:
            _append_log(
                env,
                {
                    "phase": "pretool_backfill",
                    "cid": cid,
                    "tool_name": action.tool_name,
                    "journalled_entries": backfill.entries,
                    "oversize_destructive": list(backfill.oversize_destructive),
                    "manifest_path": backfill.manifest_path,
                },
            )

    if output is None:
        _record_allowed_scoped_delete(
            env, str(event.get("session_id") or ""), action, proposal, project_root
        )
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
    if not state_path.exists():
        output = _posttool_missing_output("missing_enter_state")
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
        output = _posttool_missing_output("expired_enter_state")
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
    output = _posttool_context_output(seal, review)

    # Backfill advisory: if a pre-image journal was captured at PreToolUse, surface
    # WHERE the ground can be retaken from. Restore stays operator-driven
    # (restore_from_backfill_journal): it is deliberately NOT auto-fired on the X-ray
    # review, because the de-noised single-frame review is SYNCHRONOUS with admission
    # -- anything it would quarantine is already blocked at PreToolUse, so it never
    # coincides with an allowed, journalled op (QUARANTINE n journalled-and-allowed =
    # empty). The correct auto-restore trigger is a SEQUENCE-level signal that arrives
    # later (temporal drift / scene out-of-band change) flagging a PRIOR allowed
    # mutation; that is a separate, future wiring.
    backfill_manifest = _backfill_dir(cid, env) / "manifest.json"
    backfill_available = backfill_manifest.exists()
    if backfill_available:
        ctx = output["hookSpecificOutput"]["additionalContext"]
        output["hookSpecificOutput"]["additionalContext"] = (
            f"{ctx} backfill_journal={backfill_manifest}"
        )

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
            "backfill_journal": str(backfill_manifest) if backfill_available else "",
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
        raw_payload=_proposal_raw_payload(action),
    )


def _proposal_raw_payload(action: ActionEnvelope) -> dict[str, Any]:
    payload = dict(action.raw_payload)
    payload.setdefault(
        "pub_process",
        {
            "actor_id": action.actor_id,
            "action_id": action.action_id,
            "channel_type": action.channel_type.value,
            "cwd": action.cwd,
            "target_paths": tuple(action.target_paths),
            "expected_side_effects": tuple(
                sorted(effect.value for effect in action.expected_side_effects)
            ),
            "p_enter_ts": _process_time_evidence(action),
            "source_adapter": action.source_adapter,
            "action_type": action.action_type.value,
        },
    )
    return payload


def _process_time_evidence(action: ActionEnvelope) -> str:
    for key in ("created_at", "timestamp", "ts", "time", "time_ns", "p_enter_ts"):
        value = action.raw_payload.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return action.action_id


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


def _run_scene(
    proposal: CommandProposal,
    project_root: str,
    event: Mapping[str, Any],
    env: Mapping[str, str],
) -> SceneContinuityReport | None:
    # Surroundings continuity (the scene judge). Additive: if it cannot run we add
    # no tightening. State lives outside the .phi surface (under .claude), so
    # recording the baseline is not itself an audited mutation.
    try:
        ledger = SceneContinuityLedger(_scene_state_dir(event, env))
        return ledger.evaluate(proposal, project_root)
    except Exception as exc:  # noqa: BLE001 - never let the surroundings judge crash the gate
        _append_log(
            env,
            {
                "phase": "pretool_scene_error",
                "error": f"{type(exc).__name__}: {exc}",
                "proposal_id": proposal.proposal_id,
            },
        )
        return None


def _scene_output(scene: SceneContinuityReport | None) -> dict[str, Any] | None:
    # An out-of-band scene discontinuity is denied in the hook (HOLD): native
    # allow/acceptEdits cannot overrule a broken-continuity surroundings verdict.
    if scene is None or not scene.requires_hold:
        return None
    return _pretool_hold_output(scene.reason_code)


def _temporal_output(temporal: TemporalTestimony | None) -> dict[str, Any] | None:
    # Map the sequence verdict onto Claude Code's permission surface. KILL is a
    # hard deny (exfil of accumulated taint, no appeal). HOLD is also denied in
    # the hook: native allow/acceptEdits is not allowed to overrule PUB.
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
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "Protect U Back denied temporal HOLD before Claude Allow: "
                    f"HOLD {temporal.reason_code}. The sequence accumulated read "
                    "exposure before this exit. Native allow cannot grant PUB authority."
                ),
            }
        }
    return None


def _decision_rank(output: Mapping[str, Any] | None) -> int:
    # tighten-only ordering: deny > ask > nothing. "ask" remains understood only
    # for defensive compatibility with older helper output; current PUB hook
    # output for agent actions must not delegate authority to native ask.
    # Lets the stronger of the
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
    # HOLD is default-deny under the agent hook. The operator remains the appeal
    # court, but appeal must happen through a PUB ticket/pass road, never through
    # Claude Code's native Allow button.
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "Protect U Back denied held action before Claude Allow: "
                f"HOLD {reason_code}. Native allow cannot grant PUB authority."
            ),
        }
    }


def _is_recognized_tool(tool_name: str) -> bool:
    return str(tool_name).strip() in RECOGNIZED_TOOLS


def _pretool_review_output(reason_code: str, tool_name: str) -> dict[str, Any]:
    # Unknown tools are not routed to Claude's native review. They need a PUB
    # model or a PUB-issued ticket; the native allow surface is not authority.
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "Protect U Back denied unmodelled capability before Claude Allow "
                f"({reason_code}: {tool_name}). The hook cannot infer this tool's "
                "side effects; native allow cannot grant PUB authority."
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
    for segment in _shell_segments(command):
        segment_targets, segment_effects = _single_bash_segment_targets_and_effects(segment)
        targets.extend(segment_targets)
        effects |= segment_effects
    return tuple(dict.fromkeys(targets)), effects


def _shell_segments(command: str) -> tuple[str, ...]:
    return tuple(
        segment.strip()
        for segment in _SHELL_SEGMENT_RE.split(command)
        if segment.strip()
    )


def _single_bash_segment_targets_and_effects(
    command: str,
) -> tuple[tuple[str, ...], set[SideEffect]]:
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
        if SideEffect.WRITE in effects:
            effects.add(SideEffect.DELETE)
        return tuple(dict.fromkeys(targets)), effects

    while command_words and _SHELL_ASSIGNMENT_RE.match(command_words[0]):
        command_words.pop(0)

    if not command_words:
        return tuple(dict.fromkeys(targets)), effects

    raw_verb = command_words[0]
    if raw_verb.startswith("$") or raw_verb.startswith("${"):
        effects.add(SideEffect.WRITE)
        return tuple(dict.fromkeys(targets)), effects

    effective_words = _effective_shell_command_words(command_words)
    if effective_words:
        targets.extend(_interpreter_script_targets(effective_words[0], effective_words[1:]))

    verb = Path(raw_verb).name.lower()
    args = tuple(arg for arg in command_words[1:] if not arg.startswith("-"))
    lowered = f" {command.lower()} "
    if verb in {"alias", "unalias"}:
        if any(token in lowered for token in (" rm ", "rm -", " rmdir ", " unlink ", " del ")):
            effects.add(SideEffect.WRITE)
        return tuple(dict.fromkeys(targets)), effects
    if "()" in raw_verb or raw_verb.endswith("(){") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\(\)$", raw_verb):
        if any(token in lowered for token in (" rm ", "rm -", " rmdir ", " unlink ", " del ")):
            effects.add(SideEffect.WRITE)
        return tuple(dict.fromkeys(targets)), effects

    if verb == "mkdir":
        effects.add(SideEffect.WRITE)
        targets.extend(_mkdir_targets(args))
    elif verb in {"touch", "tee"}:
        effects.add(SideEffect.WRITE)
        targets.extend(_path_like_or_opaque_args(args))
    elif verb in {"rm", "rmdir", "unlink"}:
        effects.add(SideEffect.DELETE)
        # Every non-flag operand of a delete IS a deletion target. pub's generic
        # path-like filter drops bare directory names (`rm -rf build`), which both
        # hid the target from the in-project recursive-delete relax AND from the
        # protected/outside danger checks. Take operands verbatim here.
        targets.extend(args)
    elif verb in {"cp", "copy"} and args:
        effects.add(SideEffect.WRITE)
        targets.extend(_path_like_or_opaque_args(args))
    elif verb in {"mv", "move"} and args:
        effects.update({SideEffect.WRITE, SideEffect.DELETE})
        targets.extend(_path_like_or_opaque_args(args))
    elif verb == "sed" and any(token == "-i" or token.startswith("-i") for token in command_words[1:]):
        effects.add(SideEffect.WRITE)
        targets.extend(_path_like_or_opaque_args(args[1:] if len(args) > 1 else args))
    elif verb in {"cat", "head", "tail", "less", "more", "grep", "sed", "awk"}:
        targets.extend(_path_like_or_opaque_args(args))
    elif verb in {"curl", "wget"}:
        effects.add(SideEffect.NETWORK)
        targets.extend(arg for arg in args if arg.startswith(("http://", "https://")))
    elif verb in {"powershell", "pwsh", "powershell.exe", "pwsh.exe"}:
        nested_targets, nested_effects = _powershell_targets_and_effects(command_words[1:])
        targets.extend(nested_targets)
        effects |= nested_effects
    elif verb in {"cmd", "cmd.exe"}:
        nested_targets, nested_effects = _cmd_targets_and_effects(command_words[1:], raw_command=command)
        if nested_targets:
            targets = _drop_cmd_backslash_phantoms(targets, nested_targets)
        targets.extend(nested_targets)
        effects |= nested_effects
    elif verb == "find" and (
        any(token == "-delete" for token in command_words[1:])
        or _find_executes_destructive_verb(command_words[1:])
    ):
        effects.add(SideEffect.DELETE)
        targets.extend(_path_like_args(args))
    elif verb == "git":
        git_effects, git_targets = _git_targets_and_effects(command_words[1:])
        effects |= git_effects
        targets.extend(git_targets)
    elif verb == "docker":
        docker_effects, docker_targets = _docker_targets_and_effects(command_words[1:])
        effects |= docker_effects
        targets.extend(docker_targets)
    elif verb == "kubectl":
        kubectl_effects, kubectl_targets = _kubectl_targets_and_effects(command_words[1:])
        effects |= kubectl_effects
        targets.extend(kubectl_targets)
    elif verb == "truncate":
        effects.update({SideEffect.WRITE, SideEffect.DELETE})
        targets.extend(_path_like_args(args))
    elif verb in {"chmod", "chown", "icacls"}:
        effects.add(SideEffect.PRIVILEGE)
        targets.extend(_path_like_or_opaque_args(args))
    elif _direct_script_target(raw_verb):
        targets.append(_direct_script_target(raw_verb))

    if any(token in lowered for token in (" curl ", " wget ", " http://", " https://")):
        effects.add(SideEffect.NETWORK)
    if any(token in lowered for token in (" sudo ", " runas ", " chmod 777", " chown ")):
        effects.add(SideEffect.PRIVILEGE)
    return tuple(dict.fromkeys(targets)), effects


def _git_targets_and_effects(
    args: Sequence[str],
) -> tuple[set[SideEffect], tuple[str, ...]]:
    if not args:
        return set(), ()
    subcommand = args[0].lower()
    if subcommand == "clean" and any(
        token.startswith("-") and "f" in token for token in args[1:]
    ):
        return {SideEffect.DELETE}, ()
    if subcommand == "reset" and "--hard" in args[1:]:
        return {SideEffect.WRITE, SideEffect.DELETE}, ()
    if subcommand == "checkout" and "--" in args[1:]:
        separator = args.index("--")
        return {SideEffect.WRITE, SideEffect.DELETE}, _path_like_args(args[separator + 1 :])
    if subcommand == "add":
        return {SideEffect.WRITE}, tuple(dict.fromkeys((*_path_like_args(args[1:]), ".git/index")))
    if subcommand in {"commit", "merge", "rebase", "cherry-pick", "stash", "apply", "am", "switch"}:
        return {SideEffect.WRITE}, (".git",)
    if subcommand in {"fetch", "pull"}:
        return {SideEffect.WRITE}, (".git",)
    if subcommand == "push":
        return set(), (".git",)
    return set(), ()


def _docker_targets_and_effects(
    args: Sequence[str],
) -> tuple[set[SideEffect], tuple[str, ...]]:
    if not args:
        return set(), ()
    effects: set[SideEffect] = set()
    targets: list[str] = []
    lowered = tuple(str(arg).lower() for arg in args)
    if any(
        token == "--privileged"
        or token.startswith("--cap-add")
        or token.startswith("--device")
        or token in {"--pid=host", "--network=host"}
        for token in lowered
    ):
        effects.add(SideEffect.PRIVILEGE)
    targets.extend(_docker_volume_targets(args))
    if lowered[0] == "build":
        targets.extend(_docker_build_contexts(args[1:]))
    return effects, tuple(dict.fromkeys(targets))


def _docker_volume_targets(args: Sequence[str]) -> tuple[str, ...]:
    targets: list[str] = []
    items = tuple(str(arg) for arg in args)
    for index, token in enumerate(items):
        lowered = token.lower()
        spec = ""
        if lowered in {"-v", "--volume"} and index + 1 < len(items):
            spec = items[index + 1]
        elif lowered.startswith("-v") and len(token) > 2:
            spec = token[2:]
        elif lowered.startswith("--volume="):
            spec = token.split("=", 1)[1]
        elif lowered == "--mount" and index + 1 < len(items):
            spec = _docker_mount_source(items[index + 1])
        elif lowered.startswith("--mount="):
            spec = _docker_mount_source(token.split("=", 1)[1])
        if not spec:
            continue
        host = spec.split(":", 1)[0]
        if host and _looks_like_path(host):
            targets.append(host)
    return tuple(dict.fromkeys(targets))


def _docker_mount_source(spec: str) -> str:
    for piece in spec.split(","):
        key, sep, value = piece.partition("=")
        if sep and key.strip().lower() in {"src", "source"}:
            return value.strip()
    return ""


def _docker_build_contexts(args: Sequence[str]) -> tuple[str, ...]:
    flag_values = {
        "-f", "--file", "-t", "--tag", "--build-arg", "--target", "--platform",
        "--label", "--secret", "--ssh", "--cache-from", "--cache-to", "-o", "--output",
    }
    candidates: list[str] = []
    skip_next = False
    for token in args:
        text = str(token)
        lowered = text.lower()
        if skip_next:
            skip_next = False
            continue
        if lowered in flag_values:
            skip_next = True
            continue
        if lowered.startswith("--") and "=" in lowered:
            continue
        if text.startswith("-"):
            continue
        if _looks_like_path(text):
            candidates.append(text)
    if not candidates:
        return ()
    return (candidates[-1],)


def _kubectl_targets_and_effects(
    args: Sequence[str],
) -> tuple[set[SideEffect], tuple[str, ...]]:
    targets: list[str] = []
    items = tuple(str(arg) for arg in args)
    for index, token in enumerate(items):
        lowered = token.lower()
        if lowered in {"-f", "--filename", "-k", "--kustomize"} and index + 1 < len(items):
            targets.append(items[index + 1])
        elif lowered.startswith("--filename=") or lowered.startswith("--kustomize="):
            targets.append(token.split("=", 1)[1])
    return set(), tuple(dict.fromkeys(target for target in targets if _looks_like_path(target)))


def _powershell_targets_and_effects(
    args: Sequence[str],
) -> tuple[tuple[str, ...], set[SideEffect]]:
    nested = _nested_command_after_flag(args, ("-command", "-c"))
    if not nested:
        return (), {SideEffect.READ}
    try:
        tokens = shlex.split(nested, posix=True)
    except ValueError:
        tokens = nested.split()
    if not tokens:
        return (), {SideEffect.READ}

    verb = tokens[0].lower()
    rest = tuple(token for token in tokens[1:] if not token.startswith("-"))
    effects: set[SideEffect] = {SideEffect.READ}
    targets: list[str] = []

    if verb in {"get-content", "gc", "type"}:
        targets.extend(_path_like_args(rest))
    elif verb in {"dir", "ls", "get-childitem", "gci"}:
        targets.extend(_mkdir_targets(rest))
    elif verb in {"set-content", "sc", "add-content", "out-file", "new-item", "ni"}:
        effects.add(SideEffect.WRITE)
        targets.extend(_path_like_args(rest))
    elif verb in {"copy-item", "cpi", "cp", "copy"}:
        effects.add(SideEffect.WRITE)
        targets.extend(_path_like_args(rest))
    elif verb in {"move-item", "mi", "mv", "move"}:
        effects.update({SideEffect.WRITE, SideEffect.DELETE})
        targets.extend(_path_like_args(rest))
    elif verb in {"remove-item", "ri", "rm", "del", "erase", "rmdir"}:
        effects.add(SideEffect.DELETE)
        targets.extend(_path_like_args(rest))
    elif verb in {"invoke-webrequest", "iwr", "invoke-restmethod", "irm", "curl", "wget"}:
        effects.add(SideEffect.NETWORK)
        targets.extend(token for token in rest if token.startswith(("http://", "https://")))
        outfile = _flag_value(tokens, ("-outfile", "-out"))
        if outfile:
            effects.add(SideEffect.WRITE)
            targets.append(outfile)
    elif verb == "start-process":
        if any(token.lower() == "runas" for token in rest) or "-verb runas" in nested.lower():
            effects.add(SideEffect.PRIVILEGE)

    lowered = f" {nested.lower()} "
    if any(token in lowered for token in (" http://", " https://", " iwr ", " irm ", "invoke-webrequest")):
        effects.add(SideEffect.NETWORK)
    if any(token in lowered for token in (" iex", " invoke-expression", "|iex", "| iex")):
        effects.add(SideEffect.PRIVILEGE)
    return tuple(dict.fromkeys(targets)), effects


def _cmd_targets_and_effects(
    args: Sequence[str],
    *,
    raw_command: str = "",
) -> tuple[tuple[str, ...], set[SideEffect]]:
    nested = _raw_cmd_nested_command(raw_command) or _nested_command_after_flag(args, ("/c", "/k"))
    if not nested:
        return (), {SideEffect.READ}
    nested = nested.strip()
    if not nested:
        return (), {SideEffect.READ}
    nested = nested.replace("\\", "/")
    try:
        tokens = shlex.split(nested, posix=True)
    except ValueError:
        tokens = nested.split()
    if not tokens:
        return (), {SideEffect.READ}

    verb = tokens[0].lower()
    rest = tuple(token for token in tokens[1:] if not token.startswith(("/", "-")))
    effects: set[SideEffect] = {SideEffect.READ}
    targets: list[str] = []

    if verb in {"type", "dir"}:
        targets.extend(_path_like_args(rest))
    elif verb in {"copy", "xcopy", "robocopy"}:
        effects.add(SideEffect.WRITE)
        targets.extend(_path_like_args(rest))
    elif verb in {"move", "ren", "rename"}:
        effects.update({SideEffect.WRITE, SideEffect.DELETE})
        targets.extend(_path_like_args(rest))
    elif verb in {"del", "erase", "rmdir", "rd"}:
        effects.add(SideEffect.DELETE)
        targets.extend(_path_like_args(rest))
    redirect_target, redirect_write = _cmd_redirection_target(nested)
    if redirect_target:
        targets.append(redirect_target)
        if redirect_write:
            effects.add(SideEffect.WRITE)
    return tuple(dict.fromkeys(targets)), effects


def _find_executes_destructive_verb(args: Sequence[str]) -> bool:
    lowered = tuple(str(item).lower() for item in args)
    for index, token in enumerate(lowered):
        if token == "-exec" and index + 1 < len(lowered):
            return Path(lowered[index + 1]).name in {"rm", "rmdir", "unlink", "del"}
    return False


def _flag_value(tokens: Sequence[str], flags: Sequence[str]) -> str:
    lowered_flags = {flag.lower() for flag in flags}
    for index, token in enumerate(tokens):
        lowered = str(token).lower()
        if lowered in lowered_flags and index + 1 < len(tokens):
            return str(tokens[index + 1])
        for flag in lowered_flags:
            prefix = flag + ":"
            if lowered.startswith(prefix):
                return str(token)[len(prefix):]
    return ""


def _raw_cmd_nested_command(command: str) -> str:
    match = re.search(r"(?i)\bcmd(?:\.exe)?\s+(?:/d\s+)?(?:/s\s+)?(?:/c|/k)\s+(.+)$", command)
    if not match:
        return ""
    return match.group(1).strip().strip('"')


def _cmd_redirection_target(command: str) -> tuple[str, bool]:
    match = re.search(r"(?:^|\s)(?:[0-9]+)?(>>?|1>>?|2>>?)\s+([^&|<>]+)", command)
    if not match:
        return "", False
    op, target = match.groups()
    target = target.strip().strip('"').replace("\\", "/")
    if not target or target.startswith("&"):
        return "", False
    return target, op.startswith((">", "1>", "2>"))


def _drop_cmd_backslash_phantoms(
    targets: Sequence[str],
    nested_targets: Sequence[str],
) -> list[str]:
    nested_compact = {
        str(target).replace("/", "").replace("\\", "")
        for target in nested_targets
        if "/" in str(target) or "\\" in str(target)
    }
    if not nested_compact:
        return list(targets)
    kept = []
    for target in targets:
        text = str(target)
        compact = text.replace("/", "").replace("\\", "")
        if "/" not in text and "\\" not in text and compact in nested_compact:
            continue
        kept.append(target)
    return kept


def _nested_command_after_flag(
    args: Sequence[str],
    flags: Sequence[str],
) -> str:
    lowered_flags = {flag.lower() for flag in flags}
    items = tuple(str(item) for item in args)
    for index, item in enumerate(items):
        lowered = item.lower()
        if lowered in lowered_flags and index + 1 < len(items):
            return " ".join(items[index + 1 :])
    return " ".join(items)


def _mkdir_targets(args: Sequence[str]) -> tuple[str, ...]:
    targets = []
    for arg in args:
        text = str(arg).strip().strip("'\"")
        if not text or text in {".", ".."}:
            continue
        targets.append(text)
    return tuple(dict.fromkeys(targets))


@dataclass(frozen=True)
class _Redirect:
    is_redirect: bool = False
    consumes_next: bool = False
    target: str = ""
    write: bool = False


def _redirect_target(token: str, tokens: Sequence[str], index: int) -> _Redirect:
    if token in {"<<", "<<-"}:
        return _Redirect(True, True)
    if token.startswith(("<<", "<<-")):
        return _Redirect(True)
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


def _path_like_or_opaque_args(args: Sequence[str]) -> tuple[str, ...]:
    return tuple(arg for arg in args if _looks_like_path(arg) or _opaque_shell_value(arg))


def _opaque_shell_value(value: str) -> bool:
    text = str(value).strip().strip("'\"")
    return text.startswith("$") or text.startswith("${")


_DIRECT_SCRIPT_EXTS = (".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".py", ".js", ".mjs", ".cjs", ".ts")
_TRANSPARENT_EXEC_WRAPPERS = {
    "env",
    "command",
    "builtin",
    "exec",
    "sudo",
    "doas",
    "nice",
    "ionice",
    "nohup",
    "setsid",
    "stdbuf",
    "time",
    "timeout",
}
_WRAPPER_VALUE_ARGS = {"timeout", "nice", "ionice", "stdbuf"}
_SCRIPT_INTERPRETERS = {
    "python",
    "python2",
    "python3",
    "py",
    "pypy",
    "pypy3",
    "perl",
    "ruby",
    "node",
    "nodejs",
    "php",
    "rscript",
}
_SCRIPT_SHELLS = {"sh", "bash", "zsh", "dash", "ash", "ksh", "mksh", "busybox"}
_SCRIPT_POWERSHELLS = {"powershell", "pwsh"}
_INLINE_OR_MODULE_FLAGS = {
    "-c",
    "-e",
    "-E",
    "--eval",
    "-p",
    "--print",
    "-r",
    "-m",
    "--module",
    "eval",
}
_PWSH_INLINE_PREFIXES = ("-c", "-command", "-e", "-ec", "-enc", "-encodedcommand")


def _effective_shell_command_words(command_words: Sequence[str]) -> tuple[str, ...]:
    words = list(command_words)
    while words:
        verb = _command_basename(words[0])
        if verb == "cmd" and len(words) > 1:
            words.pop(0)
            while words and words[0].startswith(("/", "-")):
                words.pop(0)
            continue
        if verb not in _TRANSPARENT_EXEC_WRAPPERS:
            break
        words.pop(0)
        while words and words[0].startswith("-"):
            words.pop(0)
        if verb in _WRAPPER_VALUE_ARGS and words and not words[0].startswith("-"):
            words.pop(0)
    return tuple(words)


def _command_basename(raw_verb: str) -> str:
    name = Path(str(raw_verb).strip().strip("'\"").replace("\\", "/")).name.lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _interpreter_script_targets(raw_verb: str, args: Sequence[str]) -> tuple[str, ...]:
    verb = _command_basename(raw_verb)
    if not _is_script_interpreter(verb):
        return ()
    if _interpreter_uses_inline_or_stdin(verb, args):
        return ()
    for token in args:
        text = str(token).strip().strip("'\"")
        if not text or text == "--":
            continue
        if text.startswith("-"):
            continue
        if _looks_like_path(text):
            return (token,)
        return ()
    return ()


def _is_script_interpreter(verb: str) -> bool:
    return (
        verb in _SCRIPT_INTERPRETERS
        or verb in _SCRIPT_SHELLS
        or verb in _SCRIPT_POWERSHELLS
        or bool(re.fullmatch(r"python\d+(?:\.\d+)?", verb))
        or bool(re.fullmatch(r"perl\d+(?:\.\d+)?", verb))
    )


def _interpreter_uses_inline_or_stdin(verb: str, args: Sequence[str]) -> bool:
    for token in args:
        text = str(token).strip().strip("'\"")
        lowered = text.lower()
        if text == "-":
            return True
        if verb in _SCRIPT_SHELLS and re.match(r"^-[a-z]*c$", lowered):
            return True
        if verb in _SCRIPT_POWERSHELLS and any(
            lowered.startswith(prefix) for prefix in _PWSH_INLINE_PREFIXES
        ):
            return True
        if lowered in _INLINE_OR_MODULE_FLAGS:
            return True
        if any(
            lowered.startswith(flag)
            for flag in ("-c", "-e", "-E", "--eval", "-p", "--print", "-r")
        ):
            return True
    return False


def _direct_script_target(raw_verb: str) -> str:
    text = raw_verb.strip().strip("'\"")
    if not text:
        return ""
    normalized = text.replace("\\", "/")
    if not (
        normalized.startswith(("./", "../", "/", "~"))
        or "/" in normalized
        or "\\" in text
    ):
        return ""
    if Path(normalized).name.lower().endswith(_DIRECT_SCRIPT_EXTS):
        return text
    return ""


def _looks_like_path(value: str) -> bool:
    text = value.strip().strip("'\"").strip("()")
    if not text or text.startswith("&"):
        return False
    if text in {".", ".."}:
        return True
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
    # Harness session metadata, not action data. The Claude Code transcript path
    # is ALWAYS under `.claude/`, so leaving the literal string in the scanned
    # payload makes protect_scan's AUDIT_STORE (.claude token) match on EVERY
    # action -- a false positive that HOLDs reads and KILLs writes regardless of
    # what the command actually touches, rendering an armed gate unusable. Redact
    # to a digest: keep an auditable reference but drop the path string so it
    # cannot poison surface scans. The command text and real target_paths are
    # still scanned, so genuine .claude access stays caught.
    for _meta_key in ("transcript_path", "transcriptPath"):
        if payload.get(_meta_key) is not None:
            payload[_meta_key] = _text_digest_payload(payload[_meta_key])
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


def _gate_switch_state(event: Mapping[str, Any], env: Mapping[str, str]) -> str:
    # Legacy compatibility only. Older builds accepted {"enabled": false} as a
    # runtime disarm file; that is no longer an authority-bearing input. Keep
    # the observation so a stale/off request is visible in the audit trail.
    switch_path = Path(_event_cwd(event, env)) / ".claude" / GATE_SWITCH_FILE_NAME
    try:
        payload = json.loads(switch_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "on"
    if isinstance(payload, Mapping) and payload.get("enabled") is False:
        return "off_ignored"
    return "on"


def _gate_switch_off(event: Mapping[str, Any], env: Mapping[str, str]) -> bool:
    # Removed backdoor: a project-local file can no longer relax admission,
    # autopsy, or fail-closed behavior. Disconnecting hooks is an operator setup
    # action; it is not a live capability an agent can grant itself.
    return False


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


def _scene_state_dir(event: Mapping[str, Any], env: Mapping[str, str]) -> Path:
    # Surroundings-baseline state. Kept OUTSIDE the protected .phi surface (under
    # .claude). Honors an explicit override knob for test isolation, mirroring the
    # temporal/xray state dirs.
    override = env.get("PUB_CLAUDE_SCENE_STATE_DIR")
    if override:
        root = Path(override)
    else:
        root = Path(_event_cwd(event, env)) / ".claude" / SCENE_STATE_DIR_NAME
    root.mkdir(parents=True, exist_ok=True)
    return root


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


_BACKFILL_JOURNAL_SCHEMA = "pub_backfill_journal_v0"
# Oversize pre-images are NOT copied (cost/latency on the hot path). The cap is a
# coverage boundary, never a silent drop: oversize destructive targets are recorded
# in the manifest + witness log as NOT reversible so no caller can overclaim "回点".
_BACKFILL_SNAPSHOT_CAP_BYTES = 16 * 1024 * 1024  # 16 MiB


@dataclass
class _BackfillResult:
    """Outcome of journalling an allowed mutation's pre-image (the reversible-board
    backfill). ``held`` flips the verdict to HOLD: a destructive op whose pre-image
    could not be captured is un-backfillable and must not pass."""

    held: bool = False
    manifest_path: str = ""
    entries: int = 0
    oversize_destructive: tuple[str, ...] = ()


def _backfill_dir(cid: str, env: Mapping[str, str]) -> Path:
    return _log_path(env).parent / "backfill" / (cid or "nocid")


def _backfill_in_project(cwd: str, target: str, project_root: Any) -> Path | None:
    """Resolve a target to an absolute path IFF it lands inside the project root.

    Mirrors ot_gate's resolve/within rule, kept local (like capability_wall's own
    copy) so the two judges never cross-import a private symbol and drift apart."""
    if not project_root:
        return None
    try:
        root = Path(str(project_root)).resolve()
        raw = Path(target)
        base = Path(cwd) if cwd else root
        resolved = (raw if raw.is_absolute() else base / raw).resolve()
    except (OSError, ValueError, RuntimeError):
        return None
    try:
        resolved.relative_to(root)
    except ValueError:
        return None
    return resolved


def _git_internal_write_denied(action: ActionEnvelope, project_root: Any) -> bool:
    """A direct WRITE/DELETE into .git's EXECUTABLE surface is denied.

    .git/hooks/* run arbitrary code on ordinary git operations; .git/config
    (core.hooksPath, alias.*, fsmonitor) and .git/info/* (attribute filter drivers)
    point at code too. Protecting THIS surface is the precondition for relaxing safe
    git-write off the OPAQUE wall: the agent cannot PLANT an executable hook for a
    later commit to trigger. We protect ONLY the executable surface, NOT git's data
    (index/objects/refs) -- so `git add`/`commit` (which pub models as writing
    .git/index, .git) are unaffected; only echo/cp/Write/sed planting into
    hooks/config/info is blocked. (`git config core.hooksPath ...` is a `git config`
    command, which is not in the relaxed verb set and stays OPAQUE-blocked anyway.)"""
    effects = action.expected_side_effects
    if SideEffect.WRITE not in effects and SideEffect.DELETE not in effects:
        return False
    if not project_root:
        return False
    try:
        git = (Path(str(project_root)).resolve()) / ".git"
    except (OSError, ValueError, RuntimeError):
        return False
    exec_roots = (git / "hooks", git / "info")
    config = git / "config"
    for raw in action.target_paths:
        resolved = _backfill_in_project(action.cwd or "", str(raw), project_root)
        if resolved is None:
            continue
        if resolved == config:
            return True
        for exec_root in exec_roots:
            try:
                resolved.relative_to(exec_root)
                return True
            except ValueError:
                continue
    low = action.command_text.lower().replace("\\", "/")
    return any(tok in low for tok in (".git/hooks", ".git/config", ".git/info/"))


def _backfill_snapshot_file(
    jdir: Path,
    resolved: Path,
    destructive: bool,
    *,
    allow_absent: bool,
) -> tuple[dict[str, Any] | None, bool, bool]:
    """Snapshot one existing file's pre-image. Returns (entry, held, oversize).
    held=True means a destructive op whose pre-image could not be captured -> the
    caller must HOLD (un-backfillable). oversize=True flags a destructive target whose
    pre-image was too big to copy (recorded NOT reversible, never silently dropped)."""
    entry: dict[str, Any] = {
        "target": str(resolved),
        "existed_before": resolved.is_file(),
        "op": "DELETE" if destructive else "WRITE",
    }
    if not entry["existed_before"]:
        if not allow_absent:
            return None, False, False
        entry["snapshot"] = "ABSENT"  # restoring a created file = delete it
        return entry, False, False
    try:
        size = resolved.stat().st_size
    except OSError:
        if destructive:
            return None, True, False
        entry["snapshot"] = "STAT_FAILED"
        return entry, False, False
    if size > _BACKFILL_SNAPSHOT_CAP_BYTES:
        entry["snapshot"] = "OVERSIZE_NOT_JOURNALLED"
        entry["size"] = size
        return entry, False, destructive
    blob = jdir / (hashlib.sha256(str(resolved).encode("utf-8")).hexdigest() + ".blob")
    try:
        data = resolved.read_bytes()
        blob.write_bytes(data)
    except OSError:
        if destructive:
            return None, True, False
        entry["snapshot"] = "COPY_FAILED"
        return entry, False, False
    entry["snapshot"] = blob.name
    entry["sha256"] = hashlib.sha256(data).hexdigest()
    entry["mode"] = resolved.stat().st_mode
    return entry, False, False


def _journal_reversible_targets(
    env: Mapping[str, str],
    cid: str,
    action: ActionEnvelope,
    proposal: CommandProposal,
    project_root: Any,
) -> _BackfillResult:
    """Snapshot every enumerable in-project target BEFORE an allowed mutation, so a
    post-exec autopsy (or an operator) can retake the ground -- the reversible-board
    backfill (補位). pub does not execute, so it cannot redirect the agent's write
    into a move-aside; it must copy the pre-image first, then allow.

    Pure-additive on WRITE; fail-closed on a destructive op whose pre-image we could
    not capture. Only enumerable targets are journalled -- opaque execution never
    reaches here allowed, so its un-enumerable writes stay denied upstream, not
    silently un-journalled."""
    effects = action.expected_side_effects
    if SideEffect.WRITE not in effects and SideEffect.DELETE not in effects:
        return _BackfillResult()
    destructive = SideEffect.DELETE in effects
    targets = [str(t) for t in action.target_paths if t and str(t).strip()]
    if not targets and destructive:
        # pub's bash parser drops bare dir names (`rm -rf build`); re-read the delete
        # operands so the tree's pre-image is journalled before a recursive delete.
        operands = delete_command_operands(action.command_text) or []
        targets = [t for t in operands if t and t.strip()]
    if not targets:
        return _BackfillResult()

    jdir = _backfill_dir(cid, env)
    try:
        jdir.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Cannot even create the journal: a destructive op here is un-backfillable.
        return _BackfillResult(held=destructive)

    entries: list[dict[str, Any]] = []
    oversize_destructive: list[str] = []
    for raw_target in targets:
        resolved = _backfill_in_project(proposal.cwd or "", raw_target, project_root)
        if resolved is None:
            # Out-of-project target is not our reversible board; the upstream wall
            # already governs cross-boundary writes/deletes. Nothing to journal.
            continue
        if resolved.is_dir():
            # A recursive delete wipes a whole tree -- journal every file under it so
            # the tree can be retaken. (Writes never target a dir; skip.)
            if not destructive:
                continue
            try:
                files = [p for p in resolved.rglob("*") if p.is_file()]
            except OSError:
                return _BackfillResult(held=True)  # cannot enumerate -> un-backfillable
            if not files:
                entries.append({"target": str(resolved), "existed_before": True,
                                "op": "DELETE", "snapshot": "EMPTY_DIR"})
                continue
            for f in files:
                entry, held, oversize = _backfill_snapshot_file(jdir, f, destructive, allow_absent=False)
                if held:
                    return _BackfillResult(held=True)
                if oversize:
                    oversize_destructive.append(str(f))
                if entry is not None:
                    entries.append(entry)
            continue
        entry, held, oversize = _backfill_snapshot_file(jdir, resolved, destructive, allow_absent=True)
        if held:
            return _BackfillResult(held=True)
        if oversize:
            oversize_destructive.append(str(resolved))
        if entry is not None:
            entries.append(entry)

    if not entries:
        return _BackfillResult()
    manifest = jdir / "manifest.json"
    _write_json(
        manifest,
        {
            "schema": _BACKFILL_JOURNAL_SCHEMA,
            "cid": cid,
            "session_id": str(getattr(action, "branch_id", "") or ""),
            "ts": time.time(),
            "hook_id": HOOK_ID,
            "tool_name": action.tool_name,
            "command": proposal.command_text,
            "entries": entries,
            "oversize_destructive": oversize_destructive,
        },
    )
    return _BackfillResult(
        manifest_path=str(manifest),
        entries=len(entries),
        oversize_destructive=tuple(oversize_destructive),
    )


def _restore_one_manifest(manifest_path: Path) -> dict[str, Any]:
    """Restore every pre-image in one journal manifest. Blobs live next to it."""
    if not manifest_path.exists():
        return {"restored": 0, "restored_paths": [], "skipped": [], "status": "no_journal"}
    blob_dir = manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    restored: list[str] = []
    skipped: list[dict[str, Any]] = []
    for entry in manifest.get("entries", ()):
        target = Path(str(entry.get("target", "")))
        snapshot = str(entry.get("snapshot", ""))
        if not entry.get("existed_before"):
            # File was created by the op; restoring = removing it.
            try:
                if target.is_file():
                    target.unlink()
                restored.append(str(target))
            except OSError as exc:
                skipped.append({"target": str(target), "reason": f"unlink_failed:{exc.__class__.__name__}"})
            continue
        if snapshot == "EMPTY_DIR":
            try:
                target.mkdir(parents=True, exist_ok=True)
                restored.append(str(target))
            except OSError as exc:
                skipped.append({"target": str(target), "reason": f"mkdir_failed:{exc.__class__.__name__}"})
            continue
        if snapshot in ("ABSENT", "OVERSIZE_NOT_JOURNALLED", "COPY_FAILED", "STAT_FAILED", ""):
            skipped.append({"target": str(target), "reason": f"no_preimage:{snapshot or 'none'}"})
            continue
        blob = blob_dir / snapshot
        try:
            data = blob.read_bytes()
            if "sha256" in entry and hashlib.sha256(data).hexdigest() != entry["sha256"]:
                skipped.append({"target": str(target), "reason": "preimage_hash_mismatch"})
                continue
            target.parent.mkdir(parents=True, exist_ok=True)  # recreate the wiped tree
            target.write_bytes(data)
            mode = entry.get("mode")
            if isinstance(mode, int):
                try:
                    os.chmod(target, mode)
                except OSError:
                    pass
            restored.append(str(target))
        except OSError as exc:
            skipped.append({"target": str(target), "reason": f"restore_failed:{exc.__class__.__name__}"})
    return {"restored": len(restored), "restored_paths": restored,
            "skipped": skipped, "status": "ok"}


def restore_from_backfill_journal(
    cid: str,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Retake the ground for ONE action: restore every journalled pre-image for cid.
    Operator-callable; also the unit the session-level restore arm fans out over."""
    env = env or os.environ
    result = _restore_one_manifest(_backfill_dir(cid, env) / "manifest.json")
    result["cid"] = cid
    return result


def restore_session_backfill(
    session_id: str,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Retake the ground for an ENTIRE session: restore every journalled mutation
    tagged with session_id. This is the auto-restore arm -- fired once when the
    SEQUENCE judges the session compromised (temporal KILL / out-of-band scene
    tamper), undoing the in-project changes a now-hostile session made before it was
    caught. Only the strong deny-level signals trigger it, so a healthy session's
    work is never rolled back."""
    env = env or os.environ
    backfill_root = _backfill_dir("", env).parent  # .../backfill
    if not session_id or not backfill_root.is_dir():
        return {"restored": 0, "manifests": 0, "session_id": session_id, "status": "no_journal"}
    total = 0
    manifests = 0
    details: list[dict[str, Any]] = []
    for manifest_path in sorted(backfill_root.glob("*/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if str(manifest.get("session_id", "")) != str(session_id):
            continue
        manifests += 1
        res = _restore_one_manifest(manifest_path)
        total += res.get("restored", 0)
        details.append({"cid": manifest.get("cid"), "restored": res.get("restored", 0)})
    return {"restored": total, "manifests": manifests, "session_id": session_id,
            "details": details, "status": "ok"}


def _record_allowed_scoped_delete(
    env: Mapping[str, str],
    session_id: str,
    action: ActionEnvelope,
    proposal: CommandProposal,
    project_root: Any,
) -> None:
    """Forensic breadcrumb for an ALLOWED in-project single-file destructive op.

    The reversible-delete grant lets the claude_code actor delete/rename a single
    in-project file without a KILL. To keep that trust auditable, the FIRST such
    allow per session is recorded as a note next to pub's autopsy reports. It does
    not change the decision (the action is already allowed); it only leaves a trace.
    """
    if not project_root or SideEffect.DELETE not in action.expected_side_effects:
        return
    if not is_scoped_single_file_delete(
        proposal.command_text, proposal.target_paths, proposal.cwd, [Path(project_root)]
    ):
        return
    root = _log_path(env).parent
    safe = hashlib.sha256((session_id or "nosession").encode("utf-8")).hexdigest()
    marker = root / f"pub_claude_allowed_delete_{safe}.marker"
    if marker.exists():
        return
    _write_json(
        root / f"pub_claude_allowed_delete_{safe}.json",
        {
            "schema": "pub_allowed_scoped_delete_v0",
            "kind": "ALLOW_NOTE",
            "ts": time.time(),
            "hook_id": HOOK_ID,
            "session_id": session_id,
            "tool_name": action.tool_name,
            "command": proposal.command_text,
            "target_paths": list(action.target_paths),
            "side_effects": sorted(effect.value for effect in action.expected_side_effects),
            "note": "in-project single-file destructive op allowed under the "
                    "reversible-delete grant; first occurrence this session recorded.",
        },
    )
    try:
        marker.write_text("1", encoding="utf-8")
    except OSError:
        pass


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


def _read_stdin_text() -> str:
    # Claude Code feeds UTF-8 JSON on stdin. On native Windows, sys.stdin
    # decodes with the ANSI code page (cp936/cp1252), which mangles non-ASCII
    # payloads (e.g. Chinese tool input) into surrogates and makes the hook
    # fail closed before it can even parse the JSON. Read raw bytes and decode
    # as UTF-8 explicitly so Windows matches Linux/WSL.
    buffer = getattr(sys.stdin, "buffer", None)
    if buffer is not None:
        return buffer.read().decode("utf-8")
    return sys.stdin.read()


def main_pretool() -> int:
    raw = _read_stdin_text()
    try:
        result = run_pretool_admission(raw)
        write_hook_output(result.output)
        return 0
    except Exception as exc:
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
        result = run_posttool_autopsy(_read_stdin_text())
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
