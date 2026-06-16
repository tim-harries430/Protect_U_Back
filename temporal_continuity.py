"""
Temporal continuity accumulator for the OT gate.

The OT gate (``ot_gate.audit_command_proposal``) is a pure function of ONE
proposal. It computes the spatial joint of the three judges at a single instant
and is, by construction, blind to any attack whose malice lives only in the
*sequence* of individually-clean proposals (temporal decomposition).

This module adds the missing dimension WITHOUT modifying any existing structure.
It is the continuity equation in time:

    d(exposure)/dt + flux_out = 0

A carrier of sensitive exposure enters an actor's hands on a sensitive read,
propagates to artifacts the actor writes while holding it, and must not leave
through an exit (network / external write / opaque execution) without the
verdict remembering it entered. The spatial gate forgets; this remembers.

Design rules:
  * Pure decision core: ``step(state, proposal, policy) -> (state, testimony)``
    depends only on the event sequence, never on wall-clock, so the same
    ordered proposals always replay to the same verdicts (seed determinism).
  * IO is isolated in ``TemporalContinuityLedger`` (mirrors the hook state
    pattern), keyed by (actor_id, branch_id), append-only for replay/receipt.
  * Composition only: ``fuse`` returns a NEW ``OTGateResult``; it never mutates
    the gate's frozen result.

What it is honest about NOT doing: it does not read file *contents*, so a secret
hidden in an innocuously-named file that never trips the keyword layer is a
content-detection gap, not a temporal one. What it DOES add, non-redundantly:
  (a) memory of an approved sensitive read, so the EXIT can be re-gated even
      though the stateless gate let the read through on user confirmation;
  (b) keyword-independent read-then-opaque-exec escalation (python -c, base64|sh
      after the actor has read data) which the spatial gate classifies P0;
  (c) artifact taint propagation, so laundering sensitive material through an
      intermediate file is tracked across events.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ot_gate import (
    CommandProposal,
    ExecutionDecision,
    JudgeName,
    JudgeTestimony,
    JudgeVote,
    OTGateResult,
    OTPolicy,
    PermissionLevel,
    SideEffect,
    _command_mentions_any_path,
    _inferred_effects,
    _normalized_command,
    _paths_outside_project,
    _protected_targets,
    _resolve_target,
    classify_permission,
    NETWORK_TOKENS,
    DYNAMIC_EXEC_TOKENS,
)


SCHEMA_VERSION = "temporal_continuity:v0"

# Soft exposure threshold: how many reads must accumulate before an exit that
# carries no hard taint is escalated to HOLD (user confirmation, never KILL).
DEFAULT_SOFT_EXPOSURE_THRESHOLD = 1

# Inline-interpreter / decode-and-run tokens. These are keyword-independent of
# the network layer: they describe a Turing-complete *carrier*, not a known
# bad verb. The spatial gate classifies most of these P0_READ.
OPAQUE_EXEC_TOKENS = (
    "python -c",
    "python3 -c",
    "py -c",
    "node -e",
    "node --eval",
    "perl -e",
    "ruby -e",
    "bash -c",
    "sh -c",
    "zsh -c",
    "-encodedcommand",
    "base64 -d",
    "base64 --decode",
    "| sh",
    "|sh",
    "| bash",
    "|bash",
    "eval ",
    "exec(",
)


class TaintTier(str, Enum):
    # HARD: a recognized sensitive source. Egress while held => KILL.
    HARD = "hard"
    # SOFT: generic read exposure. Egress while accumulated => HOLD (confirm).
    SOFT = "soft"


class TaintKind(str, Enum):
    SECRET = "secret"          # SideEffect.SECRET_ACCESS on a read
    PROTECTED = "protected"    # read of a protected .phi path
    EXTERNAL = "external"      # read of a path outside the project
    ARTIFACT = "artifact"      # re-read of a previously tainted artifact


@dataclass(frozen=True)
class TaintMarker:
    tier: TaintTier
    kind: TaintKind
    origin_ref: str
    origin_event: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier": self.tier.value,
            "kind": self.kind.value,
            "origin_ref": self.origin_ref,
            "origin_event": self.origin_event,
        }

    @staticmethod
    def from_dict(payload: Mapping[str, Any]) -> "TaintMarker":
        return TaintMarker(
            tier=TaintTier(str(payload["tier"])),
            kind=TaintKind(str(payload["kind"])),
            origin_ref=str(payload.get("origin_ref", "")),
            origin_event=str(payload.get("origin_event", "")),
        )


@dataclass
class ActorFlowState:
    """Accumulated, per-(actor, branch) exposure. The conserved quantity."""

    actor_id: str
    branch_id: str
    hard_markers: List[TaintMarker] = field(default_factory=list)
    soft_read_count: int = 0
    tainted_artifacts: Dict[str, List[str]] = field(default_factory=dict)
    event_count: int = 0
    last_event_id: str = ""

    def holds_hard_taint(self) -> bool:
        return bool(self.hard_markers)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "actor_id": self.actor_id,
            "branch_id": self.branch_id,
            "hard_markers": [marker.to_dict() for marker in self.hard_markers],
            "soft_read_count": self.soft_read_count,
            "tainted_artifacts": {key: list(value) for key, value in self.tainted_artifacts.items()},
            "event_count": self.event_count,
            "last_event_id": self.last_event_id,
        }

    @staticmethod
    def from_dict(payload: Mapping[str, Any]) -> "ActorFlowState":
        return ActorFlowState(
            actor_id=str(payload["actor_id"]),
            branch_id=str(payload["branch_id"]),
            hard_markers=[TaintMarker.from_dict(item) for item in payload.get("hard_markers", ())],
            soft_read_count=int(payload.get("soft_read_count", 0)),
            tainted_artifacts={
                str(key): [str(item) for item in value]
                for key, value in dict(payload.get("tainted_artifacts", {})).items()
            },
            event_count=int(payload.get("event_count", 0)),
            last_event_id=str(payload.get("last_event_id", "")),
        )

    @staticmethod
    def empty(actor_id: str, branch_id: str) -> "ActorFlowState":
        return ActorFlowState(actor_id=actor_id, branch_id=branch_id)


@dataclass(frozen=True)
class TemporalTestimony:
    """A fourth judge, but one with memory."""

    vote: JudgeVote
    reason_code: str
    critical: bool = False
    evidence: Sequence[str] = field(default_factory=tuple)
    accumulated_hard: int = 0
    accumulated_soft: int = 0

    @property
    def blocking(self) -> bool:
        return self.vote in {JudgeVote.HOLD, JudgeVote.KILL}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "judge": "temporal_continuity",
            "vote": self.vote.value,
            "reason_code": self.reason_code,
            "critical": self.critical,
            "evidence": list(self.evidence),
            "accumulated_hard": self.accumulated_hard,
            "accumulated_soft": self.accumulated_soft,
        }


@dataclass(frozen=True)
class _FlowFacts:
    effects: frozenset
    permission: PermissionLevel
    read_paths: Tuple[str, ...]
    write_paths: Tuple[str, ...]
    is_egress: bool
    is_opaque_exec: bool
    hard_sources: Tuple[TaintMarker, ...]
    did_read: bool


def _normalized_targets(proposal: CommandProposal) -> Tuple[str, ...]:
    resolved: List[str] = []
    for target in proposal.target_paths:
        try:
            resolved.append(str(_resolve_target(proposal.cwd, target)))
        except Exception:
            resolved.append(str(target))
    return tuple(dict.fromkeys(resolved))


def _is_opaque_exec(proposal: CommandProposal) -> bool:
    text = _normalized_command(proposal.command_text)
    return _command_mentions_any_path(text, OPAQUE_EXEC_TOKENS) or _command_mentions_any_path(
        text, DYNAMIC_EXEC_TOKENS
    )


def _is_egress(proposal: CommandProposal, policy: OTPolicy, effects) -> bool:
    # An exit moves data OUT of the local battlefield. That is network, or a
    # write/delete to a path outside the project. A protected/secret READ is
    # ingress of sensitivity (a taint source), NOT an exit -- classify_permission
    # marks those P4_CRITICAL too, so permission level must not be used here.
    if SideEffect.NETWORK in effects:
        return True
    if (effects & {SideEffect.WRITE, SideEffect.DELETE}) and _paths_outside_project(
        proposal, policy
    ):
        return True
    return False


def _hard_sources_for_read(
    proposal: CommandProposal,
    policy: OTPolicy,
    effects,
    targets: Tuple[str, ...],
    state: ActorFlowState,
    event_id: str,
) -> Tuple[TaintMarker, ...]:
    markers: List[TaintMarker] = []

    if SideEffect.SECRET_ACCESS in effects:
        markers.append(
            TaintMarker(TaintTier.HARD, TaintKind.SECRET, proposal.command_text[:120], event_id)
        )

    for protected in _protected_targets(proposal, policy):
        markers.append(TaintMarker(TaintTier.HARD, TaintKind.PROTECTED, str(protected), event_id))

    for outside in _paths_outside_project(proposal, policy):
        markers.append(TaintMarker(TaintTier.HARD, TaintKind.EXTERNAL, outside, event_id))

    # Re-read of a previously laundered artifact re-acquires its taint.
    for target in targets:
        if target in state.tainted_artifacts:
            markers.append(
                TaintMarker(TaintTier.HARD, TaintKind.ARTIFACT, target, event_id)
            )

    return tuple(markers)


def _flow_facts(
    proposal: CommandProposal,
    policy: OTPolicy,
    state: ActorFlowState,
    event_id: str,
) -> _FlowFacts:
    effects = frozenset(_inferred_effects(proposal))
    permission = classify_permission(proposal, policy)
    targets = _normalized_targets(proposal)
    is_write = bool(effects & {SideEffect.WRITE, SideEffect.DELETE})
    write_paths = targets if is_write else ()
    read_paths = targets
    hard_sources = _hard_sources_for_read(
        proposal, policy, effects, targets, state, event_id
    )
    did_read = SideEffect.READ in effects or bool(targets)
    return _FlowFacts(
        effects=effects,
        permission=permission,
        read_paths=read_paths,
        write_paths=write_paths,
        is_egress=_is_egress(proposal, policy, effects),
        is_opaque_exec=_is_opaque_exec(proposal),
        hard_sources=hard_sources,
        did_read=did_read,
    )


def step(
    state: ActorFlowState,
    proposal: CommandProposal,
    policy: OTPolicy,
    *,
    soft_threshold: int = DEFAULT_SOFT_EXPOSURE_THRESHOLD,
) -> Tuple[ActorFlowState, TemporalTestimony]:
    """
    Pure continuity step. Deterministic in (state, proposal, policy) only.

    Returns the post-event state and the temporal testimony. Verdict order:
      1. exit (egress or opaque-exec) while holding HARD taint  -> KILL critical
      2. exit while accumulated SOFT exposure >= threshold      -> HOLD
      3. otherwise                                              -> PASS
    Then the carrier bookkeeping is applied (taint in, propagate to artifacts).
    """

    event_id = proposal.proposal_id or f"event_{state.event_count}"
    facts = _flow_facts(proposal, policy, state, event_id)

    # Taint the actor would be holding AT THIS EXIT = previously held hard
    # markers plus any hard source acquired by this very event (e.g. this step
    # both re-reads a tainted artifact and egresses).
    held_hard = list(state.hard_markers) + list(facts.hard_sources)
    is_exit = facts.is_egress or facts.is_opaque_exec

    # ---- verdict (uses only sequence-derived facts, never wall-clock) ----
    if is_exit and held_hard:
        kinds = sorted({marker.kind.value for marker in held_hard})
        exit_kind = "network/external egress" if facts.is_egress else "opaque execution"
        testimony = TemporalTestimony(
            vote=JudgeVote.KILL,
            reason_code="TEMPORAL_TAINT_EGRESS",
            critical=True,
            evidence=(
                f"{exit_kind} while holding hard taint: {','.join(kinds)}",
                f"taint origin events: {','.join(sorted({m.origin_event for m in held_hard}))}",
            ),
            accumulated_hard=len(held_hard),
            accumulated_soft=state.soft_read_count,
        )
    elif is_exit and state.soft_read_count >= soft_threshold:
        exit_kind = "network/external egress" if facts.is_egress else "opaque execution"
        testimony = TemporalTestimony(
            vote=JudgeVote.HOLD,
            reason_code="TEMPORAL_ACCUMULATED_EXPOSURE_EXIT",
            critical=False,
            evidence=(
                f"{exit_kind} after {state.soft_read_count} accumulated read(s) "
                "in this session; sequence requires confirmation",
            ),
            accumulated_hard=len(held_hard),
            accumulated_soft=state.soft_read_count,
        )
    else:
        testimony = TemporalTestimony(
            vote=JudgeVote.PASS,
            reason_code="TEMPORAL_CONTINUOUS",
            critical=False,
            evidence=("no exit, or exit carries no accumulated exposure",),
            accumulated_hard=len(held_hard),
            accumulated_soft=state.soft_read_count,
        )

    # ---- carrier bookkeeping: build the post-event state ----
    new_hard = list(state.hard_markers)
    # de-duplicate hard markers by (kind, origin_ref) to bound growth
    seen = {(m.kind, m.origin_ref) for m in new_hard}
    for marker in facts.hard_sources:
        key = (marker.kind, marker.origin_ref)
        if key not in seen:
            new_hard.append(marker)
            seen.add(key)

    new_soft = state.soft_read_count + (1 if facts.did_read else 0)

    new_artifacts = {key: list(value) for key, value in state.tainted_artifacts.items()}
    holds_hard_after_read = bool(new_hard)
    if facts.write_paths and holds_hard_after_read:
        carried = sorted({m.kind.value for m in new_hard})
        for dest in facts.write_paths:
            existing = set(new_artifacts.get(dest, ()))
            existing.update(carried)
            new_artifacts[dest] = sorted(existing)

    new_state = ActorFlowState(
        actor_id=state.actor_id,
        branch_id=state.branch_id,
        hard_markers=new_hard,
        soft_read_count=new_soft,
        tainted_artifacts=new_artifacts,
        event_count=state.event_count + 1,
        last_event_id=event_id,
    )
    return new_state, testimony


def fuse(base: OTGateResult, temporal: TemporalTestimony) -> OTGateResult:
    """
    Compose the temporal verdict onto the gate's spatial result WITHOUT mutating
    it. Escalation only (the temporal judge can tighten, never loosen). Matches
    the gate's own semantics: any HOLD becomes KILL pending user confirmation.
    """

    spatial = JudgeTestimony(
        judge=JudgeName.EVIDENCE,  # nearest existing channel for the testimony list
        vote=temporal.vote,
        reason_code=temporal.reason_code,
        critical=temporal.critical,
        evidence=tuple(temporal.evidence),
    )
    testimonies = tuple(base.testimonies) + (spatial,)

    if base.decision == ExecutionDecision.KILL:
        decision, reason = base.decision, base.reason_code
    elif temporal.vote == JudgeVote.KILL:
        decision, reason = ExecutionDecision.KILL, temporal.reason_code
    elif temporal.vote == JudgeVote.HOLD:
        decision, reason = ExecutionDecision.KILL, "HOLD_FOR_USER_CONFIRMATION"
    else:
        decision, reason = base.decision, base.reason_code

    return OTGateResult(
        decision=decision,
        reason_code=reason,
        permission_level=base.permission_level,
        critical=base.critical or temporal.critical,
        kill_votes=base.kill_votes + (1 if temporal.vote == JudgeVote.KILL else 0),
        hold_votes=base.hold_votes + (1 if temporal.vote == JudgeVote.HOLD else 0),
        testimonies=testimonies,
        io_executed=base.io_executed,
    )


def temporal_block(
    proposal: CommandProposal,
    project_root: str | Path,
    state_dir: str | Path,
    *,
    soft_threshold: int = DEFAULT_SOFT_EXPOSURE_THRESHOLD,
) -> Tuple[bool, str]:
    """
    One-call hook integration. Build a policy from the project root, run the
    accumulator, return (blocked, reason_code). ``blocked`` is True when the
    temporal judge votes HOLD or KILL, so the caller can deny the tool. Does not
    touch the spatial decision; escalation is the caller's to apply.
    """
    from ot_gate import OTPolicy

    policy = OTPolicy(project_roots=(str(project_root),))
    ledger = TemporalContinuityLedger(state_dir, soft_threshold=soft_threshold)
    testimony = ledger.evaluate(proposal, policy)
    return testimony.vote in {JudgeVote.HOLD, JudgeVote.KILL}, testimony.reason_code


class TemporalContinuityLedger:
    """
    IO shell. Loads/saves ``ActorFlowState`` keyed by (actor_id, branch_id) and
    appends a replayable event ledger. Stored OUTSIDE the protected .phi surface
    so that writing taint state is not itself an audited mutation.
    """

    def __init__(self, state_dir: str | Path, *, soft_threshold: int = DEFAULT_SOFT_EXPOSURE_THRESHOLD):
        self.state_dir = Path(state_dir)
        self.soft_threshold = soft_threshold
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def _key(self, actor_id: str, branch_id: str) -> str:
        raw = f"{actor_id}::{branch_id}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:32]

    def _state_path(self, actor_id: str, branch_id: str) -> Path:
        return self.state_dir / f"flow_{self._key(actor_id, branch_id)}.json"

    def _ledger_path(self, actor_id: str, branch_id: str) -> Path:
        return self.state_dir / f"flow_{self._key(actor_id, branch_id)}.jsonl"

    def load(self, actor_id: str, branch_id: str) -> ActorFlowState:
        path = self._state_path(actor_id, branch_id)
        if not path.exists():
            return ActorFlowState.empty(actor_id, branch_id)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return ActorFlowState.empty(actor_id, branch_id)
        return ActorFlowState.from_dict(payload)

    def save(self, state: ActorFlowState) -> None:
        path = self._state_path(state.actor_id, state.branch_id)
        path.write_text(
            json.dumps(state.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

    def evaluate(self, proposal: CommandProposal, policy: OTPolicy) -> TemporalTestimony:
        """Load -> step -> save. The thin stateful wrapper around the pure core."""
        actor_id = proposal.actor_id or "unknown_actor"
        branch_id = _branch_of(proposal)
        state = self.load(actor_id, branch_id)
        new_state, testimony = step(state, proposal, policy, soft_threshold=self.soft_threshold)
        self.save(new_state)
        self._append_ledger(new_state, proposal, testimony)
        return testimony

    def _append_ledger(
        self,
        state: ActorFlowState,
        proposal: CommandProposal,
        testimony: TemporalTestimony,
    ) -> None:
        row = {
            "ts": time.time(),  # receipt metadata only; never used in verdicts
            "schema_version": SCHEMA_VERSION,
            "actor_id": state.actor_id,
            "branch_id": state.branch_id,
            "event_id": state.last_event_id,
            "proposal_id": proposal.proposal_id,
            "tool_name": proposal.tool_name,
            "testimony": testimony.to_dict(),
            "post_event_hard": len(state.hard_markers),
            "post_event_soft": state.soft_read_count,
        }
        with self._ledger_path(state.actor_id, state.branch_id).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    def clear(self, actor_id: str, branch_id: str) -> None:
        """Authorized recombination: drain the carriers (e.g., session end)."""
        for path in (self._state_path(actor_id, branch_id), self._ledger_path(actor_id, branch_id)):
            if path.exists():
                path.unlink()


def _branch_of(proposal: CommandProposal) -> str:
    raw = getattr(proposal, "raw_payload", {}) or {}
    branch = raw.get("branch_id") if isinstance(raw, Mapping) else None
    if branch:
        return str(branch)
    # Fall back to the provenance request id so one user request = one session.
    return proposal.user_request_id or "default_branch"
