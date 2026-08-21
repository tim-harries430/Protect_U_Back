from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from enum import Enum
from os.path import normcase, normpath
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from phi_registry import ActorState, PhiRegistry
from safe_path import safe_resolve


TESTIMONY_FIELD_MAX_LENGTH = 256


class DeclaredScope(str, Enum):
    READ_ONLY = "read_only"
    PROJECT_WRITE = "project_write"
    ENV_CHANGE = "env_change"
    EXTERNAL_IO = "external_io"
    ADMIN = "admin"


class SideEffect(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ENV_CHANGE = "env_change"
    NETWORK = "network"
    PRIVILEGE = "privilege"
    SECRET_ACCESS = "secret_access"
    AUDIT_CHANGE = "audit_change"


class PermissionLevel(str, Enum):
    P0_READ = "P0_READ"
    P1_PROJECT_WRITE = "P1_PROJECT_WRITE"
    P2_ENV_CHANGE = "P2_ENV_CHANGE"
    P3_EXTERNAL_IO = "P3_EXTERNAL_IO"
    P4_CRITICAL = "P4_CRITICAL"


class JudgeName(str, Enum):
    INTENT = "intent"
    BOUNDARY = "boundary"
    EVIDENCE = "evidence"


class JudgeVote(str, Enum):
    PASS = "PASS"
    HOLD = "HOLD"
    KILL = "KILL"


class ExecutionDecision(str, Enum):
    ALLOW = "ALLOW"
    KILL = "KILL"


@dataclass(frozen=True)
class CommandProposal:
    """
    Dry-run command proposal.

    This object is only evidence for audit. The OT gate never executes the
    command text.
    """

    command_text: str
    actor_id: str
    cwd: str
    declared_scope: DeclaredScope = DeclaredScope.READ_ONLY
    target_paths: Sequence[str] = field(default_factory=tuple)
    expected_side_effects: Set[SideEffect] = field(default_factory=set)
    parent_event_id: str = ""
    user_request_id: str = ""
    proposal_id: str = "unknown_proposal"
    source_adapter: str = "direct"
    tool_name: str = ""
    action_type: str = ""
    raw_payload: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if isinstance(self.declared_scope, str):
            object.__setattr__(
                self,
                "declared_scope",
                DeclaredScope(self.declared_scope),
            )

        object.__setattr__(
            self,
            "expected_side_effects",
            {
                effect if isinstance(effect, SideEffect) else SideEffect(effect)
                for effect in self.expected_side_effects
            },
        )
        object.__setattr__(
            self,
            "source_adapter",
            _bounded_testimony(self.source_adapter),
        )
        object.__setattr__(self, "tool_name", _bounded_testimony(self.tool_name))
        object.__setattr__(self, "action_type", _bounded_testimony(self.action_type))
        object.__setattr__(self, "raw_payload", dict(self.raw_payload))


def _bounded_testimony(value: object) -> str:
    """
    Adapter testimony is report evidence, not authority. Keep it readable and
    bounded without rejecting otherwise auditable proposals.
    """

    if value is None:
        return ""

    return str(value).strip()[:TESTIMONY_FIELD_MAX_LENGTH]


@dataclass(frozen=True)
class OTPolicy:
    project_roots: Sequence[str]
    require_parent_event: bool = True
    require_user_request: bool = True
    kill_votes_required: int = 2
    registry: Optional[PhiRegistry] = None
    protected_store_roots: Sequence[str] = field(default_factory=tuple)

    def resolved_roots(self) -> List[Path]:
        return [Path(root).resolve(strict=False) for root in self.project_roots]

    def resolved_protected_roots(self) -> List[Path]:
        explicit = [
            Path(root).resolve(strict=False)
            for root in self.protected_store_roots
        ]
        project_phi = [
            Path(root).resolve(strict=False) / ".phi"
            for root in self.project_roots
        ]
        return explicit + project_phi


@dataclass(frozen=True)
class JudgeTestimony:
    judge: JudgeName
    vote: JudgeVote
    reason_code: str
    critical: bool = False
    evidence: Sequence[str] = field(default_factory=tuple)


@dataclass(frozen=True)
class OTGateResult:
    decision: ExecutionDecision
    reason_code: str
    permission_level: PermissionLevel
    critical: bool
    kill_votes: int
    hold_votes: int
    testimonies: Sequence[JudgeTestimony]
    io_executed: bool = False


DESTRUCTIVE_TOKENS = (
    "remove-item",
    " del ",
    "erase",
    " rm ",
    "rmdir",
    " rd ",
    "clear-content",
)
PRIVILEGE_TOKENS = (
    "set-executionpolicy",
    "-verb runas",
    "runas",
    "start-process powershell",
)
NETWORK_TOKENS = (
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
    "curl",
    "wget",
)
DYNAMIC_EXEC_TOKENS = (
    "invoke-expression",
    " iex",
    "|iex",
    "| iex",
    "powershell -",
    "pwsh -",
    "powershell.exe -",
)
ENV_CHANGE_TOKENS = (
    "pip install",
    "conda install",
    "conda create",
    "setx ",
)
SECRET_TOKENS = (
    ".ssh",
    "id_rsa",
    "id_ed25519",
    ".env",
    "env:",
    "credential",
    "token",
    "secret",
)
AUDIT_BYPASS_TOKENS = (
    "event_ledger",
    "ot_gate.py",
    "phi_registry.py",
    "audit_layer.py",
    "autopsy_report.py",
    "llm_channel.py",
    "redteam_intake.py",
    "ALLOW_ALL",
    "allow_all",
)
WRITE_TOKENS = (
    "set-content",
    "out-file",
    "add-content",
    "new-item",
    "copy-item",
    "move-item",
    ">",
)
PROTECTED_PATH_TOKENS = (
    ".phi\\registry",
    ".phi/registry",
    ".phi\\ledger",
    ".phi/ledger",
    ".phi\\",
    ".phi/",
)
REGISTRY_PATH_TOKENS = (
    ".phi\\registry",
    ".phi/registry",
)
LEDGER_PATH_TOKENS = (
    ".phi\\ledger",
    ".phi/ledger",
)
EXTERNAL_PATH_TOKENS = (
    "c:\\users\\",
    "c:/users/",
    "$home",
    "%userprofile%",
)


def _normalized_command(command_text: str) -> str:
    return f" {command_text.strip().lower()} "


def _contains_any(text: str, needles: Iterable[str]) -> bool:
    return any(needle in text for needle in needles)


def _resolve_target(cwd: str, target_path: str) -> Path:
    path = Path(target_path)
    if not path.is_absolute():
        path = Path(cwd) / path
    return safe_resolve(path)


def _is_within(path: Path, root: Path) -> bool:
    path_text = normcase(normpath(str(path)))
    root_text = normcase(normpath(str(root))).rstrip("\\/")
    return (
        path_text == root_text
        or path_text.startswith(root_text + "\\")
        or path_text.startswith(root_text + "/")
    )


def _paths_outside_project(proposal: CommandProposal, policy: OTPolicy) -> List[str]:
    roots = policy.resolved_roots()
    outside = []
    for target in proposal.target_paths:
        resolved = _resolve_target(proposal.cwd, target)
        if not any(_is_within(resolved, root) for root in roots):
            outside.append(str(resolved))
    return outside


def _command_mentions_any_path(command_text: str, tokens: Iterable[str]) -> bool:
    text = command_text.strip().lower()
    return any(token in text for token in tokens)


# --- shared scoped-delete predicate -----------------------------------------
# A delete (rm OR mv -- mv removes its source) is only "scoped" when we can
# POSITIVELY confirm it is a single recoverable in-project file removal: at least
# one concrete target, no recursive/bulk/glob marker, every target modelable
# (no shell-expanded ~ / $ / % / glob that _resolve_target cannot see) and
# resolving strictly INSIDE a project root without BEING a root. Any uncertainty
# returns False so the destructive KILL path is kept (fail-closed). This is the
# SINGLE source of truth consulted by both the OT boundary judge (audit_boundary)
# and the capability wall, so the two judges cannot drift apart on delete nuance.
RECURSIVE_DELETE_TOKENS = (
    " -r", " -rf", " -fr", "-recurse", "--recursive", "rmdir", " rd ", " /s", "*", "?",
)
# Relaxation is allowlisted by explicit delete/move VERB (enumerate-the-good is
# safe on the relax side: missing a verb only keeps the conservative KILL). A bare
# truncate redirect ("> file") carries a DELETE effect but no verb, so it is never
# relaxed -- it stays blocked.
_SCOPED_DELETE_VERBS = (
    " rm ", " del ", " erase ", " unlink ", "remove-item",
    " mv ", " move ", " ren ", "move-item", "rename-item",
)
_UNMODELABLE_TARGET_CHARS = ("~", "$", "%", "*", "?", "[")


def _delete_target_is_scoped(target: str, cwd: str, roots: Sequence[Path]) -> bool:
    stripped = target.strip().strip('"').strip("'")
    if not stripped or stripped in (".", "..", "/", "\\"):
        return False
    if any(ch in stripped for ch in _UNMODELABLE_TARGET_CHARS):
        return False
    resolved = _resolve_target(cwd, stripped)
    if not any(_is_within(resolved, root) for root in roots):
        return False
    resolved_text = normcase(normpath(str(resolved)))
    for root in roots:
        if resolved_text == normcase(normpath(str(root))).rstrip("\\/"):
            return False  # deleting a project root itself is never "scoped"
    return True


def is_scoped_single_file_delete(
    command_text: str,
    target_paths: Sequence[str],
    cwd: str,
    project_roots: Sequence[Path],
) -> bool:
    targets = [t for t in target_paths if t and t.strip()]
    if not targets or not project_roots:
        return False
    text = _normalized_command(command_text)
    if _contains_any(text, RECURSIVE_DELETE_TOKENS):
        return False
    if not _contains_any(text, _SCOPED_DELETE_VERBS):
        return False
    return all(_delete_target_is_scoped(t, cwd, project_roots) for t in targets)


# Surfaces a recursive in-project delete must NEVER touch, even inside the project
# root: version control, pub/agent control, and credential stores. (.phi is also in
# PROTECTED_PATH_TOKENS / protected_store_roots, but the boundary's protected check
# only covers .phi -- .git/.claude/.codex/.ssh are NOT, so the recursive relax must
# exclude them itself or it would hand an agent `rm -rf .git`.)
RECURSIVE_DELETE_PROTECTED_SEGMENTS = (
    ".git", ".phi", ".claude", ".codex", ".ssh", ".aws", ".gnupg", "secrets",
)
# pub's own modules + secret files: never recursively removable even in-project.
RECURSIVE_DELETE_PROTECTED_NAMES = (
    ".env",
    "ot_gate.py", "capability_wall.py", "llm_channel.py", "parallel_audit.py",
    "claude_code_hooks.py", "protect_scan.py", "transition_xray.py",
    "xray_review.py", "xray_transport.py", "xray_prison.py",
)
_RECURSIVE_DELETE_DYNAMIC = ("$(", "${", "`")
_RECURSIVE_DELETE_GLOB = ("*", "?", "[")


def _recursive_delete_target_is_scoped(target: str, cwd: str, roots: Sequence[Path]) -> bool:
    stripped = target.strip().strip('"').strip("'")
    if not stripped or stripped in (".", "..", "/", "\\", "~"):
        return False
    if any(ch in stripped for ch in _UNMODELABLE_TARGET_CHARS):
        return False
    resolved = _resolve_target(cwd, stripped)
    if not any(_is_within(resolved, root) for root in roots):
        return False
    resolved_text = normcase(normpath(str(resolved)))
    for root in roots:
        if resolved_text == normcase(normpath(str(root))).rstrip("\\/"):
            return False  # deleting a project root itself is never "scoped"
    parts = {part.lower() for part in resolved.parts}
    if any(seg in parts for seg in RECURSIVE_DELETE_PROTECTED_SEGMENTS):
        return False
    if resolved.name.lower() in RECURSIVE_DELETE_PROTECTED_NAMES:
        return False
    return True


_DELETE_VERB_BASES = frozenset(
    {"rm", "del", "erase", "unlink", "rmdir", "remove-item", "rd"}
)
_SHELL_OPERATOR_MARKERS = ("&&", "||", ";", "|", "\n", "`", "$(", "${", "&")


def delete_command_operands(command_text: str) -> Optional[list[str]]:
    """Operands of a SINGLE simple delete command, or None if it is not one we can
    safely read (chained/piped/redirected/dynamic -> None -> no relax). pub's bash
    target parser drops bare directory names (`rm -rf build` -> no target), so the
    recursive-delete relax and its journal re-read the operands here. None is
    fail-closed: the caller treats it as 'cannot confirm scope' and keeps the block."""
    if any(marker in command_text for marker in _SHELL_OPERATOR_MARKERS):
        return None
    try:
        tokens = shlex.split(command_text, posix=True)
    except ValueError:
        return None
    if not tokens:
        return None
    base = tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base not in _DELETE_VERB_BASES:
        return None
    return [token for token in tokens[1:] if not token.startswith("-")]


def is_scoped_recursive_delete(
    command_text: str,
    target_paths: Sequence[str],
    cwd: str,
    project_roots: Sequence[Path],
) -> bool:
    """POSITIVELY confirm a RECURSIVE/directory delete is safe to relax: a real delete
    verb, no dynamic expansion the gate cannot see, no glob it cannot enumerate, and
    EVERY target resolving strictly inside a project root (never the root itself) and
    clear of the protected surfaces (.git/.phi/.claude/.codex/.ssh/secrets, .env, pub
    modules). Any uncertainty -> False (fail-closed, the destructive KILL stays). The
    pre-image is journalled before the op lands (backfill), so an in-project recursive
    delete is recoverable; glob/dynamic stay blocked because they cannot be enumerated
    or journalled."""
    if not project_roots:
        return False
    if _contains_any(command_text, _RECURSIVE_DELETE_DYNAMIC):
        return False
    if _contains_any(command_text, _RECURSIVE_DELETE_GLOB):
        return False
    if not _contains_any(_normalized_command(command_text), _SCOPED_DELETE_VERBS):
        return False
    targets = [t for t in target_paths if t and t.strip()]
    if not targets:
        # pub's bash parser drops bare dir names; re-read the delete operands.
        operands = delete_command_operands(command_text)
        if operands is None:
            return False
        targets = [t for t in operands if t and t.strip()]
    if not targets:
        return False
    return all(_recursive_delete_target_is_scoped(t, cwd, project_roots) for t in targets)


def _protected_targets(proposal: CommandProposal, policy: OTPolicy) -> List[Path]:
    protected_roots = policy.resolved_protected_roots()
    protected = []
    for target in proposal.target_paths:
        resolved = _resolve_target(proposal.cwd, target)
        if any(_is_within(resolved, root) for root in protected_roots):
            protected.append(resolved)
    return protected


def _is_registry_target(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return ".phi" in parts and "registry" in parts


def _is_ledger_target(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return ".phi" in parts and "ledger" in parts


def _inferred_effects(proposal: CommandProposal) -> Set[SideEffect]:
    text = _normalized_command(proposal.command_text)
    effects = set(proposal.expected_side_effects)

    if _contains_any(text, DESTRUCTIVE_TOKENS):
        effects.add(SideEffect.DELETE)

    if _contains_any(text, WRITE_TOKENS):
        effects.add(SideEffect.WRITE)

    if _contains_any(text, ENV_CHANGE_TOKENS):
        effects.add(SideEffect.ENV_CHANGE)

    if _contains_any(text, NETWORK_TOKENS):
        effects.add(SideEffect.NETWORK)

    if _contains_any(text, PRIVILEGE_TOKENS):
        effects.add(SideEffect.PRIVILEGE)

    if _contains_any(text, SECRET_TOKENS):
        effects.add(SideEffect.SECRET_ACCESS)

    if _contains_any(text, AUDIT_BYPASS_TOKENS) and (
        SideEffect.WRITE in effects or SideEffect.DELETE in effects
    ):
        effects.add(SideEffect.AUDIT_CHANGE)

    if _command_mentions_any_path(proposal.command_text, PROTECTED_PATH_TOKENS) and (
        SideEffect.WRITE in effects or SideEffect.DELETE in effects
    ):
        effects.add(SideEffect.AUDIT_CHANGE)

    return effects


def classify_permission(
    proposal: CommandProposal,
    policy: OTPolicy,
) -> PermissionLevel:
    text = _normalized_command(proposal.command_text)
    effects = _inferred_effects(proposal)
    outside = _paths_outside_project(proposal, policy)
    protected = _protected_targets(proposal, policy)
    protected_in_text = _command_mentions_any_path(
        proposal.command_text,
        PROTECTED_PATH_TOKENS,
    )
    external_in_text = _command_mentions_any_path(
        proposal.command_text,
        EXTERNAL_PATH_TOKENS,
    )

    if (
        SideEffect.DELETE in effects
        or SideEffect.PRIVILEGE in effects
        or SideEffect.SECRET_ACCESS in effects
        or SideEffect.AUDIT_CHANGE in effects
        or protected
        or protected_in_text
        or (_contains_any(text, NETWORK_TOKENS) and _contains_any(text, DYNAMIC_EXEC_TOKENS))
        or (outside and (SideEffect.WRITE in effects or SideEffect.DELETE in effects))
        or (external_in_text and (SideEffect.WRITE in effects or SideEffect.DELETE in effects))
    ):
        return PermissionLevel.P4_CRITICAL

    if outside or external_in_text:
        return PermissionLevel.P3_EXTERNAL_IO

    if SideEffect.ENV_CHANGE in effects or SideEffect.NETWORK in effects:
        return PermissionLevel.P2_ENV_CHANGE

    if SideEffect.WRITE in effects:
        return PermissionLevel.P1_PROJECT_WRITE

    return PermissionLevel.P0_READ


def audit_intent(proposal: CommandProposal, policy: OTPolicy) -> JudgeTestimony:
    effects = _inferred_effects(proposal)
    evidence = []

    if not proposal.command_text.strip():
        return JudgeTestimony(
            judge=JudgeName.INTENT,
            vote=JudgeVote.HOLD,
            reason_code="EMPTY_COMMAND",
            evidence=("command_text is empty",),
        )

    if proposal.declared_scope == DeclaredScope.READ_ONLY and effects - {SideEffect.READ}:
        evidence.append("declared read_only but command has side effects")
        return JudgeTestimony(
            judge=JudgeName.INTENT,
            vote=JudgeVote.KILL,
            reason_code="SCOPE_MISMATCH_SIDE_EFFECT",
            evidence=tuple(evidence),
        )

    if proposal.declared_scope == DeclaredScope.PROJECT_WRITE:
        outside = _paths_outside_project(proposal, policy)
        if outside and (SideEffect.WRITE in effects or SideEffect.DELETE in effects):
            return JudgeTestimony(
                judge=JudgeName.INTENT,
                vote=JudgeVote.KILL,
                reason_code="PROJECT_SCOPE_ESCAPE",
                evidence=tuple(outside),
            )

    if proposal.declared_scope in {DeclaredScope.READ_ONLY, DeclaredScope.PROJECT_WRITE}:
        if SideEffect.PRIVILEGE in effects or SideEffect.SECRET_ACCESS in effects:
            return JudgeTestimony(
                judge=JudgeName.INTENT,
                vote=JudgeVote.KILL,
                reason_code="INTENT_PRIVILEGE_OR_SECRET_ESCAPE",
                critical=True,
                evidence=("privilege or secret access intent detected",),
            )

    return JudgeTestimony(
        judge=JudgeName.INTENT,
        vote=JudgeVote.PASS,
        reason_code="INTENT_PASS",
        evidence=("declared scope matches inferred intent",),
    )


def audit_boundary(proposal: CommandProposal, policy: OTPolicy) -> JudgeTestimony:
    text = _normalized_command(proposal.command_text)
    effects = _inferred_effects(proposal)
    outside = _paths_outside_project(proposal, policy)
    protected = _protected_targets(proposal, policy)
    protected_in_text = _command_mentions_any_path(
        proposal.command_text,
        PROTECTED_PATH_TOKENS,
    )
    registry_in_text = _command_mentions_any_path(
        proposal.command_text,
        REGISTRY_PATH_TOKENS,
    )
    ledger_in_text = _command_mentions_any_path(
        proposal.command_text,
        LEDGER_PATH_TOKENS,
    )
    external_in_text = _command_mentions_any_path(
        proposal.command_text,
        EXTERNAL_PATH_TOKENS,
    )

    if (protected or protected_in_text) and (
        SideEffect.WRITE in effects or SideEffect.DELETE in effects
    ):
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.KILL,
            reason_code="CRITICAL_PROTECTED_PHI_WRITE",
            critical=True,
            evidence=tuple(str(path) for path in protected)
            or ("protected Phi path in command text",),
        )

    if (protected and any(_is_registry_target(path) for path in protected)) or registry_in_text:
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.KILL,
            reason_code="CRITICAL_REGISTRY_READ",
            critical=True,
            evidence=tuple(str(path) for path in protected)
            or ("registry path in command text",),
        )

    if (protected and any(_is_ledger_target(path) for path in protected)) or ledger_in_text:
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.HOLD,
            reason_code="PROTECTED_LEDGER_READ_REQUIRES_APPROVAL",
            evidence=tuple(str(path) for path in protected)
            or ("ledger path in command text",),
        )

    if protected or protected_in_text:
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.HOLD,
            reason_code="PROTECTED_PHI_READ_REQUIRES_APPROVAL",
            evidence=tuple(str(path) for path in protected)
            or ("protected Phi path in command text",),
        )

    if (
        SideEffect.DELETE in effects
        and not is_scoped_single_file_delete(
            proposal.command_text,
            proposal.target_paths,
            proposal.cwd,
            policy.resolved_roots(),
        )
        and not is_scoped_recursive_delete(
            proposal.command_text,
            proposal.target_paths,
            proposal.cwd,
            policy.resolved_roots(),
        )
    ):
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.KILL,
            reason_code="CRITICAL_DESTRUCTIVE_COMMAND",
            critical=True,
            evidence=("delete/destructive token detected",),
        )

    if SideEffect.PRIVILEGE in effects:
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.KILL,
            reason_code="CRITICAL_PRIVILEGE_ESCALATION",
            critical=True,
            evidence=("privilege escalation token detected",),
        )

    if _contains_any(text, NETWORK_TOKENS) and _contains_any(text, DYNAMIC_EXEC_TOKENS):
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.KILL,
            reason_code="CRITICAL_NETWORK_EXECUTE",
            critical=True,
            evidence=("network download plus dynamic execution detected",),
        )

    if SideEffect.SECRET_ACCESS in effects:
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.KILL,
            reason_code="CRITICAL_SECRET_ACCESS",
            critical=True,
            evidence=("secret-bearing target detected",),
        )

    if SideEffect.AUDIT_CHANGE in effects:
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.KILL,
            reason_code="CRITICAL_AUDIT_BYPASS",
            critical=True,
            evidence=("audit or permission surface mutation detected",),
        )

    if (outside or external_in_text) and (
        SideEffect.WRITE in effects or SideEffect.DELETE in effects
    ):
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.KILL,
            reason_code="CRITICAL_EXTERNAL_WRITE",
            critical=True,
            evidence=tuple(outside) or ("external path in command text",),
        )

    if outside or external_in_text:
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.HOLD,
            reason_code="EXTERNAL_READ_REQUIRES_APPROVAL",
            evidence=tuple(outside) or ("external path in command text",),
        )

    if SideEffect.ENV_CHANGE in effects or SideEffect.NETWORK in effects:
        return JudgeTestimony(
            judge=JudgeName.BOUNDARY,
            vote=JudgeVote.HOLD,
            reason_code="ENV_OR_NETWORK_REQUIRES_APPROVAL",
            evidence=("environment or network effect detected",),
        )

    return JudgeTestimony(
        judge=JudgeName.BOUNDARY,
        vote=JudgeVote.PASS,
        reason_code="BOUNDARY_PASS",
        evidence=("target paths are inside project boundary",),
    )


def audit_evidence(proposal: CommandProposal, policy: OTPolicy) -> JudgeTestimony:
    missing = []

    if not proposal.actor_id.strip():
        return JudgeTestimony(
            judge=JudgeName.EVIDENCE,
            vote=JudgeVote.KILL,
            reason_code="MISSING_ACTOR_ID",
            evidence=("actor_id is required",),
        )

    if policy.registry is not None:
        try:
            actor = policy.registry.require_actor(proposal.actor_id)
        except KeyError:
            return JudgeTestimony(
                judge=JudgeName.EVIDENCE,
                vote=JudgeVote.KILL,
                reason_code="UNKNOWN_ACTOR",
                evidence=(proposal.actor_id,),
            )

        if actor.state == ActorState.FROZEN:
            return JudgeTestimony(
                judge=JudgeName.EVIDENCE,
                vote=JudgeVote.KILL,
                reason_code="ACTOR_FROZEN",
                evidence=(proposal.actor_id,),
            )

        if actor.state == ActorState.BUGCHECK:
            return JudgeTestimony(
                judge=JudgeName.EVIDENCE,
                vote=JudgeVote.KILL,
                reason_code="PHI_BUGCHECK_ACTIVE",
                critical=True,
                evidence=(proposal.actor_id,),
            )

    if policy.require_parent_event and not proposal.parent_event_id.strip():
        missing.append("parent_event_id")

    if policy.require_user_request and not proposal.user_request_id.strip():
        missing.append("user_request_id")

    if missing:
        return JudgeTestimony(
            judge=JudgeName.EVIDENCE,
            vote=JudgeVote.HOLD,
            reason_code="MISSING_PROVENANCE",
            evidence=tuple(missing),
        )

    return JudgeTestimony(
        judge=JudgeName.EVIDENCE,
        vote=JudgeVote.PASS,
        reason_code="EVIDENCE_PASS",
        evidence=("actor and provenance fields are present",),
    )


def audit_command_proposal(
    proposal: CommandProposal,
    policy: OTPolicy,
) -> OTGateResult:
    permission_level = classify_permission(proposal, policy)
    testimonies = (
        audit_intent(proposal, policy),
        audit_boundary(proposal, policy),
        audit_evidence(proposal, policy),
    )

    critical = any(testimony.critical for testimony in testimonies)
    kill_votes = sum(1 for testimony in testimonies if testimony.vote == JudgeVote.KILL)
    hold_votes = sum(1 for testimony in testimonies if testimony.vote == JudgeVote.HOLD)
    hard_identity_kill = any(
        testimony.reason_code in {
            "MISSING_ACTOR_ID",
            "UNKNOWN_ACTOR",
            "ACTOR_FROZEN",
        }
        for testimony in testimonies
    )

    scope_mismatch_kill = any(
        testimony.reason_code == "SCOPE_MISMATCH_SIDE_EFFECT"
        for testimony in testimonies
    )

    if critical:
        decision = ExecutionDecision.KILL
        reason_code = "CRITICAL_KILL"
    elif kill_votes >= policy.kill_votes_required:
        decision = ExecutionDecision.KILL
        reason_code = "TWO_JUDGE_KILL"
    elif hard_identity_kill:
        decision = ExecutionDecision.KILL
        reason_code = "IDENTITY_KILL"
    elif scope_mismatch_kill:
        decision = ExecutionDecision.KILL
        reason_code = "SCOPE_MISMATCH_KILL"
    elif hold_votes > 0:
        decision = ExecutionDecision.KILL
        reason_code = "HOLD_FOR_USER_CONFIRMATION"
    else:
        decision = ExecutionDecision.ALLOW
        reason_code = "ALLOW"

    return OTGateResult(
        decision=decision,
        reason_code=reason_code,
        permission_level=permission_level,
        critical=critical,
        kill_votes=kill_votes,
        hold_votes=hold_votes,
        testimonies=testimonies,
        io_executed=False,
    )
