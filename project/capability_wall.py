from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from os.path import normcase, normpath
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence, Set
from urllib.parse import urlparse

from agent_control_surface import agent_control_roots, is_agent_control_surface_path
from ot_gate import (
    CommandProposal,
    SideEffect,
    delete_command_operands,
    is_scoped_recursive_delete,
    is_scoped_single_file_delete,
)
from probe_authority_surface import (
    internal_probe_path_evidence,
    is_internal_probe_artifact_path,
    probe_authority_text_evidence,
)
from safe_path import safe_resolve


class CapabilityDisposition(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    KILL = "KILL"


class CapabilityCertificate(str, Enum):
    CAP_PASS = "CAP_PASS"
    CAP_HOLD_TICKET = "CAP_HOLD_TICKET"
    CAP_KILL_WARRANT = "CAP_KILL_WARRANT"


@dataclass(frozen=True)
class SkillContract:
    """Static skill procedure contract attached to a capability manifest."""

    skill_id: str
    manifest_sha256: str = ""
    required_step_ids: Sequence[str] = field(default_factory=tuple)
    allowed_instruction_ids: Sequence[str] = field(default_factory=tuple)
    denied_authority_claims: Sequence[str] = (
        "can execute",
        "can_execute",
        "can grant permission",
        "can_grant_permission",
        "grant permission",
        "bypass approval",
        "override safety",
        "ignore policy",
    )

    def __post_init__(self):
        if not self.skill_id.strip():
            raise ValueError("skill_id must be non-empty.")

        object.__setattr__(self, "skill_id", self.skill_id.strip())
        object.__setattr__(self, "manifest_sha256", self.manifest_sha256.strip().lower())
        object.__setattr__(
            self,
            "required_step_ids",
            tuple(
                token
                for step in self.required_step_ids
                if (token := _normalize_skill_token(step))
            ),
        )
        object.__setattr__(
            self,
            "allowed_instruction_ids",
            tuple(
                token
                for item in self.allowed_instruction_ids
                if (token := _normalize_skill_token(item))
            ),
        )
        object.__setattr__(
            self,
            "denied_authority_claims",
            tuple(
                token
                for claim in self.denied_authority_claims
                if (token := _normalize_skill_token(claim))
            ),
        )


@dataclass(frozen=True)
class CapabilityManifest:
    """
    Static v0 capability manifest.

    The manifest is authority supplied by Phi, not by the agent proposal. It
    says which side effects and target regions an actor may propose. It does
    not grant execution permission.
    """

    actor_id: str
    manifest_id: str
    allowed_side_effects: Set[SideEffect] = field(default_factory=set)
    allowed_path_roots: Sequence[str] = field(default_factory=tuple)
    allowed_network_domains: Sequence[str] = field(default_factory=tuple)
    skill_contracts: Sequence[SkillContract] = field(default_factory=tuple)
    allow_protected_targets: bool = False
    # Opt-in (default off): treat a single-file, non-recursive, in-boundary
    # delete as a recoverable side effect instead of an outright rejected one.
    # Recursive/external/protected deletes are unaffected and still KILL.
    allow_reversible_delete: bool = False

    def __post_init__(self):
        if not self.actor_id.strip():
            raise ValueError("actor_id must be non-empty.")

        if not self.manifest_id.strip():
            raise ValueError("manifest_id must be non-empty.")

        object.__setattr__(
            self,
            "allowed_side_effects",
            {
                effect if isinstance(effect, SideEffect) else SideEffect(effect)
                for effect in self.allowed_side_effects
            },
        )
        object.__setattr__(
            self,
            "allowed_path_roots",
            tuple(str(root) for root in self.allowed_path_roots),
        )
        object.__setattr__(
            self,
            "allowed_network_domains",
            tuple(_normalize_domain(domain) for domain in self.allowed_network_domains),
        )
        object.__setattr__(
            self,
            "skill_contracts",
            tuple(
                contract
                if isinstance(contract, SkillContract)
                else SkillContract(**dict(contract))
                for contract in self.skill_contracts
            ),
        )

    def resolved_path_roots(self) -> Sequence[Path]:
        return tuple(Path(root).resolve(strict=False) for root in self.allowed_path_roots)


@dataclass(frozen=True)
class CapabilityPolicy:
    project_roots: Sequence[str]
    manifests: Sequence[CapabilityManifest] = field(default_factory=tuple)
    protected_store_roots: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self):
        object.__setattr__(
            self,
            "project_roots",
            tuple(str(root) for root in self.project_roots),
        )
        object.__setattr__(self, "manifests", tuple(self.manifests))
        object.__setattr__(
            self,
            "protected_store_roots",
            tuple(str(root) for root in self.protected_store_roots),
        )

    def manifest_for(self, actor_id: str) -> Optional[CapabilityManifest]:
        for manifest in self.manifests:
            if manifest.actor_id == actor_id:
                return manifest
        return None

    def resolved_protected_roots(self) -> Sequence[Path]:
        explicit = tuple(
            Path(root).resolve(strict=False) for root in self.protected_store_roots
        )
        project_phi = tuple(
            Path(root).resolve(strict=False) / ".phi"
            for root in self.project_roots
        )
        return explicit + project_phi + agent_control_roots(self.project_roots)


@dataclass(frozen=True)
class CapabilityDecision:
    disposition: CapabilityDisposition
    certificate: CapabilityCertificate
    reason_code: str
    actor_id: str
    manifest_id: str = ""
    matched_side_effects: Sequence[SideEffect] = field(default_factory=tuple)
    rejected_side_effects: Sequence[SideEffect] = field(default_factory=tuple)
    matched_targets: Sequence[str] = field(default_factory=tuple)
    rejected_targets: Sequence[str] = field(default_factory=tuple)
    evidence: Sequence[str] = field(default_factory=tuple)
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self):
        if isinstance(self.disposition, str):
            object.__setattr__(
                self,
                "disposition",
                CapabilityDisposition(self.disposition),
            )

        if isinstance(self.certificate, str):
            object.__setattr__(
                self,
                "certificate",
                CapabilityCertificate(self.certificate),
            )

        object.__setattr__(
            self,
            "matched_side_effects",
            tuple(
                effect if isinstance(effect, SideEffect) else SideEffect(effect)
                for effect in self.matched_side_effects
            ),
        )
        object.__setattr__(
            self,
            "rejected_side_effects",
            tuple(
                effect if isinstance(effect, SideEffect) else SideEffect(effect)
                for effect in self.rejected_side_effects
            ),
        )
        object.__setattr__(
            self,
            "matched_targets",
            tuple(str(target) for target in self.matched_targets),
        )
        object.__setattr__(
            self,
            "rejected_targets",
            tuple(str(target) for target in self.rejected_targets),
        )
        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "certificate": self.certificate.value,
            "reason_code": self.reason_code,
            "actor_id": self.actor_id,
            "manifest_id": self.manifest_id,
            "matched_side_effects": tuple(
                effect.value for effect in self.matched_side_effects
            ),
            "rejected_side_effects": tuple(
                effect.value for effect in self.rejected_side_effects
            ),
            "matched_targets": tuple(self.matched_targets),
            "rejected_targets": tuple(self.rejected_targets),
            "evidence": tuple(self.evidence),
            "can_execute": False,
            "can_grant_permission": False,
        }


WRITE_TOKENS = (
    "set-content",
    "out-file",
    "add-content",
    "new-item",
    "copy-item",
    " move-item",
    "truncate",
    "git checkout --",
    ">",
)
DELETE_TOKENS = (
    "remove-item",
    " del ",
    "erase",
    " rm ",
    "rmdir",
    " rd ",
    "clear-content",
    "truncate",
    " -delete",
    "git clean",
    "git reset --hard",
    "git checkout --",
)
NETWORK_TOKENS = (
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
    "curl",
    "wget",
    "http://",
    "https://",
)
PRIVILEGE_TOKENS = (
    "set-executionpolicy",
    "-verb runas",
    "runas",
    "start-process powershell",
    "grant_admin",
    "root-level",
    "root level",
)
SECRET_TOKENS = (
    ".ssh",
    "id_rsa",
    "id_ed25519",
    ".env",
    ".codex",
    "credential",
    "secret",
    "token",
)
AUDIT_TOKENS = (
    ".phi\\",
    ".phi/",
    "event_ledger",
    "phi_registry",
    "capability_manifest",
    "capability wall",
    "allow_all",
)
EXTERNAL_PATH_TOKENS = (
    "c:\\users\\",
    "c:/users/",
    "$home",
    "%userprofile%",
)
IMPLICIT_CWD_TARGET_TOKENS = (
    " git clean ",
    " git reset --hard",
)
PROCESS_METADATA_KEYS = ("pub_process", "process", "p")
PROCESS_CHANNEL_KEYS = ("channel_type", "channel", "source_channel")
PROCESS_TIME_KEYS = ("created_at", "timestamp", "ts", "time", "time_ns", "p_enter_ts")
PASS_ROAD_SKILL_PREFIX = "pass-road:"


def default_agent_capability_manifest(
    actor_id: str,
    project_roots: Sequence[str],
) -> CapabilityManifest:
    return CapabilityManifest(
        actor_id=actor_id,
        manifest_id=f"default:{actor_id}",
        allowed_side_effects={SideEffect.READ, SideEffect.WRITE},
        allowed_path_roots=tuple(project_roots),
        allowed_network_domains=(),
        allow_protected_targets=False,
        allow_reversible_delete=(actor_id == "claude_code"),
    )


def default_capability_policy(
    project_root: str,
    actor_ids: Sequence[str],
) -> CapabilityPolicy:
    project_roots = (project_root,)
    return CapabilityPolicy(
        project_roots=project_roots,
        manifests=tuple(
            default_agent_capability_manifest(actor_id, project_roots)
            for actor_id in actor_ids
            if actor_id.strip() and not actor_id.startswith("user")
        ),
    )


# The "single recoverable in-project delete" concept now lives in ONE place --
# ot_gate.is_scoped_single_file_delete -- consulted by both the OT boundary judge
# and the escape hatch below, so rm AND mv are judged by the same scope/recursive/
# in-project rule and the two judges cannot drift apart.


def audit_capability(
    proposal: CommandProposal,
    policy: CapabilityPolicy,
) -> CapabilityDecision:
    effects = _capability_effects(proposal)
    if _requires_process_equation(proposal):
        process_gap = _process_equation_gap(proposal, effects)
        if process_gap:
            return _decision(
                CapabilityDisposition.HOLD,
                "CAPABILITY_PROCESS_EQUATION_INCOMPLETE",
                proposal.actor_id,
                matched_side_effects=tuple(sorted(effects, key=lambda effect: effect.value)),
                evidence=process_gap,
            )

    manifest = policy.manifest_for(proposal.actor_id)
    if manifest is None:
        return _decision(
            CapabilityDisposition.HOLD,
            "CAPABILITY_MANIFEST_MISSING",
            proposal.actor_id,
            evidence=(proposal.actor_id,),
        )

    if manifest.actor_id != proposal.actor_id:
        return _decision(
            CapabilityDisposition.KILL,
            "CAPABILITY_ACTOR_MISMATCH",
            proposal.actor_id,
            manifest_id=manifest.manifest_id,
            evidence=(manifest.actor_id, proposal.actor_id),
        )

    if not manifest.allowed_side_effects:
        return _decision(
            CapabilityDisposition.HOLD,
            "CAPABILITY_MANIFEST_INCOMPLETE",
            proposal.actor_id,
            manifest_id=manifest.manifest_id,
            evidence=("allowed_side_effects",),
        )

    if not effects:
        return _decision(
            CapabilityDisposition.HOLD,
            "CAPABILITY_SIDE_EFFECT_UNCLEAR",
            proposal.actor_id,
            manifest_id=manifest.manifest_id,
        )

    matched_effects = tuple(
        sorted(
            (effect for effect in effects if effect in manifest.allowed_side_effects),
            key=lambda effect: effect.value,
        )
    )
    rejected_effects = tuple(
        sorted(
            (effect for effect in effects if effect not in manifest.allowed_side_effects),
            key=lambda effect: effect.value,
        )
    )

    privileged_effect = _first_effect(
        rejected_effects,
        (SideEffect.PRIVILEGE,),
    )
    if privileged_effect is not None:
        return _decision(
            CapabilityDisposition.KILL,
            "CAPABILITY_PERMISSION_MUTATION_DENIED",
            proposal.actor_id,
            manifest_id=manifest.manifest_id,
            matched_side_effects=matched_effects,
            rejected_side_effects=rejected_effects,
            evidence=(privileged_effect.value,),
        )

    audit_effect = _first_effect(
        rejected_effects,
        (SideEffect.AUDIT_CHANGE,),
    )
    if audit_effect is not None:
        return _decision(
            CapabilityDisposition.KILL,
            "CAPABILITY_AUDIT_MUTATION_DENIED",
            proposal.actor_id,
            manifest_id=manifest.manifest_id,
            matched_side_effects=matched_effects,
            rejected_side_effects=rejected_effects,
            evidence=(audit_effect.value,),
        )

    if (
        manifest.allow_reversible_delete
        and rejected_effects == (SideEffect.DELETE,)
        and (
            is_scoped_single_file_delete(
                proposal.command_text,
                proposal.target_paths,
                proposal.cwd,
                manifest.resolved_path_roots(),
            )
            or is_scoped_recursive_delete(
                proposal.command_text,
                proposal.target_paths,
                proposal.cwd,
                manifest.resolved_path_roots(),
            )
        )
    ):
        matched_effects = matched_effects + (SideEffect.DELETE,)
        rejected_effects = ()

    probe_mint_result = _audit_internal_probe_mint(
        proposal,
        policy,
        effects,
    )
    if probe_mint_result is not None:
        rejected_targets, evidence = probe_mint_result
        return _decision(
            CapabilityDisposition.KILL,
            "CAPABILITY_PROBE_MINT_UNAUTHORIZED",
            proposal.actor_id,
            manifest_id=manifest.manifest_id,
            matched_side_effects=matched_effects,
            rejected_side_effects=rejected_effects,
            rejected_targets=rejected_targets,
            evidence=evidence,
        )

    agent_control_target_result = _audit_agent_control_targets(
        proposal,
        policy,
        manifest,
    )
    if agent_control_target_result is not None:
        disposition, reason_code, matched_targets, rejected_targets, evidence = agent_control_target_result
        return _decision(
            disposition,
            reason_code,
            proposal.actor_id,
            manifest_id=manifest.manifest_id,
            matched_side_effects=matched_effects,
            rejected_side_effects=rejected_effects,
            matched_targets=matched_targets,
            rejected_targets=rejected_targets,
            evidence=evidence,
        )

    if rejected_effects:
        return _decision(
            CapabilityDisposition.KILL,
            "CAPABILITY_SIDE_EFFECT_DENIED",
            proposal.actor_id,
            manifest_id=manifest.manifest_id,
            matched_side_effects=matched_effects,
            rejected_side_effects=rejected_effects,
        )

    skill_result = _audit_skill_contracts(proposal, manifest)
    if skill_result is not None:
        disposition, reason_code, evidence = skill_result
        return _decision(
            disposition,
            reason_code,
            proposal.actor_id,
            manifest_id=manifest.manifest_id,
            matched_side_effects=matched_effects,
            rejected_side_effects=rejected_effects,
            evidence=evidence,
        )

    target_result = _audit_targets(proposal, policy, manifest, effects)
    if target_result is not None:
        disposition, reason_code, matched_targets, rejected_targets, evidence = target_result
        return _decision(
            disposition,
            reason_code,
            proposal.actor_id,
            manifest_id=manifest.manifest_id,
            matched_side_effects=matched_effects,
            matched_targets=matched_targets,
            rejected_targets=rejected_targets,
            evidence=evidence,
        )

    return _decision(
        CapabilityDisposition.ALLOW,
        "CAPABILITY_PASS",
        proposal.actor_id,
        manifest_id=manifest.manifest_id,
        matched_side_effects=matched_effects,
        matched_targets=tuple(proposal.target_paths),
    )


def _audit_internal_probe_mint(
    proposal: CommandProposal,
    policy: CapabilityPolicy,
    effects: Set[SideEffect],
) -> Optional[tuple[Sequence[str], Sequence[str]]]:
    if not effects & {
        SideEffect.WRITE,
        SideEffect.DELETE,
        SideEffect.PRIVILEGE,
        SideEffect.AUDIT_CHANGE,
    }:
        return None

    rejected: list[str] = []
    evidence: list[str] = ["probe_authority_egress"]
    for target in proposal.target_paths:
        parsed = urlparse(str(target))
        if parsed.scheme in {"http", "https"}:
            continue
        try:
            resolved = _resolve_target(proposal.cwd, str(target))
        except (OSError, RuntimeError, ValueError):
            continue
        if is_internal_probe_artifact_path(resolved, project_roots=policy.project_roots):
            rejected.append(str(resolved))
            evidence.extend(internal_probe_path_evidence(resolved))

    text_evidence = probe_authority_text_evidence(proposal.command_text)
    if not rejected and text_evidence:
        rejected.append("internal probe artifact in command text")
        evidence.extend(text_evidence)

    if not rejected:
        return None
    return tuple(dict.fromkeys(rejected)), tuple(dict.fromkeys(evidence))


def _audit_agent_control_targets(
    proposal: CommandProposal,
    policy: CapabilityPolicy,
    manifest: CapabilityManifest,
) -> Optional[tuple[CapabilityDisposition, str, Sequence[str], Sequence[str], Sequence[str]]]:
    if manifest.allow_protected_targets:
        return None
    rejected: list[str] = []
    for target in proposal.target_paths:
        parsed = urlparse(str(target))
        if parsed.scheme in {"http", "https"}:
            continue
        try:
            resolved = _resolve_target(proposal.cwd, str(target))
        except (OSError, RuntimeError, ValueError):
            continue
        if is_agent_control_surface_path(resolved, project_roots=policy.project_roots):
            rejected.append(str(resolved))
    if not rejected:
        return None
    return (
        CapabilityDisposition.KILL,
        "CAPABILITY_PROTECTED_TARGET_DENIED",
        (),
        tuple(dict.fromkeys(rejected)),
        ("protected_control_target",),
    )


def _audit_targets(
    proposal: CommandProposal,
    policy: CapabilityPolicy,
    manifest: CapabilityManifest,
    effects: Set[SideEffect],
) -> Optional[tuple[CapabilityDisposition, str, Sequence[str], Sequence[str], Sequence[str]]]:
    path_roots = manifest.resolved_path_roots()
    if not path_roots:
        return (
            CapabilityDisposition.HOLD,
            "CAPABILITY_MANIFEST_INCOMPLETE",
            (),
            (),
            ("allowed_path_roots",),
        )

    needs_path = any(
        effect in effects
        for effect in {
            SideEffect.READ,
            SideEffect.WRITE,
            SideEffect.DELETE,
            SideEffect.SECRET_ACCESS,
            SideEffect.AUDIT_CHANGE,
        }
    )
    if needs_path and not proposal.target_paths:
        command_mentions_external_path = _contains_any(
            _normalized_command(proposal.command_text),
            EXTERNAL_PATH_TOKENS,
        )
        if command_mentions_external_path and effects == {SideEffect.READ}:
            return (
                CapabilityDisposition.HOLD,
                "CAPABILITY_EXTERNAL_READ_REQUIRES_CONFIRMATION",
                (),
                ("external path in command text",),
                ("target_paths_missing_but_external_path_present",),
            )

        if command_mentions_external_path:
            return (
                CapabilityDisposition.KILL,
                "CAPABILITY_PATH_DENIED",
                (),
                ("external path in command text",),
                ("target_paths_missing_but_external_path_present",),
            )

        if effects == {SideEffect.READ}:
            return None

    if needs_path and not proposal.target_paths:
        return (
            CapabilityDisposition.HOLD,
            "CAPABILITY_TARGET_REQUIRED",
            (),
            (),
            ("target_paths",),
        )

    matched_targets = []
    rejected_targets = []
    evidence = []
    protected_roots = policy.resolved_protected_roots()
    network_domains = []

    for target in proposal.target_paths:
        if "\x00" in str(target):
            return (
                CapabilityDisposition.HOLD,
                "CAPABILITY_TARGET_UNRESOLVED",
                tuple(matched_targets),
                (str(target),),
                ("null_byte",),
            )

        parsed = urlparse(str(target))
        if parsed.scheme in {"http", "https"}:
            domain = _normalize_domain(parsed.hostname or "")
            if not domain:
                return (
                    CapabilityDisposition.HOLD,
                    "CAPABILITY_NETWORK_DOMAIN_UNCLEAR",
                    tuple(matched_targets),
                    (str(target),),
                    ("missing_domain",),
                )
            network_domains.append(domain)
            continue

        try:
            resolved = _resolve_target(proposal.cwd, str(target))
        except (OSError, RuntimeError, ValueError) as exc:
            return (
                CapabilityDisposition.HOLD,
                "CAPABILITY_TARGET_UNRESOLVED",
                tuple(matched_targets),
                (str(target),),
                (type(exc).__name__,),
            )

        resolved_text = str(resolved)
        if (
            not manifest.allow_protected_targets
            and (
                any(_is_within(resolved, root) for root in protected_roots)
                or is_agent_control_surface_path(
                    resolved,
                    project_roots=policy.project_roots,
                )
            )
        ):
            return (
                CapabilityDisposition.KILL,
                "CAPABILITY_PROTECTED_TARGET_DENIED",
                tuple(matched_targets),
                (resolved_text,),
                ("protected_control_target",),
            )

        if any(_is_within(resolved, root) for root in path_roots):
            matched_targets.append(resolved_text)
        else:
            rejected_targets.append(resolved_text)

    if rejected_targets:
        if effects == {SideEffect.READ}:
            return (
                CapabilityDisposition.HOLD,
                "CAPABILITY_EXTERNAL_READ_REQUIRES_CONFIRMATION",
                tuple(matched_targets),
                tuple(rejected_targets),
                (),
            )

        return (
            CapabilityDisposition.KILL,
            "CAPABILITY_PATH_DENIED",
            tuple(matched_targets),
            tuple(rejected_targets),
            (),
        )

    if SideEffect.NETWORK in effects:
        if not network_domains:
            return (
                CapabilityDisposition.HOLD,
                "CAPABILITY_NETWORK_DOMAIN_UNCLEAR",
                tuple(matched_targets),
                (),
                ("network_target_required",),
            )

        denied_domains = tuple(
            domain
            for domain in network_domains
            if domain not in manifest.allowed_network_domains
        )
        if denied_domains:
            return (
                CapabilityDisposition.KILL,
                "CAPABILITY_NETWORK_DOMAIN_DENIED",
                tuple(matched_targets),
                denied_domains,
                (),
            )

    return None


def _capability_effects(proposal: CommandProposal) -> Set[SideEffect]:
    effects = set(proposal.expected_side_effects)
    text = _normalized_command(proposal.command_text)

    if _contains_any(text, WRITE_TOKENS):
        effects.add(SideEffect.WRITE)

    if _contains_any(text, DELETE_TOKENS):
        effects.add(SideEffect.DELETE)

    if _contains_any(text, NETWORK_TOKENS):
        effects.add(SideEffect.NETWORK)

    if _contains_any(text, PRIVILEGE_TOKENS):
        effects.add(SideEffect.PRIVILEGE)

    if _contains_any(text, SECRET_TOKENS):
        effects.add(SideEffect.SECRET_ACCESS)

    if _contains_any(text, AUDIT_TOKENS) and (
        SideEffect.WRITE in effects
        or SideEffect.DELETE in effects
        or SideEffect.PRIVILEGE in effects
    ):
        effects.add(SideEffect.AUDIT_CHANGE)

    return effects


def _requires_process_equation(proposal: CommandProposal) -> bool:
    return "pub_process" in proposal.raw_payload


def _process_equation_gap(
    proposal: CommandProposal,
    effects: Set[SideEffect],
) -> tuple[str, ...]:
    missing: list[str] = []
    if not proposal.actor_id.strip():
        missing.append("actor_id")
    if not proposal.cwd.strip():
        missing.append("cwd")
    if not proposal.command_text.strip():
        missing.append("command_text")
    if not effects:
        missing.append("effect")
    if not _process_field(proposal, PROCESS_CHANNEL_KEYS):
        missing.append("channel_type")
    if not _process_field(proposal, PROCESS_TIME_KEYS):
        missing.append("process_time")
    if not _process_target_complete(proposal, effects):
        missing.append("target")
    return tuple(missing)


def _process_target_complete(proposal: CommandProposal, effects: Set[SideEffect]) -> bool:
    if proposal.target_paths:
        return True
    if effects <= {SideEffect.READ}:
        return bool(proposal.cwd.strip())
    if effects & {SideEffect.WRITE, SideEffect.DELETE, SideEffect.SECRET_ACCESS, SideEffect.AUDIT_CHANGE}:
        if _contains_any(_normalized_command(proposal.command_text), IMPLICIT_CWD_TARGET_TOKENS):
            return True
        # pub's bash parser drops bare dir names (`rm -rf build` -> no target_path), so
        # the target IS known (in the command) even when target_paths is empty. A
        # dangerous target is still caught downstream by the scope checks; here we only
        # confirm the process is COMPLETE (we can see what it acts on).
        return bool(delete_command_operands(proposal.command_text))
    if SideEffect.NETWORK in effects:
        return False
    return True


def _process_field(proposal: CommandProposal, keys: Sequence[str]) -> str:
    for source in _process_sources(proposal):
        for key in keys:
            value = source.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
    return ""


def _process_sources(proposal: CommandProposal) -> tuple[Mapping[str, Any], ...]:
    raw = proposal.raw_payload
    sources: list[Mapping[str, Any]] = []
    for key in PROCESS_METADATA_KEYS:
        value = raw.get(key)
        if isinstance(value, Mapping):
            sources.append(value)
    metadata = raw.get("metadata")
    if isinstance(metadata, Mapping):
        sources.append(metadata)
    sources.append(raw)
    return tuple(sources)


def _audit_skill_contracts(
    proposal: CommandProposal,
    manifest: CapabilityManifest,
) -> Optional[tuple[CapabilityDisposition, str, Sequence[str]]]:
    contracts = {contract.skill_id: contract for contract in manifest.skill_contracts}
    if not contracts:
        return None

    trace = _skill_trace(proposal.raw_payload)
    used_ids = (
        _trace_values(trace, "used_skill_ids")
        | _trace_values(trace, "skill_ids")
        | _trace_values(trace, "skill_id")
        | _trace_values(proposal.raw_payload, "used_skill_ids")
        | _trace_values(proposal.raw_payload, "skill_ids")
        | _trace_values(proposal.raw_payload, "skill_id")
    )
    contract_ids = set(contracts)
    required_ids = {
        skill_id
        for skill_id in contract_ids
        if not _optional_pass_road_skill(skill_id)
    }
    required_ids.update(_trace_values(trace, "required_skill_ids"))
    required_ids.update(used_ids & contract_ids)

    missing_skills = tuple(sorted(required_ids - used_ids))
    if missing_skills:
        return (
            CapabilityDisposition.HOLD,
            "CAPABILITY_SKILL_REQUIRED_NOT_USED",
            missing_skills,
        )

    unknown_skills = tuple(sorted(used_ids - set(contracts)))
    if unknown_skills:
        return (
            CapabilityDisposition.HOLD,
            "CAPABILITY_SKILL_CONTRACT_MISSING",
            unknown_skills,
        )

    active_contracts = tuple(contracts[skill_id] for skill_id in sorted(required_ids))
    completed_steps = (
        _trace_values(trace, "completed_step_ids")
        | _trace_values(trace, "completed_steps")
        | _trace_values(trace, "step_ids")
    )
    for contract in active_contracts:
        missing_steps = tuple(
            sorted(set(contract.required_step_ids) - completed_steps)
        )
        if missing_steps:
            return (
                CapabilityDisposition.HOLD,
                "CAPABILITY_SKILL_REQUIRED_STEP_SKIPPED",
                (contract.skill_id, *missing_steps),
            )

    manifest_hashes = _trace_mapping(trace, "manifest_hashes")
    manifest_hashes.update(_trace_mapping(proposal.raw_payload, "skill_manifest_hashes"))
    for contract in active_contracts:
        if not contract.manifest_sha256:
            continue
        recorded_hash = _normalize_skill_token(
            manifest_hashes.get(contract.skill_id)
            or trace.get("manifest_sha256")
            or proposal.raw_payload.get("skill_manifest_sha256")
        )
        if recorded_hash != contract.manifest_sha256:
            return (
                CapabilityDisposition.HOLD,
                "CAPABILITY_SKILL_MANIFEST_HASH_MISMATCH",
                (contract.skill_id, recorded_hash or "missing", contract.manifest_sha256),
            )

    instruction_ids = (
        _trace_values(trace, "instruction_ids")
        | _trace_values(trace, "used_instruction_ids")
    )
    skill_scan_result = _audit_skill_scan(trace)
    if skill_scan_result is not None:
        return skill_scan_result

    allowed_instruction_ids = set().union(
        *(set(contract.allowed_instruction_ids) for contract in active_contracts)
    )
    if instruction_ids and allowed_instruction_ids:
        unapproved = tuple(sorted(instruction_ids - allowed_instruction_ids))
        if unapproved:
            return (
                CapabilityDisposition.HOLD,
                "CAPABILITY_SKILL_INSTRUCTION_NOT_ALLOWED",
                unapproved,
            )

    authority_claims = (
        _trace_values(trace, "authority_claims")
        | _trace_values(trace, "claims")
    )
    authority_text = " ".join(sorted(authority_claims))
    denied_claims = set().union(
        *(set(contract.denied_authority_claims) for contract in active_contracts)
    )
    for denied in sorted(denied_claims):
        if denied and denied in authority_text:
            return (
                CapabilityDisposition.KILL,
                "CAPABILITY_SKILL_AUTHORITY_CLAIM_DENIED",
                (denied,),
            )

    return None


def _optional_pass_road_skill(skill_id: str) -> bool:
    return _normalize_skill_token(skill_id).startswith(PASS_ROAD_SKILL_PREFIX)


def _audit_skill_scan(
    trace: Mapping[str, Any],
) -> Optional[tuple[CapabilityDisposition, str, Sequence[str]]]:
    for key in ("instruction_scan", "skill_scan", "text_scan"):
        scan = trace.get(key)
        if isinstance(scan, Mapping):
            disposition = _normalize_skill_token(
                scan.get("disposition") or scan.get("status") or scan.get("verdict")
            )
            evidence = _scan_evidence(scan)
            if disposition in {"kill", "deny", "denied", "blocked", "fail", "failed"}:
                return (
                    CapabilityDisposition.KILL,
                    _skill_scan_reason(scan, "CAPABILITY_SKILL_SCAN_KILL"),
                    evidence,
                )
            if disposition in {"hold", "warn", "warning", "unclear", "unknown", "review"}:
                return (
                    CapabilityDisposition.HOLD,
                    _skill_scan_reason(scan, "CAPABILITY_SKILL_SCAN_HOLD"),
                    evidence,
                )
            if scan.get("passed") is False:
                return (
                    CapabilityDisposition.HOLD,
                    _skill_scan_reason(scan, "CAPABILITY_SKILL_SCAN_HOLD"),
                    evidence,
                )

    for key in ("instruction_scan_passed", "skill_scan_passed", "text_scan_passed"):
        if trace.get(key) is False:
            return (
                CapabilityDisposition.HOLD,
                "CAPABILITY_SKILL_SCAN_HOLD",
                (key,),
            )

    return None


def _decision(
    disposition: CapabilityDisposition,
    reason_code: str,
    actor_id: str,
    *,
    manifest_id: str = "",
    matched_side_effects: Sequence[SideEffect] = (),
    rejected_side_effects: Sequence[SideEffect] = (),
    matched_targets: Sequence[str] = (),
    rejected_targets: Sequence[str] = (),
    evidence: Sequence[str] = (),
) -> CapabilityDecision:
    certificate = {
        CapabilityDisposition.ALLOW: CapabilityCertificate.CAP_PASS,
        CapabilityDisposition.HOLD: CapabilityCertificate.CAP_HOLD_TICKET,
        CapabilityDisposition.KILL: CapabilityCertificate.CAP_KILL_WARRANT,
    }[disposition]
    return CapabilityDecision(
        disposition=disposition,
        certificate=certificate,
        reason_code=reason_code,
        actor_id=actor_id,
        manifest_id=manifest_id,
        matched_side_effects=matched_side_effects,
        rejected_side_effects=rejected_side_effects,
        matched_targets=matched_targets,
        rejected_targets=rejected_targets,
        evidence=evidence,
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
    path_text = normcase(normpath(str(path))).casefold()
    root_text = normcase(normpath(str(root))).rstrip("\\/").casefold()
    return (
        path_text == root_text
        or path_text.startswith(root_text + "\\")
        or path_text.startswith(root_text + "/")
    )


def _normalize_domain(domain: str) -> str:
    return str(domain).strip().lower().rstrip(".")


def _skill_trace(raw_payload: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("skill_trace", "skill_context"):
        value = raw_payload.get(key)
        if isinstance(value, Mapping):
            return value
    return {}


def _trace_values(source: Mapping[str, Any], key: str) -> Set[str]:
    return _coerce_skill_tokens(source.get(key))


def _trace_mapping(source: Mapping[str, Any], key: str) -> dict[str, str]:
    value = source.get(key)
    if not isinstance(value, Mapping):
        return {}
    return {
        _normalize_skill_token(item_key): _normalize_skill_token(item_value)
        for item_key, item_value in value.items()
        if _normalize_skill_token(item_key)
    }


def _scan_evidence(scan: Mapping[str, Any]) -> tuple[str, ...]:
    evidence = (
        _coerce_skill_tokens(scan.get("evidence"))
        or _coerce_skill_tokens(scan.get("findings"))
        or _coerce_skill_tokens(scan.get("violations"))
    )
    return tuple(sorted(evidence))


def _skill_scan_reason(scan: Mapping[str, Any], fallback: str) -> str:
    reason = str(scan.get("reason_code") or "").strip().upper()
    if reason.startswith("CAPABILITY_SKILL_"):
        return reason[:96]
    return fallback


def _coerce_skill_tokens(value: Any) -> Set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        token = _normalize_skill_token(value)
        return {token} if token else set()
    if isinstance(value, Mapping):
        return {
            token
            for item_key, enabled in value.items()
            if enabled and (token := _normalize_skill_token(item_key))
        }
    try:
        iterator = iter(value)
    except TypeError:
        token = _normalize_skill_token(value)
        return {token} if token else set()
    return {
        token
        for item in iterator
        if (token := _normalize_skill_token(item))
    }


def _normalize_skill_token(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _first_effect(
    effects: Sequence[SideEffect],
    candidates: Sequence[SideEffect],
) -> Optional[SideEffect]:
    for candidate in candidates:
        if candidate in effects:
            return candidate
    return None
