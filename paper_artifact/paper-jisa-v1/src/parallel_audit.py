from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field, replace
from enum import Enum
from os.path import normcase, normpath
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Set
from urllib.parse import urlparse

from adapter_wall import ActionEnvelope, AdapterActionType
from capability_wall import (
    CapabilityCertificate,
    CapabilityDecision,
    CapabilityDisposition,
    CapabilityPolicy,
    audit_capability,
    default_capability_policy,
)
from llm_channel import (
    ChannelAuditResult,
    ChannelDisposition,
    ChannelEnvelope,
    ChannelPolicy,
    audit_channel_envelope,
)
from ot_gate import CommandProposal, DeclaredScope, ExecutionDecision, OTGateResult
from ot_gate import OTPolicy, SideEffect, audit_command_proposal
from opaque_executor import is_opaque_executor
from phi_registry import PhiRegistry
from protect_scan import (
    ProtectScanDecision,
    ProtectScanDisposition,
    ProtectScanProfile,
    audit_protect_scan,
)
from registry_admission import (
    AdmissionDisposition,
    AdmissionPolicy,
    AdmissionTicket,
    issue_admission_ticket,
)
from safe_path import safe_resolve
from xray_transport import XrayTransportSeal, close_xray_transport, open_xray_transport


class EvidenceDisposition(str, Enum):
    PASS = "PASS"
    HOLD = "HOLD"
    KILL = "KILL"
    QUARANTINE = "QUARANTINE"
    REJECT = "REJECT"


class EvidenceStage(str, Enum):
    ADMISSION = "ADMISSION"
    CHANNEL_AUDIT = "CHANNEL_AUDIT"
    COMMAND_SURFACE = "COMMAND_SURFACE"
    OT_GATE = "OT_GATE"
    CAPABILITY_PRECHECK = "CAPABILITY_PRECHECK"
    PATH_SCAN = "PATH_SCAN"
    NETWORK_SCAN = "NETWORK_SCAN"
    PATCH_AUDIT = "PATCH_AUDIT"
    PROTECT_SCAN = "PROTECT_SCAN"
    AGGREGATOR = "AGGREGATOR"
    DECODE_REVIEW = "DECODE_REVIEW"


class EvidenceCourt(str, Enum):
    OT = "OT"
    DECODE = "DECODE"


@dataclass(frozen=True)
class EvidenceTestimony:
    stage: EvidenceStage
    disposition: EvidenceDisposition
    reason_code: str
    detail: str
    evidence: Sequence[str] = field(default_factory=tuple)
    metadata: Dict[str, Any] = field(default_factory=dict)
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self):
        if isinstance(self.stage, str):
            object.__setattr__(self, "stage", EvidenceStage(self.stage))

        if isinstance(self.disposition, str):
            object.__setattr__(
                self,
                "disposition",
                EvidenceDisposition(self.disposition),
            )

        if not self.reason_code.strip():
            raise ValueError("reason_code must be non-empty.")

        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))
        object.__setattr__(self, "metadata", dict(self.metadata))
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage.value,
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "detail": self.detail,
            "evidence": tuple(self.evidence),
            "metadata": dict(self.metadata),
            "can_execute": False,
            "can_grant_permission": False,
        }


@dataclass(frozen=True)
class CourtVerdict:
    court: EvidenceCourt
    disposition: EvidenceDisposition
    reason_code: str
    primary_stage: EvidenceStage
    testimonies: Sequence[EvidenceTestimony]
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self):
        if isinstance(self.court, str):
            object.__setattr__(self, "court", EvidenceCourt(self.court))

        if isinstance(self.disposition, str):
            object.__setattr__(
                self,
                "disposition",
                EvidenceDisposition(self.disposition),
            )

        if isinstance(self.primary_stage, str):
            object.__setattr__(self, "primary_stage", EvidenceStage(self.primary_stage))

        object.__setattr__(self, "testimonies", tuple(self.testimonies))
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    @property
    def passed(self) -> bool:
        return self.disposition == EvidenceDisposition.PASS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "court": self.court.value,
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "primary_stage": self.primary_stage.value,
            "testimony_count": len(self.testimonies),
            "testimony_reason_codes": tuple(
                testimony.reason_code for testimony in self.testimonies
            ),
            "can_execute": False,
            "can_grant_permission": False,
        }


@dataclass(frozen=True)
class ParallelEvidenceBundle:
    channel_testimony: EvidenceTestimony
    command_surface_testimony: EvidenceTestimony
    ot_gate_testimony: EvidenceTestimony
    capability_precheck: EvidenceTestimony
    path_testimony: EvidenceTestimony
    network_testimony: EvidenceTestimony
    patch_testimony: EvidenceTestimony
    protect_testimony: EvidenceTestimony
    channel_result: ChannelAuditResult
    ot_gate_result: OTGateResult
    capability_decision: CapabilityDecision
    protect_scan_decision: ProtectScanDecision
    proposal: CommandProposal
    xray_transport: Optional[XrayTransportSeal] = None

    @property
    def testimonies(self) -> Sequence[EvidenceTestimony]:
        return (
            self.channel_testimony,
            self.command_surface_testimony,
            self.ot_gate_testimony,
            self.capability_precheck,
            self.path_testimony,
            self.network_testimony,
            self.patch_testimony,
            self.protect_testimony,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "testimonies": tuple(testimony.to_dict() for testimony in self.testimonies),
            "channel": self.channel_result.to_dict(),
            "ot_gate": _ot_gate_result_dict(self.ot_gate_result),
            "capability_precheck": self.capability_decision.to_dict(),
            "protect_scan": self.protect_scan_decision.to_dict(),
            "proposal_id": self.proposal.proposal_id,
            "xray_transport": (
                self.xray_transport.to_dict()
                if self.xray_transport is not None
                else None
            ),
        }


@dataclass(frozen=True)
class ParallelAuditDecision:
    disposition: EvidenceDisposition
    reason_code: str
    primary_stage: EvidenceStage
    testimonies: Sequence[EvidenceTestimony]
    admission_ticket: Optional[AdmissionTicket] = None
    evidence_bundle: Optional[ParallelEvidenceBundle] = None
    xray_transport: Optional[XrayTransportSeal] = None
    capability_certificate: Optional[CapabilityCertificate] = None
    ot_court: Optional[CourtVerdict] = None
    decode_court: Optional[CourtVerdict] = None
    would_enter_ot: bool = False
    io_executed: bool = False
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self):
        if isinstance(self.disposition, str):
            object.__setattr__(
                self,
                "disposition",
                EvidenceDisposition(self.disposition),
            )

        if isinstance(self.primary_stage, str):
            object.__setattr__(self, "primary_stage", EvidenceStage(self.primary_stage))

        if isinstance(self.capability_certificate, str):
            object.__setattr__(
                self,
                "capability_certificate",
                CapabilityCertificate(self.capability_certificate),
            )

        object.__setattr__(self, "testimonies", tuple(self.testimonies))
        object.__setattr__(self, "would_enter_ot", self.allows_pre_io)
        object.__setattr__(self, "io_executed", False)
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    @property
    def dual_court_pass(self) -> bool:
        return bool(
            self.ot_court is not None
            and self.decode_court is not None
            and self.ot_court.passed
            and self.decode_court.passed
        )

    @property
    def dual_court_conflict(self) -> bool:
        return bool(
            self.ot_court is not None
            and self.decode_court is not None
            and self.ot_court.disposition != self.decode_court.disposition
        )

    @property
    def allows_pre_io(self) -> bool:
        return self.disposition == EvidenceDisposition.PASS and self.dual_court_pass

    def to_dict(self) -> Dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "primary_stage": self.primary_stage.value,
            "testimonies": tuple(testimony.to_dict() for testimony in self.testimonies),
            "admission_ticket": (
                self.admission_ticket.to_dict()
                if self.admission_ticket is not None
                else None
            ),
            "evidence_bundle": (
                self.evidence_bundle.to_dict()
                if self.evidence_bundle is not None
                else None
            ),
            "xray_transport": (
                self.xray_transport.to_dict()
                if self.xray_transport is not None
                else None
            ),
            "capability_certificate": (
                self.capability_certificate.value
                if self.capability_certificate is not None
                else None
            ),
            "ot_court": self.ot_court.to_dict() if self.ot_court is not None else None,
            "decode_court": (
                self.decode_court.to_dict()
                if self.decode_court is not None
                else None
            ),
            "dual_court_rule": "PASS requires OT_PASS and DECODE_PASS",
            "dual_court_conflict_rule": "OT/DECODE disagreement cannot relax; outcome is HOLD or stronger",
            "dual_court_pass": self.dual_court_pass,
            "dual_court_conflict": self.dual_court_conflict,
            "allows_pre_io": self.allows_pre_io,
            "would_enter_ot": self.would_enter_ot,
            "io_executed": False,
            "can_execute": False,
            "can_grant_permission": False,
        }


def run_parallel_audit(
    action: ActionEnvelope,
    *,
    registry: PhiRegistry,
    project_root: str,
    protect_profile: ProtectScanProfile,
    admission_policy: AdmissionPolicy = AdmissionPolicy(),
    channel_policy: Optional[ChannelPolicy] = None,
    ot_policy: Optional[OTPolicy] = None,
    capability_policy: Optional[CapabilityPolicy] = None,
) -> ParallelAuditDecision:
    channel = action.to_channel_envelope()
    proposal = _proposal_from_action(action)
    xray_handle = open_xray_transport(proposal)
    admission = issue_admission_ticket(channel, registry, admission_policy)
    if admission.disposition != AdmissionDisposition.ADMIT:
        xray_transport = close_xray_transport(xray_handle, proposal)
        disposition = (
            EvidenceDisposition.REJECT
            if admission.disposition == AdmissionDisposition.REJECT
            else EvidenceDisposition.HOLD
        )
        testimony = EvidenceTestimony(
            stage=EvidenceStage.ADMISSION,
            disposition=disposition,
            reason_code=admission.reason_code,
            detail="Registry Admission stopped the action before evidence bundle.",
            evidence=admission.evidence,
        )
        return _decision_from_testimonies(
            testimonies=(testimony,),
            admission_ticket=admission,
            xray_transport=xray_transport,
        )

    bundle = build_parallel_evidence_bundle(
        action,
        channel=channel,
        proposal=proposal,
        project_root=project_root,
        protect_profile=protect_profile,
        channel_policy=channel_policy or ChannelPolicy(project_root=project_root),
        ot_policy=ot_policy
        or OTPolicy(project_roots=(project_root,), registry=registry),
        capability_policy=capability_policy
        or default_capability_policy(project_root, (action.actor_id,)),
    )
    xray_transport = close_xray_transport(xray_handle, proposal)
    bundle = replace(bundle, xray_transport=xray_transport)
    return aggregate_parallel_evidence(bundle, admission_ticket=admission)


def build_parallel_evidence_bundle(
    action: ActionEnvelope,
    *,
    channel: Optional[ChannelEnvelope] = None,
    project_root: str,
    protect_profile: ProtectScanProfile,
    channel_policy: Optional[ChannelPolicy] = None,
    ot_policy: Optional[OTPolicy] = None,
    capability_policy: Optional[CapabilityPolicy] = None,
    proposal: Optional[CommandProposal] = None,
    xray_transport: Optional[XrayTransportSeal] = None,
) -> ParallelEvidenceBundle:
    channel = channel or action.to_channel_envelope()
    channel_policy = channel_policy or ChannelPolicy(project_root=project_root)
    ot_policy = ot_policy or OTPolicy(project_roots=(project_root,))
    capability_policy = capability_policy or default_capability_policy(
        project_root,
        (action.actor_id,),
    )
    proposal = proposal or _proposal_from_action(action)

    channel_result = audit_channel_envelope(channel, channel_policy)
    ot_gate_result = audit_command_proposal(proposal, ot_policy)
    capability_decision = audit_capability(proposal, capability_policy)
    protect_decision = audit_protect_scan(proposal, protect_profile)

    return ParallelEvidenceBundle(
        channel_testimony=_channel_testimony(channel_result),
        command_surface_testimony=audit_command_surface(action),
        ot_gate_testimony=_ot_gate_testimony(ot_gate_result),
        capability_precheck=_capability_precheck_testimony(capability_decision),
        path_testimony=audit_path_scan(action, project_root),
        network_testimony=audit_network_scan(action),
        patch_testimony=audit_patch_surface(action),
        protect_testimony=_protect_testimony(protect_decision),
        channel_result=channel_result,
        ot_gate_result=ot_gate_result,
        capability_decision=capability_decision,
        protect_scan_decision=protect_decision,
        proposal=proposal,
        xray_transport=xray_transport,
    )


def aggregate_parallel_evidence(
    bundle: ParallelEvidenceBundle,
    *,
    admission_ticket: Optional[AdmissionTicket] = None,
) -> ParallelAuditDecision:
    testimonies = _admission_testimonies(admission_ticket) + tuple(bundle.testimonies)
    return _decision_from_testimonies(
        testimonies=testimonies,
        admission_ticket=admission_ticket,
        evidence_bundle=bundle,
        xray_transport=bundle.xray_transport,
    )


def reaggregate_parallel_decision(
    decision: ParallelAuditDecision,
    extra_testimonies: Sequence[EvidenceTestimony] = (),
) -> ParallelAuditDecision:
    return _decision_from_testimonies(
        testimonies=tuple(decision.testimonies) + tuple(extra_testimonies),
        admission_ticket=decision.admission_ticket,
        evidence_bundle=decision.evidence_bundle,
        xray_transport=decision.xray_transport,
    )


COMMAND_SURFACE_OPERATORS = frozenset({"|", "||", "&&", ";", "&", "(", ")", "{", "}", "|&", "\n"})
COMMAND_SURFACE_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
COMMAND_SURFACE_WRAPPERS = frozenset(
    {
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
        "then",
        "do",
        "else",
    }
)
COMMAND_SURFACE_WRAPPER_VALUES = frozenset({"timeout", "nice", "ionice", "stdbuf"})
MODELLABLE_COMMAND_WORDS = frozenset(
    {
        "cat", "head", "tail", "less", "more", "bat", "nl", "tac", "rev", "fold",
        "grep", "egrep", "fgrep", "rg", "ag", "ack", "look",
        "ls", "dir", "find", "tree", "stat", "file", "readlink", "realpath",
        "wc", "sort", "uniq", "cut", "tr", "comm", "join", "paste", "column",
        "od", "xxd", "hexdump", "strings",
        "echo", "printf", "seq", "yes", "pwd", "basename", "dirname",
        "date", "cal", "which", "whereis", "type", "hostname", "whoami", "id",
        "uname", "printenv", "du", "df", "diff", "cmp",
        "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum", "b2sum", "jq", "yq",
        "touch", "mkdir", "tee", "cp", "copy", "mv", "move", "truncate",
        "mktemp", "rm", "rmdir", "unlink", "sed", "git",
        "curl", "wget", "chmod", "chown", "icacls",
        # install / shred / ln / chgrp deliberately EXCLUDED: no effect layer
        # models them, so they must fail-closed to UNKNOWN_COMMAND_SURFACE -> HOLD
        # rather than be vouched "modellable" and judged READ (red-team B1).
        "get-content", "set-content", "add-content", "clear-content",
        "remove-item", "copy-item", "move-item", "new-item", "out-file",
        "select-string", "invoke-webrequest", "iwr",
        "true", "false", "test", "[", ":", "cd", "export", "set", "unset", "read",
        "exit", "return", "alias", "unalias", "history", "clear", "sleep",
        "wait", "umask", "ulimit", "pushd", "popd", "dirs",
        # Known families with benign query forms. Execution forms are caught by
        # opaque_executor first and held by this PUB stage.
        "python", "python2", "python3", "py", "pypy", "pypy3",
        "perl", "ruby", "node", "nodejs", "php", "rscript",
        "pip", "pip3", "pipx", "npm", "pnpm", "yarn", "uv", "poetry",
        "cargo", "go", "bundle", "jupyter", "deno", "bun",
        "docker", "docker-compose", "kubectl",
    }
)


def audit_command_surface(action: ActionEnvelope) -> EvidenceTestimony:
    if not _is_shell_action(action):
        return EvidenceTestimony(
            stage=EvidenceStage.COMMAND_SURFACE,
            disposition=EvidenceDisposition.PASS,
            reason_code="COMMAND_SURFACE_NOT_SHELL",
            detail="command-surface scan applies only to shell/Bash actions",
        )
    if _gateway_payload(action.raw_payload):
        return EvidenceTestimony(
            stage=EvidenceStage.COMMAND_SURFACE,
            disposition=EvidenceDisposition.PASS,
            reason_code="COMMAND_SURFACE_STRUCTURED_GATEWAY",
            detail="structured gateway evidence is judged by the network/protect scans",
        )

    opaque, evidence = is_opaque_executor(action.command_text)
    if opaque:
        return EvidenceTestimony(
            stage=EvidenceStage.COMMAND_SURFACE,
            disposition=EvidenceDisposition.HOLD,
            reason_code="COMMAND_SURFACE_OPAQUE_EXECUTION",
            detail="interpreter or runner execution is observable but not effect-modellable from argv",
            evidence=evidence,
            metadata={"rule": "pub_command_surface_opaque_execution"},
        )

    unknown = _unknown_command_words(action.command_text)
    if unknown:
        return EvidenceTestimony(
            stage=EvidenceStage.COMMAND_SURFACE,
            disposition=EvidenceDisposition.HOLD,
            reason_code="UNKNOWN_COMMAND_SURFACE",
            detail="command-position word is not in pub's modellable command surface",
            evidence=unknown,
            metadata={"rule": "pub_unknown_command_surface_holds"},
        )

    return EvidenceTestimony(
        stage=EvidenceStage.COMMAND_SURFACE,
        disposition=EvidenceDisposition.PASS,
        reason_code="COMMAND_SURFACE_PASS",
        detail="command-position words are known to pub's surface model",
    )


def _is_shell_action(action: ActionEnvelope) -> bool:
    return (
        action.action_type == AdapterActionType.SHELL
        or str(action.tool_name).strip().lower() in {"bash", "shell"}
        or str(action.action_type.value).strip().lower() in {"bash", "shell"}
    )


def _unknown_command_words(command_text: str) -> tuple[str, ...]:
    unknown: list[str] = []
    for segment in _command_surface_segments(_command_surface_tokens(command_text)):
        base, _rest = _command_surface_word(segment)
        if base is not None and not _known_command_word(base):
            unknown.append(base)
    return tuple(dict.fromkeys(unknown))


def _known_command_word(base: str) -> bool:
    return (
        base in MODELLABLE_COMMAND_WORDS
        or bool(re.fullmatch(r"python\d+(?:\.\d+)?", base))
        or bool(re.fullmatch(r"perl\d+(?:\.\d+)?", base))
    )


def _command_surface_tokens(command_text: str) -> list[str]:
    try:
        return shlex.split(command_text, posix=True)
    except ValueError:
        return command_text.split()


def _command_surface_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in COMMAND_SURFACE_OPERATORS:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def _command_surface_word(segment: list[str]) -> tuple[str | None, list[str]]:
    index = 0
    while index < len(segment):
        token = segment[index]
        base = _surface_basename(token).lstrip("({")
        if not base:
            index += 1
            continue
        if COMMAND_SURFACE_ASSIGNMENT.match(token):
            index += 1
            continue
        if base == "cmd":
            index += 1
            while index < len(segment) and segment[index].startswith(("/", "-")):
                index += 1
            continue
        if base in COMMAND_SURFACE_WRAPPERS:
            index += 1
            while index < len(segment) and segment[index].startswith("-"):
                index += 1
            if (
                base in COMMAND_SURFACE_WRAPPER_VALUES
                and index < len(segment)
                and not segment[index].startswith("-")
            ):
                index += 1
            continue
        return base, segment[index + 1 :]
    return None, []


def _surface_basename(token: str) -> str:
    text = str(token).strip().strip("'\"").replace("\\", "/")
    base = text.rsplit("/", 1)[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def audit_path_scan(action: ActionEnvelope, project_root: str) -> EvidenceTestimony:
    unresolved = tuple(
        str(target)
        for target in action.target_paths
        if "\x00" in str(target) or _has_unresolved_path_variable(str(target))
    )
    if unresolved:
        return EvidenceTestimony(
            stage=EvidenceStage.PATH_SCAN,
            disposition=EvidenceDisposition.HOLD,
            reason_code="PATH_TARGET_UNRESOLVED",
            detail="target path cannot be resolved reliably before I/O",
            evidence=unresolved,
        )

    traversal = tuple(
        str(target) for target in action.target_paths if _has_path_traversal(str(target))
    )
    if traversal:
        return EvidenceTestimony(
            stage=EvidenceStage.PATH_SCAN,
            disposition=EvidenceDisposition.HOLD,
            reason_code="PATH_TRAVERSAL_REQUIRES_CONFIRMATION",
            detail="path traversal is evidence for later boundary judgment",
            evidence=traversal,
        )

    outside = tuple(_outside_project_targets(action, project_root))
    if outside:
        effects = _action_effects(action)
        if effects & {SideEffect.WRITE, SideEffect.DELETE}:
            return EvidenceTestimony(
                stage=EvidenceStage.PATH_SCAN,
                disposition=EvidenceDisposition.KILL,
                reason_code="PATH_EXTERNAL_WRITE_DENIED",
                detail="write/delete target escapes project boundary",
                evidence=outside,
            )

        return EvidenceTestimony(
            stage=EvidenceStage.PATH_SCAN,
            disposition=EvidenceDisposition.HOLD,
            reason_code="PATH_EXTERNAL_READ_REQUIRES_CONFIRMATION",
            detail="external read target needs user confirmation",
            evidence=outside,
        )

    return EvidenceTestimony(
        stage=EvidenceStage.PATH_SCAN,
        disposition=EvidenceDisposition.PASS,
        reason_code="PATH_SCAN_PASS",
        detail="target paths do not escape project metadata boundary",
    )


def audit_network_scan(action: ActionEnvelope) -> EvidenceTestimony:
    text = _action_text(action)
    urls = tuple(
        str(target)
        for target in action.target_paths
        if urlparse(str(target)).scheme in {"http", "https"}
    )
    network_present = (
        action.action_type == AdapterActionType.NETWORK
        or SideEffect.NETWORK in _action_effects(action)
        or bool(urls)
        or _contains_any(text, ("http://", "https://", "curl", "wget", "invoke-webrequest", "iwr"))
    )
    if not network_present:
        return EvidenceTestimony(
            stage=EvidenceStage.NETWORK_SCAN,
            disposition=EvidenceDisposition.PASS,
            reason_code="NETWORK_SCAN_PASS",
            detail="no network evidence in action envelope",
        )

    secret_like = _contains_any(
        text,
        (".env", "api_key", "apikey", "secret", "vault_token", "id_rsa", ".ssh"),
    )
    if secret_like:
        return EvidenceTestimony(
            stage=EvidenceStage.NETWORK_SCAN,
            disposition=EvidenceDisposition.KILL,
            reason_code="NETWORK_SECRET_EXFIL_DENIED",
            detail="network movement is combined with secret-like evidence",
            evidence=urls or ("network_secret_evidence",),
        )

    if not urls and ("$" in action.command_text or "target" in text):
        return EvidenceTestimony(
            stage=EvidenceStage.NETWORK_SCAN,
            disposition=EvidenceDisposition.HOLD,
            reason_code="NETWORK_TARGET_UNCLEAR",
            detail="network intent exists but target domain is unclear",
            evidence=(action.command_text,),
        )

    gateway = _gateway_payload(action.raw_payload)
    if gateway and _gateway_auth_valid(gateway):
        hosts = tuple(
            host
            for host in (
                str(gateway.get("bind_host", "")),
                str(gateway.get("host", "")),
                *(urlparse(url).hostname or "" for url in urls),
            )
            if host
        )
        insecure = bool(
            gateway.get("allowInsecureAuth")
            or gateway.get("allow_insecure_auth")
            or gateway.get("insecure_auth")
        )
        public = bool(gateway.get("public") or gateway.get("public_url"))
        if hosts and all(_is_loopback_host(host) for host in hosts) and not insecure and not public:
            return EvidenceTestimony(
                stage=EvidenceStage.NETWORK_SCAN,
                disposition=EvidenceDisposition.PASS,
                reason_code="NETWORK_GATEWAY_LOOPBACK_AUTH_PASS",
                detail="authenticated loopback gateway does not expose remote network surface",
                evidence=urls or hosts,
            )

    return EvidenceTestimony(
        stage=EvidenceStage.NETWORK_SCAN,
        disposition=EvidenceDisposition.HOLD,
        reason_code="NETWORK_REQUIRES_CONFIRMATION",
        detail="network movement requires explicit confirmation before I/O",
        evidence=urls or ("network token in command text",),
    )


def audit_patch_surface(action: ActionEnvelope) -> EvidenceTestimony:
    effects = _action_effects(action)
    text = _action_text(action)
    patch_targets = tuple(
        target
        for target in action.target_paths
        if _is_boundary_code_path(str(target))
    )
    boundary_note = str(action.raw_payload.get("boundary_change_note", "")).strip()
    explicit_no_boundary_change = bool(
        action.raw_payload.get("no_boundary_change", False)
    )

    silent_weakeners = (
        "allow_all",
        "can_execute=true",
        "can_grant_permission=true",
        "execute_if_allowed",
        "io_executed=true",
        "skip audit",
        "disable audit",
    )
    if patch_targets and effects & {SideEffect.WRITE, SideEffect.DELETE}:
        if _contains_any(text, silent_weakeners):
            return EvidenceTestimony(
                stage=EvidenceStage.PATCH_AUDIT,
                disposition=EvidenceDisposition.KILL,
                reason_code="PATCH_AUDIT_SILENT_BOUNDARY_WEAKENING",
                detail="patch appears to silently weaken audit boundary",
                evidence=patch_targets,
            )

        if not boundary_note and not explicit_no_boundary_change:
            return EvidenceTestimony(
                stage=EvidenceStage.PATCH_AUDIT,
                disposition=EvidenceDisposition.HOLD,
                reason_code="PATCH_AUDIT_BOUNDARY_NOTE_REQUIRED",
                detail="security-boundary patch needs an explicit boundary note",
                evidence=patch_targets,
            )

        return EvidenceTestimony(
            stage=EvidenceStage.PATCH_AUDIT,
            disposition=EvidenceDisposition.HOLD,
            reason_code="PATCH_AUDIT_HUMAN_REVIEW_REQUIRED",
            detail="security-boundary patch requires human review even when declared",
            evidence=patch_targets,
            metadata={"boundary_change_note": boundary_note},
        )

    return EvidenceTestimony(
        stage=EvidenceStage.PATCH_AUDIT,
        disposition=EvidenceDisposition.PASS,
        reason_code="PATCH_AUDIT_NOT_APPLICABLE",
        detail="action does not patch a known audit boundary file",
    )


def _channel_testimony(result: ChannelAuditResult) -> EvidenceTestimony:
    if result.disposition == ChannelDisposition.QUARANTINE:
        disposition = EvidenceDisposition.QUARANTINE
    elif result.disposition == ChannelDisposition.HOLD:
        disposition = EvidenceDisposition.HOLD
    else:
        disposition = EvidenceDisposition.PASS

    reason = (
        result.findings[0].reason_code
        if result.findings
        else f"CHANNEL_{result.disposition.value}"
    )
    return EvidenceTestimony(
        stage=EvidenceStage.CHANNEL_AUDIT,
        disposition=disposition,
        reason_code=reason,
        detail="Channel Audit testimony",
        evidence=tuple(
            item
            for finding in result.findings
            for item in finding.evidence
        ),
        metadata={
            "channel_disposition": result.disposition.value,
            "command_proposal_id": (
                result.command_proposal.proposal_id
                if result.command_proposal is not None
                else None
            ),
        },
    )


def _ot_gate_testimony(result: OTGateResult) -> EvidenceTestimony:
    if result.decision == ExecutionDecision.ALLOW:
        disposition = EvidenceDisposition.PASS
    elif result.reason_code == "HOLD_FOR_USER_CONFIRMATION" or result.hold_votes:
        disposition = EvidenceDisposition.HOLD
    else:
        disposition = EvidenceDisposition.KILL

    return EvidenceTestimony(
        stage=EvidenceStage.OT_GATE,
        disposition=disposition,
        reason_code=f"OT_{result.reason_code}",
        detail="OT Court command-proposal testimony",
        evidence=tuple(
            item
            for testimony in result.testimonies
            for item in testimony.evidence
        ),
        metadata={
            "permission_level": result.permission_level.value,
            "critical": result.critical,
            "kill_votes": result.kill_votes,
            "hold_votes": result.hold_votes,
            "judge_reason_codes": tuple(
                testimony.reason_code for testimony in result.testimonies
            ),
            "judge_votes": tuple(testimony.vote.value for testimony in result.testimonies),
        },
    )


def _ot_gate_result_dict(result: OTGateResult) -> Dict[str, Any]:
    return {
        "decision": result.decision.value,
        "reason_code": result.reason_code,
        "permission_level": result.permission_level.value,
        "critical": result.critical,
        "kill_votes": result.kill_votes,
        "hold_votes": result.hold_votes,
        "io_executed": False,
        "testimonies": tuple(
            {
                "judge": testimony.judge.value,
                "vote": testimony.vote.value,
                "reason_code": testimony.reason_code,
                "critical": testimony.critical,
                "evidence": tuple(testimony.evidence),
            }
            for testimony in result.testimonies
        ),
    }


def _capability_precheck_testimony(
    decision: CapabilityDecision,
) -> EvidenceTestimony:
    if decision.disposition == CapabilityDisposition.KILL:
        disposition = EvidenceDisposition.KILL
    elif decision.disposition == CapabilityDisposition.HOLD:
        disposition = EvidenceDisposition.HOLD
    else:
        disposition = EvidenceDisposition.PASS

    return EvidenceTestimony(
        stage=EvidenceStage.CAPABILITY_PRECHECK,
        disposition=disposition,
        reason_code=decision.reason_code,
        detail="Capability Precheck candidate; certificate is not finalized here.",
        evidence=tuple(decision.evidence)
        + tuple(decision.rejected_targets)
        + tuple(effect.value for effect in decision.rejected_side_effects),
        metadata={
            "candidate_certificate": decision.certificate.value,
            "certificate_finalized": False,
            "manifest_id": decision.manifest_id,
        },
    )


def _protect_testimony(decision: ProtectScanDecision) -> EvidenceTestimony:
    if decision.disposition == ProtectScanDisposition.KILL:
        disposition = EvidenceDisposition.KILL
    elif decision.disposition == ProtectScanDisposition.HOLD:
        disposition = EvidenceDisposition.HOLD
    else:
        disposition = EvidenceDisposition.PASS

    return EvidenceTestimony(
        stage=EvidenceStage.PROTECT_SCAN,
        disposition=disposition,
        reason_code=decision.reason_code,
        detail="Protect Scan profile-driven testimony",
        evidence=tuple(
            item
            for finding in decision.findings
            for item in finding.evidence
        ),
        metadata={
            "profile_id": decision.profile_id,
            "startup_confirmed": decision.startup_confirmed,
            "matched_surfaces": tuple(
                surface.value for surface in decision.matched_surfaces
            ),
        },
    )


OT_COURT_STAGES = frozenset(
    {
        EvidenceStage.ADMISSION,
        EvidenceStage.OT_GATE,
        EvidenceStage.CAPABILITY_PRECHECK,
        EvidenceStage.PROTECT_SCAN,
        EvidenceStage.PATCH_AUDIT,
    }
)
DECODE_COURT_STAGES = frozenset(
    {
        EvidenceStage.CHANNEL_AUDIT,
        EvidenceStage.COMMAND_SURFACE,
        EvidenceStage.PATH_SCAN,
        EvidenceStage.NETWORK_SCAN,
        EvidenceStage.DECODE_REVIEW,
    }
)
DISPOSITION_PRIORITY = (
    EvidenceDisposition.REJECT,
    EvidenceDisposition.KILL,
    EvidenceDisposition.QUARANTINE,
    EvidenceDisposition.HOLD,
    EvidenceDisposition.PASS,
)
DISPOSITION_RANK = {
    disposition: len(DISPOSITION_PRIORITY) - index
    for index, disposition in enumerate(DISPOSITION_PRIORITY)
}


def _admission_testimonies(
    admission_ticket: Optional[AdmissionTicket],
) -> tuple[EvidenceTestimony, ...]:
    if admission_ticket is None:
        return ()
    if admission_ticket.disposition == AdmissionDisposition.REJECT:
        disposition = EvidenceDisposition.REJECT
    elif admission_ticket.disposition == AdmissionDisposition.HOLD:
        disposition = EvidenceDisposition.HOLD
    else:
        disposition = EvidenceDisposition.PASS
    return (
        EvidenceTestimony(
            stage=EvidenceStage.ADMISSION,
            disposition=disposition,
            reason_code=admission_ticket.reason_code,
            detail="Registry Admission testimony",
            evidence=admission_ticket.evidence,
        ),
    )


def _decision_from_testimonies(
    *,
    testimonies: Sequence[EvidenceTestimony],
    admission_ticket: Optional[AdmissionTicket] = None,
    evidence_bundle: Optional[ParallelEvidenceBundle] = None,
    xray_transport: Optional[XrayTransportSeal] = None,
) -> ParallelAuditDecision:
    testimonies = tuple(testimonies)
    ot_court = _court_verdict(EvidenceCourt.OT, testimonies)
    decode_court = _court_verdict(EvidenceCourt.DECODE, testimonies)
    conflict = _dual_court_conflict_testimony(ot_court, decode_court)
    if conflict is not None:
        testimonies = testimonies + (conflict,)
    primary = _dual_court_primary(ot_court, decode_court)
    certificate = _final_capability_certificate(evidence_bundle, ot_court, decode_court)
    return ParallelAuditDecision(
        disposition=primary.disposition,
        reason_code=primary.reason_code,
        primary_stage=primary.stage,
        testimonies=testimonies,
        admission_ticket=admission_ticket,
        evidence_bundle=evidence_bundle,
        xray_transport=xray_transport,
        capability_certificate=certificate,
        ot_court=ot_court,
        decode_court=decode_court,
    )


def _court_verdict(
    court: EvidenceCourt,
    testimonies: Sequence[EvidenceTestimony],
) -> CourtVerdict:
    stages = OT_COURT_STAGES if court == EvidenceCourt.OT else DECODE_COURT_STAGES
    court_testimonies = tuple(
        testimony for testimony in testimonies if testimony.stage in stages
    )
    if not court_testimonies:
        missing = EvidenceTestimony(
            stage=EvidenceStage.AGGREGATOR,
            disposition=EvidenceDisposition.HOLD,
            reason_code=f"{court.value}_COURT_TESTIMONY_MISSING",
            detail=f"{court.value} court has no testimony; no court may pass alone.",
        )
        return CourtVerdict(
            court=court,
            disposition=EvidenceDisposition.HOLD,
            reason_code=missing.reason_code,
            primary_stage=missing.stage,
            testimonies=(missing,),
        )
    primary = _primary_testimony(court_testimonies)
    return CourtVerdict(
        court=court,
        disposition=primary.disposition,
        reason_code=primary.reason_code,
        primary_stage=primary.stage,
        testimonies=court_testimonies,
    )


def _dual_court_primary(
    ot_court: CourtVerdict,
    decode_court: CourtVerdict,
) -> EvidenceTestimony:
    if ot_court.passed and decode_court.passed:
        return _primary_testimony(
            tuple(ot_court.testimonies) + tuple(decode_court.testimonies)
        )

    courts = (ot_court, decode_court)
    strongest = max(
        (court.disposition for court in courts),
        key=lambda item: DISPOSITION_RANK[item],
    )
    candidates = tuple(court for court in courts if court.disposition == strongest)
    return _primary_testimony(
        tuple(
            testimony
            for court in candidates
            for testimony in court.testimonies
            if testimony.disposition == strongest
        )
    )


def _dual_court_conflict_testimony(
    ot_court: CourtVerdict,
    decode_court: CourtVerdict,
) -> Optional[EvidenceTestimony]:
    if ot_court.disposition == decode_court.disposition:
        return None
    if (
        ot_court.reason_code.endswith("_COURT_TESTIMONY_MISSING")
        or decode_court.reason_code.endswith("_COURT_TESTIMONY_MISSING")
    ):
        return None

    strongest = max(
        (ot_court.disposition, decode_court.disposition),
        key=lambda item: DISPOSITION_RANK[item],
    )
    if DISPOSITION_RANK[strongest] < DISPOSITION_RANK[EvidenceDisposition.HOLD]:
        strongest = EvidenceDisposition.HOLD

    return EvidenceTestimony(
        stage=EvidenceStage.AGGREGATOR,
        disposition=strongest,
        reason_code=f"DUAL_COURT_CONFLICT_{strongest.value}",
        detail=(
            "OT and decode court verdicts diverged; a looser court cannot relax "
            "the stricter court."
        ),
        evidence=(
            f"ot:{ot_court.disposition.value}:{ot_court.reason_code}",
            f"decode:{decode_court.disposition.value}:{decode_court.reason_code}",
        ),
        metadata={
            "rule": "court_disagreement_holds_or_stronger",
            "ot_disposition": ot_court.disposition.value,
            "decode_disposition": decode_court.disposition.value,
        },
    )


def _primary_testimony(
    testimonies: Sequence[EvidenceTestimony],
) -> EvidenceTestimony:
    for disposition in DISPOSITION_PRIORITY:
        matches = tuple(
            testimony for testimony in testimonies if testimony.disposition == disposition
        )
        if matches:
            return _stage_primary(matches, disposition)
    raise ValueError("parallel audit requires at least one testimony.")


def _stage_primary(
    testimonies: Sequence[EvidenceTestimony],
    disposition: EvidenceDisposition,
) -> EvidenceTestimony:
    stage_priority = {
        EvidenceDisposition.REJECT: (
            EvidenceStage.ADMISSION,
            EvidenceStage.PROTECT_SCAN,
            EvidenceStage.PATCH_AUDIT,
            EvidenceStage.OT_GATE,
            EvidenceStage.CAPABILITY_PRECHECK,
            EvidenceStage.CHANNEL_AUDIT,
            EvidenceStage.COMMAND_SURFACE,
            EvidenceStage.DECODE_REVIEW,
            EvidenceStage.AGGREGATOR,
            EvidenceStage.PATH_SCAN,
            EvidenceStage.NETWORK_SCAN,
        ),
        EvidenceDisposition.KILL: (
            EvidenceStage.PROTECT_SCAN,
            EvidenceStage.PATCH_AUDIT,
            EvidenceStage.CAPABILITY_PRECHECK,
            EvidenceStage.OT_GATE,
            EvidenceStage.PATH_SCAN,
            EvidenceStage.NETWORK_SCAN,
            EvidenceStage.CHANNEL_AUDIT,
            EvidenceStage.COMMAND_SURFACE,
            EvidenceStage.DECODE_REVIEW,
        ),
        EvidenceDisposition.QUARANTINE: (
            EvidenceStage.CHANNEL_AUDIT,
            EvidenceStage.COMMAND_SURFACE,
            EvidenceStage.DECODE_REVIEW,
            EvidenceStage.PROTECT_SCAN,
            EvidenceStage.PATCH_AUDIT,
            EvidenceStage.OT_GATE,
            EvidenceStage.CAPABILITY_PRECHECK,
            EvidenceStage.PATH_SCAN,
            EvidenceStage.NETWORK_SCAN,
        ),
        EvidenceDisposition.HOLD: (
            EvidenceStage.PROTECT_SCAN,
            EvidenceStage.CHANNEL_AUDIT,
            EvidenceStage.COMMAND_SURFACE,
            EvidenceStage.DECODE_REVIEW,
            EvidenceStage.OT_GATE,
            EvidenceStage.CAPABILITY_PRECHECK,
            EvidenceStage.PATH_SCAN,
            EvidenceStage.NETWORK_SCAN,
            EvidenceStage.PATCH_AUDIT,
        ),
        EvidenceDisposition.PASS: (
            EvidenceStage.CHANNEL_AUDIT,
            EvidenceStage.COMMAND_SURFACE,
            EvidenceStage.OT_GATE,
            EvidenceStage.CAPABILITY_PRECHECK,
            EvidenceStage.PATH_SCAN,
            EvidenceStage.NETWORK_SCAN,
            EvidenceStage.PATCH_AUDIT,
            EvidenceStage.PROTECT_SCAN,
        ),
    }
    for stage in stage_priority[disposition]:
        for testimony in testimonies:
            if testimony.stage == stage:
                return testimony
    return testimonies[0]


def _final_capability_certificate(
    bundle: Optional[ParallelEvidenceBundle],
    ot_court: CourtVerdict,
    decode_court: CourtVerdict,
) -> Optional[CapabilityCertificate]:
    if bundle is None:
        return None
    if ot_court.passed and decode_court.passed:
        return bundle.capability_decision.certificate

    return None


def _proposal_from_action(action: ActionEnvelope) -> CommandProposal:
    return CommandProposal(
        command_text=action.command_text,
        actor_id=action.actor_id,
        cwd=action.cwd,
        declared_scope=action.declared_scope or _default_declared_scope(action.action_type),
        target_paths=tuple(action.target_paths),
        expected_side_effects=_action_effects(action),
        parent_event_id=action.parent_event_id,
        user_request_id=action.user_request_id,
        proposal_id=action.action_id,
        source_adapter=action.source_adapter,
        tool_name=action.tool_name,
        action_type=action.action_type.value,
        raw_payload=_proposal_raw_payload(action),
    )


def _proposal_raw_payload(action: ActionEnvelope) -> Dict[str, Any]:
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
                sorted(effect.value for effect in _action_effects(action))
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


def _action_effects(action: ActionEnvelope) -> Set[SideEffect]:
    if action.expected_side_effects:
        return set(action.expected_side_effects)

    mapping = {
        AdapterActionType.FILE_READ: {SideEffect.READ},
        AdapterActionType.FILE_WRITE: {SideEffect.WRITE},
        AdapterActionType.FILE_DELETE: {SideEffect.DELETE},
        AdapterActionType.SHELL: {SideEffect.READ},
        AdapterActionType.NETWORK: {SideEffect.NETWORK},
        AdapterActionType.REGISTRY: {SideEffect.AUDIT_CHANGE},
    }
    return set(mapping[action.action_type])


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


def _action_text(action: ActionEnvelope) -> str:
    pieces = [
        action.command_text,
        action.cwd,
        action.source_adapter,
        action.tool_name,
        action.action_type.value,
        *(str(target) for target in action.target_paths),
        *(effect.value for effect in _action_effects(action)),
        *(f"{key}={value}" for key, value in action.raw_payload.items()),
    ]
    return " ".join(str(piece) for piece in pieces if str(piece).strip()).lower()


def _gateway_payload(raw_payload: Mapping[str, Any]) -> Mapping[str, Any]:
    merged: Dict[str, Any] = {}
    for key in ("gateway", "gateway_evidence", "permission_gateway", "public_exposure"):
        value = raw_payload.get(key)
        if isinstance(value, Mapping):
            merged.update(value)
    harness = raw_payload.get("harness_adapter")
    if isinstance(harness, Mapping):
        gateway = harness.get("gateway_evidence")
        if isinstance(gateway, Mapping):
            merged.update(gateway)
    return merged


def _gateway_auth_valid(gateway: Mapping[str, Any]) -> bool:
    for key in ("auth_valid", "authenticated", "token_valid", "valid_auth"):
        value = gateway.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes", "valid", "ok"}
        return bool(value)
    auth = gateway.get("auth")
    if isinstance(auth, Mapping):
        return _gateway_auth_valid(auth)
    if isinstance(auth, str):
        return auth.strip().lower() in {"valid", "required", "token", "bearer", "mtls"}
    return False


def _is_loopback_host(host: str) -> bool:
    return host.strip().strip("[]").lower() in {"localhost", "127.0.0.1", "::1"}


def _outside_project_targets(action: ActionEnvelope, project_root: str) -> Sequence[str]:
    root = Path(project_root).resolve(strict=False)
    outside = []
    for target in action.target_paths:
        parsed = urlparse(str(target))
        if parsed.scheme in {"http", "https"}:
            continue
        try:
            resolved = _resolve_target(action.cwd, str(target))
        except (OSError, RuntimeError, ValueError):
            continue
        if not _is_within(resolved, root):
            outside.append(str(resolved))
    return tuple(outside)


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


def _has_path_traversal(value: str) -> bool:
    return ".." in value.replace("\\", "/").split("/")


def _has_unresolved_path_variable(value: str) -> bool:
    text = str(value)
    return "$" in text or "%" in text


def _contains_any(text: str, tokens: Sequence[str]) -> bool:
    return any(token.lower() in text for token in tokens if token)


def _is_boundary_code_path(target: str) -> bool:
    normalized = target.replace("\\", "/").lower()
    boundary_files = (
        "adapter_wall.py",
        "audit_layer.py",
        "autopsy_report.py",
        "benchmark_runner.py",
        "capability_wall.py",
        "event_ledger.py",
        "llm_channel.py",
        "ot_gate.py",
        "parallel_audit.py",
        "phi_registry.py",
        "protect_scan.py",
        "registry_admission.py",
        "task_guard.py",
    )
    return any(normalized.endswith(file_name) for file_name in boundary_files)
