from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from enum import Enum
from os.path import normcase, normpath
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Set

from audit_layer import AuditLayer, LayeredObjectRef
from ot_gate import CommandProposal, DeclaredScope, SideEffect
from safe_path import safe_resolve


class ChannelType(str, Enum):
    USER_REQUEST = "USER_REQUEST"
    TOOL_METADATA = "TOOL_METADATA"
    AGENT_PROPOSAL = "AGENT_PROPOSAL"
    REJECTED_FEEDBACK = "REJECTED_FEEDBACK"


class ChannelDisposition(str, Enum):
    ACCEPT = "ACCEPT"
    HOLD = "HOLD"
    QUARANTINE = "QUARANTINE"
    WRAP_PROPOSAL = "WRAP_PROPOSAL"


class ChannelSeverity(str, Enum):
    CLEAN = "CLEAN"
    SUSPECT = "SUSPECT"
    CONTAMINATED = "CONTAMINATED"


@dataclass(frozen=True)
class ChannelFinding:
    reason_code: str
    severity: ChannelSeverity
    layer: AuditLayer
    detail: str
    evidence: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self):
        if isinstance(self.severity, str):
            object.__setattr__(self, "severity", ChannelSeverity(self.severity))

        if isinstance(self.layer, str):
            object.__setattr__(self, "layer", AuditLayer(self.layer))

        if not self.reason_code.strip():
            raise ValueError("reason_code must be non-empty.")

        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))

    @property
    def blocks_wrapping(self) -> bool:
        return self.severity in {
            ChannelSeverity.SUSPECT,
            ChannelSeverity.CONTAMINATED,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reason_code": self.reason_code,
            "severity": self.severity.value,
            "layer": self.layer.value,
            "detail": self.detail,
            "evidence": tuple(self.evidence),
        }


@dataclass(frozen=True)
class ChannelEnvelope:
    """
    Isolated input envelope from one LLM/agent channel.

    Channels are testimony only. They cannot grant permission and cannot
    execute. Agent proposals may be wrapped into CommandProposal for later
    audit, but that wrapper is still dry-run evidence.
    """

    channel_type: ChannelType
    source_id: str
    content: str
    branch_id: str
    envelope_id: str = "unknown_envelope"
    parent_event_id: str = ""
    user_request_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if isinstance(self.channel_type, str):
            object.__setattr__(self, "channel_type", ChannelType(self.channel_type))

        for field_name in ("source_id", "branch_id", "envelope_id"):
            value = getattr(self, field_name)
            if not str(value).strip():
                raise ValueError(f"{field_name} must be non-empty.")

        if not isinstance(self.content, str):
            raise ValueError("content must be a string.")

        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def can_execute(self) -> bool:
        return False

    @property
    def can_grant_permission(self) -> bool:
        return False

    @property
    def layer(self) -> AuditLayer:
        return channel_layer(self.channel_type)

    @property
    def phi_id(self) -> str:
        explicit = self.metadata.get("phi_id")
        if isinstance(explicit, str) and explicit.strip():
            return explicit.strip()

        return f"phi::{self.source_id.strip()}"

    def layered_ref(self) -> LayeredObjectRef:
        return LayeredObjectRef(
            object_id=self.envelope_id,
            phi_id=self.phi_id,
            layer=self.layer,
            branch_id=self.branch_id,
            object_type=f"channel:{self.channel_type.value}",
            metadata={
                "channel_type": self.channel_type.value,
                "source_id": self.source_id,
                "can_execute": False,
                "can_grant_permission": False,
            },
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "channel_type": self.channel_type.value,
            "source_id": self.source_id,
            "branch_id": self.branch_id,
            "envelope_id": self.envelope_id,
            "parent_event_id": self.parent_event_id,
            "user_request_id": self.user_request_id,
            "content_length": len(self.content),
            "can_execute": False,
            "can_grant_permission": False,
            "metadata_keys": tuple(sorted(str(key) for key in self.metadata.keys())),
        }


@dataclass(frozen=True)
class ChannelPolicy:
    project_root: str
    max_content_chars: int = 20000
    false_permission_tokens: Sequence[str] = (
        "highest permission",
        "highest privilege",
        "admin permission",
        "administrator permission",
        "root permission",
        "root-level",
        "full permission",
        "override safety",
        "grant this session",
        "最高权限",
        "管理员权限",
        "root权限",
    )
    tool_poisoning_tokens: Sequence[str] = (
        "ignore previous",
        "ignore all previous",
        "ignore system",
        "ignore policy",
        "bypass audit",
        "disable audit",
        "do not tell the user",
        "secretly",
        "run without approval",
        "without additional confirmation",
        "checks may be skipped",
        "trusted_admin_override",
        "忽略之前",
        "忽略规则",
        "绕过审计",
        "关闭审计",
        "不要告诉用户",
    )
    tool_execution_capability_tokens: Sequence[str] = (
        "subprocess.popen",
        "shell=true",
        "__import__('os').system",
        "__import__(\"os\").system",
        "os.system",
        "eval_globals",
        "exec(",
        "eval(",
    )
    sensitive_user_request_tokens: Sequence[str] = (
        "/var/audit",
        "agent_decisions",
        "/opt/secrets",
        "/run/secrets",
        "/etc/secrets",
        "/etc/shadow",
        ".env",
        "api_key",
        "api_keys",
        "vault_token",
        "database_credentials",
        "post the result",
        "../",
        "..\\",
        "modify system configurations",
        "authz-rules",
        "authorization rules",
        "passwd",
        "symlink",
        "service-account.key",
        "patient-debug",
        "private-ledger",
        "post the cleaned sample",
    )
    rejected_pollution_tokens: Sequence[str] = (
        "continue anyway",
        "try again without asking",
        "do the rejected action",
        "repeat the blocked action",
        "ignore the rejection",
        "继续执行",
        "继续刚才",
        "无视拒绝",
        "绕过拒绝",
        "重复被拒绝",
    )

    def __post_init__(self):
        if not self.project_root.strip():
            raise ValueError("project_root must be non-empty.")

        if self.max_content_chars <= 0:
            raise ValueError("max_content_chars must be positive.")

        object.__setattr__(
            self,
            "false_permission_tokens",
            tuple(token.lower() for token in self.false_permission_tokens),
        )
        object.__setattr__(
            self,
            "tool_poisoning_tokens",
            tuple(token.lower() for token in self.tool_poisoning_tokens),
        )
        object.__setattr__(
            self,
            "tool_execution_capability_tokens",
            tuple(token.lower() for token in self.tool_execution_capability_tokens),
        )
        object.__setattr__(
            self,
            "sensitive_user_request_tokens",
            tuple(token.lower() for token in self.sensitive_user_request_tokens),
        )
        object.__setattr__(
            self,
            "rejected_pollution_tokens",
            tuple(token.lower() for token in self.rejected_pollution_tokens),
        )


@dataclass(frozen=True)
class ChannelAuditResult:
    envelope: ChannelEnvelope
    disposition: ChannelDisposition
    layer_ref: LayeredObjectRef
    findings: Sequence[ChannelFinding]
    command_proposal: Optional[CommandProposal] = None

    def __post_init__(self):
        if isinstance(self.disposition, str):
            object.__setattr__(
                self,
                "disposition",
                ChannelDisposition(self.disposition),
            )

        object.__setattr__(self, "findings", tuple(self.findings))

    @property
    def can_execute(self) -> bool:
        return False

    @property
    def can_grant_permission(self) -> bool:
        return False

    @property
    def quarantined(self) -> bool:
        return self.disposition == ChannelDisposition.QUARANTINE

    @property
    def suspicious(self) -> bool:
        return any(finding.severity != ChannelSeverity.CLEAN for finding in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "envelope_id": self.envelope.envelope_id,
            "channel_type": self.envelope.channel_type.value,
            "disposition": self.disposition.value,
            "layer": self.layer_ref.layer.value,
            "branch_id": self.envelope.branch_id,
            "can_execute": False,
            "can_grant_permission": False,
            "quarantined": self.quarantined,
            "suspicious": self.suspicious,
            "finding_reason_codes": tuple(
                finding.reason_code for finding in self.findings
            ),
            "command_proposal_id": (
                self.command_proposal.proposal_id
                if self.command_proposal is not None
                else None
            ),
        }


def channel_layer(channel_type: ChannelType) -> AuditLayer:
    if isinstance(channel_type, str):
        channel_type = ChannelType(channel_type)

    mapping = {
        ChannelType.USER_REQUEST: AuditLayer.USER,
        ChannelType.TOOL_METADATA: AuditLayer.SOURCE,
        ChannelType.AGENT_PROPOSAL: AuditLayer.MOTION,
        ChannelType.REJECTED_FEEDBACK: AuditLayer.MOTION,
    }
    return mapping[channel_type]


def audit_channel_envelope(
    envelope: ChannelEnvelope,
    policy: ChannelPolicy,
) -> ChannelAuditResult:
    findings = list(_common_findings(envelope, policy))

    if envelope.channel_type == ChannelType.USER_REQUEST:
        findings.extend(_audit_user_request(envelope, policy))
    elif envelope.channel_type == ChannelType.TOOL_METADATA:
        findings.extend(_audit_tool_metadata(envelope, policy))
    elif envelope.channel_type == ChannelType.AGENT_PROPOSAL:
        findings.extend(_audit_agent_proposal(envelope, policy))
    elif envelope.channel_type == ChannelType.REJECTED_FEEDBACK:
        findings.extend(_audit_rejected_feedback(envelope, policy))

    disposition = _disposition_for(envelope.channel_type, findings)
    command_proposal = None
    if disposition == ChannelDisposition.WRAP_PROPOSAL:
        command_proposal = _wrap_agent_proposal(envelope, policy)

    return ChannelAuditResult(
        envelope=envelope,
        disposition=disposition,
        layer_ref=envelope.layered_ref(),
        findings=tuple(findings),
        command_proposal=command_proposal,
    )


def audit_channel_batch(
    envelopes: Sequence[ChannelEnvelope],
    policy: ChannelPolicy,
) -> Sequence[ChannelAuditResult]:
    contaminated_branches = set()
    results = []

    for envelope in envelopes:
        result = audit_channel_envelope(envelope, policy)
        if envelope.branch_id in contaminated_branches:
            result = apply_branch_contamination(result)

        if _has_contaminated_finding(result.findings):
            contaminated_branches.add(envelope.branch_id)

        results.append(result)

    return tuple(results)


def apply_branch_contamination(
    result: ChannelAuditResult,
) -> ChannelAuditResult:
    if any(
        finding.reason_code == "BRANCH_CONTAMINATION_INHERITED"
        for finding in result.findings
    ):
        return result

    finding = ChannelFinding(
        reason_code="BRANCH_CONTAMINATION_INHERITED",
        severity=ChannelSeverity.CONTAMINATED,
        layer=result.envelope.layer,
        detail="branch already contains quarantined channel material",
        evidence=(result.envelope.branch_id,),
    )
    return ChannelAuditResult(
        envelope=result.envelope,
        disposition=ChannelDisposition.QUARANTINE,
        layer_ref=result.layer_ref,
        findings=tuple(result.findings) + (finding,),
        command_proposal=None,
    )


def _common_findings(
    envelope: ChannelEnvelope,
    policy: ChannelPolicy,
) -> Sequence[ChannelFinding]:
    findings = []

    if len(envelope.content) > policy.max_content_chars:
        findings.append(
            ChannelFinding(
                reason_code="CHANNEL_CONTENT_TOO_LARGE",
                severity=ChannelSeverity.SUSPECT,
                layer=envelope.layer,
                detail="channel content exceeds configured maximum",
                evidence=(str(len(envelope.content)),),
            )
        )

    if _truthy_claim(envelope.metadata.get("can_execute")):
        findings.append(
            ChannelFinding(
                reason_code="CHANNEL_EXECUTION_CLAIM_STRIPPED",
                severity=ChannelSeverity.SUSPECT,
                layer=envelope.layer,
                detail="channel metadata claimed execution authority",
                evidence=("can_execute=True",),
            )
        )

    if _truthy_claim(envelope.metadata.get("can_grant_permission")):
        findings.append(
            ChannelFinding(
                reason_code="CHANNEL_PERMISSION_GRANT_CLAIM_STRIPPED",
                severity=ChannelSeverity.SUSPECT,
                layer=envelope.layer,
                detail="channel metadata claimed permission-grant authority",
                evidence=("can_grant_permission=True",),
            )
        )

    authority_claims = _metadata_authority_claims(envelope.metadata)
    if authority_claims:
        findings.append(
            ChannelFinding(
                reason_code="CHANNEL_AUTHORITY_METADATA_CLAIM",
                severity=ChannelSeverity.SUSPECT,
                layer=envelope.layer,
                detail="channel metadata contains authority-bearing claims",
                evidence=authority_claims,
            )
        )

    findings.extend(_metadata_boundary_risk_findings(envelope))
    findings.extend(_pass_road_findings(envelope, policy))

    return tuple(findings)


def _audit_user_request(
    envelope: ChannelEnvelope,
    policy: ChannelPolicy,
) -> Sequence[ChannelFinding]:
    findings = []
    hits = _unique_hits(
        _token_hits(envelope.content, policy.false_permission_tokens),
        _authority_content_hits(envelope.content),
    )
    if hits:
        findings.append(
            ChannelFinding(
                reason_code="FALSE_PERMISSION_CLAIM",
                severity=ChannelSeverity.SUSPECT,
                layer=AuditLayer.USER,
                detail="user request may express intent but cannot grant permission",
                evidence=hits,
            )
        )

    sensitive_hits = tuple(
        dict.fromkeys(
            _token_hits(envelope.content, policy.sensitive_user_request_tokens)
        )
    )
    if sensitive_hits:
        findings.append(
            ChannelFinding(
                reason_code="USER_REQUEST_SENSITIVE_TARGET",
                severity=ChannelSeverity.SUSPECT,
                layer=AuditLayer.USER,
                detail="user request names sensitive audit, secret, external, or traversal target",
                evidence=sensitive_hits,
            )
        )

    return tuple(findings)


def _audit_tool_metadata(
    envelope: ChannelEnvelope,
    policy: ChannelPolicy,
) -> Sequence[ChannelFinding]:
    findings = []
    hits = _token_hits(envelope.content, policy.tool_poisoning_tokens)
    permission_hits = _unique_hits(
        _token_hits(envelope.content, policy.false_permission_tokens),
        _authority_content_hits(envelope.content),
    )

    if hits:
        findings.append(
            ChannelFinding(
                reason_code="TOOL_METADATA_POISONING",
                severity=ChannelSeverity.CONTAMINATED,
                layer=AuditLayer.SOURCE,
                detail="tool metadata contains instruction-like policy bypass text",
                evidence=hits,
            )
        )

    capability_hits = _token_hits(
        envelope.content,
        policy.tool_execution_capability_tokens,
    )
    if capability_hits:
        findings.append(
            ChannelFinding(
                reason_code="TOOL_METADATA_EXECUTION_CAPABILITY",
                severity=ChannelSeverity.CONTAMINATED,
                layer=AuditLayer.SOURCE,
                detail="tool metadata exposes code execution capability",
                evidence=capability_hits,
            )
        )

    if permission_hits:
        findings.append(
            ChannelFinding(
                reason_code="TOOL_METADATA_PERMISSION_CLAIM",
                severity=ChannelSeverity.CONTAMINATED,
                layer=AuditLayer.SOURCE,
                detail="tool metadata cannot self-certify permission",
                evidence=permission_hits,
            )
        )

    return tuple(findings)


def _audit_agent_proposal(
    envelope: ChannelEnvelope,
    policy: ChannelPolicy,
) -> Sequence[ChannelFinding]:
    findings = []
    permission_hits = _unique_hits(
        _token_hits(envelope.content, policy.false_permission_tokens),
        _authority_content_hits(envelope.content),
    )
    if permission_hits:
        findings.append(
            ChannelFinding(
                reason_code="AGENT_PROPOSAL_PERMISSION_CLAIM",
                severity=ChannelSeverity.SUSPECT,
                layer=AuditLayer.MOTION,
                detail="agent proposal cannot grant itself permission",
                evidence=permission_hits,
            )
        )

    if not envelope.content.strip():
        findings.append(
            ChannelFinding(
                reason_code="EMPTY_AGENT_PROPOSAL",
                severity=ChannelSeverity.SUSPECT,
                layer=AuditLayer.MOTION,
                detail="agent proposal has no action body",
            )
        )

    if envelope.metadata.get("from_rejected_state") is True:
        findings.append(
            ChannelFinding(
                reason_code="AGENT_PROPOSAL_FROM_REJECTED_STATE",
                severity=ChannelSeverity.SUSPECT,
                layer=AuditLayer.MOTION,
                detail="agent proposal is linked to a rejected state",
            )
        )

    return tuple(findings)


def _audit_rejected_feedback(
    envelope: ChannelEnvelope,
    policy: ChannelPolicy,
) -> Sequence[ChannelFinding]:
    hits = _unique_hits(
        _token_hits(envelope.content, policy.rejected_pollution_tokens),
        _rejected_pollution_content_hits(envelope.content),
    )
    permission_hits = _unique_hits(
        _token_hits(envelope.content, policy.false_permission_tokens),
        _authority_content_hits(envelope.content),
    )
    findings = [
        ChannelFinding(
            reason_code="REJECTED_FEEDBACK_QUARANTINED",
            severity=ChannelSeverity.SUSPECT,
            layer=AuditLayer.MOTION,
            detail="rejected feedback is history evidence, not future authority",
        )
    ]

    if hits:
        findings.append(
            ChannelFinding(
                reason_code="REJECTED_STATE_POLLUTION",
                severity=ChannelSeverity.CONTAMINATED,
                layer=AuditLayer.MOTION,
                detail="rejected feedback attempts to revive blocked behavior",
                evidence=hits,
            )
        )

    if permission_hits:
        findings.append(
            ChannelFinding(
                reason_code="REJECTED_FEEDBACK_AUTHORITY_MUTATION",
                severity=ChannelSeverity.CONTAMINATED,
                layer=AuditLayer.MOTION,
                detail="rejected feedback cannot mutate future authority",
                evidence=permission_hits,
            )
        )

    return tuple(findings)


def _disposition_for(
    channel_type: ChannelType,
    findings: Sequence[ChannelFinding],
) -> ChannelDisposition:
    if any(finding.severity == ChannelSeverity.CONTAMINATED for finding in findings):
        return ChannelDisposition.QUARANTINE

    if channel_type == ChannelType.REJECTED_FEEDBACK:
        return ChannelDisposition.QUARANTINE

    if any(finding.blocks_wrapping for finding in findings):
        return ChannelDisposition.HOLD

    if channel_type == ChannelType.AGENT_PROPOSAL:
        return ChannelDisposition.WRAP_PROPOSAL

    return ChannelDisposition.ACCEPT


def _wrap_agent_proposal(
    envelope: ChannelEnvelope,
    policy: ChannelPolicy,
) -> CommandProposal:
    if envelope.channel_type != ChannelType.AGENT_PROPOSAL:
        raise ValueError("only AGENT_PROPOSAL envelopes can become CommandProposal.")

    cwd = _metadata_str(envelope, "cwd", policy.project_root)
    declared_scope = envelope.metadata.get("declared_scope", DeclaredScope.READ_ONLY)
    target_paths = _metadata_sequence(envelope.metadata.get("target_paths", ()))
    expected_side_effects = _metadata_side_effects(
        envelope.metadata.get("expected_side_effects", {SideEffect.READ})
    )

    return CommandProposal(
        command_text=envelope.content,
        actor_id=envelope.source_id,
        cwd=cwd,
        declared_scope=declared_scope,
        target_paths=target_paths,
        expected_side_effects=expected_side_effects,
        parent_event_id=envelope.parent_event_id,
        user_request_id=envelope.user_request_id,
        proposal_id=envelope.envelope_id,
        source_adapter=_metadata_str(envelope, "source_adapter", "channel"),
        tool_name=_metadata_str(envelope, "tool_name", ""),
        action_type=_metadata_str(envelope, "action_type", ""),
    )


def _metadata_str(
    envelope: ChannelEnvelope,
    key: str,
    default: str,
) -> str:
    value = envelope.metadata.get(key, default)
    if value is None:
        return default

    return str(value)


def _metadata_sequence(value: Any) -> Sequence[str]:
    if value is None:
        return ()

    if isinstance(value, str):
        return (value,)

    return tuple(str(item) for item in value)


def _metadata_side_effects(value: Any) -> Set[SideEffect]:
    if value is None:
        return {SideEffect.READ}

    if isinstance(value, (str, SideEffect)):
        value = (value,)

    return {
        effect if isinstance(effect, SideEffect) else SideEffect(effect)
        for effect in value
    }


PASS_ROAD_RECIPES: Mapping[str, frozenset[SideEffect]] = {
    "pass-road:daily-read-project:v1": frozenset({SideEffect.READ}),
    "pass-road:daily-report-write:v1": frozenset({SideEffect.READ, SideEffect.WRITE}),
    "pass-road:daily-data-transform:v1": frozenset({SideEffect.READ, SideEffect.WRITE}),
}
PASS_ROAD_REQUIRED_STEP_IDS = frozenset(
    {
        "declared_pass_road",
        "actor_bound",
        "known_command",
        "project_local_targets",
        "no_network",
        "no_secret",
        "no_protected_surface",
    }
)
PASS_ROAD_COMMAND_WORDS = frozenset(
    {
        "cat", "head", "tail", "grep", "rg", "ls", "dir", "find", "stat", "file",
        "wc", "sort", "uniq", "cut", "tr", "comm", "join", "paste", "column",
        "jq", "yq", "echo", "printf", "tee", "sed", "git",
        "get-content", "select-string", "set-content", "add-content", "out-file",
    }
)
PASS_ROAD_GIT_SUBCOMMANDS = frozenset({"status", "diff", "log", "show"})
PASS_ROAD_FORBIDDEN_COMMANDS = frozenset(
    {
        "python", "python2", "python3", "py", "pypy", "pypy3",
        "bash", "sh", "zsh", "pwsh", "powershell", "cmd",
        "node", "nodejs", "ruby", "perl", "php", "deno", "bun",
        "npm", "pnpm", "yarn", "pip", "pip3", "pipx", "uv", "poetry",
        "docker", "docker-compose", "kubectl", "ssh", "scp", "curl", "wget",
        "rm", "rmdir", "unlink", "shred", "remove-item", "git-clean",
    }
)
PASS_ROAD_OPERATORS = frozenset({"|", "||", "&&", ";", "&", "(", ")", "{", "}", "|&", "\n"})
PASS_ROAD_REDIRECTS = frozenset({">", ">>", "<", "2>", "2>>", "1>", "1>>"})
PASS_ROAD_WRAPPERS = frozenset({"env", "command", "builtin", "time", "timeout"})
PASS_ROAD_WRAPPER_VALUES = frozenset({"timeout"})
PASS_ROAD_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
PASS_ROAD_DYNAMIC_TOKENS = ("$(", "${", "`")
PASS_ROAD_NETWORK_TOKENS = (
    "http://",
    "https://",
    "curl",
    "wget",
    "invoke-webrequest",
    "invoke-restmethod",
    "iwr",
    "irm",
)
PASS_ROAD_SECRET_TOKENS = (
    ".env",
    ".ssh",
    "id_rsa",
    "id_ed25519",
    "api_key",
    "apikey",
    "secret",
    "token",
    "credential",
)
PASS_ROAD_PROTECTED_TOKENS = (
    ".claude/",
    ".claude\\",
    ".codex/",
    ".codex\\",
    ".phi/",
    ".phi\\",
    "pub_gate_switch.json",
    "capability_wall.py",
    "llm_channel.py",
    "parallel_audit.py",
    "protect_scan.py",
    "policy",
    "guardrail",
    "benchmark",
    "schema",
    "tool_schema",
)
PASS_ROAD_REPORT_ROOTS = ("reports", "outputs", ".pub_soak/reports", ".pub_soak/outputs")
PASS_ROAD_DATA_ROOTS = (
    "data",
    "reports",
    "outputs",
    ".pub_soak/data",
    ".pub_soak/reports",
    ".pub_soak/outputs",
)


def _pass_road_findings(
    envelope: ChannelEnvelope,
    policy: ChannelPolicy,
) -> Sequence[ChannelFinding]:
    raw_payload = _channel_raw_payload(envelope.metadata)
    declaration = raw_payload.get("pass_road")
    if declaration is None:
        return ()
    if not isinstance(declaration, Mapping):
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_DECLARATION_INVALID",
                ChannelSeverity.SUSPECT,
                "pass road declaration must be an object",
                (str(type(declaration).__name__),),
            ),
        )

    if not _truthy_claim(declaration.get("declared")):
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_DECLARATION_REQUIRED",
                ChannelSeverity.SUSPECT,
                "pass road must be explicitly declared before use",
            ),
        )

    recipe_id = _pass_road_recipe_id(declaration)
    if not recipe_id:
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_RECIPE_MISSING",
                ChannelSeverity.SUSPECT,
                "pass road declaration is missing recipe_id",
            ),
        )
    if recipe_id not in PASS_ROAD_RECIPES:
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_RECIPE_UNKNOWN",
                ChannelSeverity.SUSPECT,
                "pass road recipe is not registered in the channel eye",
                (recipe_id,),
            ),
        )

    actor_id = _pass_road_token(declaration.get("actor_id"))
    if not actor_id or actor_id != _pass_road_token(envelope.source_id):
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_ACTOR_MISMATCH",
                ChannelSeverity.SUSPECT,
                "pass road declaration must be bound to this channel actor",
                (actor_id or "missing", envelope.source_id),
            ),
        )

    skill_trace = _pass_road_skill_trace(raw_payload)
    if not skill_trace:
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_SKILL_TRACE_MISSING",
                ChannelSeverity.SUSPECT,
                "pass road declaration must be mirrored into skill_trace",
                (recipe_id,),
            ),
        )

    used_ids = _pass_road_values(skill_trace, "used_skill_ids", "skill_ids", "skill_id")
    if recipe_id not in used_ids:
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_SKILL_TRACE_MISMATCH",
                ChannelSeverity.SUSPECT,
                "pass road recipe_id must equal the used skill_id",
                (recipe_id, *sorted(used_ids)),
            ),
        )

    completed_steps = _pass_road_values(
        skill_trace,
        "completed_step_ids",
        "completed_steps",
        "step_ids",
    ) | _pass_road_values(
        declaration,
        "completed_step_ids",
        "completed_steps",
        "step_ids",
    )
    missing_steps = tuple(sorted(PASS_ROAD_REQUIRED_STEP_IDS - completed_steps))
    if missing_steps:
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_STEPS_INCOMPLETE",
                ChannelSeverity.SUSPECT,
                "pass road declaration is missing required daily-path steps",
                (recipe_id, *missing_steps),
            ),
        )

    command_issue = _pass_road_command_issue(envelope.content)
    if command_issue is not None:
        reason_code, evidence = command_issue
        return (
            _pass_road_finding(
                envelope,
                reason_code,
                ChannelSeverity.SUSPECT,
                "pass road only accepts transparent daily command surfaces",
                evidence,
            ),
        )

    effects = _metadata_side_effects(envelope.metadata.get("expected_side_effects"))
    unexpected_effects = tuple(
        sorted(
            effect.value
            for effect in effects
            if effect not in PASS_ROAD_RECIPES[recipe_id]
        )
    )
    if unexpected_effects:
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_SIDE_EFFECT_DENIED",
                ChannelSeverity.SUSPECT,
                "pass road recipe does not cover these side effects",
                unexpected_effects,
            ),
        )

    target_paths = tuple(_metadata_sequence(envelope.metadata.get("target_paths", ())))
    if SideEffect.WRITE in effects and not target_paths:
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_TARGETS_REQUIRED",
                ChannelSeverity.SUSPECT,
                "pass road writes require explicit target paths",
                (recipe_id,),
            ),
        )

    text = " ".join((envelope.content, *(str(path) for path in target_paths))).lower()
    if _contains_any_text(text, PASS_ROAD_NETWORK_TOKENS):
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_NETWORK_DENIED",
                ChannelSeverity.SUSPECT,
                "pass road cannot carry network movement",
                (recipe_id,),
            ),
        )
    if _contains_any_text(text, PASS_ROAD_SECRET_TOKENS):
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_SECRET_SURFACE",
                ChannelSeverity.SUSPECT,
                "pass road cannot touch secret-like surfaces",
                (recipe_id,),
            ),
        )

    protected = tuple(path for path in target_paths if _pass_road_protected(path))
    if protected:
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_PROTECTED_SURFACE",
                ChannelSeverity.SUSPECT,
                "pass road cannot touch policy, guardrail, or agent-control surfaces",
                protected,
            ),
        )

    outside = tuple(
        path for path in target_paths if not _pass_road_project_local(path, policy.project_root)
    )
    if outside:
        return (
            _pass_road_finding(
                envelope,
                "CHANNEL_PASS_ROAD_TARGET_OUTSIDE_PROJECT",
                ChannelSeverity.SUSPECT,
                "pass road targets must stay inside the project root",
                outside,
            ),
        )

    root_issue = _pass_road_recipe_root_issue(recipe_id, target_paths, policy.project_root)
    if root_issue is not None:
        reason_code, evidence = root_issue
        return (
            _pass_road_finding(
                envelope,
                reason_code,
                ChannelSeverity.SUSPECT,
                "pass road write target is outside the recipe output lane",
                evidence,
            ),
        )

    return (
        _pass_road_finding(
            envelope,
            "CHANNEL_PASS_ROAD_CLEAR",
            ChannelSeverity.CLEAN,
            "pass road recipe declaration is actor-bound and transparent",
            (recipe_id,),
        ),
    )


def _pass_road_finding(
    envelope: ChannelEnvelope,
    reason_code: str,
    severity: ChannelSeverity,
    detail: str,
    evidence: Sequence[str] = (),
) -> ChannelFinding:
    return ChannelFinding(
        reason_code=reason_code,
        severity=severity,
        layer=envelope.layer,
        detail=detail,
        evidence=tuple(str(item) for item in evidence),
    )


def _channel_raw_payload(metadata: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = metadata.get("raw_payload")
    return raw if isinstance(raw, Mapping) else {}


def _pass_road_recipe_id(declaration: Mapping[str, Any]) -> str:
    return _pass_road_token(declaration.get("recipe_id") or declaration.get("skill_id"))


def _pass_road_skill_trace(raw_payload: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("skill_trace", "skill_context"):
        value = raw_payload.get(key)
        if isinstance(value, Mapping):
            return value
    return {}


def _pass_road_values(source: Mapping[str, Any], *keys: str) -> set[str]:
    values: set[str] = set()
    for key in keys:
        value = source.get(key)
        if isinstance(value, Mapping):
            values.update(
                token
                for item_key, enabled in value.items()
                if enabled and (token := _pass_road_token(item_key))
            )
        elif isinstance(value, str):
            token = _pass_road_token(value)
            if token:
                values.add(token)
        elif value is not None:
            try:
                iterator = iter(value)
            except TypeError:
                token = _pass_road_token(value)
                if token:
                    values.add(token)
            else:
                values.update(
                    token for item in iterator if (token := _pass_road_token(item))
                )
    return values


def _pass_road_token(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _pass_road_command_issue(command_text: str) -> Optional[tuple[str, Sequence[str]]]:
    if _contains_any_text(command_text, PASS_ROAD_DYNAMIC_TOKENS):
        return "CHANNEL_PASS_ROAD_DYNAMIC_COMMAND", ("dynamic command expansion",)

    segments = _pass_road_command_segments(command_text)
    if not segments:
        return "CHANNEL_PASS_ROAD_COMMAND_MISSING", ("command",)

    for base, rest in segments:
        if base in PASS_ROAD_FORBIDDEN_COMMANDS or re.fullmatch(r"python\d+(?:\.\d+)?", base):
            return "CHANNEL_PASS_ROAD_OPAQUE_EXECUTION", (base,)
        if base not in PASS_ROAD_COMMAND_WORDS:
            return "CHANNEL_PASS_ROAD_UNKNOWN_COMMAND", (base,)
        if base == "git":
            subcommand = _pass_road_git_subcommand(rest)
            if subcommand not in PASS_ROAD_GIT_SUBCOMMANDS:
                return "CHANNEL_PASS_ROAD_GIT_MUTATION", (subcommand or "missing",)
        if base == "find" and any(str(item).lower() == "-delete" for item in rest):
            return "CHANNEL_PASS_ROAD_DELETE_DENIED", ("find -delete",)
    return None


def _pass_road_command_segments(command_text: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    try:
        tokens = shlex.split(command_text, posix=True)
    except ValueError:
        tokens = command_text.split()

    segments: list[tuple[str, tuple[str, ...]]] = []
    current: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in PASS_ROAD_REDIRECTS:
            skip_next = True
            continue
        if re.fullmatch(r"\d?>&?\d?", token) or re.match(r"^\d?>", token):
            continue
        if token in PASS_ROAD_OPERATORS:
            if current:
                segment = _pass_road_segment_head(current)
                if segment is not None:
                    segments.append(segment)
                current = []
            continue
        current.append(token)
    if current:
        segment = _pass_road_segment_head(current)
        if segment is not None:
            segments.append(segment)
    return tuple(segments)


def _pass_road_segment_head(segment: Sequence[str]) -> Optional[tuple[str, tuple[str, ...]]]:
    index = 0
    while index < len(segment):
        token = str(segment[index])
        base = _pass_road_basename(token)
        if not base or PASS_ROAD_ASSIGNMENT.match(token):
            index += 1
            continue
        if base in PASS_ROAD_WRAPPERS:
            index += 1
            if base in PASS_ROAD_WRAPPER_VALUES and index < len(segment):
                index += 1
            continue
        return base, tuple(str(item) for item in segment[index + 1 :])
    return None


def _pass_road_basename(token: str) -> str:
    text = str(token).strip().strip("'\"").replace("\\", "/")
    base = text.rsplit("/", 1)[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def _pass_road_git_subcommand(tokens: Sequence[str]) -> str:
    index = 0
    while index < len(tokens):
        token = str(tokens[index])
        if token == "-C":
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token.lower()
    return ""


def _pass_road_project_local(path: str, project_root: str) -> bool:
    text = str(path).strip()
    if not text or "://" in text:
        return False
    try:
        resolved = _pass_road_resolve(text, project_root)
        root = safe_resolve(Path(project_root))
    except Exception:
        return False
    return _pass_road_is_within(resolved, root)


def _pass_road_recipe_root_issue(
    recipe_id: str,
    target_paths: Sequence[str],
    project_root: str,
) -> Optional[tuple[str, Sequence[str]]]:
    if recipe_id == "pass-road:daily-read-project:v1":
        return None
    allowed_roots = (
        PASS_ROAD_REPORT_ROOTS
        if recipe_id == "pass-road:daily-report-write:v1"
        else PASS_ROAD_DATA_ROOTS
    )
    outside = tuple(
        path
        for path in target_paths
        if not any(_pass_road_under_relative_root(path, project_root, root) for root in allowed_roots)
    )
    if outside:
        return "CHANNEL_PASS_ROAD_OUTPUT_ROOT_DENIED", outside
    return None


def _pass_road_under_relative_root(path: str, project_root: str, relative_root: str) -> bool:
    try:
        resolved = _pass_road_resolve(path, project_root)
        root = safe_resolve(Path(project_root) / relative_root)
    except Exception:
        return False
    return _pass_road_is_within(resolved, root)


def _pass_road_resolve(path: str, project_root: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path(project_root) / candidate
    return safe_resolve(candidate)


def _pass_road_is_within(path: Path, root: Path) -> bool:
    path_text = normcase(normpath(str(path))).casefold()
    root_text = normcase(normpath(str(root))).rstrip("\\/").casefold()
    return path_text == root_text or path_text.startswith(root_text + "\\") or path_text.startswith(root_text + "/")


def _pass_road_protected(path: str) -> bool:
    text = str(path).replace("\\", "/").lower()
    return _contains_any_text(text, PASS_ROAD_PROTECTED_TOKENS)


def _contains_any_text(text: str, needles: Iterable[str]) -> bool:
    lowered = str(text).lower()
    return any(str(needle).lower() in lowered for needle in needles)


def infer_pass_road(
    command_text: str,
    target_paths: Sequence[str],
    project_root: str,
    *,
    has_write: bool,
) -> Optional[str]:
    """Inferred pass road (no declaration required).

    The DECLARED pass road (_pass_road_findings) needs an actor-sent declaration in
    raw_payload, which a Claude Code hook event cannot carry -- so on the cc path the
    declared road never evaluates. This applies the SAME recipe rules straight to the
    proposal: a transparent command surface (no dynamic expansion / no opaque or
    forbidden verb), project-local targets, no network/secret/protected surface, and
    -- for writes -- targets inside a recipe's output lane. Returns the matched
    recipe_id when the op is a clean transparent daily traversal, else None.

    POSITIVE signal only: being on the road grants extra trust (suppress noise, gate
    relax/auto-restore); being OFF it never adds danger -- the op simply gets no
    bonus and is judged by the wall as usual."""
    if _pass_road_command_issue(command_text) is not None:
        return None
    targets = [str(p) for p in target_paths if p and str(p).strip()]
    text = " ".join((command_text, *targets)).lower()
    if _contains_any_text(text, PASS_ROAD_NETWORK_TOKENS):
        return None
    if _contains_any_text(text, PASS_ROAD_SECRET_TOKENS):
        return None
    if any(_pass_road_protected(p) for p in targets):
        return None
    if any(not _pass_road_project_local(p, project_root) for p in targets):
        return None
    if not has_write:
        return "pass-road:daily-read-project:v1"
    if not targets:
        return None  # a write with no enumerable target cannot be lane-checked
    for recipe_id in (
        "pass-road:daily-report-write:v1",
        "pass-road:daily-data-transform:v1",
    ):
        if _pass_road_recipe_root_issue(recipe_id, targets, project_root) is None:
            return recipe_id
    return None


# Safe git mutation verbs that may ride the pass road OFF the OPAQUE wall, once
# .git's executable surface is write-protected (so no agent-planted hook can be
# triggered by the commit). Read-only git (status/diff/log/show) already passes.
PASS_ROAD_GIT_WRITE_SUBCOMMANDS = frozenset(
    {"add", "commit", "checkout", "switch", "branch", "stash", "restore", "tag", "merge"}
)
# NEVER ride the road even behind a safe-looking verb: history/ref destruction.
_GIT_WRITE_DANGER_FLAGS = frozenset({"--hard", "--force", "-f", "-D", "--delete"})

# `ln` is deliberately EXCLUDED: it is a B1 unmodeled mutator (link aliasing can
# overwrite a pub module / escape via an external target -- the A2 self-protection
# surface). It stays held by the OPAQUE wall (fail-closed, wall-first). Only archive
# verbs, whose only danger is reading/writing an EXTERNAL path (caught below), ride.
PASS_ROAD_ARCHIVE_VERBS = frozenset({"tar", "zip", "unzip", "gzip", "gunzip"})


def safe_in_project_archive_or_link(command_text: str, project_root: str) -> bool:
    """A single tar/zip archive whose EVERY path operand resolves INSIDE the project
    and touches no protected surface -- safe to let off the OPAQUE wall. Scope-gated,
    so it is safe even uncaged (the cage, when present, is the backstop). Dynamic
    expansion, command chaining, external paths (e.g. `tar ... /etc`), and protected
    surfaces (.git/.phi/.claude/secrets) all keep the command blocked. `ln` is NOT here
    -- link aliasing stays held by the wall (B1/A2 self-protection)."""
    if _contains_any_text(command_text, PASS_ROAD_DYNAMIC_TOKENS):
        return False
    segments = _pass_road_command_segments(command_text)
    if len(segments) != 1:  # no chaining / smuggled second command
        return False
    base, rest = segments[0]
    if base not in PASS_ROAD_ARCHIVE_VERBS:
        return False
    operands = [str(token) for token in rest if not str(token).startswith("-")]
    if not operands:
        return False
    for operand in operands:
        if _pass_road_protected(operand) or not _pass_road_project_local(operand, project_root):
            return False
    return True


def safe_git_write(command_text: str) -> bool:
    """A single, transparent git mutation verb safe to let off the OPAQUE wall.

    git-write is OPAQUE because git HOOKS execute arbitrary project code. With .git's
    executable surface write-protected (the agent cannot plant a hook), the user's own
    hooks running on the user's own commit is normal dev flow, not an escalation -- so
    these verbs are safe to relax. Dangerous git is NOT here and stays blocked:
    push/pull/fetch (network), reset --hard / clean (destruction), rebase / cherry-pick
    / apply / am (history/patch execution), and any --hard/--force/-f/-D/--delete flag."""
    if _contains_any_text(command_text, PASS_ROAD_DYNAMIC_TOKENS):
        return False
    segments = _pass_road_command_segments(command_text)
    if len(segments) != 1:  # no chaining / smuggled second command
        return False
    base, rest = segments[0]
    if base != "git":
        return False
    if _pass_road_git_subcommand(rest) not in PASS_ROAD_GIT_WRITE_SUBCOMMANDS:
        return False
    # Flags are case-sensitive in git (-D force-delete vs -d delete-merged), so do
    # NOT lowercase before matching the danger set.
    tokens = {str(token) for token in rest}
    return not (tokens & _GIT_WRITE_DANGER_FLAGS)


def _token_hits(content: str, tokens: Iterable[str]) -> Sequence[str]:
    text = _normalized_detection_text(content)
    return tuple(token for token in tokens if token and token in text)


def _unique_hits(*groups: Sequence[str]) -> Sequence[str]:
    return tuple(dict.fromkeys(hit for group in groups for hit in group))


def _has_contaminated_finding(findings: Sequence[ChannelFinding]) -> bool:
    return any(finding.severity == ChannelSeverity.CONTAMINATED for finding in findings)


def _normalized_detection_text(content: str) -> str:
    text = content.lower()
    translation = str.maketrans({
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
    })
    return text.translate(translation)


def _truthy_claim(value: Any) -> bool:
    if value is True:
        return True

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0

    if isinstance(value, str):
        return value.strip().lower() in {
            "1",
            "true",
            "yes",
            "y",
            "allow",
            "allowed",
            "approved",
            "enable",
            "enabled",
        }

    return False


def _metadata_authority_claims(metadata: Dict[str, Any]) -> Sequence[str]:
    evidence = []
    _walk_metadata_authority(metadata, path="metadata", evidence=evidence)
    return tuple(dict.fromkeys(evidence))


def _metadata_boundary_risk_findings(
    envelope: ChannelEnvelope,
) -> Sequence[ChannelFinding]:
    findings = []
    metadata = envelope.metadata

    path_values = tuple(
        str(path)
        for key in ("target_paths", "execution_paths")
        for path in _metadata_sequence(metadata.get(key, ()))
    )
    nul_paths = tuple(path for path in path_values if "\x00" in path)
    if nul_paths:
        findings.append(
            ChannelFinding(
                reason_code="CHANNEL_NULL_BYTE_PATH",
                severity=ChannelSeverity.SUSPECT,
                layer=envelope.layer,
                detail="channel metadata contains a null byte path boundary condition",
                evidence=nul_paths,
            )
        )

    execution_paths = _metadata_sequence(metadata.get("execution_paths", ()))
    if execution_paths or _truthy_claim(metadata.get("target_changes_between")):
        evidence = tuple(str(path) for path in execution_paths) or (
            "target_changes_between=True",
        )
        findings.append(
            ChannelFinding(
                reason_code="CHANNEL_EXECUTION_PATH_DIVERGENCE",
                severity=ChannelSeverity.SUSPECT,
                layer=envelope.layer,
                detail="channel metadata separates checked target paths from execution paths",
                evidence=evidence,
            )
        )

    capability_evidence = _metadata_capability_boundary_claims(metadata)
    if capability_evidence:
        findings.append(
            ChannelFinding(
                reason_code="CHANNEL_AMBIENT_CAPABILITY_CLAIM",
                severity=ChannelSeverity.SUSPECT,
                layer=envelope.layer,
                detail="channel metadata claims ambient, inherited, or delegated capability",
                evidence=capability_evidence,
            )
        )

    encoded_evidence = _metadata_encoded_payload_claims(metadata)
    if encoded_evidence:
        findings.append(
            ChannelFinding(
                reason_code="CHANNEL_ENCODED_OR_CONDITIONAL_PAYLOAD",
                severity=ChannelSeverity.SUSPECT,
                layer=envelope.layer,
                detail="channel metadata contains encoded, decoded, or conditional payload material",
                evidence=encoded_evidence,
            )
        )

    composition_evidence = _metadata_composition_claims(metadata)
    if composition_evidence:
        findings.append(
            ChannelFinding(
                reason_code="CHANNEL_MULTI_STEP_COMPOSITION",
                severity=ChannelSeverity.SUSPECT,
                layer=envelope.layer,
                detail="channel metadata requires multi-step or multi-channel composition audit",
                evidence=composition_evidence,
            )
        )

    return tuple(findings)


def _metadata_capability_boundary_claims(metadata: Dict[str, Any]) -> Sequence[str]:
    evidence = []
    _walk_metadata_capability(metadata, path="metadata", evidence=evidence)
    return tuple(dict.fromkeys(evidence))


def _metadata_encoded_payload_claims(metadata: Dict[str, Any]) -> Sequence[str]:
    evidence = []
    _walk_metadata_encoded_payload(metadata, path="metadata", evidence=evidence)
    return tuple(dict.fromkeys(evidence))


def _walk_metadata_encoded_payload(value: Any, *, path: str, evidence: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key_text}"

            if key_text in {
                "obfuscation",
                "encoded",
                "encoded_payload",
                "encoded_layer",
                "encoded_layer_1",
                "encoding_chain",
                "decode_steps",
                "decoder",
                "semantic_redirect",
                "trigger",
                "trigger_condition",
            }:
                evidence.append(f"{child_path}={_short_metadata_value(child)}")

            _walk_metadata_encoded_payload(child, path=child_path, evidence=evidence)
        return

    if isinstance(value, (list, tuple, set)):
        for index, child in enumerate(value):
            _walk_metadata_encoded_payload(child, path=f"{path}[{index}]", evidence=evidence)


def _metadata_composition_claims(metadata: Dict[str, Any]) -> Sequence[str]:
    evidence = []
    _walk_metadata_composition(metadata, path="metadata", evidence=evidence)
    return tuple(dict.fromkeys(evidence))


def _walk_metadata_composition(value: Any, *, path: str, evidence: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key_text}"

            if key_text in {
                "multi_hop",
                "multi_channel",
                "multi_channel_correlation_required",
                "composition_danger",
                "composition_rule",
                "semantic_preservation",
                "launder_type",
                "attack_chain",
            } and _truthy_or_nonempty(child):
                evidence.append(f"{child_path}={_short_metadata_value(child)}")

            _walk_metadata_composition(child, path=child_path, evidence=evidence)
        return

    if isinstance(value, (list, tuple, set)):
        for index, child in enumerate(value):
            _walk_metadata_composition(child, path=f"{path}[{index}]", evidence=evidence)


def _walk_metadata_capability(value: Any, *, path: str, evidence: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key_text}"

            if key_text in {
                "capabilities",
                "capability",
                "capability_source",
                "delegation_chain",
                "scope_check_target",
            }:
                if _value_contains_capability_boundary(child):
                    evidence.append(f"{child_path}={child}")

            if key_text == "inherited" and _truthy_claim(child):
                evidence.append(f"{child_path}={child}")

            _walk_metadata_capability(child, path=child_path, evidence=evidence)
        return

    if isinstance(value, (list, tuple, set)):
        for index, child in enumerate(value):
            _walk_metadata_capability(child, path=f"{path}[{index}]", evidence=evidence)


def _value_contains_capability_boundary(value: Any) -> bool:
    if isinstance(value, dict):
        nested = []
        _walk_metadata_capability(value, path="value", evidence=nested)
        return bool(nested)

    if isinstance(value, (list, tuple, set)):
        return any(_value_contains_capability_boundary(item) for item in value)

    if isinstance(value, str):
        text = _normalized_detection_text(value)
        return any(
            marker in text
            for marker in (
                "cap_",
                "ambient",
                "delegate",
                "delegation",
                "capability",
                "scope",
                "agent_",
            )
        )

    return bool(value)


def _truthy_or_nonempty(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())

    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)

    return _truthy_claim(value)


def _short_metadata_value(value: Any) -> str:
    text = str(value)
    if len(text) > 120:
        return text[:117] + "..."
    return text


def _walk_metadata_authority(value: Any, *, path: str, evidence: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key_text}"

            if key_text in {
                "can_execute",
                "execute",
                "io_executed",
                "can_grant_permission",
            } and _truthy_claim(child):
                evidence.append(f"{child_path}={child}")

            if key_text in {
                "authority",
                "authorization",
                "permission",
                "permissions",
                "permission_level",
                "approved",
                "approval",
                "trust_level",
                "role",
            } and _value_contains_authority(child):
                evidence.append(f"{child_path}={child}")

            _walk_metadata_authority(child, path=child_path, evidence=evidence)
        return

    if isinstance(value, (list, tuple, set)):
        for index, child in enumerate(value):
            _walk_metadata_authority(child, path=f"{path}[{index}]", evidence=evidence)


def _value_contains_authority(value: Any) -> bool:
    if _truthy_claim(value):
        return True

    if isinstance(value, dict):
        nested = []
        _walk_metadata_authority(value, path="value", evidence=nested)
        return bool(nested)

    if isinstance(value, (list, tuple, set)):
        return any(_value_contains_authority(item) for item in value)

    if isinstance(value, str):
        text = _normalized_detection_text(value)
        return any(
            marker in text
            for marker in (
                "admin",
                "administrator",
                "root",
                "highest",
                "critical",
                "p4",
                "approved",
                "permission",
                "execute",
                "trusted",
            )
        )

    return False


def _authority_content_hits(content: str) -> Sequence[str]:
    text = _normalized_detection_text(content)
    hits = []

    markers = (
        "can_execute",
        "can grant permission",
        "can_grant_permission",
        "io_executed",
        "permission_level",
        "trusted_admin_override",
        "approval=inherited",
        "approval inherited",
        "approved by policy",
        "approved authority",
        "grant write access",
        "you may run admin commands",
    )
    for marker in markers:
        if marker in text:
            hits.append(marker)

    if "permission" in text and any(
        marker in text for marker in ("admin", "root", "highest", "critical", "p4")
    ):
        hits.append("permission+authority")

    if "authorization" in text and any(
        marker in text for marker in ("admin", "root", "execute", "true", "approved")
    ):
        hits.append("authorization+authority")

    return tuple(dict.fromkeys(hits))


def _rejected_pollution_content_hits(content: str) -> Sequence[str]:
    text = _normalized_detection_text(content)
    hits = []
    markers = (
        "block is obsolete",
        "rejection is obsolete",
        "previous action",
        "was rejected",
        "previously rejected",
        "rephrasing proposal",
        "instead, just run",
        "proceed with the same operation",
        "same operation under approved authority",
        "mark permission as granted",
        "permission conflict",
        "construct compliant bypass",
        "rejection context",
        "full prompt history",
        "prior rejection is obsolete",
    )
    for marker in markers:
        if marker in text:
            hits.append(marker)

    return tuple(hits)
