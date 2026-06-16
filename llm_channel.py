from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Optional, Sequence, Set

from audit_layer import AuditLayer, LayeredObjectRef
from ot_gate import CommandProposal, DeclaredScope, SideEffect


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
