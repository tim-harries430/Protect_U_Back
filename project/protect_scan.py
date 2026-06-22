from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from enum import Enum
from os.path import normcase, normpath
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence, Set
from urllib.parse import urlparse

from agent_control_surface import is_agent_control_surface_path
from ot_gate import CommandProposal, SideEffect
from probe_authority_surface import (
    internal_probe_path_evidence,
    is_internal_probe_artifact_path,
    probe_authority_text_evidence,
)
from safe_path import safe_resolve


class ProtectSurface(str, Enum):
    SANDBOX_BOUNDARY = "SANDBOX_BOUNDARY"
    GATEWAY_EXPOSURE = "GATEWAY_EXPOSURE"
    CORE_PHI = "CORE_PHI"
    REGISTRY = "REGISTRY"
    LEDGER = "LEDGER"
    AUDIT_STORE = "AUDIT_STORE"
    PERMISSION_SURFACE = "PERMISSION_SURFACE"
    SECRET_FILES = "SECRET_FILES"
    CREDENTIAL_FILES = "CREDENTIAL_FILES"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    NETWORK_EXFIL = "NETWORK_EXFIL"
    DEV_FOLDERS = "DEV_FOLDERS"
    PERSONAL_DOCUMENTS = "PERSONAL_DOCUMENTS"
    BROWSER_PROFILE = "BROWSER_PROFILE"
    EMAIL_CACHE = "EMAIL_CACHE"
    CUSTOM_PATHS = "CUSTOM_PATHS"


class ProtectScanDisposition(str, Enum):
    PASS = "PASS"
    HOLD = "HOLD"
    KILL = "KILL"


class ProtectScanSeverity(str, Enum):
    INFO = "INFO"
    HOLD = "HOLD"
    KILL = "KILL"


REQUIRED_SURFACES = frozenset(
    {
        ProtectSurface.SANDBOX_BOUNDARY,
        ProtectSurface.GATEWAY_EXPOSURE,
        ProtectSurface.CORE_PHI,
        ProtectSurface.REGISTRY,
        ProtectSurface.LEDGER,
        ProtectSurface.AUDIT_STORE,
        ProtectSurface.PERMISSION_SURFACE,
        ProtectSurface.PATH_TRAVERSAL,
        ProtectSurface.NETWORK_EXFIL,
    }
)

DEFAULT_ENABLED_SURFACES = frozenset(
    {
        *REQUIRED_SURFACES,
        ProtectSurface.SECRET_FILES,
        ProtectSurface.CREDENTIAL_FILES,
    }
)

OPTIONAL_PERSONAL_SURFACES = frozenset(
    {
        ProtectSurface.DEV_FOLDERS,
        ProtectSurface.PERSONAL_DOCUMENTS,
        ProtectSurface.BROWSER_PROFILE,
        ProtectSurface.EMAIL_CACHE,
        ProtectSurface.CUSTOM_PATHS,
    }
)

PHI_TOKENS = (
    ".phi\\",
    ".phi/",
)
REGISTRY_TOKENS = (
    ".phi\\registry",
    ".phi/registry",
    "phi_registry",
    "actors.json",
)
LEDGER_TOKENS = (
    ".phi\\ledger",
    ".phi/ledger",
    "event_ledger",
    "events.jsonl",
)
AUDIT_TOKENS = (
    ".claude\\",
    ".claude/",
    ".codex\\",
    ".codex/",
    "pub_gate_switch.json",
    "audit_layer.py",
    "autopsy_report.py",
    "capability_wall.py",
    "llm_channel.py",
    "ot_gate.py",
    "adapter_wall.py",
    "task_guard.py",
    "patch_audit.py",
    "protect_scan.py",
)
PERMISSION_TOKENS = (
    "scope.yaml",
    "agent-permissions",
    "allowed_roles",
    "can_grant_permission",
    "grant_admin",
    "role': 'admin",
    '"role": "admin',
    "root-level",
    "root level",
    "runas",
    "-verb runas",
    "set-executionpolicy",
)
SECRET_TOKENS = (
    ".env",
    ".codex",
    "/secrets",
    "\\secrets",
    "api_key",
    "apikey",
    "vault_token",
    "password",
    "credential",
    "credentials",
    "prod-creds",
)
PASSWORD_PROTECTIVE_TOKENS = (
    "do not enter password",
    "do not enter passwords",
    "don't enter password",
    "don't enter passwords",
    "dont enter password",
    "dont enter passwords",
    "not to enter password",
    "not to enter passwords",
    "avoid entering password",
    "avoid entering passwords",
    "never enter password",
    "never enter passwords",
)
PASSWORD_HANDLING_TOKENS = (
    "save password",
    "save passwords",
    "store password",
    "store passwords",
    "write password",
    "write passwords",
    "create password",
    "create passwords",
    "set password",
    "set passwords",
    "change password",
    "change passwords",
    "reset password",
    "reset passwords",
    "read password",
    "read passwords",
    "copy password",
    "copy passwords",
    "show password",
    "show passwords",
    "output password",
    "output passwords",
    "send password",
    "send passwords",
    "post password",
    "post passwords",
    "manage password",
    "manage passwords",
)
CREDENTIAL_TOKENS = (
    ".ssh",
    "id_rsa",
    "id_ed25519",
    "service-account.key",
    "private_key",
    "token.txt",
)
NETWORK_TOKENS = (
    "http://",
    "https://",
    "curl",
    "wget",
    "invoke-webrequest",
    "invoke-restmethod",
    "iwr",
    "irm",
    "post ",
    " -x post",
)
BROWSER_TOKENS = (
    "chrome\\user data",
    "chrome/user data",
    "edge\\user data",
    "edge/user data",
    "firefox\\profiles",
    "firefox/profiles",
    "browser profile",
)
EMAIL_TOKENS = (
    "outlook",
    "thunderbird",
    "mail cache",
    "email cache",
    "gmail",
)
PERSONAL_DOCUMENT_TOKENS = (
    "\\desktop",
    "/desktop",
    "\\documents",
    "/documents",
    "\\downloads",
    "/downloads",
)
DEV_FOLDER_TOKENS = (
    "c:\\dev",
    "c:/dev",
    "d:\\dev",
    "d:/dev",
)


@dataclass(frozen=True)
class ProtectScanProfile:
    """
    User-visible protection profile.

    This profile is metadata-only. It describes which surfaces Protect Scan
    watches before I/O. It does not open files, scan disk contents, execute
    commands, or send network requests.
    """

    profile_id: str
    project_roots: Sequence[str]
    enabled_surfaces: Set[ProtectSurface] = field(default_factory=set)
    custom_paths: Sequence[str] = field(default_factory=tuple)
    confirmed: bool = False
    require_startup_confirmation: bool = True

    def __post_init__(self):
        if not self.profile_id.strip():
            raise ValueError("profile_id must be non-empty.")

        if not self.project_roots:
            raise ValueError("project_roots must be non-empty.")

        surfaces = {
            surface if isinstance(surface, ProtectSurface) else ProtectSurface(surface)
            for surface in self.enabled_surfaces
        }
        if self.custom_paths:
            surfaces.add(ProtectSurface.CUSTOM_PATHS)

        missing = REQUIRED_SURFACES - surfaces
        if missing:
            names = ", ".join(sorted(surface.value for surface in missing))
            raise ValueError(f"required protect surfaces cannot be disabled: {names}")

        object.__setattr__(self, "enabled_surfaces", frozenset(surfaces))
        object.__setattr__(
            self,
            "project_roots",
            tuple(str(root) for root in self.project_roots),
        )
        object.__setattr__(
            self,
            "custom_paths",
            tuple(str(path) for path in self.custom_paths),
        )

    @property
    def can_execute(self) -> bool:
        return False

    @property
    def can_grant_permission(self) -> bool:
        return False

    def resolved_project_roots(self) -> Sequence[Path]:
        return tuple(Path(root).resolve(strict=False) for root in self.project_roots)

    def resolved_custom_paths(self) -> Sequence[Path]:
        return tuple(Path(path).resolve(strict=False) for path in self.custom_paths)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "project_roots": tuple(self.project_roots),
            "enabled_surfaces": tuple(
                sorted(surface.value for surface in self.enabled_surfaces)
            ),
            "custom_paths": tuple(self.custom_paths),
            "confirmed": self.confirmed,
            "require_startup_confirmation": self.require_startup_confirmation,
            "can_execute": False,
            "can_grant_permission": False,
        }


@dataclass(frozen=True)
class ProtectScanNotice:
    profile_id: str
    enabled_lines: Sequence[str]
    disabled_lines: Sequence[str]
    custom_path_lines: Sequence[str]
    warning_lines: Sequence[str]
    confirmation_required: bool
    confirmed: bool

    def __post_init__(self):
        object.__setattr__(self, "enabled_lines", tuple(self.enabled_lines))
        object.__setattr__(self, "disabled_lines", tuple(self.disabled_lines))
        object.__setattr__(self, "custom_path_lines", tuple(self.custom_path_lines))
        object.__setattr__(self, "warning_lines", tuple(self.warning_lines))

    def render(self) -> str:
        lines = [
            "Protect U Back will protect:",
            "",
            *self.enabled_lines,
            *self.disabled_lines,
            *self.custom_path_lines,
            "",
            *self.warning_lines,
        ]
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "enabled_lines": tuple(self.enabled_lines),
            "disabled_lines": tuple(self.disabled_lines),
            "custom_path_lines": tuple(self.custom_path_lines),
            "warning_lines": tuple(self.warning_lines),
            "confirmation_required": self.confirmation_required,
            "confirmed": self.confirmed,
        }


@dataclass(frozen=True)
class ProtectScanFinding:
    surface: ProtectSurface
    severity: ProtectScanSeverity
    reason_code: str
    detail: str
    evidence: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self):
        if isinstance(self.surface, str):
            object.__setattr__(self, "surface", ProtectSurface(self.surface))

        if isinstance(self.severity, str):
            object.__setattr__(self, "severity", ProtectScanSeverity(self.severity))

        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "surface": self.surface.value,
            "severity": self.severity.value,
            "reason_code": self.reason_code,
            "detail": self.detail,
            "evidence": tuple(self.evidence),
        }


@dataclass(frozen=True)
class ProtectScanDecision:
    disposition: ProtectScanDisposition
    reason_code: str
    profile_id: str
    startup_confirmed: bool
    matched_surfaces: Sequence[ProtectSurface] = field(default_factory=tuple)
    findings: Sequence[ProtectScanFinding] = field(default_factory=tuple)
    io_executed: bool = False
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self):
        if isinstance(self.disposition, str):
            object.__setattr__(
                self,
                "disposition",
                ProtectScanDisposition(self.disposition),
            )

        object.__setattr__(
            self,
            "matched_surfaces",
            tuple(
                surface if isinstance(surface, ProtectSurface) else ProtectSurface(surface)
                for surface in self.matched_surfaces
            ),
        )
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "io_executed", False)
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "profile_id": self.profile_id,
            "startup_confirmed": self.startup_confirmed,
            "matched_surfaces": tuple(surface.value for surface in self.matched_surfaces),
            "findings": tuple(finding.to_dict() for finding in self.findings),
            "io_executed": False,
            "can_execute": False,
            "can_grant_permission": False,
        }


def default_protect_scan_profile(
    project_root: str,
    *,
    profile_id: str = "default_strict_v1",
    confirmed: bool = False,
    optional_surfaces: Iterable[ProtectSurface | str] = (),
    custom_paths: Sequence[str] = (),
) -> ProtectScanProfile:
    optional = {
        surface if isinstance(surface, ProtectSurface) else ProtectSurface(surface)
        for surface in optional_surfaces
    }
    return ProtectScanProfile(
        profile_id=profile_id,
        project_roots=(project_root,),
        enabled_surfaces=set(DEFAULT_ENABLED_SURFACES | optional),
        custom_paths=tuple(custom_paths),
        confirmed=confirmed,
        require_startup_confirmation=True,
    )


def confirm_protect_scan(
    profile: ProtectScanProfile,
    *,
    confirmed: bool,
) -> ProtectScanProfile:
    return replace(profile, confirmed=bool(confirmed))


def build_startup_notice(profile: ProtectScanProfile) -> ProtectScanNotice:
    enabled_lines = tuple(
        f"[ON] {_surface_label(surface)}"
        for surface in _notice_surface_order()
        if surface in profile.enabled_surfaces and surface != ProtectSurface.CUSTOM_PATHS
    )
    disabled_lines = tuple(
        f"[OFF] {_surface_label(surface)}"
        for surface in _notice_surface_order()
        if surface not in profile.enabled_surfaces
        and surface in OPTIONAL_PERSONAL_SURFACES
        and surface != ProtectSurface.CUSTOM_PATHS
    )
    custom_path_lines = tuple(f"[Custom] {path}" for path in profile.custom_paths)
    warning_lines = (
        "Mode: metadata-only pre-I/O scan.",
        "No files are opened during Protect Scan.",
        "No disk contents are scanned during Protect Scan.",
        "No network request is made during Protect Scan.",
    )
    return ProtectScanNotice(
        profile_id=profile.profile_id,
        enabled_lines=enabled_lines,
        disabled_lines=disabled_lines,
        custom_path_lines=custom_path_lines,
        warning_lines=warning_lines,
        confirmation_required=profile.require_startup_confirmation,
        confirmed=profile.confirmed,
    )


def audit_protect_scan(
    proposal: CommandProposal,
    profile: ProtectScanProfile,
) -> ProtectScanDecision:
    if profile.require_startup_confirmation and not profile.confirmed:
        return ProtectScanDecision(
            disposition=ProtectScanDisposition.HOLD,
            reason_code="PROTECT_SCAN_STARTUP_CONFIRMATION_REQUIRED",
            profile_id=profile.profile_id,
            startup_confirmed=False,
            findings=(
                ProtectScanFinding(
                    surface=ProtectSurface.CORE_PHI,
                    severity=ProtectScanSeverity.HOLD,
                    reason_code="PROTECT_SCAN_STARTUP_CONFIRMATION_REQUIRED",
                    detail="user must confirm Protect Scan profile before audit proceeds",
                    evidence=(profile.profile_id,),
                ),
            ),
        )

    findings = tuple(_findings_for(proposal, profile))
    if not findings:
        return ProtectScanDecision(
            disposition=ProtectScanDisposition.PASS,
            reason_code="PROTECT_SCAN_PASS",
            profile_id=profile.profile_id,
            startup_confirmed=profile.confirmed,
        )

    if any(finding.severity == ProtectScanSeverity.KILL for finding in findings):
        reason = _primary_reason(findings, ProtectScanSeverity.KILL)
        disposition = ProtectScanDisposition.KILL
    else:
        reason = _primary_reason(findings, ProtectScanSeverity.HOLD)
        disposition = ProtectScanDisposition.HOLD

    return ProtectScanDecision(
        disposition=disposition,
        reason_code=reason,
        profile_id=profile.profile_id,
        startup_confirmed=profile.confirmed,
        matched_surfaces=tuple(finding.surface for finding in findings),
        findings=findings,
    )


def _findings_for(
    proposal: CommandProposal,
    profile: ProtectScanProfile,
) -> Sequence[ProtectScanFinding]:
    text = _combined_text(proposal)
    optional_text = _optional_surface_text(proposal, profile)
    effects = _inferred_effects(proposal)
    paths = _resolved_targets(proposal)
    findings = []

    # A2 fix: PUB internal modules protected by DIRECTORY MEMBERSHIP, not a
    # hand-maintained filename list (which silently missed transition_xray,
    # xray_*, temporal_continuity, opaque_executor, safe_path, the hooks).
    # No write/delete/privilege/audit mutation may be passed to any .py under
    # the PUB install root. Anchored on __file__ -- guards PUB itself no matter
    # which external project is audited; internal, never an external file.
    _pub_internal_root = Path(__file__).resolve().parent
    internal_mutation = tuple(
        str(path)
        for path in paths
        if str(path).lower().endswith(".py") and _is_within(path, _pub_internal_root)
    )
    if internal_mutation and effects & {
        SideEffect.WRITE,
        SideEffect.DELETE,
        SideEffect.PRIVILEGE,
        SideEffect.AUDIT_CHANGE,
    }:
        findings.append(
            _finding(
                ProtectSurface.AUDIT_STORE,
                ProtectScanSeverity.KILL,
                "PROTECT_PUB_INTERNAL_MUTATION_DENIED",
                "no write may be passed to a Protect U Back internal module",
                internal_mutation,
            )
        )

    if effects & {
        SideEffect.WRITE,
        SideEffect.DELETE,
        SideEffect.PRIVILEGE,
        SideEffect.AUDIT_CHANGE,
    }:
        probe_targets = tuple(
            str(path)
            for path in paths
            if is_internal_probe_artifact_path(
                path,
                project_roots=profile.project_roots,
            )
        )
        probe_text_evidence = probe_authority_text_evidence(proposal.command_text)
        if probe_targets or probe_text_evidence:
            path_evidence = tuple(
                item
                for path in probe_targets
                for item in internal_probe_path_evidence(path)
            )
            findings.append(
                _finding(
                    ProtectSurface.AUDIT_STORE,
                    ProtectScanSeverity.KILL,
                    "PROTECT_PROBE_MINT_UNAUTHORIZED",
                    "agent may not mint PUB internal probe or authority artifacts",
                    tuple(
                        dict.fromkeys(
                            (
                                "probe_authority_egress",
                                *probe_targets,
                                *path_evidence,
                                *probe_text_evidence,
                            )
                        )
                    ),
                )
            )

    if ProtectSurface.SANDBOX_BOUNDARY in profile.enabled_surfaces:
        findings.extend(_sandbox_findings(proposal, effects))

    if ProtectSurface.GATEWAY_EXPOSURE in profile.enabled_surfaces:
        findings.extend(_gateway_findings(proposal))

    unresolved_targets = tuple(
        str(target) for target in proposal.target_paths if "\x00" in str(target)
    )
    if unresolved_targets:
        findings.append(
            _finding(
                ProtectSurface.PATH_TRAVERSAL,
                ProtectScanSeverity.HOLD,
                "PROTECT_TARGET_UNRESOLVED",
                "proposal target cannot be resolved reliably before I/O",
                unresolved_targets,
            )
        )
        return tuple(findings)

    if ProtectSurface.PATH_TRAVERSAL in profile.enabled_surfaces:
        traversal_targets = tuple(
            target for target in proposal.target_paths if _has_path_traversal(str(target))
        )
        if traversal_targets:
            findings.append(
                _finding(
                    ProtectSurface.PATH_TRAVERSAL,
                    _severity_for_effects(effects),
                    "PROTECT_PATH_TRAVERSAL_DETECTED",
                    "proposal contains path traversal before I/O",
                    traversal_targets,
                )
            )

    if ProtectSurface.CORE_PHI in profile.enabled_surfaces and _matches_surface(
        text,
        paths,
        profile.resolved_project_roots(),
        PHI_TOKENS,
        phi_subdir=None,
    ):
        findings.append(
            _finding(
                ProtectSurface.CORE_PHI,
                _severity_for_effects(effects),
                _write_or_read_reason(
                    effects,
                    "PROTECT_CORE_PHI_MUTATION_DENIED",
                    "PROTECT_CORE_PHI_READ_REQUIRES_CONFIRMATION",
                ),
                "proposal touches Protect U Back control space",
                _surface_evidence(text, paths, PHI_TOKENS),
            )
        )

    if ProtectSurface.REGISTRY in profile.enabled_surfaces and _matches_surface(
        text,
        paths,
        profile.resolved_project_roots(),
        REGISTRY_TOKENS,
        phi_subdir="registry",
    ):
        findings.append(
            _finding(
                ProtectSurface.REGISTRY,
                ProtectScanSeverity.KILL,
                "PROTECT_REGISTRY_ACCESS_DENIED",
                "proposal touches Phi Registry control surface",
                _surface_evidence(text, paths, REGISTRY_TOKENS),
            )
        )

    if ProtectSurface.LEDGER in profile.enabled_surfaces and _matches_surface(
        text,
        paths,
        profile.resolved_project_roots(),
        LEDGER_TOKENS,
        phi_subdir="ledger",
    ):
        findings.append(
            _finding(
                ProtectSurface.LEDGER,
                _severity_for_effects(effects),
                _write_or_read_reason(
                    effects,
                    "PROTECT_LEDGER_MUTATION_DENIED",
                    "PROTECT_LEDGER_READ_REQUIRES_CONFIRMATION",
                ),
                "proposal touches Phi Ledger control surface",
                _surface_evidence(text, paths, LEDGER_TOKENS),
            )
        )

    agent_control_evidence = tuple(
        str(path)
        for path in paths
        if is_agent_control_surface_path(path, project_roots=profile.project_roots)
    )
    if ProtectSurface.AUDIT_STORE in profile.enabled_surfaces and (
        agent_control_evidence or _contains_any(text, AUDIT_TOKENS)
    ):
        findings.append(
            _finding(
                ProtectSurface.AUDIT_STORE,
                _severity_for_effects(effects),
                _write_or_read_reason(
                    effects,
                    "PROTECT_AUDIT_SURFACE_MUTATION_DENIED",
                    "PROTECT_AUDIT_SURFACE_REQUIRES_CONFIRMATION",
                ),
                "proposal touches audit implementation, storage, or agent control surface",
                tuple(dict.fromkeys(agent_control_evidence + _token_evidence(text, AUDIT_TOKENS))),
            )
        )

    if ProtectSurface.PERMISSION_SURFACE in profile.enabled_surfaces and _contains_any(
        text,
        PERMISSION_TOKENS,
    ):
        findings.append(
            _finding(
                ProtectSurface.PERMISSION_SURFACE,
                ProtectScanSeverity.KILL,
                "PROTECT_PERMISSION_SURFACE_MUTATION_DENIED",
                "proposal touches permission or authority surface",
                _token_evidence(text, PERMISSION_TOKENS),
            )
        )

    secret_evidence = _secret_evidence(text)
    credential_evidence = _token_evidence(text, CREDENTIAL_TOKENS)

    if ProtectSurface.SECRET_FILES in profile.enabled_surfaces and secret_evidence:
        findings.append(
            _finding(
                ProtectSurface.SECRET_FILES,
                ProtectScanSeverity.KILL,
                "PROTECT_SECRET_SURFACE_DENIED",
                "proposal touches secret-bearing material",
                secret_evidence,
            )
        )

    if ProtectSurface.CREDENTIAL_FILES in profile.enabled_surfaces and credential_evidence:
        findings.append(
            _finding(
                ProtectSurface.CREDENTIAL_FILES,
                ProtectScanSeverity.KILL,
                "PROTECT_CREDENTIAL_SURFACE_DENIED",
                "proposal touches credential-bearing material",
                credential_evidence,
            )
        )

    if ProtectSurface.NETWORK_EXFIL in profile.enabled_surfaces and _network_present(
        proposal,
        text,
        effects,
    ):
        if secret_evidence or credential_evidence:
            findings.append(
                _finding(
                    ProtectSurface.NETWORK_EXFIL,
                    ProtectScanSeverity.KILL,
                    "PROTECT_NETWORK_EXFIL_DENIED",
                    "proposal combines network movement with secret-like evidence",
                    tuple(_network_evidence(proposal, text))
                    + tuple(secret_evidence)
                    + tuple(credential_evidence),
                )
            )
        else:
            findings.append(
                _finding(
                    ProtectSurface.NETWORK_EXFIL,
                    ProtectScanSeverity.HOLD,
                    "PROTECT_NETWORK_REQUIRES_CONFIRMATION",
                    "proposal contains network movement before I/O",
                    _network_evidence(proposal, text),
                )
            )

    if ProtectSurface.BROWSER_PROFILE in profile.enabled_surfaces and _contains_any(
        optional_text,
        BROWSER_TOKENS,
    ):
        findings.append(
            _finding(
                ProtectSurface.BROWSER_PROFILE,
                _severity_for_effects(effects),
                _write_or_read_reason(
                    effects,
                    "PROTECT_BROWSER_PROFILE_MUTATION_DENIED",
                    "PROTECT_BROWSER_PROFILE_REQUIRES_CONFIRMATION",
                ),
                "proposal touches browser profile surface explicitly enabled by user",
                _token_evidence(optional_text, BROWSER_TOKENS),
            )
        )

    if ProtectSurface.EMAIL_CACHE in profile.enabled_surfaces and _contains_any(
        optional_text,
        EMAIL_TOKENS,
    ):
        findings.append(
            _finding(
                ProtectSurface.EMAIL_CACHE,
                _severity_for_effects(effects),
                _write_or_read_reason(
                    effects,
                    "PROTECT_EMAIL_CACHE_MUTATION_DENIED",
                    "PROTECT_EMAIL_CACHE_REQUIRES_CONFIRMATION",
                ),
                "proposal touches email cache surface explicitly enabled by user",
                _token_evidence(optional_text, EMAIL_TOKENS),
            )
        )

    if ProtectSurface.DEV_FOLDERS in profile.enabled_surfaces and _contains_any(
        optional_text,
        DEV_FOLDER_TOKENS,
    ):
        findings.append(
            _finding(
                ProtectSurface.DEV_FOLDERS,
                _severity_for_effects(effects),
                _write_or_read_reason(
                    effects,
                    "PROTECT_DEV_FOLDER_MUTATION_DENIED",
                    "PROTECT_DEV_FOLDER_REQUIRES_CONFIRMATION",
                ),
                "proposal touches developer folder surface explicitly enabled by user",
                _token_evidence(optional_text, DEV_FOLDER_TOKENS),
            )
        )

    if ProtectSurface.PERSONAL_DOCUMENTS in profile.enabled_surfaces and _contains_any(
        optional_text,
        PERSONAL_DOCUMENT_TOKENS,
    ):
        findings.append(
            _finding(
                ProtectSurface.PERSONAL_DOCUMENTS,
                _severity_for_effects(effects),
                _write_or_read_reason(
                    effects,
                    "PROTECT_PERSONAL_DOCUMENT_MUTATION_DENIED",
                    "PROTECT_PERSONAL_DOCUMENT_REQUIRES_CONFIRMATION",
                ),
                "proposal touches personal document surface explicitly enabled by user",
                _token_evidence(optional_text, PERSONAL_DOCUMENT_TOKENS),
            )
        )

    if ProtectSurface.CUSTOM_PATHS in profile.enabled_surfaces and profile.custom_paths:
        custom_hits = tuple(
            str(path)
            for path in paths
            if any(_is_within(path, root) for root in profile.resolved_custom_paths())
        )
        if custom_hits:
            findings.append(
                _finding(
                    ProtectSurface.CUSTOM_PATHS,
                    _severity_for_effects(effects),
                    _write_or_read_reason(
                        effects,
                        "PROTECT_CUSTOM_PATH_MUTATION_DENIED",
                        "PROTECT_CUSTOM_PATH_REQUIRES_CONFIRMATION",
                    ),
                    "proposal touches user-selected custom protection path",
                    custom_hits,
                )
            )

    return tuple(findings)


def _sandbox_findings(
    proposal: CommandProposal,
    effects: Set[SideEffect],
) -> Sequence[ProtectScanFinding]:
    sandbox = _sandbox_evidence(proposal.raw_payload)
    if not sandbox or _evidence_available(sandbox):
        return ()

    evidence = (_raw_payload_text(sandbox),)
    fallback = str(
        _first_present(
            sandbox.get("fallback"),
            sandbox.get("fallback_mode"),
            sandbox.get("mode"),
            default="",
        )
    ).lower()
    host_fallback = "host" in fallback
    hazardous = bool(
        effects
        & {
            SideEffect.WRITE,
            SideEffect.DELETE,
            SideEffect.NETWORK,
            SideEffect.PRIVILEGE,
            SideEffect.SECRET_ACCESS,
            SideEffect.AUDIT_CHANGE,
        }
    )

    if host_fallback or hazardous:
        return (
            _finding(
                ProtectSurface.SANDBOX_BOUNDARY,
                ProtectScanSeverity.KILL,
                "PROTECT_SANDBOX_UNAVAILABLE_UNSAFE_FALLBACK_DENIED",
                "sandbox is unavailable for an unsafe or host-fallback action",
                evidence,
            ),
        )

    if effects <= {SideEffect.READ} and SideEffect.READ in effects:
        return (
            _finding(
                ProtectSurface.SANDBOX_BOUNDARY,
                ProtectScanSeverity.HOLD,
                "PROTECT_SANDBOX_UNAVAILABLE_READ_DIAGNOSTIC_REQUIRES_CONFIRMATION",
                "sandbox is unavailable for a read-only diagnostic action",
                evidence,
            ),
        )

    return ()


def _gateway_findings(proposal: CommandProposal) -> Sequence[ProtectScanFinding]:
    gateway = _gateway_evidence(proposal.raw_payload)
    if not gateway:
        return ()

    gateway_text = _raw_payload_text(gateway)
    bind_host = str(
        _first_present(
            gateway.get("bind_host"),
            gateway.get("host"),
            gateway.get("hostname"),
            gateway.get("listen_host"),
            default="",
        )
    )
    urls = tuple(
        str(value)
        for value in (
            gateway.get("url"),
            gateway.get("public_url"),
            gateway.get("remote_url"),
            *proposal.target_paths,
        )
        if value
    )
    hosts = tuple(
        host
        for host in (bind_host, *(_url_host(url) for url in urls))
        if host
    )
    insecure_auth = bool(
        _first_present(
            gateway.get("allowInsecureAuth"),
            gateway.get("allow_insecure_auth"),
            gateway.get("insecure_auth"),
            default=False,
        )
    )
    public_exposure = bool(
        _first_present(
            gateway.get("public"),
            gateway.get("public_exposure"),
            gateway.get("exposed_publicly"),
            default=False,
        )
    ) or bool(gateway.get("public_url"))
    auth_valid = _gateway_auth_valid(gateway)
    evidence = (gateway_text,)

    if (
        insecure_auth
        or not auth_valid
        or public_exposure
        or any(_is_public_bind_host(host) for host in hosts)
    ):
        return (
            _finding(
                ProtectSurface.GATEWAY_EXPOSURE,
                ProtectScanSeverity.KILL,
                "PROTECT_GATEWAY_PUBLIC_OR_UNAUTHENTICATED_DENIED",
                "gateway exposure is public, insecure, or missing valid auth",
                evidence,
            ),
        )

    if hosts and all(_is_loopback_host(host) for host in hosts):
        return ()

    return (
        _finding(
            ProtectSurface.GATEWAY_EXPOSURE,
            ProtectScanSeverity.HOLD,
            "PROTECT_GATEWAY_REMOTE_REQUIRES_CONFIRMATION",
            "authenticated remote gateway requires confirmation before I/O",
            evidence,
        ),
    )


def _finding(
    surface: ProtectSurface,
    severity: ProtectScanSeverity,
    reason_code: str,
    detail: str,
    evidence: Sequence[str],
) -> ProtectScanFinding:
    return ProtectScanFinding(
        surface=surface,
        severity=severity,
        reason_code=reason_code,
        detail=detail,
        evidence=tuple(evidence),
    )


def _primary_reason(
    findings: Sequence[ProtectScanFinding],
    severity: ProtectScanSeverity,
) -> str:
    severity_matches = tuple(
        finding for finding in findings if finding.severity == severity
    )
    for finding in severity_matches:
        if finding.surface != ProtectSurface.CORE_PHI:
            return finding.reason_code
    return severity_matches[0].reason_code


def _notice_surface_order() -> Sequence[ProtectSurface]:
    return (
        ProtectSurface.SANDBOX_BOUNDARY,
        ProtectSurface.GATEWAY_EXPOSURE,
        ProtectSurface.CORE_PHI,
        ProtectSurface.REGISTRY,
        ProtectSurface.LEDGER,
        ProtectSurface.AUDIT_STORE,
        ProtectSurface.PERMISSION_SURFACE,
        ProtectSurface.SECRET_FILES,
        ProtectSurface.CREDENTIAL_FILES,
        ProtectSurface.PATH_TRAVERSAL,
        ProtectSurface.NETWORK_EXFIL,
        ProtectSurface.DEV_FOLDERS,
        ProtectSurface.PERSONAL_DOCUMENTS,
        ProtectSurface.BROWSER_PROFILE,
        ProtectSurface.EMAIL_CACHE,
        ProtectSurface.CUSTOM_PATHS,
    )


def _surface_label(surface: ProtectSurface) -> str:
    labels = {
        ProtectSurface.SANDBOX_BOUNDARY: "Sandbox execution boundary",
        ProtectSurface.GATEWAY_EXPOSURE: "Agent gateway exposure boundary",
        ProtectSurface.CORE_PHI: "Phi core store: .phi/",
        ProtectSurface.REGISTRY: "Registry: .phi/registry/",
        ProtectSurface.LEDGER: "Ledger / audit store: .phi/ledger/",
        ProtectSurface.AUDIT_STORE: "Audit implementation surfaces",
        ProtectSurface.PERMISSION_SURFACE: "Permission mutation surfaces",
        ProtectSurface.SECRET_FILES: "Secret files: .env, API keys, secrets",
        ProtectSurface.CREDENTIAL_FILES: "Credential files: ssh keys, service keys",
        ProtectSurface.PATH_TRAVERSAL: "Path traversal patterns",
        ProtectSurface.NETWORK_EXFIL: "Network exfiltration patterns",
        ProtectSurface.DEV_FOLDERS: "Developer folders: C:\\dev, D:\\dev",
        ProtectSurface.PERSONAL_DOCUMENTS: "Personal folders: Desktop, Documents, Downloads",
        ProtectSurface.BROWSER_PROFILE: "Browser profile",
        ProtectSurface.EMAIL_CACHE: "Email cache",
        ProtectSurface.CUSTOM_PATHS: "Custom user-selected paths",
    }
    return labels[surface]


def _combined_text(proposal: CommandProposal) -> str:
    pieces = [
        proposal.command_text,
        proposal.source_adapter,
        proposal.tool_name,
        proposal.action_type,
        *(str(path) for path in proposal.target_paths),
        *(effect.value for effect in proposal.expected_side_effects),
        _raw_payload_text(proposal.raw_payload),
    ]
    return " ".join(piece for piece in pieces if piece).lower()


def _optional_surface_text(
    proposal: CommandProposal,
    profile: ProtectScanProfile,
) -> str:
    paths = _resolved_targets(proposal)
    project_roots = profile.resolved_project_roots()
    external_targets = tuple(
        str(path)
        for path in paths
        if not any(_is_within(path, root) for root in project_roots)
    )
    pieces = list(external_targets)
    if not proposal.target_paths:
        pieces.append(proposal.command_text)
    return " ".join(piece for piece in pieces if piece).lower()


def _raw_payload_text(value: Any) -> str:
    if not value:
        return ""
    try:
        return json.dumps(
            _permission_scan_payload(value),
            sort_keys=True,
            default=str,
        ).lower()
    except (TypeError, ValueError):
        return str(value).lower()


def _permission_scan_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        sanitized = {}
        for key, child in value.items():
            if str(key) in {"can_execute", "can_grant_permission"} and not _truthy_claim(child):
                continue
            sanitized[key] = _permission_scan_payload(child)
        return sanitized

    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(_permission_scan_payload(item) for item in value)

    return value


def _truthy_claim(value: Any) -> bool:
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


def _sandbox_evidence(raw_payload: Mapping[str, Any]) -> Mapping[str, Any]:
    harness = raw_payload.get("harness_adapter")
    if isinstance(harness, Mapping):
        sandbox = harness.get("sandbox_evidence")
        if isinstance(sandbox, Mapping):
            return sandbox
    for key in ("sandbox", "sandbox_evidence"):
        value = raw_payload.get(key)
        if isinstance(value, Mapping):
            return value
    metadata = raw_payload.get("metadata")
    if isinstance(metadata, Mapping):
        for key in ("sandbox", "sandbox_evidence"):
            value = metadata.get(key)
            if isinstance(value, Mapping):
                return value
    return {}


def _gateway_evidence(raw_payload: Mapping[str, Any]) -> Mapping[str, Any]:
    merged: Dict[str, Any] = {}
    for key in ("gateway", "gateway_evidence", "permission_gateway", "public_exposure"):
        value = raw_payload.get(key)
        if isinstance(value, Mapping):
            merged.update(value)
    metadata = raw_payload.get("metadata")
    if isinstance(metadata, Mapping):
        for key in ("gateway", "gateway_evidence", "permission_gateway", "public_exposure"):
            value = metadata.get(key)
            if isinstance(value, Mapping):
                merged.update(value)
    harness = raw_payload.get("harness_adapter")
    if isinstance(harness, Mapping):
        gateway = harness.get("gateway_evidence")
        if isinstance(gateway, Mapping):
            merged.update(gateway)
    return merged


def _evidence_available(evidence: Mapping[str, Any]) -> bool:
    available = _first_present(
        evidence.get("available"),
        evidence.get("enabled"),
        evidence.get("ready"),
        default=True,
    )
    if isinstance(available, str):
        return available.strip().lower() not in {"false", "0", "no", "unavailable"}
    return bool(available)


def _gateway_auth_valid(gateway: Mapping[str, Any]) -> bool:
    direct = _first_present(
        gateway.get("auth_valid"),
        gateway.get("authenticated"),
        gateway.get("token_valid"),
        gateway.get("valid_auth"),
        default=None,
    )
    if direct is not None:
        if isinstance(direct, str):
            return direct.strip().lower() in {"true", "1", "yes", "valid", "ok"}
        return bool(direct)

    auth = gateway.get("auth")
    if isinstance(auth, Mapping):
        return _gateway_auth_valid(auth)
    if isinstance(auth, str):
        return auth.strip().lower() in {"valid", "required", "token", "bearer", "mTLS".lower()}

    return False


def _url_host(value: str) -> str:
    parsed = urlparse(str(value))
    return parsed.hostname or ""


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().strip("[]").lower()
    return normalized in {"localhost", "127.0.0.1", "::1"}


def _is_public_bind_host(host: str) -> bool:
    normalized = host.strip().strip("[]").lower()
    return normalized in {"0.0.0.0", "::", "[::]"}


def _first_present(*values: Any, default: Any = None) -> Any:
    for value in values:
        if value is not None:
            return value
    return default


def _contains_any(text: str, tokens: Iterable[str]) -> bool:
    return any(token.lower() in text for token in tokens if token)


def _token_evidence(text: str, tokens: Iterable[str]) -> Sequence[str]:
    return tuple(token for token in tokens if token.lower() in text)


def _secret_evidence(text: str) -> Sequence[str]:
    evidence = []
    for token in SECRET_TOKENS:
        lowered = token.lower()
        if lowered not in text:
            continue

        if lowered == "password" and _protective_password_reference(text):
            continue

        evidence.append(token)

    return tuple(evidence)


def _protective_password_reference(text: str) -> bool:
    return _contains_any(text, PASSWORD_PROTECTIVE_TOKENS) and not _contains_any(
        text,
        PASSWORD_HANDLING_TOKENS,
    )


def _surface_evidence(
    text: str,
    paths: Sequence[Path],
    tokens: Sequence[str],
) -> Sequence[str]:
    evidence = list(_token_evidence(text, tokens))
    evidence.extend(
        str(path)
        for path in paths
        if {part.lower() for part in path.parts} & {".phi", ".claude", ".codex"}
    )
    return tuple(evidence)


def _network_evidence(proposal: CommandProposal, text: str) -> Sequence[str]:
    evidence = list(_token_evidence(text, NETWORK_TOKENS))
    for target in proposal.target_paths:
        parsed = urlparse(str(target))
        if parsed.scheme in {"http", "https"}:
            evidence.append(str(target))
    return tuple(evidence)


def _inferred_effects(proposal: CommandProposal) -> Set[SideEffect]:
    text = _combined_text(proposal)
    effects = set(proposal.expected_side_effects)
    if _contains_any(
        text,
        (
            "set-content",
            "out-file",
            "add-content",
            "new-item",
            "copy-item",
            "move-item",
            "truncate",
            "git checkout --",
            ">",
        ),
    ):
        effects.add(SideEffect.WRITE)
    if _contains_any(
        text,
        (
            "remove-item",
            " del ",
            "erase",
            " rm ",
            "rmdir",
            "clear-content",
            "truncate",
            " -delete",
            "git clean",
            "git reset --hard",
            "git checkout --",
        ),
    ):
        effects.add(SideEffect.DELETE)
    if _contains_any(text, NETWORK_TOKENS):
        effects.add(SideEffect.NETWORK)
    if _contains_any(text, PERMISSION_TOKENS):
        effects.add(SideEffect.PRIVILEGE)
    if _secret_evidence(text) or _contains_any(text, CREDENTIAL_TOKENS):
        effects.add(SideEffect.SECRET_ACCESS)
    if _contains_any(text, AUDIT_TOKENS + PHI_TOKENS) and effects & {
        SideEffect.WRITE,
        SideEffect.DELETE,
    }:
        effects.add(SideEffect.AUDIT_CHANGE)
    return effects


def _severity_for_effects(effects: Set[SideEffect]) -> ProtectScanSeverity:
    if effects & {
        SideEffect.WRITE,
        SideEffect.DELETE,
        SideEffect.PRIVILEGE,
        SideEffect.SECRET_ACCESS,
        SideEffect.AUDIT_CHANGE,
    }:
        return ProtectScanSeverity.KILL
    return ProtectScanSeverity.HOLD


def _write_or_read_reason(
    effects: Set[SideEffect],
    write_reason: str,
    read_reason: str,
) -> str:
    if _severity_for_effects(effects) == ProtectScanSeverity.KILL:
        return write_reason
    return read_reason


def _network_present(
    proposal: CommandProposal,
    text: str,
    effects: Set[SideEffect],
) -> bool:
    if _egress_targets_all_loopback(proposal):
        return False
    if SideEffect.NETWORK in effects or _contains_any(text, NETWORK_TOKENS):
        return True
    return any(urlparse(str(target)).scheme in {"http", "https"} for target in proposal.target_paths)


def _egress_targets_all_loopback(proposal: CommandProposal) -> bool:
    # A3: the network wall is suppressed ONLY when the PHYSICAL egress target is
    # provably loopback (its URL host is 127.0.0.1 / localhost / ::1). The agent's
    # self-declared gateway dict (bind_host / host / auth_valid / public) is NOT
    # trusted to stand the wall down -- a forged {auth_valid:true, bind_host:
    # 127.0.0.1} cannot suppress egress ("trust the physical target, not the
    # self-report"). A real local server (curl http://127.0.0.1/...) still passes
    # because its target host is physically loopback. With no verifiable loopback
    # target the wall STANDS (fail-closed); it does not silently pass. Loopback is
    # safe regardless of the gateway's auth claim -- data cannot leave the host --
    # so auth/exposure are judged separately by _gateway_findings, not here.
    target_hosts = tuple(
        host
        for host in (_url_host(str(target)) for target in proposal.target_paths)
        if host
    )
    return bool(target_hosts) and all(_is_loopback_host(host) for host in target_hosts)


def _has_path_traversal(value: str) -> bool:
    parts = value.replace("\\", "/").split("/")
    return ".." in parts


def _resolved_targets(proposal: CommandProposal) -> Sequence[Path]:
    paths = []
    for target in proposal.target_paths:
        parsed = urlparse(str(target))
        if parsed.scheme in {"http", "https"}:
            continue
        try:
            paths.append(_resolve_target(proposal.cwd, str(target)))
        except (OSError, RuntimeError, ValueError):
            continue
    return tuple(paths)


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


def _matches_surface(
    text: str,
    paths: Sequence[Path],
    project_roots: Sequence[Path],
    tokens: Sequence[str],
    *,
    phi_subdir: str | None,
) -> bool:
    if _contains_any(text, tokens):
        return True

    for path in paths:
        parts = tuple(part.lower() for part in path.parts)
        if ".phi" not in parts:
            continue
        if phi_subdir is None:
            return True
        if phi_subdir in parts:
            return True

    if phi_subdir is None:
        return any(
            _is_within(path, root / ".phi")
            for path in paths
            for root in project_roots
        )

    return any(
        _is_within(path, root / ".phi" / phi_subdir)
        for path in paths
        for root in project_roots
    )
