"""PUB-OS cc sandbox clamp (ride Claude Code's own sandbox + launch clamp).

Correction to the earlier cc design: Claude Code ships its OWN OS-level sandbox
(Seatbelt on macOS, bubblewrap+socat on Linux/WSL2), configured through
``settings.json`` ``sandbox.*`` keys. So cc -- like Codex -- already has hands;
pub must not bring its own bwrap cage for cc. pub's leverage is the SAME shape
as the cd clamp: at launch, positively assert that Claude Code's sandbox is
armed fail-closed; refuse to fly otherwise. Eyes stay on the hook layer
(existing ``check_claude_code_profile``); this module is the hands check.

This module touches no existing code. It is a pure assessor over a resolved
settings object plus a generator for the managed-settings template an operator
should apply. Wiring it into the cc launch path would touch ``pub_os_runner`` and
is left as a separate, authorized step.

Verified against Claude Code docs (code.claude.com/docs/en/sandboxing, /settings):
  - sandbox.enabled / sandbox.failIfUnavailable / sandbox.allowUnsandboxedCommands
  - sandbox.filesystem.{allowWrite,denyWrite,denyRead,allowRead}
  - sandbox.allowManagedReadPathsOnly / sandbox.allowManagedDomainsOnly
  - the sandbox auto-denies writes to settings.json at every scope (Bash only)

KNOWN COVERAGE BOUNDARY (carried in the verdict so callers cannot overclaim):
the sandbox isolates Bash subprocesses ONLY. Built-in Read/Edit/Write run through
the permission system, NOT the sandbox. The in-process Write/Edit seam is closed
by permission deny rules + protected paths + pub's PreToolUse hook, not by this
sandbox. And the sandbox is unavailable on native Windows: on Windows, cc must run
inside WSL2 or the clamp will (correctly) HOLD.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


# Credential / escalation-prone locations the sandbox's default read policy still
# exposes (docs: default read is whole-computer except denied dirs). Must be in
# sandbox.filesystem.denyRead for a contained posture.
DEFAULT_REQUIRED_DENY_READ = (
    "~/.ssh",
    "~/.aws",
    "~/.config/gcloud",
    "~/.netrc",
    "~/.npmrc",
)

# Shell-init / PATH locations whose write enables code execution in other
# security contexts (docs: filesystem permission escalation). Recommended denyWrite.
DEFAULT_RECOMMENDED_DENY_WRITE = (
    "~/.bashrc",
    "~/.zshrc",
    "~/.profile",
)


class CcSandboxState(str, Enum):
    SUPERVISED = "SUPERVISED"
    HOLD = "HOLD"


@dataclass(frozen=True)
class SandboxPosture:
    enabled: bool = False
    fail_if_unavailable: bool = False
    allow_unsandboxed_commands: bool = True  # unsafe default; assessor must HOLD
    deny_read: tuple[str, ...] = ()
    allow_managed_read_paths_only: bool = False
    allow_managed_domains_only: bool = False
    allowed_domains: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "fail_if_unavailable": self.fail_if_unavailable,
            "allow_unsandboxed_commands": self.allow_unsandboxed_commands,
            "deny_read": list(self.deny_read),
            "allow_managed_read_paths_only": self.allow_managed_read_paths_only,
            "allow_managed_domains_only": self.allow_managed_domains_only,
            "allowed_domains": list(self.allowed_domains),
        }


@dataclass(frozen=True)
class CcSandboxVerdict:
    state: CcSandboxState | str
    reason_code: str
    evidence: Sequence[str] = field(default_factory=tuple)
    posture: SandboxPosture | None = None
    # Honesty markers: what riding the CC sandbox does and does NOT contain.
    bash_isolated: bool = False
    inprocess_write_isolated: bool = False  # Write/Edit are NOT sandboxed (docs)
    can_execute: bool = False
    can_grant_permission: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", CcSandboxState(self.state))
        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence))
        object.__setattr__(self, "can_execute", False)
        object.__setattr__(self, "can_grant_permission", False)

    @property
    def supervised(self) -> bool:
        return self.state == CcSandboxState.SUPERVISED

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "reason_code": self.reason_code,
            "evidence": tuple(self.evidence),
            "posture": self.posture.to_dict() if self.posture else None,
            "bash_isolated": self.bash_isolated,
            "inprocess_write_isolated": self.inprocess_write_isolated,
            "can_execute": False,
            "can_grant_permission": False,
        }


def _sandbox_block(settings: Mapping[str, Any]) -> dict[str, Any]:
    block = settings.get("sandbox")
    return dict(block) if isinstance(block, Mapping) else {}


def _norm(path: str) -> str:
    return str(path).replace("\\", "/").rstrip("/").lower()


def effective_sandbox_posture(settings: Mapping[str, Any]) -> SandboxPosture:
    """Extract the sandbox posture from a (merged) settings object."""
    sb = _sandbox_block(settings)
    fs = sb.get("filesystem") if isinstance(sb.get("filesystem"), Mapping) else {}
    net = sb.get("network") if isinstance(sb.get("network"), Mapping) else {}

    def _bool(container: Mapping[str, Any], key: str, default: bool) -> bool:
        value = container.get(key, default)
        return value if isinstance(value, bool) else default

    # allowManaged*Only may live under sandbox; tolerate a top-level fallback.
    def _managed(key: str) -> bool:
        if key in sb:
            return _bool(sb, key, False)
        return _bool(settings, key, False)

    return SandboxPosture(
        enabled=_bool(sb, "enabled", False),
        fail_if_unavailable=_bool(sb, "failIfUnavailable", False),
        # absence of the escape-hatch key means the hatch is OPEN (docs default).
        allow_unsandboxed_commands=_bool(sb, "allowUnsandboxedCommands", True),
        deny_read=tuple(str(p) for p in fs.get("denyRead", ()) if isinstance(fs.get("denyRead", ()), (list, tuple))),
        allow_managed_read_paths_only=_managed("allowManagedReadPathsOnly"),
        allow_managed_domains_only=_managed("allowManagedDomainsOnly"),
        allowed_domains=tuple(str(d) for d in net.get("allowedDomains", ()) if isinstance(net.get("allowedDomains", ()), (list, tuple))),
    )


def assess_cc_sandbox(
    settings: Mapping[str, Any],
    *,
    required_deny_read: Sequence[str] = DEFAULT_REQUIRED_DENY_READ,
    require_managed_lockdowns: bool = True,
) -> CcSandboxVerdict:
    """Fail-closed launch clamp for riding Claude Code's built-in sandbox.

    Returns SUPERVISED only when the sandbox is provably armed tight; any gap is
    a HOLD. The verdict always records that in-process Write/Edit are NOT covered
    by the sandbox, so a caller cannot read SUPERVISED as full containment.
    """
    posture = effective_sandbox_posture(settings)

    def hold(code: str, evidence: Sequence[str] = ()) -> CcSandboxVerdict:
        return CcSandboxVerdict(
            CcSandboxState.HOLD, code, tuple(evidence),
            posture=posture, bash_isolated=False, inprocess_write_isolated=False,
        )

    if not posture.enabled:
        return hold("CC_SANDBOX_NOT_ENABLED", ("sandbox.enabled:false_or_missing",))
    if not posture.fail_if_unavailable:
        return hold("CC_SANDBOX_NOT_FAIL_CLOSED", ("sandbox.failIfUnavailable:false_or_missing",))
    if posture.allow_unsandboxed_commands:
        return hold("CC_SANDBOX_ESCAPE_HATCH_OPEN", ("sandbox.allowUnsandboxedCommands:true_or_default",))

    denied = {_norm(p) for p in posture.deny_read}
    missing = [p for p in required_deny_read if _norm(p) not in denied]
    if missing:
        return hold("CC_SANDBOX_CREDENTIALS_READABLE", tuple(f"denyRead_missing:{p}" for p in missing))

    if require_managed_lockdowns and not (posture.allow_managed_read_paths_only and posture.allow_managed_domains_only):
        return hold(
            "CC_SANDBOX_POLICY_NOT_LOCKED",
            (
                f"allowManagedReadPathsOnly:{posture.allow_managed_read_paths_only}",
                f"allowManagedDomainsOnly:{posture.allow_managed_domains_only}",
            ),
        )

    return CcSandboxVerdict(
        CcSandboxState.SUPERVISED,
        "CC_SANDBOX_CONTAINED",
        ("bash:os_isolated", "fail_closed", "creds:denied", "policy:managed_locked"),
        posture=posture,
        bash_isolated=True,
        # The CC sandbox isolates Bash subprocesses only; Read/Edit/Write run
        # through the permission system. The in-process write seam is delegated
        # to permission deny rules + protected paths + pub's PreToolUse hook.
        inprocess_write_isolated=False,
    )


def recommended_managed_settings(
    *,
    required_deny_read: Sequence[str] = DEFAULT_REQUIRED_DENY_READ,
    recommended_deny_write: Sequence[str] = DEFAULT_RECOMMENDED_DENY_WRITE,
) -> dict[str, Any]:
    """The managed-settings ``sandbox`` block pub recommends an operator apply.

    Applying this (via MDM / server-managed settings) is what actually arms the
    fail-closed posture this module asserts. By construction it passes
    ``assess_cc_sandbox``. It contains only verified ``sandbox.*`` keys; the
    in-process Write/Edit control-plane protection is a companion concern (a
    permission deny rule on the settings files) -- see module docstring -- and is
    deliberately NOT fabricated here to avoid emitting unverified rule syntax.
    """
    return {
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "allowManagedReadPathsOnly": True,
            "allowManagedDomainsOnly": True,
            "filesystem": {
                "denyRead": list(required_deny_read),
                "denyWrite": list(recommended_deny_write),
            },
            "network": {"allowedDomains": []},
        }
    }


def merge_settings(*scopes: Mapping[str, Any]) -> dict[str, Any]:
    """Merge settings scopes in precedence order (managed LAST = wins for scalars;
    arrays are unioned; nested mappings merge recursively). A pragmatic model of
    the documented precedence/merge behaviour, for feeding ``assess_cc_sandbox``."""
    out: dict[str, Any] = {}
    for scope in scopes:
        _merge_into(out, dict(scope))
    return out


def _merge_into(dst: dict[str, Any], src: Mapping[str, Any]) -> None:
    for key, value in src.items():
        if isinstance(value, Mapping) and isinstance(dst.get(key), dict):
            _merge_into(dst[key], dict(value))
        elif isinstance(value, (list, tuple)) and isinstance(dst.get(key), (list, tuple)):
            merged = list(dst[key])
            for item in value:
                if item not in merged:
                    merged.append(item)
            dst[key] = merged
        elif isinstance(value, Mapping):
            dst[key] = dict(value)
        else:
            dst[key] = value
