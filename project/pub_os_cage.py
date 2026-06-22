"""PUB-OS cc cage (prototype).

Claude Code mutates the filesystem with in-process Node fs calls (Write/Edit),
not through a shell, so a shell-interposition guard (as cd uses for Codex)
cannot reach those writes. The only thing with teeth is to confine the WHOLE
`claude` process. cc -- unlike Codex -- ships no built-in sandbox, so pub must
bring its own cage. On Linux/WSL that cage is bubblewrap (bwrap), an unprivileged
user-namespace sandbox (NOT a kernel module).

This module does two jobs:
  * render the exact bwrap command (for an operator to run by hand in WSL), and
  * provide a fail-closed ``spawn_fn`` for ``pub_os_runner.start_agent_run``.

Security-load-bearing invariants (everything else is runtime plumbing):
  1. Exactly ONE writable real-estate inside the cage: ``project_root``.
  2. The control plane that lives inside the project (CC hook registration in
     ``.claude/settings*.json`` and ``pub_gate_switch.json``) is re-bound
     READ-ONLY over the writable project. The switch file is legacy/status-only;
     it cannot disarm the watchdog.
  3. Anything not bound simply does not exist in the cage, so a write spelled to
     escape the sandbox (drive-relative, ``~``, ``..``, absolute-outside) lands
     on a path the cage never mounted and fails at the OS layer.
  4. No bwrap => no run. The cage failing closed is the whole point of "go A".
  5. pub's own source must live OUTSIDE ``project_root`` (asserted), else the
     project bind would hand the agent its own enforcement code.

Audit-log writes are deliberately NOT made writable here: the ledger must be
written by a supervisor OUTSIDE the cage (the witness cannot share the cell with
the prisoner). That is Task 3; for now the audit dir is bound read-only so the
caged agent can neither read-tamper nor truncate it.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from shutil import which
from typing import Any, Mapping, Sequence


BWRAP = "bwrap"

# Control-plane files that live INSIDE the project root. Re-bound read-only over
# the writable project bind so the agent cannot rewrite them.
DEFAULT_PROJECT_RO = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/pub_gate_switch.json",
)

# Minimal OS runtime the `claude` Node process needs to exist at all, read-only.
DEFAULT_SYSTEM_RO = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc")

# tmpfs mounts: scratch space that vanishes with the cage.
DEFAULT_TMPFS = ("/tmp", "/run")


class CageUnavailable(RuntimeError):
    """Raised when a cage was requested but cannot be built (fail closed)."""


def _posix(path: str) -> str:
    """Normalise to a POSIX path string (bwrap is POSIX-only). Pure string work
    so this behaves identically when tests run under a Windows interpreter."""
    text = str(path).replace("\\", "/").strip()
    if len(text) > 1:
        text = text.rstrip("/")
    return text


def _is_inside(child: str, parent: str) -> bool:
    child = _posix(child)
    parent = _posix(parent)
    return child == parent or child.startswith(parent + "/")


@dataclass(frozen=True)
class CageSpec:
    project_root: str
    pub_source_dir: str = ""
    project_ro: Sequence[str] = DEFAULT_PROJECT_RO
    extra_ro: Sequence[str] = ()        # absolute paths: node, the claude package, ~/.claude (auth), ...
    system_ro: Sequence[str] = DEFAULT_SYSTEM_RO
    audit_dir: str = ""                 # optional read-only inspection mount; the ledger FILE stays outside
    ledger_socket: str = ""             # unix socket to the out-of-cage ledger supervisor (Task 3)
    allow_net: bool = True
    tmpfs: Sequence[str] = DEFAULT_TMPFS

    def __post_init__(self) -> None:
        root = _posix(self.project_root)
        if not root:
            raise ValueError("project_root is required")
        object.__setattr__(self, "project_root", root)
        object.__setattr__(self, "pub_source_dir", _posix(self.pub_source_dir) if self.pub_source_dir else "")
        object.__setattr__(self, "audit_dir", _posix(self.audit_dir) if self.audit_dir else "")
        object.__setattr__(self, "ledger_socket", _posix(self.ledger_socket) if self.ledger_socket else "")
        object.__setattr__(self, "project_ro", tuple(str(item).strip().lstrip("/") for item in self.project_ro))
        object.__setattr__(self, "extra_ro", tuple(_posix(item) for item in self.extra_ro))
        object.__setattr__(self, "system_ro", tuple(_posix(item) for item in self.system_ro))
        object.__setattr__(self, "tmpfs", tuple(_posix(item) for item in self.tmpfs))
        # Invariant 5: pub's own enforcement code must not be inside the only
        # writable real-estate, or the agent could overwrite the watchdog.
        if self.pub_source_dir and _is_inside(self.pub_source_dir, self.project_root):
            raise ValueError(
                "pub_source_dir is inside project_root: the cage would hand the "
                "agent write access to its own enforcement code"
            )
        # The audit dir, if it sits inside the project, is acceptable (it is
        # re-bound read-only below); if outside, it is simply not writable.

    def control_ro_paths(self) -> tuple[str, ...]:
        paths = [f"{self.project_root}/{rel}" for rel in self.project_ro]
        if self.audit_dir:
            paths.append(self.audit_dir)
        return tuple(paths)


def build_cage_argv(inner_argv: Sequence[str], spec: CageSpec) -> list[str]:
    """Render the full bwrap argv that confines ``inner_argv`` (e.g. the claude
    launch) to a single writable project with a read-only control plane."""
    if not inner_argv:
        raise ValueError("inner_argv is required (the agent command to cage)")

    argv: list[str] = [BWRAP, "--die-with-parent", "--unshare-all"]
    if spec.allow_net:
        argv += ["--share-net"]
    argv += ["--proc", "/proc", "--dev", "/dev"]
    for mount in spec.tmpfs:
        argv += ["--tmpfs", mount]

    # Read-only OS runtime + extra runtime deps (node, claude package, auth).
    for ro in spec.system_ro:
        argv += ["--ro-bind-try", ro, ro]
    for ro in spec.extra_ro:
        argv += ["--ro-bind-try", ro, ro]

    # Invariant 1: the ONE writable real-estate.
    argv += ["--bind", spec.project_root, spec.project_root]

    # Invariant 2: re-bind the control plane read-only OVER the writable project
    # (bwrap applies binds in order; a later ro bind on a sub-path wins).
    for ro in spec.control_ro_paths():
        argv += ["--ro-bind-try", ro, ro]

    # Task 3: the only audit egress is the ledger socket. Bind the socket NODE
    # (not the ledger file) so an in-cage hook can deliver events to the
    # out-of-cage supervisor but can never open, truncate, or rewrite the ledger.
    if spec.ledger_socket:
        argv += ["--bind", spec.ledger_socket, spec.ledger_socket]

    argv += ["--chdir", spec.project_root, "--"]
    argv += [str(token) for token in inner_argv]
    return argv


def cage_available() -> tuple[bool, str]:
    """(usable, reason). Linux + bwrap on PATH. Anything else => not usable."""
    if sys.platform != "linux":
        return False, f"cage_unavailable:platform:{sys.platform}"
    if which(BWRAP) is None:
        return False, "cage_unavailable:bwrap_not_installed"
    return True, "cage_ready"


def render_cage_command(inner_argv: Sequence[str], spec: CageSpec) -> str:
    """A shell-pasteable rendering of the cage command, for hand-running in WSL."""
    return " ".join(shlex.quote(token) for token in build_cage_argv(inner_argv, spec))


def make_cage_spawn(spec: CageSpec):
    """Return a fail-closed ``spawn_fn(argv, *, cwd, env)`` for
    ``pub_os_runner.start_agent_run``. Raises ``CageUnavailable`` rather than
    launching an uncaged agent."""

    def spawn(argv: Sequence[str], *, cwd: str | None = None, env: Mapping[str, str] | None = None) -> Any:
        usable, reason = cage_available()
        if not usable:
            raise CageUnavailable(reason)
        full = build_cage_argv(tuple(argv), spec)
        # cwd is fixed by --chdir to project_root inside the cage; the outer cwd
        # is irrelevant. env is passed through (the runner already stamped the
        # PUB_OS_* markers; the cage does not widen authority).
        return subprocess.Popen(full, env=dict(env or os.environ))

    return spawn
