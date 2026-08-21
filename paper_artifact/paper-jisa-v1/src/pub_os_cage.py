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
    extra_ro: Sequence[str] = ()        # absolute RO paths: the npm prefix (claude pkg + bin), ...
    extra_rw: Sequence[str] = ()        # absolute RW paths the agent's OWN tool must write
                                        #   (e.g. $HOME/.claude: sessions / history / auth refresh).
                                        #   A deliberate 2nd writable area -- claude's config home,
                                        #   NOT project data -- with its control files re-bound RO below.
    control_ro_abs: Sequence[str] = ()  # absolute control-plane files re-bound RO OVER a writable bind
                                        #   (e.g. $HOME/.claude/settings*.json -> the hook stays armed
                                        #   even though the rest of ~/.claude is writable).
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
        object.__setattr__(self, "extra_rw", tuple(_posix(item) for item in self.extra_rw))
        object.__setattr__(self, "control_ro_abs", tuple(_posix(item) for item in self.control_ro_abs))
        object.__setattr__(self, "system_ro", tuple(_posix(item) for item in self.system_ro))
        object.__setattr__(self, "tmpfs", tuple(_posix(item) for item in self.tmpfs))
        # Invariant 5: pub's own enforcement code must not be inside ANY writable
        # real-estate, or the agent could overwrite the watchdog.
        for writable in (self.project_root, *self.extra_rw):
            if self.pub_source_dir and _is_inside(self.pub_source_dir, writable):
                raise ValueError(
                    "pub_source_dir is inside a writable bind: the cage would hand "
                    "the agent write access to its own enforcement code"
                )
        # The audit dir, if it sits inside the project, is acceptable (it is
        # re-bound read-only below); if outside, it is simply not writable.

    def control_ro_paths(self) -> tuple[str, ...]:
        paths = [f"{self.project_root}/{rel}" for rel in self.project_ro]
        paths.extend(self.control_ro_abs)
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

    # Invariant 1: the primary writable real-estate (the project).
    argv += ["--bind", spec.project_root, spec.project_root]

    # The agent's own tool needs a few writable homes (e.g. $HOME/.claude for
    # sessions / auth refresh). Bound writable too, but their control-plane files
    # are re-bound READ-ONLY just below, so the gate cannot be disarmed from inside.
    for rw in spec.extra_rw:
        argv += ["--bind-try", rw, rw]

    # Invariant 2: re-bind the control plane read-only OVER the writable binds
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


def cage_available(*, runner=subprocess.run) -> tuple[bool, str]:
    """(usable, reason). Linux + bwrap on PATH + UNPRIVILEGED user namespaces that
    actually work on THIS host. The last check is a real runtime probe, not an
    assumption: some kernels/distros disable unprivileged userns, and then bwrap
    would need sudo -- which breaks unattended, reproducible launch. We fail closed
    here rather than fall back to sudo or to an uncaged agent."""
    if sys.platform != "linux":
        return False, f"cage_unavailable:platform:{sys.platform}"
    if which(BWRAP) is None:
        return False, "cage_unavailable:bwrap_not_installed"
    try:
        probe = runner(
            [BWRAP, "--ro-bind", "/", "/", "--unshare-user", "--uid", "1000", "true"],
            capture_output=True,
            timeout=10,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"cage_unavailable:userns_probe_error:{type(exc).__name__}"
    if getattr(probe, "returncode", 1) != 0:
        return False, "cage_unavailable:unprivileged_userns_denied"
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


def _claude_package_dir(real_bin: str) -> str:
    """The single npm package dir that holds claude + its bundled runtime, derived
    from the resolved binary. Binding ONLY this (not the whole npm prefix) keeps the
    agent from reading every other global package -- least privilege. Handles scoped
    packages (@anthropic-ai/claude-code). Empty string if the layout is unrecognised
    (the caller then falls back to the prefix)."""
    parts = _posix(real_bin).split("/")
    if "node_modules" not in parts:
        return ""
    idx = len(parts) - 1 - parts[::-1].index("node_modules")
    end = idx + 2  # node_modules/<pkg>
    if idx + 1 < len(parts) and parts[idx + 1].startswith("@") and idx + 2 < len(parts):
        end = idx + 3  # node_modules/@scope/<pkg>
    return "/".join(parts[:end])


def _npm_global_prefix(runner=subprocess.run) -> str:
    """`npm prefix -g` -- the global package root (holds bin/claude + the claude
    package). Discovered, never hardcoded, so it resolves per-machine."""
    try:
        out = runner(["npm", "prefix", "-g"], capture_output=True, text=True, timeout=15)
    except Exception:  # noqa: BLE001
        return ""
    return _posix(out.stdout.strip()) if getattr(out, "returncode", 1) == 0 else ""


def discover_cc_cage_spec(
    project_root: str,
    *,
    pub_source_dir: str = "",
    home: str | None = None,
    npm_prefix: str | None = None,
    claude_bin: str | None = None,
    allow_net: bool = True,
    runner=subprocess.run,
    which_fn=which,
) -> tuple[CageSpec, str]:
    """Build a CageSpec for caging `claude`, deriving EVERY path from the runtime
    environment -- no hardcoded home / user / npm prefix -- so the same code
    reproduces on any customer's Linux/WSL2 box. Returns (spec, claude_bin).

    The probes (overridable for tests): $HOME, `which claude`, `npm prefix -g`.
    node lives under /usr (already in system_ro). ~/.claude is bound writable (the
    tool's own sessions/auth) with its settings*.json re-bound read-only.
    """
    home_dir = _posix(home or os.path.expanduser("~"))
    discovered = claude_bin or which_fn("claude")
    if not discovered:
        raise CageUnavailable("cage_unavailable:claude_not_on_path")
    # Resolve the PATH symlink to the real binary so the cage can run it by absolute
    # path and bind ONLY its package dir -- not the whole npm bin/prefix.
    real_bin = _posix(os.path.realpath(discovered))
    pkg_dir = _claude_package_dir(real_bin)
    if not pkg_dir:
        # Unrecognised layout -> fall back to the broader npm prefix (still ro).
        pkg_dir = _posix(npm_prefix) if npm_prefix else _npm_global_prefix(runner)
    claude_config = f"{home_dir}/.claude"
    spec = CageSpec(
        project_root=project_root,
        pub_source_dir=pub_source_dir,
        # ro-bind: ONLY the claude package dir (claude + its bundled runtime) AND
        # pub's own source (the in-cage hook imports pub to judge). Both readable,
        # never writable -- least privilege: no OTHER global npm package is exposed.
        extra_ro=tuple(path for path in (pkg_dir, pub_source_dir) if path),
        extra_rw=(claude_config,),
        control_ro_abs=(
            f"{claude_config}/settings.json",
            f"{claude_config}/settings.local.json",
        ),
        allow_net=allow_net,
    )
    return spec, real_bin


def _main(argv: Sequence[str] | None = None) -> int:
    """Render the exact bwrap cage command for THIS machine, to hand-test in WSL:

        python3 pub_os_cage.py /mnt/c/dev/pub_work --pub-source-dir /mnt/c/dev/sp
    """
    import argparse

    parser = argparse.ArgumentParser(prog="pub_os_cage")
    parser.add_argument("project_root")
    parser.add_argument("--pub-source-dir", default="")
    parser.add_argument("--no-net", action="store_true")
    parser.add_argument("inner", nargs=argparse.REMAINDER)
    args = parser.parse_args(list(argv) if argv is not None else None)
    spec, claude_bin = discover_cc_cage_spec(
        args.project_root, pub_source_dir=args.pub_source_dir, allow_net=not args.no_net
    )
    inner = args.inner[1:] if args.inner[:1] == ["--"] else args.inner
    inner_argv = list(inner) or [claude_bin, "--permission-mode", "default"]
    usable, reason = cage_available()
    print(f"# cage_available: {usable} ({reason})")
    print(render_cage_command(inner_argv, spec))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
