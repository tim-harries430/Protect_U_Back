"""PUB-OS box -- the prison cell that confines the untrusted agent.

The box holds the AGENT (the thing doing the work), NOT pub. pub's eyes + beast
live OUTSIDE, behind the broker window (PUB_OS_BROKER_CONTRACT.md). The box's one
job is contract invariant I1 -- **single egress**: from inside the box there is
NO network and NO filesystem beyond the project root; the only way out is the
broker's unix socket, bind-mounted in. We do NOT write an isolator -- we drive a
battle-tested one (bubblewrap / `bwrap`, unprivileged Linux namespaces). On
Windows the box runs inside WSL2 (which is itself a microVM with its own kernel).

`build_box_argv` is the whole confinement POLICY, as a pure function so it is
auditable and testable on any host. `launch` execs it (Linux only).
"""

from __future__ import annotations

import os
import shutil
import sys

# Minimal read-only host paths so a runtime exists inside (python, libc, ...).
# `--ro-bind-try` skips any that are absent, absorbing distro variance.
DEFAULT_RO_SYSTEM: tuple[str, ...] = (
    "/usr",
    "/etc/alternatives",
    "/etc/ld.so.cache",
    "/etc/ssl/certs",
)

# merged-usr symlinks so /bin /lib resolve into the bound /usr on modern distros.
_USR_SYMLINKS: tuple[tuple[str, str], ...] = (
    ("usr/bin", "/bin"),
    ("usr/sbin", "/sbin"),
    ("usr/lib", "/lib"),
    ("usr/lib64", "/lib64"),
)


def build_box_argv(
    agent_argv,
    *,
    project_root,
    broker_socket,
    ro_system=DEFAULT_RO_SYSTEM,
    env=None,
    bwrap: str = "bwrap",
):
    """Construct the bwrap argv that confines `agent_argv`. Pure + auditable.

    Confinement, clause by clause:
      * --unshare-net      -> NO network at all (no route, no interface).
      * --clearenv         -> drop ALL host env (tokens / secrets / paths).
      * --tmpfs / + binds  -> filesystem is EMPTY except a read-only system,
                              the rw project root, and the one broker socket.
      * --bind project     -> the only writable surface is the workspace.
      * --bind socket       -> the SINGLE egress: pub's window, reached over a
                              unix socket (works across the killed net namespace).
      * --die-with-parent  -> the box dies if the launcher dies (fail-closed).
    """
    project_root = os.path.abspath(str(project_root))
    broker_socket = os.path.abspath(str(broker_socket))

    argv = [
        bwrap,
        # no ambient authority
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        # a minimal, mostly read-only system so the runtime can run
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
    ]
    for target, link in _USR_SYMLINKS:
        argv += ["--symlink", target, link]
    for path in ro_system:
        argv += ["--ro-bind-try", path, path]

    # the ONLY writable surface
    argv += ["--bind", project_root, project_root]
    # the SINGLE egress
    argv += ["--bind", broker_socket, broker_socket]

    full_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": project_root,
        "TMPDIR": "/tmp",
        "PUB_OS_BROKER_SOCKET": broker_socket,
    }
    if env:
        full_env.update({str(k): str(v) for k, v in env.items()})
    for key, value in full_env.items():
        argv += ["--setenv", key, value]

    argv += ["--chdir", project_root, "--"]
    argv += list(agent_argv)
    return argv


def writable_binds(argv) -> list[str]:
    """The rw bind targets in a box argv -- audit helper. There must be exactly
    two: the project root and the broker socket."""
    binds: list[str] = []
    for i, tok in enumerate(argv):
        if tok == "--bind" and i + 2 < len(argv):
            binds.append(argv[i + 2])
    return binds


def box_available(bwrap: str = "bwrap") -> bool:
    """True only where a real box can run: Linux with bwrap present."""
    return sys.platform.startswith("linux") and shutil.which(bwrap) is not None


def launch(
    agent_argv,
    *,
    project_root,
    broker_socket,
    ro_system=DEFAULT_RO_SYSTEM,
    env=None,
    bwrap: str = "bwrap",
) -> "int":
    """Build the box and exec it (replaces this process). Linux + bwrap only.

    The broker must already be LISTENING on `broker_socket` before launch, since
    the box's only egress is that socket -- no window, no exit (fail-closed).
    """
    if not box_available(bwrap):
        raise RuntimeError(
            "no box available: need Linux + bwrap (on Windows, run inside WSL2)"
        )
    argv = build_box_argv(
        agent_argv,
        project_root=project_root,
        broker_socket=broker_socket,
        ro_system=ro_system,
        env=env,
        bwrap=bwrap,
    )
    os.execvp(argv[0], argv)
    return 127  # unreachable if execvp succeeds


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 3:
        sys.stderr.write(
            "usage: pub_os_box.py <project_root> <broker_socket> <agent_cmd> [args...]\n"
        )
        return 2
    project_root, broker_socket, *agent = args
    return launch(agent, project_root=project_root, broker_socket=broker_socket)


if __name__ == "__main__":
    raise SystemExit(main())
