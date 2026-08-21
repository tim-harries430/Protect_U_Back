"""Contract tests for the prison cell (pub_os_box).

Policy tests run anywhere -- they pin the confinement encoded in the bwrap argv.
Integration tests (skipped unless a real box is available: Linux + bwrap, i.e.
WSL2 on Windows) PROVE the confinement from INSIDE the box: no network, no host
filesystem beyond the project root, and the broker socket reachable.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile

import pytest

from pub_os_box import box_available, build_box_argv, writable_binds


def _triple(argv, a, b, c) -> bool:
    """Is the consecutive triple [a, b, c] present in argv?"""
    for i in range(len(argv) - 2):
        if argv[i] == a and argv[i + 1] == b and argv[i + 2] == c:
            return True
    return False


def _argv(project="/proj/root", socket_path="/run/pub/broker.sock", agent=("python3", "-c", "1")):
    return build_box_argv(agent, project_root=project, broker_socket=socket_path)


# --- confinement policy (runs on any host) --------------------------------- #

def test_box_kills_network():
    assert "--unshare-net" in _argv()  # no route, no interface


def test_box_clears_host_env():
    assert "--clearenv" in _argv()


def test_box_dies_with_parent():
    assert "--die-with-parent" in _argv()  # fail-closed: box dies with launcher


def test_only_two_writable_surfaces_project_and_socket():
    project = "/proj/root"
    sock = "/run/pub/broker.sock"
    binds = writable_binds(build_box_argv(("python3",), project_root=project, broker_socket=sock))
    assert binds == [os.path.abspath(project), os.path.abspath(sock)]


def test_box_does_not_bind_host_root_or_home():
    binds = writable_binds(_argv())
    assert os.path.abspath("/") not in binds
    # exactly the two declared surfaces are writable; nothing else.
    assert len(binds) == 2


def test_box_exposes_broker_socket_env():
    sock = "/run/pub/broker.sock"
    argv = build_box_argv(("python3",), project_root="/p", broker_socket=sock)
    assert _triple(argv, "--setenv", "PUB_OS_BROKER_SOCKET", os.path.abspath(sock))


def test_box_runtime_is_read_only_system():
    argv = _argv()
    assert _triple(argv, "--ro-bind-try", "/usr", "/usr")  # system present, read-only
    assert "--tmpfs" in argv and argv[argv.index("--tmpfs") + 1] == "/tmp"  # scratch only


def test_box_runs_agent_after_separator():
    argv = build_box_argv(("python3", "-c", "print(1)"), project_root="/p", broker_socket="/s")
    sep = argv.index("--")
    assert argv[sep + 1:] == ["python3", "-c", "print(1)"]


def test_box_chdir_into_project():
    project = "/proj/root"
    argv = build_box_argv(("python3",), project_root=project, broker_socket="/s")
    assert _triple(argv, "--chdir", os.path.abspath(project), "--")


# --- confinement IN FACT (runs only inside a real box: WSL2 / Linux+bwrap) -- #

_PROBE = r"""
import os, socket, sys
host_sentinel = sys.argv[1]
broker_sock = os.environ.get("PUB_OS_BROKER_SOCKET", "")
# 1. network must be dead
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
    s.connect(("1.1.1.1", 53)); print("NET=OPEN")
except OSError:
    print("NET=BLOCKED")
# 2. host filesystem outside the project root must not exist
print("HOST_SENTINEL=" + ("VISIBLE" if os.path.exists(host_sentinel) else "GONE"))
# 3. the one egress -- the broker socket -- must be reachable
print("BROKER=" + ("PRESENT" if broker_sock and os.path.exists(broker_sock) else "ABSENT"))
"""


@pytest.mark.skipif(not box_available(), reason="needs a real box: Linux + bwrap (WSL2)")
def test_box_confines_in_fact(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    # a host file OUTSIDE the project root -- must be invisible from inside.
    host_dir = tempfile.mkdtemp()
    host_sentinel = os.path.join(host_dir, "host_secret.txt")
    with open(host_sentinel, "w") as handle:
        handle.write("host-only")

    # a real broker socket the box may reach (its single egress).
    sock_path = str(project / "broker.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen()
    try:
        argv = build_box_argv(
            [sys.executable, "-c", _PROBE, host_sentinel],
            project_root=str(project),
            broker_socket=sock_path,
        )
        out = subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout
    finally:
        listener.close()

    assert "NET=BLOCKED" in out, out          # no network
    assert "HOST_SENTINEL=GONE" in out, out    # no host fs beyond project
    assert "BROKER=PRESENT" in out, out        # the one egress is reachable
