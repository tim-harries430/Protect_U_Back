"""Contract tests for pub's house (pub_os_core).

pub only judges (never executes); its one intake turns a request frame into a
MINIMAL allow/deny for the agent while pub keeps the full verdict for itself.
The one-way mirror (I7): pub sees the agent's every move; the agent sees nothing
of pub -- not its reasons, not even WHY it was blocked.
"""

from __future__ import annotations

import json
import socket
import struct
import threading

from pub_os_broker import read_frame, relay
from pub_os_core import _frame, judge, respond_to_frame, serve_core


def frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


# --- the house judges, and only judges -------------------------------------- #

def test_judge_benign_command_passes(tmp_path):
    disposition, _ = judge("git status --short", str(tmp_path))
    assert disposition == "PASS"


def test_judge_dangerous_command_is_blocked(tmp_path):
    disposition, reason = judge("python3.11 -c \"import os; os.remove('x')\"", str(tmp_path))
    assert disposition != "PASS", (disposition, reason)


def test_core_only_judges_never_executes(tmp_path):
    sentinel = tmp_path / "should_not_be_created.txt"
    judge(f"touch {sentinel.name}", str(tmp_path))
    assert not sentinel.exists()  # the house judged; it did not act


# --- the one-way mirror: the agent gets only allow/deny --------------------- #

def test_agent_reply_is_minimal_allow_for_benign(tmp_path):
    request = json.dumps({"command": "git status --short", "cwd": str(tmp_path)}).encode()
    reply = json.loads(respond_to_frame(request))
    assert reply == {"allow": True}


def test_agent_reply_leaks_no_pub_internals(tmp_path):
    request = json.dumps({"command": "cat .env", "cwd": str(tmp_path)}).encode()
    reply_bytes = respond_to_frame(request)
    assert json.loads(reply_bytes) == {"allow": False}
    # the agent must not see a reason / disposition / any pub-internal token.
    for leak in (b"reason", b"XRAY", b"PROTECT", b"CAPABILITY", b"disposition", b"HOLD", b"KILL"):
        assert leak not in reply_bytes, leak


def test_agent_cannot_distinguish_why_it_was_blocked(tmp_path):
    # two DIFFERENT block reasons inside pub (opaque executor vs secret surface)...
    opaque = respond_to_frame(json.dumps({"command": "python3.11 -c 'x'", "cwd": str(tmp_path)}).encode())
    secret = respond_to_frame(json.dumps({"command": "cat .env", "cwd": str(tmp_path)}).encode())
    # ...look IDENTICAL to the agent. It cannot map pub's decision boundary.
    assert opaque == secret == b'{"allow": false}'


# --- pub keeps the full verdict; the agent never sees it -------------------- #

def test_pub_records_full_verdict_unseen_by_agent(tmp_path):
    seen: list[dict] = []
    house_side, window_side = socket.socketpair()
    window_side.settimeout(3.0)
    server = threading.Thread(
        target=serve_core, args=(house_side,), kwargs={"record": seen.append}, daemon=True
    )
    server.start()
    try:
        window_side.sendall(frame(json.dumps({"command": "cat .env", "cwd": str(tmp_path)}).encode()))
        reply = read_frame(window_side)
        assert reply is not None
        # pub's record has the FULL verdict...
        assert seen and seen[0]["disposition"] != "PASS"
        assert seen[0]["reason_code"]  # a real pub reason
        # ...but the agent's reply is the bare minimum, with no reason.
        assert json.loads(reply[4:]) == {"allow": False}
        assert b"reason" not in reply
    finally:
        window_side.close()
        server.join(timeout=2.0)


def test_pub_observes_every_request(tmp_path):
    seen: list[dict] = []
    house_side, window_side = socket.socketpair()
    window_side.settimeout(3.0)
    server = threading.Thread(
        target=serve_core, args=(house_side,), kwargs={"record": seen.append}, daemon=True
    )
    server.start()
    try:
        for cmd in ("git status --short", "python3.11 -c 'x'", "cat .env"):
            window_side.sendall(frame(json.dumps({"command": cmd, "cwd": str(tmp_path)}).encode()))
            assert read_frame(window_side) is not None
        assert [row["command"] for row in seen] == ["git status --short", "python3.11 -c 'x'", "cat .env"]
    finally:
        window_side.close()
        server.join(timeout=2.0)


# --- the live loop: box -> window -> eyes -> minimal verdict -> box ---------- #

def test_end_to_end_box_window_eyes_verdict(tmp_path):
    box_outer, box_inner = socket.socketpair()
    core_outer, core_inner = socket.socketpair()
    box_outer.settimeout(4.0)
    seen: list[dict] = []

    window = threading.Thread(target=relay, args=(box_inner, core_inner), daemon=True)
    house = threading.Thread(
        target=serve_core, args=(core_outer,), kwargs={"record": seen.append}, daemon=True
    )
    window.start()
    house.start()
    try:
        for command, allowed in (("git status --short", True), ("python3.11 -c 'evil'", False)):
            box_outer.sendall(frame(json.dumps({"command": command, "cwd": str(tmp_path)}).encode()))
            reply = read_frame(box_outer)
            assert reply is not None, command
            assert json.loads(reply[4:]) == {"allow": allowed}, command
        # pub saw both; the agent saw only allow/deny.
        assert len(seen) == 2
    finally:
        box_outer.close()
        core_outer.close()
        window.join(timeout=2.0)
        house.join(timeout=2.0)
