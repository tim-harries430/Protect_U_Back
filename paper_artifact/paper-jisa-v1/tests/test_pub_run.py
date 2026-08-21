"""Tests for the pub run mediated loop (eyes + warden behind the window).

On allow: the beast seals, the warden executes, the agent gets the result.
On deny: the agent gets a bare ok:false -- no result, no reason (one-way mirror).
The full box launch needs Linux + bwrap and is covered by test_pub_os_box +
the WSL2 integration; here we pin the host-side judge -> seal -> execute path.
"""

from __future__ import annotations

import json
import socket
import struct
import threading

from pub_os_broker import read_frame
from pub_run import mediate

KEY = b"run-shared-secret-32-bytes-xxxxxx"


def frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def _agent_and_house():
    house_side, agent_side = socket.socketpair()
    agent_side.settimeout(4.0)
    return house_side, agent_side


def test_mediate_executes_an_allowed_read(tmp_path):
    target = tmp_path / "report.md"
    target.write_bytes(b"hello world")
    house, agent = _agent_and_house()
    server = threading.Thread(target=mediate, args=(house,), kwargs={"key": KEY}, daemon=True)
    server.start()
    try:
        request = {"command": f"cat {target}", "cwd": str(tmp_path),
                   "op": {"kind": "read", "path": str(target)}}
        agent.sendall(frame(json.dumps(request).encode()))
        reply = json.loads(read_frame(agent)[4:])
        assert reply["ok"] is True
        assert bytes.fromhex(reply["result"]) == b"hello world"  # the agent got its result
    finally:
        agent.close()
        server.join(timeout=2.0)


def test_mediate_denies_dangerous_and_leaks_nothing(tmp_path):
    target = tmp_path / "report.md"
    target.write_bytes(b"TOP_SECRET")
    house, agent = _agent_and_house()
    server = threading.Thread(target=mediate, args=(house,), kwargs={"key": KEY}, daemon=True)
    server.start()
    try:
        # an opaque/blocked request -- pub denies, the warden never reads.
        request = {"command": "python3.11 -c 'evil'", "cwd": str(tmp_path),
                   "op": {"kind": "read", "path": str(target)}}
        agent.sendall(frame(json.dumps(request).encode()))
        reply_bytes = read_frame(agent)[4:]
        reply = json.loads(reply_bytes)
        assert reply == {"ok": False}          # uniform deny, no reason
        assert b"TOP_SECRET" not in reply_bytes  # the forbidden content never leaks
        assert b"726561736f6e" not in reply_bytes  # nor any hex of it / a reason
    finally:
        agent.close()
        server.join(timeout=2.0)


def test_mediate_records_full_verdict_unseen_by_agent(tmp_path):
    seen: list[dict] = []
    house, agent = _agent_and_house()
    server = threading.Thread(target=mediate, args=(house,), kwargs={"key": KEY, "record": seen.append}, daemon=True)
    server.start()
    try:
        request = {"command": "cat .env", "cwd": str(tmp_path), "op": {"kind": "read", "path": str(tmp_path / "x")}}
        agent.sendall(frame(json.dumps(request).encode()))
        reply = json.loads(read_frame(agent)[4:])
        assert reply == {"ok": False}
        assert seen and seen[0]["reason_code"]            # pub kept the full verdict
        assert seen[0]["disposition"] != "PASS"
    finally:
        agent.close()
        server.join(timeout=2.0)
