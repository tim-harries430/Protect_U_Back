"""Contract tests for the prison-door window (pub_os_broker).

Each test pins a runtime-verifiable clause of PUB_OS_BROKER_CONTRACT.md:
relays verbatim, never inspects content, drops malformed/oversized, fails closed.
"""

from __future__ import annotations

import socket
import struct
import threading

from pub_os_broker import (
    MAX_FRAME_BYTES,
    make_listener,
    read_frame,
    relay,
    serve,
)


def frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


class Window:
    """A live window: relay() between the inner ends of two socketpairs; the test
    drives the outer ends (box side and core side)."""

    def __init__(self, max_frame: int = MAX_FRAME_BYTES):
        self.box_outer, box_inner = socket.socketpair()
        self.core_outer, core_inner = socket.socketpair()
        self.box_outer.settimeout(3.0)
        self.core_outer.settimeout(3.0)
        self.thread = threading.Thread(
            target=relay, args=(box_inner, core_inner),
            kwargs={"max_frame": max_frame}, daemon=True,
        )
        self.thread.start()

    def close(self):
        for sock in (self.box_outer, self.core_outer):
            try:
                sock.close()
            except OSError:
                pass
        self.thread.join(timeout=2.0)


# --- read_frame: framing discipline (no content interpretation) ------------ #

def test_read_frame_returns_header_plus_payload_verbatim():
    a, b = socket.socketpair()
    a.sendall(frame(b"opaque-bytes"))
    assert read_frame(b) == frame(b"opaque-bytes")
    a.close(); b.close()


def test_read_frame_rejects_zero_length():
    a, b = socket.socketpair()
    a.sendall(struct.pack("!I", 0))
    assert read_frame(b) is None  # fail-closed
    a.close(); b.close()


def test_read_frame_rejects_oversized_without_reading_payload():
    a, b = socket.socketpair()
    a.sendall(struct.pack("!I", 65))  # header only; payload never sent
    assert read_frame(b, max_frame=64) is None  # bails on length, fail-closed
    a.close(); b.close()


def test_read_frame_truncated_payload_returns_none():
    a, b = socket.socketpair()
    a.sendall(struct.pack("!I", 10) + b"abc")  # promises 10, sends 3
    a.close()  # then EOF
    assert read_frame(b) is None
    b.close()


def test_read_frame_clean_eof_returns_none():
    a, b = socket.socketpair()
    a.close()
    assert read_frame(b) is None
    b.close()


# --- relay: dumb bidirectional pass-through -------------------------------- #

def test_relay_forwards_both_directions_verbatim():
    w = Window()
    try:
        w.box_outer.sendall(frame(b"request->core"))
        assert read_frame(w.core_outer) == frame(b"request->core")
        w.core_outer.sendall(frame(b"verdict->box"))
        assert read_frame(w.box_outer) == frame(b"verdict->box")
    finally:
        w.close()


def test_relay_forwards_arbitrary_binary_unchanged():
    # Payload that "looks like" commands / control bytes / pub's own markers:
    # the window must relay it byte-identical, proving no content branching.
    w = Window()
    try:
        for payload in (
            b"rm -rf / ; python3.11 -c 'evil'",
            b"\x00\x01\x02\xff\xfe{}();|&<>",
            b"XRAY_REVIEW_SUBSTITUTION PUB_OS_OPAQUE_EXECUTION_HOLD",
            bytes(range(256)),
        ):
            w.box_outer.sendall(frame(payload))
            got = read_frame(w.core_outer)
            assert got == frame(payload)
            assert got[4:] == payload  # payload survives exactly
    finally:
        w.close()


def test_relay_many_frames_stateless():
    w = Window()
    try:
        for i in range(50):
            w.box_outer.sendall(frame(f"f{i}".encode()))
        for i in range(50):
            assert read_frame(w.core_outer) == frame(f"f{i}".encode())
    finally:
        w.close()


# --- fail-closed: a bad frame or EOF seals the window ---------------------- #

def test_relay_oversized_frame_seals_window_and_other_side_gets_eof():
    w = Window(max_frame=64)
    try:
        # box sends an oversized frame -> window tears down -> core gets EOF and
        # the frame is NOT forwarded.
        w.box_outer.sendall(struct.pack("!I", 65) + b"x" * 65)
        assert read_frame(w.core_outer) is None  # denied, not delivered
    finally:
        w.close()


def test_relay_box_eof_seals_window():
    w = Window()
    try:
        w.box_outer.close()  # box hangs up
        assert read_frame(w.core_outer) is None  # core sees the seal
    finally:
        w.thread.join(timeout=2.0)
        try:
            w.core_outer.close()
        except OSError:
            pass


# --- serve: accept box, connect core, relay (the wiring) ------------------- #

def test_serve_accepts_box_connects_core_and_relays_both_ways():
    core_listener = make_listener(("127.0.0.1", 0), family=socket.AF_INET)
    box_listener = make_listener(("127.0.0.1", 0), family=socket.AF_INET)
    core_addr = core_listener.getsockname()
    box_addr = box_listener.getsockname()

    server = threading.Thread(
        target=serve, args=(box_listener, core_addr),
        kwargs={"family": socket.AF_INET, "accept_limit": 1}, daemon=True,
    )
    server.start()

    box = socket.create_connection(box_addr, timeout=3.0)  # triggers accept
    core_conn, _ = core_listener.accept()  # broker connected out to core
    box.settimeout(3.0)
    core_conn.settimeout(3.0)
    try:
        box.sendall(frame(b"REQ"))
        assert read_frame(core_conn) == frame(b"REQ")
        core_conn.sendall(frame(b"AUTHED_VERDICT"))
        assert read_frame(box) == frame(b"AUTHED_VERDICT")
    finally:
        box.close()
        core_conn.close()
        core_listener.close()
        box_listener.close()
        server.join(timeout=2.0)
