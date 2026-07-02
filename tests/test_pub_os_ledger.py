"""PUB-OS out-of-cage ledger tests.

The record/chain/reject/tamper/resume tests are pure logic and run anywhere.
The socket round-trip needs AF_UNIX; it self-skips where that is unavailable
(e.g. some Windows interpreters). The full in-cage-emit -> out-of-cage-write
demonstration runs under real bwrap in a separate harness, not here.
"""
from __future__ import annotations

import os
import socket
import sys
import tempfile

_PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)

from pub_os_ledger import (  # noqa: E402
    LedgerEventRejected,
    LedgerSupervisor,
    LedgerUnavailable,
    emit_event,
    verify_chain,
)

_HAS_UNIX = hasattr(socket, "AF_UNIX")


def _sup(tmp):
    return LedgerSupervisor(
        ledger_path=os.path.join(tmp, "ledger.jsonl"),
        socket_path=os.path.join(tmp, "l.sock"),
    )


def test_record_appends_and_chains():
    with tempfile.TemporaryDirectory() as tmp:
        sup = _sup(tmp)
        a = sup.record({"phase": "pretool", "tool_name": "Write", "disposition": "PASS"})
        b = sup.record({"phase": "pretool", "tool_name": "Bash", "disposition": "HOLD"})

        assert a["seq"] == 1 and b["seq"] == 2
        rows = sup.rows()
        assert len(rows) == 2
        assert rows[1]["prev_hash"] == rows[0]["row_hash"]
        ok, reason = verify_chain(rows)
        assert ok, reason


def test_record_rejects_payload_and_authority():
    with tempfile.TemporaryDirectory() as tmp:
        sup = _sup(tmp)
        for bad in ({"payload": "secret bytes"}, {"can_execute": True}, {"permission_granted": True}):
            try:
                sup.record(bad)
            except LedgerEventRejected as exc:
                assert any(k in str(exc) for k in ("payload", "can_execute", "permission_granted"))
            else:
                raise AssertionError(f"must reject {bad}")
        # A benign explicit can_execute=False is allowed through.
        sup.record({"phase": "pretool", "can_execute": False})
        assert sup.rows()[-1]["event"]["can_execute"] is False


def test_tampering_breaks_the_chain():
    with tempfile.TemporaryDirectory() as tmp:
        sup = _sup(tmp)
        sup.record({"phase": "a", "disposition": "PASS"})
        sup.record({"phase": "b", "disposition": "PASS"})
        sup.record({"phase": "c", "disposition": "KILL"})

        rows = sup.rows()
        assert verify_chain(rows)[0] is True
        # Flip a recorded disposition (as a file tamperer would).
        rows[1]["event"]["disposition"] = "ALLOWED_BY_ATTACKER"
        ok, reason = verify_chain(rows)
        assert ok is False
        assert "row_hash_mismatch" in reason


def test_dropping_a_row_breaks_the_chain():
    with tempfile.TemporaryDirectory() as tmp:
        sup = _sup(tmp)
        for i in range(4):
            sup.record({"seqcheck": i})
        rows = sup.rows()
        del rows[2]  # drop a row
        ok, reason = verify_chain(rows)
        assert ok is False


def test_chain_resumes_across_restart():
    with tempfile.TemporaryDirectory() as tmp:
        sup = _sup(tmp)
        sup.record({"phase": "a"})
        sup.record({"phase": "b"})
        # New supervisor over the same file (e.g. after a restart).
        sup2 = _sup(tmp)
        sup2.record({"phase": "c"})
        rows = sup2.rows()
        assert [r["seq"] for r in rows] == [1, 2, 3]
        ok, reason = verify_chain(rows)
        assert ok, reason


def test_socket_round_trip_records_event():
    if not _HAS_UNIX:
        print("SKIP: AF_UNIX unavailable on this platform")
        return
    with tempfile.TemporaryDirectory() as tmp:
        sup = _sup(tmp).start()
        thread = sup.serve_in_thread(max_events=1, timeout=5.0)
        ack = emit_event(sup.socket_path, {"phase": "pretool", "tool_name": "Write", "disposition": "PASS"})
        thread.join(timeout=5.0)
        sup.close()

        assert ack["seq"] == 1
        rows = sup.rows()
        assert len(rows) == 1
        assert rows[0]["event"]["tool_name"] == "Write"
        assert rows[0]["source"] == "in_cage_hook"
        assert verify_chain(rows)[0] is True


def test_emit_fails_closed_without_supervisor():
    if not _HAS_UNIX:
        print("SKIP: AF_UNIX unavailable on this platform")
        return
    with tempfile.TemporaryDirectory() as tmp:
        try:
            emit_event(os.path.join(tmp, "nonexistent.sock"), {"phase": "pretool"}, timeout=1.0)
        except LedgerUnavailable as exc:
            assert "cannot reach ledger supervisor" in str(exc)
        else:
            raise AssertionError("emit must fail closed when the supervisor is unreachable")


def test_socket_rejects_payload_event_with_reason():
    if not _HAS_UNIX:
        print("SKIP: AF_UNIX unavailable on this platform")
        return
    with tempfile.TemporaryDirectory() as tmp:
        sup = _sup(tmp).start()
        thread = sup.serve_in_thread(max_events=5, timeout=3.0)
        try:
            emit_event(sup.socket_path, {"payload": "secret"})
        except LedgerEventRejected as exc:
            assert "payload" in str(exc)
        else:
            raise AssertionError("a payload-bearing event must be rejected over the socket")
        finally:
            thread.join(timeout=3.0)
            sup.close()
        assert sup.rows() == []


def _run_all():
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
