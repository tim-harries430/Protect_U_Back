"""Fail-closed witness tests (PUB-OS Task 3, final wiring).

When a cc cage's only audit egress is the out-of-cage ledger, a lost witness
must TIGHTEN admission to a denied HOLD rather than let an unrecorded action proceed.
These tests drive the escalation logic in ``run_pretool_admission`` by
monkeypatching the witness status, so they are decoupled from socket transport
and run under any interpreter (no AF_UNIX needed).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

_PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)

import claude_code_hooks as h  # noqa: E402


def _env(tmp):
    return {
        **os.environ,
        "PUB_CLAUDE_HOOK_LOG_DIR": tmp + "/logs",
        "PUB_CLAUDE_HOOK_STATE_DIR": tmp + "/state",
        "PUB_CLAUDE_TEMPORAL_STATE_DIR": tmp + "/temporal",
    }


def _admit(proj, env):
    event = {
        "session_id": "fc",
        "cwd": proj,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status --short"},
        "tool_use_id": "fc1",
    }
    return h.run_pretool_admission(json.dumps(event), environ=env)


def _decision(adm):
    return (adm.output or {}).get("hookSpecificOutput", {}).get("permissionDecision")


def _with_witness(status):
    """Context-ish helper: swap _mirror_to_ledger to report a fixed status."""
    original = h._mirror_to_ledger
    h._mirror_to_ledger = lambda env, payload: status
    return original


def test_lost_witness_escalates_a_passing_action_to_denied_hold():
    with tempfile.TemporaryDirectory() as tmp:
        proj = tmp + "/repo"
        os.makedirs(proj)
        original = _with_witness("unavailable")
        try:
            adm = _admit(proj, _env(tmp))
        finally:
            h._mirror_to_ledger = original

        assert _decision(adm) == "deny", "a lost witness must deny native allow"
        reason = adm.output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "PUB_OS_LEDGER_WITNESS_LOST" in reason


def test_recorded_witness_does_not_escalate():
    with tempfile.TemporaryDirectory() as tmp:
        proj = tmp + "/repo"
        os.makedirs(proj)
        original = _with_witness("recorded")
        try:
            adm = _admit(proj, _env(tmp))
        finally:
            h._mirror_to_ledger = original

        assert not adm.blocked, "a recorded witness must leave a passing action alone"
        assert _decision(adm) is None


def test_not_configured_is_unchanged_default_behavior():
    with tempfile.TemporaryDirectory() as tmp:
        proj = tmp + "/repo"
        os.makedirs(proj)
        # No monkeypatch, no PUB_OS_LEDGER_SOCKET -> _mirror_to_ledger returns
        # "not_configured" -> escalation never fires.
        adm = _admit(proj, _env(tmp))
        assert not adm.blocked
        assert _decision(adm) is None


def test_gate_off_file_cannot_override_lost_witness():
    with tempfile.TemporaryDirectory() as tmp:
        proj = tmp + "/repo"
        os.makedirs(proj + "/.claude")
        open(proj + "/.claude/pub_gate_switch.json", "w").write('{"enabled": false}')
        original = _with_witness("unavailable")
        try:
            adm = _admit(proj, _env(tmp))
        finally:
            h._mirror_to_ledger = original

        # A stale/off switch is only logged; lost witness remains denied HOLD.
        assert _decision(adm) == "deny"
        reason = adm.output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "PUB_OS_LEDGER_WITNESS_LOST" in reason


def test_lost_witness_does_not_downgrade_a_deny():
    # Escalation is tighten-only: an action already destined to be blocked must
    # not be softened by the witness-lost path.
    with tempfile.TemporaryDirectory() as tmp:
        proj = tmp + "/repo"
        os.makedirs(proj)
        original = _with_witness("unavailable")
        try:
            event = {
                "session_id": "fc",
                "cwd": proj,
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "python -c \"open('x','w').write('a')\""},
                "tool_use_id": "fc2",
            }
            adm = h.run_pretool_admission(json.dumps(event), environ=_env(tmp))
        finally:
            h._mirror_to_ledger = original

        # The opaque-executor blindspot already holds/denies this; witness-lost
        # must not weaken whatever the gate decided.
        assert adm.blocked
        assert _decision(adm) == "deny"


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
