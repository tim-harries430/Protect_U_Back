"""PUB-OS Codex/Claude Code supervision profile tests."""

from __future__ import annotations

import os
import sys

_PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)

from pub_os_profiles import (  # noqa: E402
    AgentRuntimeAdmission,
    ProfileState,
    check_agent_runtime,
    check_claude_code_profile,
    check_codex_profile,
    check_kingdom_supervision,
)


def _codex_status(**overrides):
    status = {
        "connected": True,
        "launcher_exists": True,
        "entry_exists": True,
        "boundary": "bwrap_shell_entry_bind_mount",
        "can_grant_permission": False,
    }
    status.update(overrides)
    return status


def _claude_status(**overrides):
    status = {
        "connected": True,
        "gate_switch": "on",
        "matcher": "*",
        "pretool_hook": True,
        "posttool_hook": True,
    }
    status.update(overrides)
    return status


def test_codex_profile_supervised_when_guard_connected():
    receipt = check_codex_profile(status_fn=lambda *args, **kwargs: _codex_status())

    assert receipt.state == ProfileState.SUPERVISED
    assert receipt.profile.value == "cd"
    assert receipt.reason_code == "CD_PROFILE_SUPERVISED"
    assert receipt.can_execute is False
    assert receipt.can_grant_permission is False


def test_codex_profile_holds_when_guard_missing_or_authority_leaks():
    receipt = check_codex_profile(
        status_fn=lambda *args, **kwargs: _codex_status(
            connected=False,
            entry_exists=False,
            can_grant_permission=True,
        )
    )

    assert receipt.state == ProfileState.HOLD
    assert receipt.reason_code == "CD_PROFILE_NOT_SUPERVISED"
    assert "cd_connector:not_connected" in receipt.evidence
    assert "cd_entry:missing" in receipt.evidence
    assert "cd_connector:authority_leak" in receipt.evidence


def test_claude_code_profile_supervised_when_all_tool_hooks_armed():
    receipt = check_claude_code_profile(status_fn=lambda *args, **kwargs: _claude_status())

    assert receipt.state == ProfileState.SUPERVISED
    assert receipt.profile.value == "cc"
    assert receipt.reason_code == "CC_PROFILE_SUPERVISED"
    assert receipt.can_execute is False
    assert receipt.can_grant_permission is False


def test_claude_code_profile_holds_when_gate_off_or_matcher_partial():
    receipt = check_claude_code_profile(
        status_fn=lambda *args, **kwargs: _claude_status(
            gate_switch="off",
            matcher="Bash",
            posttool_hook=False,
        )
    )

    assert receipt.state == ProfileState.HOLD
    assert "cc_gate:not_armed" in receipt.evidence
    assert "cc_matcher:not_all_tools" in receipt.evidence
    assert "cc_posttool:missing" in receipt.evidence


def test_agent_runtime_checks_only_active_cd_profile():
    admission = check_agent_runtime(
        "cd",
        cd_status_fn=lambda *args, **kwargs: _codex_status(),
    )

    assert admission.state == ProfileState.HOLD
    assert admission.reason_code == "AGENT_RUNTIME_UNMANAGED"
    assert "runner:not_attached" in admission.evidence
    assert admission.to_dict()["active_profile"] == "cd"
    assert admission.to_dict()["runner_attached"] is False


def test_agent_runtime_supervised_only_when_runner_attached_cd():
    admission = check_agent_runtime(
        "cd",
        cd_status_fn=lambda *args, **kwargs: _codex_status(),
        runner_attached=True,
    )

    assert admission.state == ProfileState.SUPERVISED
    assert admission.reason_code == "AGENT_RUNTIME_SUPERVISED"
    assert admission.to_dict()["active_profile"] == "cd"
    assert admission.to_dict()["runner_attached"] is True


def test_agent_runtime_checks_only_active_cc_profile():
    admission = check_agent_runtime(
        "cc",
        cc_status_fn=lambda *args, **kwargs: _claude_status(),
        cd_status_fn=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("cd was checked")),
    )

    assert admission.state == ProfileState.HOLD
    assert admission.reason_code == "AGENT_RUNTIME_UNMANAGED"
    assert "runner:not_attached" in admission.evidence
    assert admission.to_dict()["active_profile"] == "cc"


def test_agent_runtime_supervised_only_when_runner_attached_cc():
    admission = check_agent_runtime(
        "cc",
        cc_status_fn=lambda *args, **kwargs: _claude_status(),
        cd_status_fn=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("cd was checked")),
        runner_attached=True,
    )

    assert admission.state == ProfileState.SUPERVISED
    assert admission.reason_code == "AGENT_RUNTIME_SUPERVISED"
    assert admission.to_dict()["active_profile"] == "cc"


def test_agent_runtime_holds_profile_mismatch():
    receipt = check_codex_profile(status_fn=lambda *args, **kwargs: _codex_status())
    admission = AgentRuntimeAdmission("cc", receipt)

    assert admission.state == ProfileState.HOLD
    assert admission.reason_code == "AGENT_RUNTIME_PROFILE_MISMATCH"
    assert "active_profile:cc" in admission.evidence
    assert "receipt_profile:cd" in admission.evidence


def test_kingdom_supervision_is_active_profile_adapter():
    ok = check_kingdom_supervision(
        active_profile="cc",
        cc_status_fn=lambda *args, **kwargs: _claude_status(),
        runner_attached=True,
    )
    bad = check_kingdom_supervision(
        active_profile="cd",
        cd_status_fn=lambda *args, **kwargs: _codex_status(connected=False),
    )

    assert ok.state == ProfileState.SUPERVISED
    assert ok.reason_code == "AGENT_RUNTIME_SUPERVISED"
    assert bad.state == ProfileState.HOLD
    assert bad.reason_code == "CD_PROFILE_NOT_SUPERVISED"


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
