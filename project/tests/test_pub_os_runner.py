"""PUB-OS runner skeleton tests."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)

from pub_os_runner import RunnerState, append_ledger_entry, prepare_agent_run, start_agent_run  # noqa: E402
from pub_os_visibility import KingdomSession, SensorName, SensorState, SensorStatus  # noqa: E402


def _cd_status(**overrides):
    status = {
        "connected": True,
        "launcher_exists": True,
        "entry_exists": True,
        "boundary": "bwrap_shell_entry_bind_mount",
        "launch_command": r"C:\work\.pub_codex_guard\codex-pub",
        "can_grant_permission": False,
    }
    status.update(overrides)
    return status


def _cc_status(**overrides):
    status = {
        "connected": True,
        "gate_switch": "on",
        "matcher": "*",
        "pretool_hook": True,
        "posttool_hook": True,
    }
    status.update(overrides)
    return status


def test_cd_runner_ready_uses_pub_launcher_and_redacts_argv():
    plan = prepare_agent_run(
        "cd",
        project_root=r"C:\work",
        session_id="s1",
        actor_id="agent",
        agent_args=(
            "--model",
            "secret-ish-model-name",
            "--sandbox",
            "workspace-write",
            "--approval-policy",
            "on-request",
        ),
        cd_status_fn=lambda *args, **kwargs: _cd_status(),
    )

    data = plan.to_dict()
    assert plan.state == RunnerState.READY
    assert plan.reason_code == "RUNNER_READY"
    assert plan.argv[0].endswith("codex-pub")
    assert "cd_sandbox:contained" in plan.evidence
    assert "cd_approval:contained" in plan.evidence
    assert data["argv_sha256"].startswith("sha256:")
    assert "secret-ish-model-name" not in str(data)
    assert data["can_execute"] is False
    assert data["can_grant_permission"] is False


def test_cd_runner_fails_closed_without_declared_containment():
    # No sandbox / approval declared at all -> refuse to fly (fail closed).
    plan = prepare_agent_run(
        "cd",
        project_root=r"C:\work",
        session_id="s1-nodecl",
        agent_args=("--model", "anything"),
        cd_status_fn=lambda *args, **kwargs: _cd_status(),
    )
    assert plan.state == RunnerState.HOLD
    assert plan.reason_code == "CD_SANDBOX_NOT_DECLARED"
    assert plan.argv == ()

    # Sandbox armed but approval rail left undeclared -> still refuse.
    plan = prepare_agent_run(
        "cd",
        project_root=r"C:\work",
        session_id="s1-noappr",
        agent_args=("--sandbox", "workspace-write"),
        cd_status_fn=lambda *args, **kwargs: _cd_status(),
    )
    assert plan.state == RunnerState.HOLD
    assert plan.reason_code == "CD_APPROVAL_NOT_DECLARED"


def test_cd_runner_holds_unknown_sandbox_value_blacklist_misses():
    # "experimental-mode" is not in the denied blacklist, yet it is not a known
    # contained mode either -> the positive allowlist must still refuse it.
    plan = prepare_agent_run(
        "cd",
        project_root=r"C:\work",
        session_id="s1-unknown",
        agent_args=("--sandbox", "experimental-mode", "--approval-policy", "on-request"),
        cd_status_fn=lambda *args, **kwargs: _cd_status(),
    )
    assert plan.state == RunnerState.HOLD
    assert plan.reason_code == "CD_SANDBOX_NOT_CONTAINED"
    assert "cd_sandbox:experimental-mode" in plan.evidence


def test_cd_runner_allows_tighter_readonly_and_untrusted():
    plan = prepare_agent_run(
        "cd",
        project_root=r"C:\work",
        session_id="s1-tight",
        agent_args=("--sandbox", "read-only", "--approval-policy", "untrusted"),
        cd_status_fn=lambda *args, **kwargs: _cd_status(),
    )
    assert plan.state == RunnerState.READY
    assert "cd_sandbox:contained" in plan.evidence


def test_cd_runner_holds_dangerous_supervision_bypass_args():
    cases = (
        ("--dangerously-bypass-approvals-and-sandbox",),
        ("--full-auto",),
        ("--sandbox", "danger-full-access"),
        ("--sandbox=danger-full-access",),
        ("-s", "full"),
        ("--approval-policy", "never"),
        ("--approval-policy=never",),
        ("--ask-for-approval", "never"),
        ("--ask-for-approval=never",),
        ("-a", "never"),
        ("--config", "sandbox_mode=danger-full-access"),
        ("--config=approval_policy=never",),
        ("-c", "ask_for_approval=never"),
    )

    for args in cases:
        plan = prepare_agent_run(
            "cd",
            project_root=r"C:\work",
            session_id="s1-cd-bypass",
            agent_args=args,
            cd_status_fn=lambda *fn_args, **kwargs: _cd_status(),
        )

        assert plan.state == RunnerState.HOLD
        assert plan.reason_code == "CD_UNSUPERVISED_ARG"
        assert plan.argv == ()


def test_cd_runner_holds_missing_policy_values():
    cases = (
        (("--sandbox",), "CD_SANDBOX_MODE_MISSING"),
        (("--approval-policy",), "CD_APPROVAL_POLICY_MISSING"),
        (("--config",), "CD_CONFIG_MISSING"),
    )

    for args, reason_code in cases:
        plan = prepare_agent_run(
            "cd",
            project_root=r"C:\work",
            session_id="s1-cd-missing",
            agent_args=args,
            cd_status_fn=lambda *fn_args, **kwargs: _cd_status(),
        )

        assert plan.state == RunnerState.HOLD
        assert plan.reason_code == reason_code


def test_cd_runner_allows_supervised_sandbox_and_approval_modes():
    plan = prepare_agent_run(
        "cd",
        project_root=r"C:\work",
        session_id="s1-cd-ok",
        agent_args=(
            "--sandbox",
            "workspace-write",
            "--approval-policy",
            "on-request",
            "--config",
            "sandbox_mode=workspace-write",
        ),
        cd_status_fn=lambda *args, **kwargs: _cd_status(),
    )

    assert plan.state == RunnerState.READY
    assert plan.argv[0].endswith("codex-pub")
    assert "--sandbox" in plan.argv


def test_runner_holds_when_profile_is_not_supervised():
    plan = prepare_agent_run(
        "cd",
        project_root=r"C:\work",
        session_id="s2",
        cd_status_fn=lambda *args, **kwargs: _cd_status(connected=False),
    )

    assert plan.state == RunnerState.HOLD
    assert plan.reason_code == "CD_PROFILE_NOT_SUPERVISED"
    assert "cd_connector:not_connected" in plan.evidence


def test_runner_holds_when_required_sensor_not_ready():
    session = KingdomSession(
        session_id="s3",
        actor_id="agent",
        project_root=r"C:\work",
        cwd=r"C:\work",
        sensors=(
            SensorState(SensorName.PROCESS, SensorStatus.READY),
            SensorState(SensorName.FILESYSTEM, SensorStatus.DEGRADED),
            SensorState(SensorName.SCENE, SensorStatus.READY),
            SensorState(SensorName.AUDIT, SensorStatus.READY),
        ),
    )
    plan = prepare_agent_run(
        "cd",
        project_root=r"C:\work",
        session=session,
        cd_status_fn=lambda *args, **kwargs: _cd_status(),
    )

    assert plan.state == RunnerState.HOLD
    assert plan.reason_code == "KINGDOM_SENSOR_NOT_READY"
    assert "filesystem:DEGRADED" in plan.evidence


def test_cc_runner_checks_only_active_cc_profile():
    plan = prepare_agent_run(
        "cc",
        project_root=r"C:\work",
        session_id="s4",
        agent_args=("--continue",),
        cc_command="claude",
        cc_status_fn=lambda *args, **kwargs: _cc_status(),
        cd_status_fn=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("cd was checked")),
    )

    assert plan.state == RunnerState.READY
    assert plan.argv == ("claude", "--continue")
    assert "cc_hooks:armed" in plan.evidence


def test_cc_runner_holds_dangerous_supervision_bypass_args():
    cases = (
        ("--bare",),
        ("--safe-mode",),
        ("--dangerously-skip-permissions",),
        ("--allow-dangerously-skip-permissions",),
        ("--permission-mode", "bypassPermissions"),
        ("--permission-mode=bypassPermissions",),
        ("--permission-mode", "dontAsk"),
        ("--permission-mode=dontAsk",),
        ("--permission-mode", "acceptEdits"),
        ("--permission-mode=acceptEdits",),
    )

    for args in cases:
        plan = prepare_agent_run(
            "cc",
            project_root=r"C:\work",
            session_id="s4-bypass",
            agent_args=args,
            cc_status_fn=lambda *fn_args, **kwargs: _cc_status(),
        )

        assert plan.state == RunnerState.HOLD
        assert plan.reason_code == "CC_UNSUPERVISED_ARG"
        assert plan.argv == ()


def test_cc_runner_holds_missing_permission_mode_value():
    plan = prepare_agent_run(
        "cc",
        project_root=r"C:\work",
        session_id="s4-missing-mode",
        agent_args=("--permission-mode",),
        cc_status_fn=lambda *args, **kwargs: _cc_status(),
    )

    assert plan.state == RunnerState.HOLD
    assert plan.reason_code == "CC_PERMISSION_MODE_MISSING"
    assert "cc_arg:--permission-mode" in plan.evidence


def test_cc_runner_allows_supervised_permission_mode_default():
    plan = prepare_agent_run(
        "cc",
        project_root=r"C:\work",
        session_id="s4-default-mode",
        agent_args=("--permission-mode", "default"),
        cc_status_fn=lambda *args, **kwargs: _cc_status(),
    )

    assert plan.state == RunnerState.READY
    assert plan.argv == ("claude", "--permission-mode", "default")


def test_start_requires_explicit_executor_then_records_root_pid():
    plan = prepare_agent_run(
        "cc",
        project_root=r"C:\work",
        session_id="s5",
        cc_status_fn=lambda *args, **kwargs: _cc_status(),
    )
    dry = start_agent_run(plan)
    calls = []

    class FakeProcess:
        pid = 4321

    def fake_spawn(argv, *, cwd, env):
        calls.append((argv, cwd, env["PUB_OS_SESSION_ID"]))
        return FakeProcess()

    started = start_agent_run(plan, spawn_fn=fake_spawn)

    assert dry.state == RunnerState.HOLD
    assert dry.reason_code == "RUNNER_EXECUTOR_REQUIRED"
    assert started.state == RunnerState.STARTED
    assert started.root_pid == 4321
    assert calls == [(("claude",), str(Path(r"C:\work").resolve(strict=False)), "s5")]
    assert started.can_execute is False
    assert started.can_grant_permission is False


def test_ledger_is_append_only_and_rejects_payload_fields():
    plan = prepare_agent_run(
        "cc",
        project_root=r"C:\work",
        session_id="s6",
        cc_status_fn=lambda *args, **kwargs: _cc_status(),
    )
    with tempfile.TemporaryDirectory() as tmp:
        ledger = Path(tmp) / "session.jsonl"
        append_ledger_entry(ledger, plan)
        line = ledger.read_text(encoding="utf-8").strip()

    assert '"session_id":"s6"' in line
    assert "payload" not in line
    try:
        append_ledger_entry(Path(tempfile.gettempdir()) / "pub_os_bad_ledger.jsonl", {"payload": "blocked"})
    except ValueError as exc:
        assert "payload" in str(exc)
    else:
        raise AssertionError("ledger must reject payload fields")


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
