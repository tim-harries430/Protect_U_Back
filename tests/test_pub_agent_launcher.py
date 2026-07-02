from __future__ import annotations

import contextlib
import io
from pathlib import Path

import pub_agent_launcher
from pub_os_profiles import AgentRuntimeAdmission, ProfileReceipt, ProfileState
from pub_os_runner import AgentRunPlan, RunnerReceipt, RunnerState
from pub_os_visibility import default_kingdom_session


def _admission(profile: str = "cc") -> AgentRuntimeAdmission:
    receipt = ProfileReceipt(
        profile,
        ProfileState.SUPERVISED,
        f"{profile.upper()}_PROFILE_SUPERVISED",
        evidence=("test:connected",),
    )
    return AgentRuntimeAdmission(profile, receipt, runner_attached=True)


def _plan(profile: str, tmp_path: Path) -> AgentRunPlan:
    return AgentRunPlan(
        session=default_kingdom_session(
            session_id=f"{profile}-session",
            actor_id="test",
            project_root=str(tmp_path),
            cwd=str(tmp_path),
        ),
        active_profile=profile,
        state=RunnerState.READY,
        reason_code="RUNNER_READY",
        admission=_admission(profile),
        argv=("agent",),
    )


def _hold_plan(profile: str, tmp_path: Path) -> AgentRunPlan:
    return AgentRunPlan(
        session=default_kingdom_session(
            session_id=f"{profile}-hold",
            actor_id="test",
            project_root=str(tmp_path),
            cwd=str(tmp_path),
        ),
        active_profile=profile,
        state=RunnerState.HOLD,
        reason_code="TEST_HOLD",
        admission=_admission(profile),
    )


class FakeProcess:
    pid = 9001

    def wait(self) -> int:
        return 0


def _run(argv, deps):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = pub_agent_launcher.main(argv, deps=deps)
    return code, out.getvalue()


def test_cc_launcher_connects_gates_verifies_prepares_and_starts(tmp_path):
    calls = []

    def prepare(profile, **kwargs):
        calls.append(("prepare", profile, kwargs["agent_args"]))
        return _plan(profile, tmp_path)

    def start(plan, *, spawn_fn, extra_env=None):
        calls.append(("start", plan.active_profile.value))
        process = spawn_fn(plan.argv, cwd=str(tmp_path), env={})
        return RunnerReceipt(
            plan.session.session_id,
            plan.active_profile,
            RunnerState.STARTED,
            "RUNNER_STARTED",
            pid=process.pid,
            root_pid=process.pid,
        )

    deps = pub_agent_launcher.LauncherDeps(
        cc_connect=lambda *args, **kwargs: calls.append(("connect", kwargs["protect_root"])) or {"connected": True},
        cc_gate=lambda *args, **kwargs: calls.append(("gate", kwargs["enabled"])) or {"connected": True},
        cc_verify=lambda *args, **kwargs: calls.append(("verify", None)) or {"preflight_blocked": True},
        cc_status=lambda *args, **kwargs: {"connected": True},
        prepare=prepare,
        start=start,
        spawn=lambda *args, **kwargs: calls.append(("spawn", args[0])) or FakeProcess(),
    )

    code, output = _run(["cc", "--project-root", str(tmp_path), "--no-verify", "--", "--continue"], deps)

    assert code == 0
    assert ("connect", str(pub_agent_launcher.CODE_ROOT)) in calls
    assert ("gate", True) in calls
    assert ("prepare", "cc", ("--permission-mode", "default", "--continue")) in calls
    assert ("start", "cc") in calls
    assert "PUB_AGENT: start state=STARTED reason_code=RUNNER_STARTED" in output


def test_cc_launcher_verify_failure_stops_before_runner(tmp_path):
    calls = []
    deps = pub_agent_launcher.LauncherDeps(
        cc_connect=lambda *args, **kwargs: {"connected": True},
        cc_gate=lambda *args, **kwargs: {"connected": True},
        cc_verify=lambda *args, **kwargs: {"preflight_blocked": False, "reason_code": "NOT_BLOCKED"},
        prepare=lambda *args, **kwargs: calls.append("prepare") or _plan("cc", tmp_path),
    )

    code, _output = _run(["cc", "--project-root", str(tmp_path)], deps)

    assert code == 1
    assert calls == []


def test_cd_launcher_adds_containment_defaults_before_user_args(tmp_path):
    seen = {}

    def prepare(profile, **kwargs):
        seen["profile"] = profile
        seen["agent_args"] = kwargs["agent_args"]
        return _plan(profile, tmp_path)

    deps = pub_agent_launcher.LauncherDeps(
        cd_connect=lambda *args, **kwargs: {"connected": True},
        cd_verify=lambda *args, **kwargs: {"preflight_blocked": True},
        cd_status=lambda *args, **kwargs: {"connected": True},
        prepare=prepare,
        start=lambda plan, *, spawn_fn, extra_env=None: RunnerReceipt(
            plan.session.session_id,
            plan.active_profile,
            RunnerState.STARTED,
            "RUNNER_STARTED",
            pid=spawn_fn(plan.argv, cwd=str(tmp_path), env={}).pid,
        ),
        spawn=lambda *args, **kwargs: FakeProcess(),
    )

    code, _output = _run(["cd", "--project-root", str(tmp_path), "--", "--model", "gpt-test"], deps)

    assert code == 0
    assert seen["profile"] == "cd"
    assert seen["agent_args"] == (
        "--sandbox",
        "workspace-write",
        "--approval-policy",
        "on-request",
        "--model",
        "gpt-test",
    )


def test_dry_run_does_not_start(tmp_path):
    calls = []
    deps = pub_agent_launcher.LauncherDeps(
        cc_connect=lambda *args, **kwargs: {"connected": True},
        cc_gate=lambda *args, **kwargs: {"connected": True},
        cc_verify=lambda *args, **kwargs: {"preflight_blocked": True},
        cc_status=lambda *args, **kwargs: {"connected": True},
        prepare=lambda *args, **kwargs: _plan("cc", tmp_path),
        start=lambda *args, **kwargs: calls.append("start"),
    )

    code, output = _run(["cc", "--project-root", str(tmp_path), "--dry-run"], deps)

    assert code == 0
    assert calls == []
    assert "PUB_AGENT: plan state=READY reason_code=RUNNER_READY" in output


def test_hold_plan_returns_hold_exit_without_start(tmp_path):
    calls = []
    deps = pub_agent_launcher.LauncherDeps(
        cc_connect=lambda *args, **kwargs: {"connected": True},
        cc_gate=lambda *args, **kwargs: {"connected": True},
        cc_verify=lambda *args, **kwargs: {"preflight_blocked": True},
        prepare=lambda *args, **kwargs: _hold_plan("cc", tmp_path),
        start=lambda *args, **kwargs: calls.append("start"),
    )

    code, output = _run(["cc", "--project-root", str(tmp_path)], deps)

    assert code == pub_agent_launcher.PLAN_HOLD_EXIT
    assert calls == []
    assert "reason_code=TEST_HOLD" in output


def test_process_wiring_error_returns_clean_exit(tmp_path):
    def fail_start(*args, **kwargs):
        raise OSError("spawn failed")

    deps = pub_agent_launcher.LauncherDeps(
        cc_connect=lambda *args, **kwargs: {"connected": True},
        cc_gate=lambda *args, **kwargs: {"connected": True},
        cc_verify=lambda *args, **kwargs: {"preflight_blocked": True},
        prepare=lambda *args, **kwargs: _plan("cc", tmp_path),
        start=fail_start,
    )

    code, _output = _run(["cc", "--project-root", str(tmp_path)], deps)

    assert code == 1


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        test_cc_launcher_connects_gates_verifies_prepares_and_starts(root)
        test_cc_launcher_verify_failure_stops_before_runner(root)
        test_cd_launcher_adds_containment_defaults_before_user_args(root)
        test_dry_run_does_not_start(root)
        test_hold_plan_returns_hold_exit_without_start(root)
        test_process_wiring_error_returns_clean_exit(root)
