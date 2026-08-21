"""PUB-OS touch-to-lease pipeline tests."""

from __future__ import annotations

import os
import sys

_PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)

from parallel_audit import (  # noqa: E402
    CourtVerdict,
    EvidenceCourt,
    EvidenceDisposition,
    EvidenceStage,
    EvidenceTestimony,
    ParallelAuditDecision,
)
from pub_os_touch_pipeline import (  # noqa: E402
    TouchPipelineState,
    authorize_touch_for_lease,
    touches_from_claude_event,
    touches_from_codex_shell_argv,
)
from pub_os_visibility import ObjectTouchEvent, TouchKind, default_kingdom_session  # noqa: E402


ROOT = os.path.dirname(_PROJECT)


def _session():
    return default_kingdom_session(
        session_id="kingdom1",
        actor_id="agent",
        project_root=ROOT,
        cwd=ROOT,
    )


def _decision(disposition=EvidenceDisposition.PASS):
    if disposition == EvidenceDisposition.PASS:
        ot_testimony = EvidenceTestimony(
            stage=EvidenceStage.OT_GATE,
            disposition=EvidenceDisposition.PASS,
            reason_code="OT_ALLOW",
            detail="test OT testimony",
        )
        decode_testimony = EvidenceTestimony(
            stage=EvidenceStage.PATH_SCAN,
            disposition=EvidenceDisposition.PASS,
            reason_code="PATH_SCAN_PASS",
            detail="test decode testimony",
        )
        return ParallelAuditDecision(
            disposition=EvidenceDisposition.PASS,
            reason_code="PATH_SCAN_PASS",
            primary_stage=EvidenceStage.PATH_SCAN,
            testimonies=(ot_testimony, decode_testimony),
            ot_court=CourtVerdict(
                EvidenceCourt.OT,
                EvidenceDisposition.PASS,
                "OT_ALLOW",
                EvidenceStage.OT_GATE,
                (ot_testimony,),
            ),
            decode_court=CourtVerdict(
                EvidenceCourt.DECODE,
                EvidenceDisposition.PASS,
                "PATH_SCAN_PASS",
                EvidenceStage.PATH_SCAN,
                (decode_testimony,),
            ),
        )

    testimony = EvidenceTestimony(
        stage=EvidenceStage.PATH_SCAN,
        disposition=disposition,
        reason_code="PATH_HOLD",
        detail="test hold testimony",
    )
    return ParallelAuditDecision(
        disposition=disposition,
        reason_code="AGGREGATE_HOLD",
        primary_stage=EvidenceStage.PATH_SCAN,
        testimonies=(testimony,),
    )


def _event(**overrides):
    values = {
        "session_id": "kingdom1",
        "event_id": "touch1",
        "pid": 100,
        "ppid": 10,
        "actor_id": "agent",
        "kind": TouchKind.FILE_READ,
        "object_ref": os.path.join(ROOT, "README.md"),
        "cwd": ROOT,
    }
    values.update(overrides)
    return ObjectTouchEvent(**values)


def test_visibility_hold_blocks_audit_and_lease():
    def audit_fn(*args, **kwargs):
        raise AssertionError("audit must not run after visibility HOLD")

    result = authorize_touch_for_lease(
        _event(kind=TouchKind.ARTIFACT_USE, metadata={"downloaded_artifact": True}),
        _session(),
        audit_fn=audit_fn,
    )

    assert result.state == TouchPipelineState.HOLD
    assert result.reason_code == "PUB_OS_ARTIFACT_REQUIRES_ADMISSION"
    assert result.audit_decision is None
    assert result.lease is None


def test_pass_audit_issues_matching_runtime_lease():
    result = authorize_touch_for_lease(
        _event(),
        _session(),
        audit_fn=lambda *args, **kwargs: _decision(),
        now_ns=1_000,
        ttl_ns=10_000,
    )

    assert result.state == TouchPipelineState.LEASED
    assert result.reason_code == "PUB_OS_TOUCH_LEASED"
    assert result.lease is not None
    assert result.lease.operation.value == "read"
    assert result.lease_check is not None
    assert result.lease_check.reason_code == "LEASE_MATCH"
    assert result.can_execute is False
    assert result.can_grant_permission is False


def test_non_pass_audit_holds_without_lease():
    result = authorize_touch_for_lease(
        _event(kind=TouchKind.FILE_WRITE),
        _session(),
        audit_fn=lambda *args, **kwargs: _decision(EvidenceDisposition.HOLD),
    )

    assert result.state == TouchPipelineState.HOLD
    assert result.reason_code == "AGGREGATE_HOLD"
    assert result.audit_decision is not None
    assert result.lease is None
    assert "audit:HOLD" in result.evidence


def test_forged_pass_audit_holds_without_lease():
    forged = ParallelAuditDecision(
        disposition=EvidenceDisposition.PASS,
        reason_code="FORGED_PASS",
        primary_stage=EvidenceStage.AGGREGATOR,
        testimonies=(),
    )
    result = authorize_touch_for_lease(
        _event(),
        _session(),
        audit_fn=lambda *args, **kwargs: forged,
    )

    assert result.state == TouchPipelineState.HOLD
    assert result.reason_code == "FORGED_PASS"
    assert result.lease is None
    assert "audit:PASS" in result.evidence
    assert "dual_court_pass:false" in result.evidence


def test_network_touch_does_not_mint_file_lease():
    result = authorize_touch_for_lease(
        _event(kind=TouchKind.NETWORK_CONNECT, object_ref="https://example.invalid"),
        _session(),
        audit_fn=lambda *args, **kwargs: _decision(),
    )

    assert result.state == TouchPipelineState.HOLD
    assert result.reason_code == "PUB_OS_LEASE_UNSUPPORTED_TOUCH"
    assert result.lease is None


def test_cc_hook_event_maps_to_object_touch_event():
    event = {
        "session_id": "cc-session",
        "transcript_path": "transcript.jsonl",
        "cwd": ROOT,
        "tool_name": "Read",
        "tool_input": {"file_path": os.path.join(ROOT, "README.md")},
        "tool_use_id": "tool1",
    }

    touches = touches_from_claude_event(event, session_id="kingdom1", pid=200, ppid=20)

    assert len(touches) == 1
    assert touches[0].kind == TouchKind.FILE_READ
    assert touches[0].source == "cc_hook"
    assert touches[0].object_ref.endswith("README.md")
    assert touches[0].payload_captured is False
    assert touches[0].llm_visible is False


def test_cd_shell_argv_maps_to_process_touch_event():
    touches = touches_from_codex_shell_argv(
        ("-lc", "echo hi"),
        session_id="kingdom1",
        pid=300,
        ppid=30,
        cwd=ROOT,
        environ={
            "PUB_CODEX_SESSION_ID": "cd-session",
            "PUB_CODEX_ACTOR_ID": "agent",
            "PUB_CODEX_PROJECT_ROOT": ROOT,
        },
    )

    assert len(touches) == 1
    assert touches[0].kind == TouchKind.PROCESS_EXEC
    assert touches[0].source == "cd_shell_guard"
    assert touches[0].metadata["runtime_modellable"] is True
    assert touches[0].command_hash.startswith("sha256:")


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
