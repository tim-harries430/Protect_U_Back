"""PUB-OS runtime lease tests."""

from __future__ import annotations

import os
import sys

_PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)

from parallel_audit import EvidenceDisposition, EvidenceStage, EvidenceTestimony, ParallelAuditDecision  # noqa: E402
from pub_os_authorization import (  # noqa: E402
    LeaseDecision,
    LeaseOperation,
    check_lease_for_touch,
    consume_lease_after_match,
    issue_lease_from_approval,
)
from pub_os_visibility import ObjectTouchEvent, TouchKind  # noqa: E402


ROOT = os.path.dirname(_PROJECT)


def _decision(disposition=EvidenceDisposition.PASS):
    testimony = EvidenceTestimony(
        stage=EvidenceStage.PATH_SCAN,
        disposition=disposition,
        reason_code="PATH_SCAN_PASS" if disposition == EvidenceDisposition.PASS else "PATH_HOLD",
        detail="test testimony",
    )
    return ParallelAuditDecision(
        disposition=disposition,
        reason_code="AGGREGATE_PASS" if disposition == EvidenceDisposition.PASS else "AGGREGATE_HOLD",
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
    }
    values.update(overrides)
    return ObjectTouchEvent(**values)


def test_pass_decision_issues_one_shot_runtime_lease():
    lease = issue_lease_from_approval(
        _decision(),
        session_id="kingdom1",
        actor_id="agent",
        operation=LeaseOperation.READ,
        object_ref=os.path.join(ROOT, "README.md"),
        pid=100,
        now_ns=1_000,
        ttl_ns=1_000,
    )

    assert lease.lease_id.startswith("lease_")
    assert lease.operation == LeaseOperation.READ
    assert lease.one_shot is True
    assert lease.can_grant_permission is False
    assert lease.authority == "runtime_lease_only"


def test_non_pass_decision_cannot_issue_lease():
    try:
        issue_lease_from_approval(
            _decision(EvidenceDisposition.HOLD),
            session_id="kingdom1",
            actor_id="agent",
            operation=LeaseOperation.READ,
            object_ref=os.path.join(ROOT, "README.md"),
        )
    except ValueError as exc:
        assert "non-PASS" in str(exc)
    else:
        raise AssertionError("non-PASS decision must not issue a lease")


def test_matching_syscall_event_allows_then_consumes():
    lease = issue_lease_from_approval(
        _decision(),
        session_id="kingdom1",
        actor_id="agent",
        operation=LeaseOperation.READ,
        object_ref=os.path.join(ROOT, "README.md"),
        pid=100,
        now_ns=1_000,
        ttl_ns=10_000,
    )

    check = check_lease_for_touch(lease, _event(), now_ns=2_000)
    consumed = consume_lease_after_match(lease, check)
    second = check_lease_for_touch(consumed, _event(event_id="touch2"), now_ns=3_000)

    assert check.decision == LeaseDecision.ALLOW
    assert check.reason_code == "LEASE_MATCH"
    assert consumed.consumed is True
    assert second.decision == LeaseDecision.HOLD
    assert second.reason_code == "LEASE_CONSUMED"


def test_missing_expired_or_mismatched_lease_holds():
    lease = issue_lease_from_approval(
        _decision(),
        session_id="kingdom1",
        actor_id="agent",
        operation=LeaseOperation.READ,
        object_ref=os.path.join(ROOT, "README.md"),
        pid=100,
        now_ns=1_000,
        ttl_ns=100,
    )

    assert check_lease_for_touch(None, _event(), now_ns=1_000).reason_code == "LEASE_MISSING"
    assert check_lease_for_touch(lease, _event(), now_ns=1_101).reason_code == "LEASE_EXPIRED"
    assert check_lease_for_touch(lease, _event(pid=101), now_ns=1_050).reason_code == "LEASE_PID_MISMATCH"
    assert check_lease_for_touch(
        lease,
        _event(kind=TouchKind.FILE_WRITE),
        now_ns=1_050,
    ).reason_code == "LEASE_OPERATION_MISMATCH"
    assert check_lease_for_touch(
        lease,
        _event(object_ref=os.path.join(ROOT, "LOCAL_ONLY.txt")),
        now_ns=1_050,
    ).reason_code == "LEASE_OBJECT_MISMATCH"


def test_file_id_can_match_renamed_path_when_present():
    lease = issue_lease_from_approval(
        _decision(),
        session_id="kingdom1",
        actor_id="agent",
        operation=LeaseOperation.READ,
        object_ref=os.path.join(ROOT, "old-name.txt"),
        file_id="dev:inode:1",
        now_ns=1_000,
        ttl_ns=10_000,
    )
    event = _event(
        object_ref=os.path.join(ROOT, "new-name.txt"),
        metadata={"file_id": "dev:inode:1"},
    )

    check = check_lease_for_touch(lease, event, now_ns=2_000)

    assert check.decision == LeaseDecision.ALLOW
    assert check.reason_code == "LEASE_MATCH"


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
