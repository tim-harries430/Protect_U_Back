"""PUB-OS visibility contract tests.

Run from project/:
    python -m pytest tests/test_pub_os_visibility.py -q
or standalone:
    python tests/test_pub_os_visibility.py
"""

from __future__ import annotations

import os
import sys

_PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)

from pub_os_visibility import (  # noqa: E402
    KingdomSession,
    ObjectTouchEvent,
    ObservationSource,
    ObservationState,
    SensorName,
    SensorFeed,
    SensorState,
    SensorStatus,
    TouchKind,
    VisibilityDecision,
    action_envelope_from_touch,
    default_kingdom_session,
    receipt_for_touch,
)


ROOT = os.path.dirname(_PROJECT)


def test_launch_barrier_holds_when_required_sensor_is_absent():
    session = KingdomSession(
        session_id="k1",
        actor_id="agent",
        project_root=ROOT,
        cwd=ROOT,
        sensors=(
            SensorState(SensorName.PROCESS, SensorStatus.READY),
            SensorState(SensorName.FILESYSTEM, SensorStatus.ABSENT),
            SensorState(SensorName.SCENE, SensorStatus.READY),
            SensorState(SensorName.AUDIT, SensorStatus.READY),
        ),
    )

    receipt = session.launch_barrier()

    assert receipt.decision == VisibilityDecision.HOLD
    assert receipt.reason_code == "KINGDOM_SENSOR_NOT_READY"
    assert "filesystem:ABSENT" in receipt.evidence
    assert receipt.can_execute is False
    assert receipt.can_grant_permission is False


def test_network_sensor_absent_is_recorded_but_not_launch_blocking():
    session = default_kingdom_session(
        session_id="k2",
        actor_id="agent",
        project_root=ROOT,
        network_sensor=SensorStatus.ABSENT,
    )

    receipt = session.launch_barrier()

    assert receipt.decision == VisibilityDecision.PASS
    assert receipt.reason_code == "KINGDOM_READY"
    assert receipt.evidence == ("network:ABSENT",)


def test_opaque_process_exec_holds_without_network_sensor():
    session = default_kingdom_session(session_id="k3", actor_id="agent", project_root=ROOT)
    event = ObjectTouchEvent(
        session_id="k3",
        event_id="exec1",
        pid=100,
        ppid=10,
        actor_id="agent",
        kind=TouchKind.PROCESS_EXEC,
        object_ref="python.exe",
        process_image="python.exe",
        command_text="python -c \"open('x','rb').read()\"",
        cwd=ROOT,
    )

    receipt = receipt_for_touch(event, session)

    assert receipt.decision == VisibilityDecision.HOLD
    assert receipt.reason_code == "PUB_OS_OPAQUE_EXECUTION_HOLD"
    assert "network_sensor:ABSENT" in receipt.evidence
    assert receipt.metadata["payload_captured"] is False
    assert receipt.metadata["llm_visible"] is False


def test_unknown_script_process_exec_holds_without_network_sensor():
    session = default_kingdom_session(session_id="k3b", actor_id="agent", project_root=ROOT)
    event = ObjectTouchEvent(
        session_id="k3b",
        event_id="exec2",
        pid=102,
        ppid=10,
        actor_id="agent",
        kind=TouchKind.PROCESS_EXEC,
        object_ref="python.exe",
        process_image="python.exe",
        command_text="python script.py",
        cwd=ROOT,
    )

    receipt = receipt_for_touch(event, session)

    assert receipt.decision == VisibilityDecision.HOLD
    assert receipt.reason_code == "PUB_OS_UNKNOWN_RUNTIME_HOLD"
    assert "network_sensor:ABSENT" in receipt.evidence


def test_downloaded_artifact_use_requires_admission():
    session = default_kingdom_session(session_id="k4", actor_id="agent", project_root=ROOT)
    event = ObjectTouchEvent(
        session_id="k4",
        event_id="artifact1",
        pid=101,
        ppid=10,
        actor_id="agent",
        kind=TouchKind.ARTIFACT_USE,
        object_ref=os.path.join(ROOT, "downloads", "pkg.whl"),
        metadata={"downloaded_artifact": True, "origin": "https://example.invalid/pkg.whl"},
    )

    receipt = receipt_for_touch(event, session)
    envelope = action_envelope_from_touch(event, project_root=ROOT)

    assert receipt.decision == VisibilityDecision.HOLD
    assert receipt.reason_code == "PUB_OS_ARTIFACT_REQUIRES_ADMISSION"
    assert envelope.can_execute is False
    assert envelope.can_grant_permission is False
    assert envelope.source_adapter == "pub_os_visibility"


def test_sensor_feed_is_testimony_only_and_structured():
    event = ObjectTouchEvent(
        session_id="k6",
        event_id="read1",
        pid=201,
        ppid=20,
        actor_id="agent",
        kind=TouchKind.FILE_READ,
        object_ref=os.path.join(ROOT, "README.md"),
    )
    feed = SensorFeed(
        feed_id="feed1",
        session_id="k6",
        action_id="read1",
        proposal_id="proposal1",
        sensor_states=(SensorState(SensorName.NETWORK, SensorStatus.ABSENT, required=False),),
        observation_state=ObservationState.PARTIAL,
        gaps=("NETWORK_SENSOR_ABSENT",),
        events=(event,),
    )
    data = feed.to_dict()

    assert data["testimony_only"] is True
    assert data["can_execute"] is False
    assert data["can_grant_permission"] is False
    assert data["observation_state"] == "PARTIAL"
    assert data["gaps"] == ("NETWORK_SENSOR_ABSENT",)
    assert data["events"][0]["payload_captured"] is False


def test_sensor_receipts_reject_payload_and_are_not_llm_visible():
    try:
        ObjectTouchEvent(
            session_id="k5",
            event_id="bad1",
            pid=1,
            ppid=0,
            actor_id="agent",
            kind=TouchKind.FILE_READ,
            object_ref="secret.txt",
            metadata={"payload": "secret bytes"},
        )
    except ValueError as exc:
        assert "payload" in str(exc)
    else:
        raise AssertionError("payload-bearing sensor event must be rejected")

    try:
        ObjectTouchEvent(
            session_id="k5",
            event_id="bad2",
            pid=1,
            ppid=0,
            actor_id="agent",
            kind=TouchKind.FILE_READ,
            object_ref="secret.txt",
            llm_visible=True,
        )
    except ValueError as exc:
        assert "LLM-visible" in str(exc)
    else:
        raise AssertionError("LLM-visible sensor event must be rejected")


def test_sensor_receipts_reject_authority_claims():
    for key in ("can_execute", "can_grant_permission", "permission_granted", "allow", "execute", "grant", "kill"):
        try:
            ObjectTouchEvent(
                session_id="k7",
                event_id=f"bad_{key}",
                pid=1,
                ppid=0,
                actor_id="agent",
                kind=TouchKind.FILE_READ,
                object_ref="target.txt",
                metadata={key: True},
            )
        except ValueError as exc:
            assert key in str(exc)
        else:
            raise AssertionError(f"authority-bearing sensor event must be rejected: {key}")


def test_touch_defaults_to_proposal_provenance_and_surfaces_in_receipt():
    session = default_kingdom_session(session_id="k8", actor_id="agent", project_root=ROOT)
    event = ObjectTouchEvent(
        session_id="k8",
        event_id="read_prov",
        pid=300,
        ppid=30,
        actor_id="agent",
        kind=TouchKind.FILE_READ,
        object_ref=os.path.join(ROOT, "README.md"),
    )

    assert event.observation_source == ObservationSource.PROPOSAL
    assert event.public_metadata()["observation_source"] == "PROPOSAL"

    receipt = receipt_for_touch(event, session)

    # A PASS must carry its provenance so it can never be read as an eyewitness record.
    assert receipt.decision == VisibilityDecision.PASS
    assert receipt.metadata["observation_source"] == "PROPOSAL"


def test_sensor_provenance_is_preserved_when_declared():
    event = ObjectTouchEvent(
        session_id="k9",
        event_id="sensor_prov",
        pid=301,
        ppid=30,
        actor_id="agent",
        kind=TouchKind.FILE_WRITE,
        object_ref=os.path.join(ROOT, "out.txt"),
        observation_source=ObservationSource.SENSOR,
    )

    assert event.observation_source == ObservationSource.SENSOR
    assert event.public_metadata()["observation_source"] == "SENSOR"


def test_sensor_feed_defaults_to_partial_observation():
    feed = SensorFeed(
        feed_id="feed_default",
        session_id="k10",
        action_id="a",
        proposal_id="p",
        sensor_states=(SensorState(SensorName.NETWORK, SensorStatus.ABSENT, required=False),),
    )

    # Default must not claim COMPLETE coverage.
    assert feed.observation_state == ObservationState.PARTIAL
    assert feed.to_dict()["observation_state"] == "PARTIAL"


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
