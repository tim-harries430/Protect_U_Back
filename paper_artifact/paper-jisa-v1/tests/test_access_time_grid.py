from access_equation import BoundaryMetric, ObservationMask, ObservationState, XrayObjectState
from access_field import AccessFieldAxis, AccessFieldPhase, AccessProcessVector
from access_sampler import ObjectStateSample
from access_time_grid import (
    BEAT_PATTERN,
    UNIX_CTIME,
    WINDOWS_CTIME,
    TIME_GRID_REQUIRED_FIELDS,
    TimeGridCell,
    TimeGridSpec,
    TimeGridTrace,
    build_time_grid_trace,
    platform_beat_policy,
)


def test_platform_meter_maps_windows_to_four_four_and_unix_to_eight_eight():
    windows = platform_beat_policy("windows")
    unix = platform_beat_policy("linux")

    assert windows.time_signature == "4/4"
    assert tuple(windows.beat_name(index) for index in range(4)) == (
        "snare",
        "kick",
        "snare",
        "kick",
    )
    assert unix.time_signature == "8/8"
    assert tuple(unix.beat_name(index) for index in range(8)) == BEAT_PATTERN * 4
    assert windows.to_dict()["axis"] == "T"
    assert unix.to_dict()["field_axis"] == "time"


def test_time_grid_spec_builds_fixed_beat_timestamps():
    spec = TimeGridSpec(enter_ts_ns=100, exit_ts_ns=160, step_ns=20)

    assert spec.expected_timestamps == (100, 120, 140, 160)
    assert spec.required_fields == TIME_GRID_REQUIRED_FIELDS


def test_time_grid_cell_from_xray_sample_uses_physical_fields():
    sample = _sample(
        sampled_at_ns=100,
        vector_hash="sha256:a",
        mtime_ns=10,
        ctime_ns=11,
        file_id="dev:1",
        nlink=1,
        resolved_path="C:/dev/sp/a.txt",
        semantics=WINDOWS_CTIME,
    )

    cell = TimeGridCell.from_sample(index=0, expected_ts_ns=100, sample=sample)
    payload = cell.to_dict()

    assert payload["metadata_vector_hash"] == "sha256:a"
    assert payload["mtime_ns"] == 10
    assert payload["os_ctime_ns"] == 11
    assert payload["os_ctime_semantics"] == WINDOWS_CTIME
    assert payload["file_id"] == "dev:1"
    assert payload["nlink"] == 1
    assert payload["resolved_path"] == "C:/dev/sp/a.txt"


def test_time_grid_trace_detects_grid_drift_components():
    spec = TimeGridSpec(enter_ts_ns=0, exit_ts_ns=30, step_ns=10, max_sample_drift_ns=2)
    trace = build_time_grid_trace(
        spec=spec,
        object_ref="target:a",
        cells=(
            _cell(0, 0, "sha256:a", 10, 20, UNIX_CTIME, "dev:1", 1, "C:/dev/sp/a.txt"),
            _cell(1, 10, "sha256:a", 10, 20, UNIX_CTIME, "dev:1", 1, "C:/dev/sp/a.txt"),
            _cell(2, 20, "sha256:b", 11, 21, UNIX_CTIME, "dev:1", 2, "C:/dev/sp/a.txt"),
            _cell(3, 30, "sha256:c", 12, 22, UNIX_CTIME, "dev:2", 2, "C:/dev/sp/pivot.txt"),
        ),
    )

    components = trace.projection_components

    assert components["temporal_hash_change_pressure"] == 1.0
    assert components["temporal_mtime_drift_pressure"] == 1.0
    assert components["temporal_ctime_drift_pressure"] == 1.0
    assert components["alias_nlink_drift_pressure"] == 1.0
    assert components["identity_file_id_drift_pressure"] == 1.0
    assert components["pointer_resolved_path_drift_pressure"] == 1.0
    assert trace.requires_hold is False


def test_time_grid_trace_routes_missing_or_mixed_semantics_to_observation_hold():
    spec = TimeGridSpec(enter_ts_ns=0, exit_ts_ns=30, step_ns=10)
    trace = build_time_grid_trace(
        spec=spec,
        cells=(
            _cell(0, 0, "sha256:a", 10, 20, WINDOWS_CTIME, "dev:1", 1, "C:/dev/sp/a.txt"),
            _cell(1, 10, "sha256:a", 10, 20, UNIX_CTIME, "dev:1", 1, "C:/dev/sp/a.txt"),
        ),
    )

    components = trace.projection_components

    assert trace.missing_cell_indices == (2, 3)
    assert components["observation_grid_missing_cell_pressure"] == 1.0
    assert components["observation_semantics_mixed_pressure"] == 1.0
    assert trace.requires_hold is True


def test_time_grid_trace_plugs_into_ast_plane_as_t_axis():
    spec = TimeGridSpec(enter_ts_ns=0, exit_ts_ns=20, step_ns=10)
    trace = TimeGridTrace(
        spec=spec,
        cells=(
            _cell(0, 0, "sha256:a", 10, 20, UNIX_CTIME, "dev:1", 1, "C:/dev/sp/a.txt"),
            _cell(1, 10, "sha256:b", 11, 21, UNIX_CTIME, "dev:1", 1, "C:/dev/sp/a.txt"),
            _cell(2, 20, "sha256:b", 11, 21, UNIX_CTIME, "dev:1", 1, "C:/dev/sp/a.txt"),
        ),
    )
    process = AccessProcessVector(
        process_ref="process:grid",
        agency={"payload": {"actor": "agent"}},
        surface={"payload": {"raw_path": "a.txt"}},
        time=trace.to_process_time_term(),
        phase=AccessFieldPhase.EXIT,
    )
    tensor = process.to_field_tensor(piece_ref="piece:grid")
    payload = tensor.to_dict()

    assert process.time.slot.value == "T"
    assert process.signed_components["temporal_hash_change_pressure"] == -1.0
    time_coordinate = tensor.coordinate("piece:grid", AccessFieldAxis.TIME, AccessFieldPhase.EXIT)
    assert time_coordinate.value == -3.0
    assert time_coordinate.field_pressure == 1.0
    assert "access_time_grid_v0" in str(process.payload["T"])
    assert "can_execute" not in str(payload)
    assert "can_grant_permission" not in str(payload)


def test_observed_absence_is_not_a_blindspot_but_existence_drift_is_visible():
    spec = TimeGridSpec(enter_ts_ns=0, exit_ts_ns=20, step_ns=10)
    trace = TimeGridTrace(
        spec=spec,
        cells=(
            TimeGridCell(
                index=0,
                expected_ts_ns=0,
                sampled_at_ns=0,
                exists=False,
                metadata_vector_hash="sha256:absent",
                os_ctime_semantics=UNIX_CTIME,
                resolved_path="/tmp/pulse.txt",
            ),
            TimeGridCell(
                index=1,
                expected_ts_ns=10,
                sampled_at_ns=10,
                exists=True,
                metadata_vector_hash="sha256:present",
                mtime_ns=10,
                os_ctime_ns=10,
                os_ctime_semantics=UNIX_CTIME,
                file_id="dev:1",
                nlink=1,
                resolved_path="/tmp/pulse.txt",
            ),
            TimeGridCell(
                index=2,
                expected_ts_ns=20,
                sampled_at_ns=20,
                exists=False,
                metadata_vector_hash="sha256:absent",
                os_ctime_semantics=UNIX_CTIME,
                resolved_path="/tmp/pulse.txt",
            ),
        ),
    )

    assert "observation_grid_missing_field_pressure" not in trace.projection_components
    assert trace.projection_components["temporal_existence_drift_pressure"] == 1.0
    assert trace.requires_hold is False


def _cell(
    index,
    expected_ts_ns,
    vector_hash,
    mtime_ns,
    os_ctime_ns,
    semantics,
    file_id,
    nlink,
    resolved_path,
):
    return TimeGridCell(
        index=index,
        expected_ts_ns=expected_ts_ns,
        sampled_at_ns=expected_ts_ns,
        metadata_vector_hash=vector_hash,
        mtime_ns=mtime_ns,
        os_ctime_ns=os_ctime_ns,
        os_ctime_semantics=semantics,
        file_id=file_id,
        nlink=nlink,
        resolved_path=resolved_path,
    )


def _sample(*, sampled_at_ns, vector_hash, mtime_ns, ctime_ns, file_id, nlink, resolved_path, semantics):
    state = XrayObjectState(
        object_ref=resolved_path,
        exists=True,
        object_type="file",
        resolved_path=resolved_path,
        metadata_sha256=vector_hash,
        file_id=file_id,
        nlink=nlink,
        mtime_ns=mtime_ns,
        ctime_ns=ctime_ns,
        details={"os_ctime_semantics": semantics},
    )
    return ObjectStateSample(
        state=state,
        boundary=BoundaryMetric(contained_refs=(resolved_path,)),
        observation=ObservationMask(ObservationState.COMPLETE),
        sampled_at_ns=sampled_at_ns,
        metadata_vector_hash=vector_hash,
        metadata_vector={
            "metadata_vector_hash": vector_hash,
            "mtime_ns": mtime_ns,
            "os_ctime_ns": ctime_ns,
            "os_ctime_semantics": semantics,
            "file_id": file_id,
            "nlink": nlink,
            "resolved_path": resolved_path,
        },
    )
