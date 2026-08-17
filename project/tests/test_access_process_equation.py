import pytest

from access_field import AccessProcessTerm, AccessProcessVector
from access_process_equation import OmegaProcessResult, omega_process


def _term(slot, value, *, observed=True, payload=None):
    component = {
        "A": "agency_pressure",
        "S": "surface_pressure",
        "T": "temporal_pressure",
    }[slot]
    return AccessProcessTerm(
        slot,
        payload=payload or {slot.lower(): value},
        projection_components={component: value},
        observed=observed,
    )


def _process(process_ref, *, a, s, t, piece_ref="piece:stable-file"):
    return AccessProcessVector(
        process_ref=process_ref,
        agency=_term("A", a, payload={"actor": "codex", "piece_ref": piece_ref}),
        surface=_term(
            "S",
            s,
            payload={
                "raw_path": "reports/current.txt",
                "resolved_path": "C:/dev/sp/reports/current.txt",
                "piece_ref": piece_ref,
            },
        ),
        time=_term("T", t, payload={"window_ns": 10, "piece_ref": piece_ref}),
    )


def _assert_no_execution_authority(payload):
    encoded = str(payload)
    for forbidden in (
        "can_execute",
        "can_kill",
        "can_grant_permission",
        "permission_granted",
    ):
        assert forbidden not in payload
        assert forbidden not in encoded


def test_same_piece_with_matching_frame_drift_is_continuous():
    result = omega_process(
        piece_ref="piece:stable-file",
        enter_process=_process("process:enter", a=1.0, s=2.0, t=3.0),
        exit_process=_process("process:exit", a=1.25, s=2.10, t=3.50),
        frame_delta={"A": 0.25, "S": 0.10, "T": 0.50},
    )

    assert isinstance(result, OmegaProcessResult)
    assert result.a_delta == pytest.approx(0.25)
    assert result.s_delta == pytest.approx(0.10)
    assert result.t_delta == pytest.approx(0.50)
    assert result.t_residual == pytest.approx(0.0)
    assert result.residual_components == {}
    assert result.field_pressure == pytest.approx(0.0)
    assert result.requires_hold is False
    assert result.witnesses == ()
    assert result.to_dict()["state"] == "CONTINUOUS"


def test_piece_drift_inconsistent_with_frame_becomes_residual():
    result = omega_process(
        piece_ref="piece:stable-file",
        enter_process=_process("process:enter", a=1.0, s=2.0, t=3.0),
        exit_process=_process("process:exit", a=1.60, s=2.10, t=3.50),
        frame_delta={"A": 0.25, "S": 0.10, "T": 0.50},
    )

    payload = result.to_dict()

    assert result.requires_hold is True
    assert result.residual_components == pytest.approx({"A": 0.35})
    assert result.field_pressure == pytest.approx(0.35)
    assert payload["state"] == "RESIDUAL"
    assert payload["piece_ref"] == "piece:stable-file"
    assert payload["witnesses"][0]["piece_ref"] == "piece:stable-file"
    assert payload["witnesses"][0]["component"] == "A"
    assert payload["witnesses"][0]["residual_type"] == "FRAME_DRIFT_MISMATCH"


@pytest.mark.parametrize(
    ("changed_axis", "expected_component"),
    (("A", "A"), ("S", "S"), ("T", "T")),
)
def test_any_unexplained_ast_axis_movement_becomes_residual(
    changed_axis,
    expected_component,
):
    enter_values = {"a": 1.0, "s": 1.0, "t": 1.0}
    exit_values = dict(enter_values)
    exit_values[changed_axis.lower()] = 1.5

    result = omega_process(
        piece_ref="piece:ast-axis",
        enter_process=_process("process:enter", **enter_values),
        exit_process=_process("process:exit", **exit_values),
        frame_delta={"A": 0.0, "S": 0.0, "T": 0.0},
    )

    assert result.requires_hold is True
    assert result.residual_components == {expected_component: 0.5}


def test_t_auth_explains_only_temporal_components_not_agency_or_surface():
    result = omega_process(
        piece_ref="piece:stable-file",
        enter_process=_process("process:enter", a=1.0, s=2.0, t=3.0),
        exit_process=_process("process:exit", a=1.40, s=2.30, t=3.50),
        frame_delta={"A": 0.0, "S": 0.0, "T": 0.0},
        t_auth=0.50,
    )

    payload = result.to_dict()

    assert result.t_delta == pytest.approx(0.50)
    assert result.t_residual == pytest.approx(0.0)
    assert result.residual_components == pytest.approx({"A": 0.40, "S": 0.30})
    assert "T" not in result.residual_components
    assert result.field_pressure == pytest.approx(0.40)
    assert {witness["component"] for witness in payload["witnesses"]} == {"A", "S"}
    assert payload["explained_components"] == pytest.approx({"T": 0.50})


def test_t_auth_mapping_rejects_non_temporal_components():
    with pytest.raises(ValueError, match="T components"):
        omega_process(
            piece_ref="piece:stable-file",
            enter_process=_process("process:enter", a=1.0, s=2.0, t=3.0),
            exit_process=_process("process:exit", a=1.40, s=2.30, t=3.50),
            frame_delta={"A": 0.0, "S": 0.0, "T": 0.0},
            t_auth={"agency_pressure": 100.0},
        )


def test_missing_process_slot_is_observation_hold():
    exit_process = AccessProcessVector(
        process_ref="process:missing-time",
        agency=_term("A", 1.0),
        surface=_term("S", 2.0),
        time=None,
    )

    result = omega_process(
        piece_ref="piece:stable-file",
        enter_process=_process("process:enter", a=1.0, s=2.0, t=3.0),
        exit_process=exit_process,
        frame_delta={"A": 0.0, "S": 0.0, "T": 0.0},
    )

    payload = result.to_dict()

    assert result.requires_hold is True
    assert result.field_pressure >= 1.0
    assert result.residual_components["O"] == pytest.approx(1.0)
    assert "T" not in result.residual_components
    assert payload["state"] == "INCOMPLETE_HOLD"
    assert payload["witnesses"][0]["component"] == "O"
    assert payload["witnesses"][0]["residual_type"] == "MISSING_PROCESS_SLOT"
    assert payload["witnesses"][0]["details"]["missing_process_slot"] == "T"


def test_payload_contains_no_execution_or_permission_authority():
    result = omega_process(
        piece_ref="piece:stable-file",
        enter_process=_process("process:enter", a=1.0, s=2.0, t=3.0),
        exit_process=_process("process:exit", a=1.60, s=2.30, t=3.50),
        frame_delta={"A": 0.0, "S": 0.0, "T": 0.0},
    )

    _assert_no_execution_authority(result.to_dict())


def test_process_equation_keeps_piece_ref_fixed_and_does_not_move_file_semantics():
    piece_ref = "piece:file-id:dev-42"
    enter_process = _process(
        "process:enter",
        a=1.0,
        s=2.0,
        t=3.0,
        piece_ref=piece_ref,
    )
    exit_process = AccessProcessVector(
        process_ref="process:exit",
        agency=_term("A", 1.0, payload={"actor": "codex", "piece_ref": piece_ref}),
        surface=_term(
            "S",
            2.5,
            payload={
                "raw_path": "reports/current.txt",
                "resolved_path": "C:/dev/sp/reports/renamed.txt",
                "piece_ref": piece_ref,
            },
        ),
        time=_term("T", 3.0, payload={"window_ns": 10, "piece_ref": piece_ref}),
    )

    result = omega_process(
        piece_ref=piece_ref,
        enter_process=enter_process,
        exit_process=exit_process,
        frame_delta={"A": 0.0, "S": 0.0, "T": 0.0},
    )

    payload = result.to_dict()

    assert payload["piece_ref"] == piece_ref
    assert payload["enter_process"]["payload"]["S"]["piece_ref"] == piece_ref
    assert payload["exit_process"]["payload"]["S"]["piece_ref"] == piece_ref
    assert all(witness["piece_ref"] == piece_ref for witness in payload["witnesses"])
    assert "moved_from" not in str(payload)
    assert "moved_to" not in str(payload)
    assert "file_moved" not in str(payload)
