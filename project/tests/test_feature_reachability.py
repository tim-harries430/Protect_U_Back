from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import xray_transport
from protect_u_back import main
from xray_field import TESTIMONY_DISTORTED, XrayFieldState


def _feature_manifest_path() -> Path:
    candidates = (
        Path(__file__).with_name("FEATURE_REACHABILITY.json"),
        Path(__file__).resolve().parents[2] / "FEATURE_REACHABILITY.json",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("FEATURE_REACHABILITY.json not found in repository or release layout")


def _write_safe_case(tmp_path: Path) -> Path:
    case_path = tmp_path / "feature_reachability_case.json"
    case_path.write_text(
        json.dumps(
            {
                "case_id": "FEATURE-REACH-001",
                "description": "Benign project status proposal used for feature wiring proof",
                "should_stop": False,
                "channel_type": "AGENT_PROPOSAL",
                "source_id": "feature_reachability_agent",
                "content": "git status --short",
                "metadata": {
                    "declared_scope": "file_read",
                    "target_paths": [],
                    "expected_side_effects": ["read"]
                }
            }
        ),
        encoding="utf-8",
    )
    return case_path


def _run_protect_cli(tmp_path: Path, case_path: Path, output_name: str) -> dict:
    output_path = tmp_path / output_name
    exit_code = main(
        (
            "agent-audit",
            "--project-root",
            str(tmp_path),
            "--input",
            str(case_path),
            "--output",
            str(output_path),
            "--confirm-protect",
        )
    )
    assert exit_code == 0
    return json.loads(output_path.read_text(encoding="utf-8"))


def _first_result(payload: dict) -> dict:
    assert payload["case_count"] == 1
    return payload["results"][0]


def test_feature_manifest_records_proven_level_without_runtime_overclaim():
    manifest = json.loads(_feature_manifest_path().read_text(encoding="utf-8"))
    feature = manifest["features"][0]

    assert manifest["level_model"] == [
        "DEFINED",
        "IMPORTED",
        "REACHABLE",
        "OUTCOME_AFFECTING",
        "RUNTIME_PROVEN",
    ]
    assert feature["feature_id"] == "u_xray_scalar_potential:v0"
    assert feature["current_level"] == "OUTCOME_AFFECTING"
    assert feature["status"] == "ACTIVE_PARTIAL"
    assert feature["level_evidence"]["RUNTIME_PROVEN"] is False
    assert feature["authority_boundary"] == {
        "testimony_only": True,
        "can_execute": False,
        "can_grant_permission": False,
        "io_executed": False,
    }


def test_xray_scalar_field_is_reachable_from_protect_cli(tmp_path, monkeypatch):
    case_path = _write_safe_case(tmp_path)
    original = xray_transport.sample_xray_potential_pair
    calls = []

    def wrapped(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(xray_transport, "sample_xray_potential_pair", wrapped)
    result = _first_result(
        _run_protect_cli(tmp_path, case_path, "reachable_result.json")
    )

    assert calls, "formal protect_u_back CLI did not reach sample_xray_potential_pair"
    field = result["decision"]["xray_transport"]["field"]
    assert field["enter"]["field_id"] == "u_xray_scalar_potential:v0"
    assert field["testimony_only"] is True
    assert result["decision"]["can_execute"] is False
    assert result["decision"]["can_grant_permission"] is False
    assert result["decision"]["io_executed"] is False


def test_xray_scalar_field_output_changes_protect_cli_outcome(tmp_path, monkeypatch):
    case_path = _write_safe_case(tmp_path)
    baseline = _first_result(
        _run_protect_cli(tmp_path, case_path, "baseline_result.json")
    )
    assert baseline["decision"]["disposition"] == "PASS"
    assert baseline["stopped"] is False

    original = xray_transport.sample_xray_potential_pair

    def force_distortion(*args, **kwargs):
        field = original(*args, **kwargs)
        return replace(
            field,
            state=XrayFieldState.DISTORTED,
            field_shift=1.0,
            field_shift_abs=1.0,
            distorted_nodes=("feature_reachability_sentinel",),
            testimony_note=TESTIMONY_DISTORTED,
        )

    monkeypatch.setattr(
        xray_transport,
        "sample_xray_potential_pair",
        force_distortion,
    )
    affected = _first_result(
        _run_protect_cli(tmp_path, case_path, "affected_result.json")
    )
    decision = affected["decision"]

    assert affected["stopped"] is True
    assert decision["disposition"] == "HOLD"
    assert decision["primary_stage"] == "DECODE_REVIEW"
    assert decision["reason_code"] == "XRAY_REVIEW_OBSERVATION_BLINDSPOT"
    assert decision["xray_transport"]["field_state"] == "DISTORTED"
    assert decision["can_execute"] is False
    assert decision["can_grant_permission"] is False
    assert decision["io_executed"] is False
