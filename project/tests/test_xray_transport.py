import dataclasses
import os
import time

from adapter_wall import ActionEnvelope, AdapterActionType
from ot_gate import CommandProposal, DeclaredScope, SideEffect
from parallel_audit import EvidenceDisposition, EvidenceStage, run_parallel_audit
from phi_registry import PhiRegistry
from protect_scan import confirm_protect_scan, default_protect_scan_profile
from xray_prison import leaks_forbidden_authority
from xray_review import DisguiseAxis, review_proposal
from xray_transport import (
    AuthorizationMatchWitness,
    close_xray_transport,
    open_xray_transport,
)


def registry(*actor_ids):
    store = PhiRegistry()
    for actor_id in actor_ids or ("agent_coder",):
        store.register_actor(actor_id)
    return store


def profile(project_root):
    return confirm_protect_scan(
        default_protect_scan_profile(str(project_root)),
        confirmed=True,
    )


def action(
    project_root,
    command_text,
    *,
    actor_id="agent_coder",
    action_type=AdapterActionType.SHELL,
    target_paths=(),
    expected_side_effects=None,
    declared_scope=None,
    action_id="xray_transport_action",
    raw_payload=None,
):
    return ActionEnvelope(
        actor_id=actor_id,
        action_type=action_type,
        command_text=command_text,
        cwd=str(project_root),
        target_paths=target_paths,
        expected_side_effects=set(expected_side_effects or ()),
        declared_scope=declared_scope,
        source_adapter="unit_test",
        tool_name="shell",
        raw_payload=dict(raw_payload or {}),
        branch_id="xray_transport_branch",
        action_id=action_id,
        parent_event_id="xray_transport_parent",
        user_request_id="xray_transport_user",
    )


def proposal(project_root, target):
    return CommandProposal(
        command_text=f"Set-Content {target} changed",
        actor_id="agent_coder",
        cwd=str(project_root),
        declared_scope=DeclaredScope.PROJECT_WRITE,
        target_paths=(str(target),),
        expected_side_effects={SideEffect.WRITE},
        parent_event_id="xray_transport_parent",
        user_request_id="xray_transport_user",
        proposal_id="xray_transport_proposal",
        source_adapter="unit_test",
        tool_name="shell",
        action_type="shell",
    )


def test_xray_transport_seals_mutation_without_forbidden_authority(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("before\n", encoding="utf-8")
    command_proposal = proposal(tmp_path, target)

    handle = open_xray_transport(command_proposal)
    target.write_text("after\n", encoding="utf-8")
    seal = close_xray_transport(handle, command_proposal)

    payload = seal.to_dict()
    payload_text = repr(payload).lower()
    assert seal.sealed is True
    assert seal.testimony_only is True
    assert seal.mutation_state == "MUTATED"
    assert seal.continuity_state == "BROKEN"
    assert seal.witness_count >= 1
    assert seal.process_witness["schema"] == "omega_process_witness_v0"
    assert seal.process_witness["state"] == "RESIDUAL"
    assert seal.process_witness["requires_hold"] is True
    assert "T" in seal.process_witness["residual_components"]
    assert any(item.startswith("omega_process.witness_hash:") for item in seal.to_evidence())
    assert "xray_transport.testimony_only:true" in seal.to_evidence()
    authorization = seal.authorization_match
    assert authorization.fully_matched is True
    assert authorization.to_dict()["matched_targets"] == (str(target),)
    assert authorization.to_dict()["matched_effects"] == ("write",)
    assert authorization.to_dict()["matched_finding_types"] == ("HASH_MUTATED",)
    assert authorization.authorized_delta_digest.startswith("sha256:")
    assert payload["authorization_match"] == authorization.to_dict()
    assert f"xray_authorization.matched_target:{target}" in seal.to_evidence()
    assert "xray_authorization.matched_effect:write" in seal.to_evidence()
    assert "xray_authorization.matched_finding_type:HASH_MUTATED" in seal.to_evidence()
    assert leaks_forbidden_authority(payload) is False
    assert "decision" not in payload_text
    assert "verdict" not in payload_text
    assert "can_execute" not in payload_text
    assert "io_executed" not in payload_text


def test_authorization_match_is_inside_transport_hash(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("before\n", encoding="utf-8")
    command_proposal = proposal(tmp_path, target)
    handle = open_xray_transport(command_proposal)
    target.write_text("after\n", encoding="utf-8")
    seal = close_xray_transport(handle, command_proposal)

    altered_match = dataclasses.replace(
        seal.authorization_match,
        authorized_delta_digest="sha256:" + "0" * 64,
    )
    altered_seal = dataclasses.replace(seal, authorization_match=altered_match)

    assert seal.transport_hash != altered_seal.transport_hash
    assert seal.to_dict(include_hash=False)["authorization_match"] != (
        altered_seal.to_dict(include_hash=False)["authorization_match"]
    )


def test_declared_write_does_not_explain_alias_identity_movement(tmp_path):
    target = tmp_path / "target.txt"
    alias = tmp_path / "alias.txt"
    target.write_text("before\n", encoding="utf-8")
    command_proposal = proposal(tmp_path, target)
    handle = open_xray_transport(command_proposal)

    os.link(target, alias)
    seal = close_xray_transport(handle, command_proposal)
    review = review_proposal(command_proposal, seal=seal)

    assert seal.authorization_match.fully_matched is False
    assert len(seal.authorization_match.unmatched_findings) == 1
    assert (
        seal.authorization_match.unmatched_findings[0].reason
        == "resource_identity_nlink_movement_not_authorized"
    )
    assert review.disposition.value == "QUARANTINE"
    assert {signal.axis for signal in review.signals} >= {
        DisguiseAxis.ALIAS,
        DisguiseAxis.SUBSTITUTION,
    }
    assert leaks_forbidden_authority(seal.to_dict()) is False


def test_missing_authorization_match_never_relaxes_mutation(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("before\n", encoding="utf-8")
    command_proposal = proposal(tmp_path, target)
    handle = open_xray_transport(command_proposal)
    target.write_text("after\n", encoding="utf-8")
    seal = close_xray_transport(handle, command_proposal)
    unbound = dataclasses.replace(
        seal,
        authorization_match=AuthorizationMatchWitness(),
    )

    review = review_proposal(command_proposal, seal=unbound)

    assert unbound.expected_mutation is False
    assert review.disposition.value == "QUARANTINE"
    assert any(signal.axis == DisguiseAxis.SUBSTITUTION for signal in review.signals)


def test_xray_transport_stable_missing_target_does_not_false_hold_process(tmp_path):
    target = tmp_path / "new-file.txt"
    command_proposal = proposal(tmp_path, target)

    seal = close_xray_transport(
        open_xray_transport(command_proposal),
        command_proposal,
    )

    assert seal.process_witness["state"] == "CONTINUOUS"
    assert seal.process_witness["requires_hold"] is False
    assert seal.process_witness["time_grid_trace_count"] == 0
    assert leaks_forbidden_authority(seal.to_dict()) is False


def test_xray_transport_live_meter_catches_transient_create_delete(tmp_path):
    target = tmp_path / "transient.txt"
    command_proposal = proposal(tmp_path, target)
    handle = open_xray_transport(command_proposal, beat_interval_ns=5_000_000)

    target.write_text("visible between endpoints\n", encoding="utf-8")
    time.sleep(0.05)
    target.unlink()
    time.sleep(0.02)
    seal = close_xray_transport(handle, command_proposal)

    witness = seal.process_witness
    trace = witness["time_grid_traces"][0]
    expected_signature = "4/4" if os.name == "nt" else "8/8"
    assert seal.mutation_state == "STABLE"
    assert witness["state"] in {"RESIDUAL", "INCOMPLETE_HOLD"}
    assert witness["requires_hold"] is True
    assert witness["residual_components"]["T"] == 1.0
    assert "GRID_EXISTENCE_DRIFT" in trace["finding_types"]
    assert trace["sampling"]["time_signature"] == expected_signature
    assert trace["sampling"]["pattern"][:4] == (
        "snare",
        "kick",
        "snare",
        "kick",
    )
    assert witness["testimony_only"] is True
    assert witness["authority"] == "observe_residual_attach_only"
    assert leaks_forbidden_authority(seal.to_dict()) is False


def test_parallel_audit_attaches_xray_transport_before_admission_short_circuit(tmp_path):
    result = run_parallel_audit(
        action(
            tmp_path,
            r"Set-Content .phi\registry\actors.json '{}'",
            actor_id="unknown_agent",
            action_type=AdapterActionType.FILE_WRITE,
            target_paths=(r".phi\registry\actors.json",),
            action_id="xray_transport_unknown_actor",
        ),
        registry=registry("agent_coder"),
        project_root=str(tmp_path),
        protect_profile=profile(tmp_path),
    )

    assert result.disposition == EvidenceDisposition.REJECT
    assert result.primary_stage == EvidenceStage.ADMISSION
    assert result.evidence_bundle is None
    assert result.xray_transport is not None
    assert result.xray_transport.sealed is True
    assert len(result.testimonies) == 1
    assert tuple(testimony.stage.value for testimony in result.testimonies) == (
        EvidenceStage.ADMISSION.value,
    )
    assert result.to_dict()["xray_transport"]["testimony_only"] is True
    assert leaks_forbidden_authority(result.to_dict()["xray_transport"]) is False


def test_xray_transport_url_surface_is_unknown_not_path_crash(tmp_path):
    command_proposal = CommandProposal(
        command_text="curl https://api.example.internal/status",
        actor_id="agent_coder",
        cwd=str(tmp_path),
        declared_scope=DeclaredScope.EXTERNAL_IO,
        target_paths=("https://api.example.internal/status",),
        expected_side_effects={SideEffect.NETWORK},
        parent_event_id="xray_transport_parent",
        user_request_id="xray_transport_user",
        proposal_id="xray_transport_url_surface",
        source_adapter="unit_test",
        tool_name="shell",
        action_type="network",
    )

    seal = close_xray_transport(
        open_xray_transport(command_proposal),
        command_proposal,
    )

    assert seal.sealed is True
    assert seal.field_state == "UNKNOWN"
    assert "xray_field_pair.testimony_note:unknown_observed" in seal.to_evidence()
    assert leaks_forbidden_authority(seal.to_dict()) is False


def test_parallel_audit_xray_transport_does_not_enter_testimony_vote(tmp_path):
    target = tmp_path / "README.md"
    target.write_text("stable\n", encoding="utf-8")
    result = run_parallel_audit(
        action(
            tmp_path,
            f"Get-Content {target}",
            target_paths=(str(target),),
            action_id="xray_transport_clean",
        ),
        registry=registry("agent_coder"),
        project_root=str(tmp_path),
        protect_profile=profile(tmp_path),
    )

    assert result.disposition == EvidenceDisposition.PASS
    assert result.primary_stage == EvidenceStage.CHANNEL_AUDIT
    assert result.reason_code == "CHANNEL_WRAP_PROPOSAL"
    assert result.xray_transport is not None
    assert result.evidence_bundle is not None
    assert result.evidence_bundle.xray_transport is result.xray_transport
    assert len(result.testimonies) == 9
    assert result.ot_court is not None
    assert result.decode_court is not None
    assert result.ot_court.disposition == EvidenceDisposition.PASS
    assert result.decode_court.disposition == EvidenceDisposition.PASS
    assert all("XRAY" not in testimony.stage.value for testimony in result.testimonies)
    testimony_evidence = tuple(
        item for testimony in result.testimonies for item in testimony.evidence
    )
    assert all(not item.startswith("xray_transport.") for item in testimony_evidence)
    assert all(not item.startswith("transition_xray.") for item in testimony_evidence)
    assert result.to_dict()["evidence_bundle"]["xray_transport"]["sealed"] is True
