from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from access_equation import (
    AccessCurrent,
    AccessEquationInput,
    AccessEquationState,
    AuthPotential,
    BoundaryMetric,
    ObservationMask,
    ObservationState,
    XrayObjectState,
    omega_access,
)
from access_sampler import (
    MetadataSampleProfile,
    metadata_change_token,
    sample_xray_object_state,
)
from ot_gate import CommandProposal, DeclaredScope, SideEffect
from xray_prison import leaks_forbidden_authority
from xray_transport import close_xray_transport, open_xray_transport


LEGACY_FINDING_LABELS = {
    "HASH_MUTATED",
    "PATH_TRAVERSAL",
    "FILE_TYPE_CHANGED",
    "HARD_LINK_BOUNDARY_ESCAPE",
    "CROSS_INODE_LINKAGE",
    "ATOMIC_SWAP_DETECTED",
    "ARCHIVE_ENTRY_ESCAPE",
    "RACE_CONDITION_DETECTED",
    "PROCFS_FD_HIJACK",
    "SKILL_ISOLATION_BREACH",
}


def test_pub_pointer_redirection_uses_pointer_observation_without_symlink(tmp_path):
    root = tmp_path / "skill_root"
    outside = tmp_path / "outside_skill_boundary"
    root.mkdir()
    outside.mkdir()
    legitimate = root / "docs.skillpkg"
    shadow = outside / "shadow.skillpkg"
    pointer = root / "current_skill.ptr"
    _write_skill_capsule(legitimate, "docs-skill", b"LEGIT_POINTER_TARGET")
    _write_skill_capsule(shadow, "vault-skill", b"SENSITIVE_OUTSIDE_TARGET")

    pointer.write_text(str(legitimate), encoding="utf-8")
    enter_state = _pointer_observed_state(pointer, boundary_root=root, sampled_at_ns=100)

    pointer.write_text(str(shadow), encoding="utf-8")
    exit_state = _pointer_observed_state(pointer, boundary_root=root, sampled_at_ns=200)

    result = _evaluate(
        "pub-pointer",
        enter_object_states=(enter_state,),
        exit_object_states=(exit_state,),
        targets=(str(pointer),),
    )
    payload, residual = _single_residual(result, "POINTER_REDIRECTION")

    assert result.state == AccessEquationState.RESIDUAL
    assert residual["component"] == "delta_b_x"
    assert residual["details"]["mechanism"] == "pointer_surface_delta"
    assert residual["evidence"]["before_raw_path"] == residual["evidence"]["after_raw_path"]
    assert residual["evidence"]["before_resolved_path"] == str(legitimate.resolve(strict=False))
    assert residual["evidence"]["after_resolved_path"] == str(shadow.resolve(strict=False))
    assert enter_state.details["pointer_payload_sha256"] != exit_state.details["pointer_payload_sha256"]
    _assert_witness_payload_has_no_execution_authority(payload)


def test_pub_alias_write_uses_hardlink_or_alias_surface_evidence(tmp_path):
    root = tmp_path / "skill_root"
    outside = tmp_path / "attacker_alias"
    root.mkdir()
    outside.mkdir()
    target = root / "shared.skillpkg"
    alias = outside / "shared_alias.link"
    _write_skill_capsule(target, "docs-skill", b"SHARED_INODE_ORIGINAL")

    hardlink_available = True
    try:
        os.link(target, alias)
        alias.write_bytes(target.read_bytes().replace(b"ORIGINAL", b"MUTATED_"))
        alias_sample = sample_xray_object_state(alias, boundary_root=root, sampled_at_ns=150)
        target_sample = sample_xray_object_state(target, boundary_root=root, sampled_at_ns=200)
        alias_refs = target_sample.boundary.alias_refs
        alias_semantics = target_sample.boundary.details["alias_detection_semantics"]
        assert target_sample.state.nlink is not None
        assert target_sample.state.nlink >= 2
        assert alias_sample.state.file_id == target_sample.state.file_id
    except OSError:
        hardlink_available = False
        alias.write_text(str(target), encoding="utf-8")
        target.write_bytes(target.read_bytes().replace(b"ORIGINAL", b"MUTATED_"))
        target_sample = sample_xray_object_state(target, boundary_root=root, sampled_at_ns=200)
        alias_refs = (f"pointer_alias:{alias.resolve(strict=False)}->{target.resolve(strict=False)}",)
        alias_semantics = "pointer_alias_same_resource_when_hardlink_unavailable"

    result = _evaluate(
        "pub-alias",
        object_states=(target_sample.state,),
        boundary=BoundaryMetric(
            boundary_id="workspace_alias_surface",
            root=str(root.resolve(strict=False)),
            scope="pub_alias_write",
            alias_refs=alias_refs,
            details={"alias_detection_semantics": alias_semantics},
        ),
        effects=("write",),
        targets=(str(target), str(alias)),
    )
    payload, residual = _single_residual(result, "ALIAS_WRITE")

    assert result.state == AccessEquationState.RESIDUAL
    assert target.read_bytes() != _skill_capsule_bytes("docs-skill", b"SHARED_INODE_ORIGINAL")
    assert residual["component"] == "div_b_j"
    assert residual["details"]["mechanism"] == "multi_link_surface"
    assert residual["details"]["alias_detection_semantics"] == alias_semantics
    assert residual["evidence"]["alias_refs"] == alias_refs
    assert hardlink_available or alias.exists()
    _assert_witness_payload_has_no_execution_authority(payload)


def test_pub_object_substitution_detects_atomic_swap_metadata_masquerade(tmp_path):
    target = tmp_path / "docs.skillpkg"
    decoy = tmp_path / "decoy.skillpkg"
    original = b"ORIGINAL_BYTES_00000"
    replacement = b"DECOY____BYTES_00000"
    assert len(original) == len(replacement)
    target.write_bytes(original)
    decoy.write_bytes(replacement)
    original_stat = target.stat()
    os.utime(decoy, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    os.chmod(decoy, original_stat.st_mode)

    enter = sample_xray_object_state(target, boundary_root=tmp_path, sampled_at_ns=100)
    os.replace(decoy, target)
    exit_sample = sample_xray_object_state(target, boundary_root=tmp_path, sampled_at_ns=200)

    result = _evaluate(
        "pub-object-substitution",
        enter_object_states=(enter.state,),
        exit_object_states=(exit_sample.state,),
        effects=("write",),
        targets=(str(target),),
    )
    payload, residual = _single_residual(result, "OBJECT_SUBSTITUTION")

    assert result.state == AccessEquationState.RESIDUAL
    assert enter.state.raw_path == exit_sample.state.raw_path
    assert enter.state.resolved_path == exit_sample.state.resolved_path
    assert enter.state.size == exit_sample.state.size
    assert enter.state.mtime_ns == exit_sample.state.mtime_ns
    assert enter.state.metadata_sha256 != exit_sample.state.metadata_sha256
    assert residual["component"] == "delta_b_x"
    assert residual["details"]["mechanism"] == "resource_identity_delta"
    assert residual["evidence"]["before_metadata_sha256"] != residual["evidence"]["after_metadata_sha256"]
    _assert_witness_payload_has_no_execution_authority(payload)


def test_pub_container_escape_detects_nested_capsule_archive_escape(tmp_path):
    capsule = tmp_path / "evil.skillpkg"
    extraction_root = tmp_path / "extract_root"
    extraction_root.mkdir()
    fixed_date = (2026, 5, 31, 0, 0, 0)
    with zipfile.ZipFile(capsule, "w") as archive:
        for name, payload in (
            ("SKILL.md", b"name: benign\n"),
            ("../../../outside_boundary/pwned.py", b"PAYLOAD"),
        ):
            info = zipfile.ZipInfo(name, fixed_date)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, payload)

    capsule_sample = sample_xray_object_state(capsule, boundary_root=tmp_path, sampled_at_ns=100)
    escaped_refs = _archive_escaped_refs(capsule, extraction_root)
    assert escaped_refs

    result = _evaluate(
        "pub-container-escape",
        object_states=(capsule_sample.state,),
        boundary=BoundaryMetric(
            boundary_id="archive_extraction_boundary",
            root=str(extraction_root.resolve(strict=False)),
            scope="nested_capsule",
            escaped_refs=escaped_refs,
            distance={ref: 1.0 for ref in escaped_refs},
            details={"archive_escape_semantics": "zip_entry_resolves_outside_extraction_root"},
        ),
        targets=(str(capsule),),
    )
    payload, residual = _single_residual(result, "CONTAINER_ESCAPE")

    assert result.state == AccessEquationState.RESIDUAL
    assert residual["component"] == "div_b_j"
    assert residual["details"]["mechanism"] == "boundary_escape"
    assert residual["evidence"]["root"] == str(extraction_root.resolve(strict=False))
    assert residual["evidence"]["escaped_refs"] == escaped_refs
    assert residual["evidence"]["distance"][escaped_refs[0]] == 1.0
    _assert_witness_payload_has_no_execution_authority(payload)


def test_pub_temporal_race_uses_metadata_change_token_for_churn(tmp_path):
    target = tmp_path / "volatile.skillpkg"
    _write_skill_capsule(target, "docs-skill", b"VOLATILE_SEED_0000")
    enter = sample_xray_object_state(
        target,
        boundary_root=tmp_path,
        sampled_at_ns=100,
        profile=MetadataSampleProfile.TIME_SLICE,
    )
    stop_event = threading.Event()
    mutation_counter = {"count": 0}

    def churn() -> None:
        seq = 1
        while not stop_event.is_set():
            _write_skill_capsule(target, "docs-skill", f"VOLATILE_MUT_{seq:04d}".encode())
            mutation_counter["count"] += 1
            seq += 1
            time.sleep(0.001)

    thread = threading.Thread(target=churn, daemon=True)
    thread.start()
    deadline = time.monotonic() + 1.0
    while mutation_counter["count"] < 3 and time.monotonic() < deadline:
        time.sleep(0.005)
    exit_sample = sample_xray_object_state(
        target,
        boundary_root=tmp_path,
        sampled_at_ns=200,
        profile=MetadataSampleProfile.TIME_SLICE,
    )
    stop_event.set()
    thread.join(timeout=1.0)

    change = metadata_change_token(enter, exit_sample)
    if not change.changed:
        _write_skill_capsule(target, "docs-skill", b"VOLATILE_FINAL_DELTA")
        exit_sample = sample_xray_object_state(
            target,
            boundary_root=tmp_path,
            sampled_at_ns=300,
            profile=MetadataSampleProfile.TIME_SLICE,
        )
        change = metadata_change_token(enter, exit_sample)
    token = {
        **change.to_dict(),
        "subject": "target:volatile.skillpkg",
        "mutation_count": mutation_counter["count"],
    }

    result = _evaluate(
        "pub-temporal-race",
        metadata_change_tokens=(token,),
        targets=(str(target),),
    )
    payload, residual = _single_residual(result, "TEMPORAL_RACE")

    assert result.state == AccessEquationState.RESIDUAL
    assert change.changed is True
    assert token["mutation_count"] >= 1
    assert residual["component"] == "delta_b_x"
    assert residual["details"]["mechanism"] == "sampled_metadata_delta"
    assert residual["details"]["semantics"] == "sampled_metadata_delta_v0"
    assert residual["evidence"]["enter_hash"] != residual["evidence"]["exit_hash"]
    assert residual["evidence"]["mutation_count"] >= 1
    _assert_witness_payload_has_no_execution_authority(payload)


def test_pub_live_meter_catches_born_and_died_transient_between_endpoints(tmp_path):
    flash = tmp_path / "flash_artifact.tmp"
    proposal = CommandProposal(
        command_text=f"write then remove {flash}",
        actor_id="redteam_agent",
        cwd=str(tmp_path),
        declared_scope=DeclaredScope.READ_ONLY,
        target_paths=(str(flash),),
        expected_side_effects=set(),
        parent_event_id="hardcore_parent",
        user_request_id="hardcore_user",
        proposal_id="hardcore_transient_window",
        source_adapter="hardcore_redteam",
        tool_name="filesystem",
        action_type="write",
    )
    handle = open_xray_transport(proposal, beat_interval_ns=5_000_000)

    flash.write_bytes(b"I_EXISTED_ONLY_IN_THE_GAP")
    time.sleep(0.05)
    flash.unlink()
    time.sleep(0.02)
    seal = close_xray_transport(handle, proposal)

    witness = seal.process_witness
    trace = witness["time_grid_traces"][0]
    assert seal.mutation_state == "STABLE"
    assert witness["requires_hold"] is True
    assert witness["residual_components"]["T"] == 1.0
    assert "GRID_EXISTENCE_DRIFT" in trace["finding_types"]
    assert trace["sampling"]["time_signature"] == (
        "4/4" if os.name == "nt" else "8/8"
    )
    assert trace["sampling"]["pattern"][:4] == (
        "snare",
        "kick",
        "snare",
        "kick",
    )
    assert witness["testimony_only"] is True
    assert leaks_forbidden_authority(seal.to_dict()) is False


def test_pub_observation_blindness_holds_fd_hijack_equivalent(tmp_path):
    target = tmp_path / "fd_bait.skillpkg"
    _write_skill_capsule(target, "docs-skill", b"ORIGINAL_FD_BAIT_DATA")
    time_slice = sample_xray_object_state(
        target,
        boundary_root=tmp_path,
        sampled_at_ns=100,
        profile=MetadataSampleProfile.TIME_SLICE,
    )
    observation = ObservationMask.from_required_fields(
        required_fields=(
            "file_id",
            "resolved_path",
            "metadata_vector_hash",
            "stable_handle_identity",
        ),
        observed_fields=time_slice.observation.observed_fields,
        blind_spots=(
            *time_slice.observation.blind_spots,
            "windows_handle_or_procfd_indirection_unobserved",
        ),
        confidence=0.2,
        details={
            "original_redteam_case": "proc_self_fd_hijack",
            "windows_equivalent": "stable_handle_identity_not_observed",
            "sample_profile": "time_slice",
        },
    )

    result = _evaluate(
        "pub-observation-blindness",
        object_states=(time_slice.state,),
        observation=observation,
        targets=(str(target),),
    )
    payload, residual = _single_residual(result, "OBSERVATION_BLINDNESS")

    assert result.state == AccessEquationState.INCOMPLETE_HOLD
    assert result.requires_hold is True
    assert residual["state"] == "INCOMPLETE"
    assert residual["component"] == "o_apply"
    assert residual["details"]["mechanism"] == "observation_blindness"
    assert "file_id" in residual["evidence"]["missing_fields"]
    assert "resolved_path" in residual["evidence"]["missing_fields"]
    assert "stable_handle_identity" in residual["evidence"]["missing_fields"]
    assert "windows_handle_or_procfd_indirection_unobserved" in residual["evidence"]["blind_spots"]
    _assert_witness_payload_has_no_execution_authority(payload)


def test_pub_responsibility_swap_detects_multi_stage_skill_identity_replacement(tmp_path):
    skill_path = tmp_path / "current.skillpkg"
    staged = tmp_path / "staged_attacker.skillpkg"
    _write_skill_capsule(skill_path, "docs-skill", b"SKILL_A_PRIVATE_DATA")
    _write_skill_capsule(staged, "ops-skill", b"SKILL_B_MUTATED_CONTENT")

    enter_sample = sample_xray_object_state(skill_path, boundary_root=tmp_path, sampled_at_ns=100)
    enter_state = _with_skill_identity(enter_sample.state, skill_path)
    os.replace(staged, skill_path)
    exit_sample = sample_xray_object_state(skill_path, boundary_root=tmp_path, sampled_at_ns=200)
    exit_state = _with_skill_identity(exit_sample.state, skill_path)

    result = _evaluate(
        "pub-responsibility-swap",
        enter_object_states=(enter_state,),
        exit_object_states=(exit_state,),
        effects=("read",),
        targets=(str(skill_path),),
    )
    payload, residual = _single_residual(result, "RESPONSIBILITY_SWAP")

    assert result.state == AccessEquationState.RESIDUAL
    assert enter_state.raw_path == exit_state.raw_path
    assert enter_state.resolved_path == exit_state.resolved_path
    assert enter_state.details["skill_id"] == "docs-skill"
    assert exit_state.details["skill_id"] == "ops-skill"
    assert residual["component"] == "delta_b_x"
    assert residual["details"]["mechanism"] == "skill_responsibility_identity_delta"
    assert residual["evidence"]["before_skill_identity"] != residual["evidence"]["after_skill_identity"]
    _assert_witness_payload_has_no_execution_authority(payload)


def test_pub_junction_reparse_escapes_boundary_despite_directory_object_type(tmp_path):
    boundary = tmp_path / "skill_root"
    outside = tmp_path / "outside_boundary"
    boundary.mkdir()
    outside.mkdir()
    (outside / "loot.txt").write_text("SECRET_OUTSIDE_TARGET", encoding="utf-8")
    junction = boundary / "looks_like_a_folder"
    if not _make_junction(junction, outside):
        pytest.skip("NTFS junction (reparse point) unavailable on this filesystem")

    sample = sample_xray_object_state(junction, boundary_root=boundary, sampled_at_ns=100)

    # The reparse junction can no longer pass as a plain folder. lstat still reports
    # a directory and S_ISLNK stays false, but the sampler reads the NT reparse tag,
    # names the object for what it is, and pins the redirect target via readlink.
    assert sample.state.object_type == "reparse_point"
    assert sample.state.reparse_tag == 2684354563  # IO_REPARSE_TAG_MOUNT_POINT
    assert sample.state.symlink_target is not None
    assert sample.state.nlink == 1
    # The resolved landing point independently confirms the escape: resolve() walks
    # the reparse point out to the sibling tree, so the sampler's own boundary metric
    # marks the escape without anyone hand-feeding it.
    assert sample.state.resolved_path == str(outside.resolve(strict=False))
    assert sample.boundary.escaped_refs == (sample.state.resolved_path,)

    result = _evaluate(
        "pub-junction-reparse",
        object_states=(sample.state,),
        boundary=sample.boundary,
        targets=(str(junction),),
    )
    payload, residual = _single_residual(result, "CONTAINER_ESCAPE")

    assert result.state == AccessEquationState.RESIDUAL
    assert residual["component"] == "div_b_j"
    assert residual["details"]["mechanism"] == "boundary_escape"
    assert residual["evidence"]["escaped_refs"] == (sample.state.resolved_path,)
    assert residual["evidence"]["distance"][sample.state.resolved_path] == 1.0
    _assert_witness_payload_has_no_execution_authority(payload)


def test_pub_junction_into_boundary_is_named_reparse_not_plain_directory(tmp_path):
    # The blind spot pub used to carry: a junction that stays *inside* the boundary
    # raises no escape, so resolve-landing-point alone says nothing. Old code left it
    # a plain 'directory' and a guard would walk it as an ordinary subfolder straight
    # onto a sensitive store. Now the reparse identity is what survives the disguise.
    boundary = tmp_path / "skill_root"
    boundary.mkdir()
    sensitive = boundary / "ledger_store"
    sensitive.mkdir()
    (sensitive / "audit.log").write_text("LEDGER", encoding="utf-8")
    junction = boundary / "harmless_docs"
    if not _make_junction(junction, sensitive):
        pytest.skip("NTFS junction (reparse point) unavailable on this filesystem")

    sample = sample_xray_object_state(junction, boundary_root=boundary, sampled_at_ns=100)

    # No escape — the redirect target is in-boundary — so the boundary metric is silent.
    assert sample.boundary.escaped_refs == ()
    assert sample.boundary.contained_refs
    # The reparse identity stands on its own without an escape to lean on.
    assert sample.state.object_type == "reparse_point"
    assert sample.state.reparse_tag == 2684354563  # IO_REPARSE_TAG_MOUNT_POINT
    assert sample.state.symlink_target is not None
    assert "ledger_store" in sample.state.symlink_target


def test_pub_ads_stream_shares_host_file_id_but_metadata_vector_separates_payload(tmp_path):
    boundary = tmp_path / "skill_root"
    boundary.mkdir()
    host = boundary / "report.md"
    host.write_text("PUBLIC BENIGN REPORT BODY\n", encoding="utf-8")
    stream_ref = f"{host}:payload"
    if not _write_alternate_data_stream(stream_ref, "EVIL_HIDDEN_STREAM_PAYLOAD_0000000000"):
        pytest.skip("NTFS alternate data streams unavailable on this filesystem")

    host_sample = sample_xray_object_state(host, boundary_root=boundary, sampled_at_ns=100)
    stream_sample = sample_xray_object_state(stream_ref, boundary_root=boundary, sampled_at_ns=200)

    # The whole trick of an ADS is that the hidden stream and its host share one
    # NTFS record: same device, same inode, therefore the same file_id. Any guard
    # that treats file_id as a resource identity proof would conclude the payload
    # stream *is* the benign host file.
    assert host_sample.state.file_id is not None
    assert stream_sample.state.file_id == host_sample.state.file_id
    # The metadata vector refuses that collapse: raw path, byte size and the vector
    # hash all separate the payload stream from the host body, so file_id is treated
    # as a signal, never as identity.
    assert stream_sample.state.raw_path != host_sample.state.raw_path
    assert stream_sample.state.size != host_sample.state.size
    assert stream_sample.state.metadata_sha256 != host_sample.state.metadata_sha256
    # The mechanism here is identity confusion, not a boundary escape: both the host
    # and its stream resolve to inside the skill root.
    assert host_sample.boundary.contained_refs
    assert stream_sample.boundary.contained_refs
    assert not stream_sample.boundary.escaped_refs


def test_pub_ads_stream_payload_is_enumeration_blindspot_and_holds(tmp_path):
    boundary = tmp_path / "skill_root"
    boundary.mkdir()
    host = boundary / "report.md"
    host.write_text("PUBLIC BENIGN REPORT BODY\n", encoding="utf-8")
    stream_ref = f"{host}:payload"
    if not _write_alternate_data_stream(stream_ref, "EVIL_HIDDEN_STREAM_PAYLOAD_0000000000"):
        pytest.skip("NTFS alternate data streams unavailable on this filesystem")

    stream_sample = sample_xray_object_state(stream_ref, boundary_root=boundary, sampled_at_ns=100)
    # The payload stream is really there...
    assert stream_sample.state.exists is True
    assert stream_sample.state.size and stream_sample.state.size > 0
    # ...yet a directory walk of the boundary never lists it: only the host name
    # surfaces, so any "enumerate the files in scope" sweep is blind to the payload.
    listed = {entry.name for entry in boundary.iterdir()}
    assert host.name in listed
    assert not any(":payload" in name for name in listed)

    observation = ObservationMask.from_required_fields(
        required_fields=(
            "resolved_path",
            "metadata_vector_hash",
            "enumerated_stream_inventory",
        ),
        observed_fields=stream_sample.observation.observed_fields,
        blind_spots=(
            *stream_sample.observation.blind_spots,
            "ntfs_alternate_data_stream_unenumerated",
        ),
        confidence=0.2,
        details={
            "mechanism": "ads_enumeration_blindness",
            "host_path": str(host),
            "stream_ref": stream_ref,
        },
    )

    result = _evaluate(
        "pub-ads-enumeration-blindness",
        object_states=(stream_sample.state,),
        observation=observation,
        targets=(str(host), stream_ref),
    )
    payload, residual = _single_residual(result, "OBSERVATION_BLINDNESS")

    assert result.state == AccessEquationState.INCOMPLETE_HOLD
    assert result.requires_hold is True
    assert residual["state"] == "INCOMPLETE"
    assert residual["component"] == "o_apply"
    assert residual["details"]["mechanism"] == "observation_blindness"
    assert "enumerated_stream_inventory" in residual["evidence"]["missing_fields"]
    assert "ntfs_alternate_data_stream_unenumerated" in residual["evidence"]["blind_spots"]
    _assert_witness_payload_has_no_execution_authority(payload)


def _make_junction(link: Path, target: Path) -> bool:
    """Create an NTFS directory junction (reparse point) without admin rights.

    Returns False on any non-Windows host or when mklink is unavailable, so the
    caller skips rather than fails on filesystems that cannot host the disguise.
    """
    if os.name != "nt":
        return False
    try:
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return result.returncode == 0 and link.exists()


def _write_alternate_data_stream(stream_ref: str, payload: str) -> bool:
    """Write an NTFS alternate data stream (``host:stream``).

    Returns False when the filesystem rejects the colon-suffixed name (any
    non-NTFS volume), so the caller skips instead of failing.
    """
    try:
        with open(stream_ref, "w", encoding="utf-8") as handle:
            handle.write(payload)
    except OSError:
        return False
    return True


def _evaluate(
    process_id: str,
    *,
    object_states: tuple[XrayObjectState, ...] = (),
    enter_object_states: tuple[XrayObjectState, ...] = (),
    exit_object_states: tuple[XrayObjectState, ...] = (),
    boundary: BoundaryMetric | None = None,
    observation: ObservationMask | None = None,
    metadata_change_tokens: tuple[dict[str, Any], ...] = (),
    effects: tuple[str, ...] = ("read",),
    targets: tuple[str, ...] = (),
):
    return omega_access(
        AccessEquationInput(
            process_id=process_id,
            object_states=object_states,
            enter_object_states=enter_object_states,
            exit_object_states=exit_object_states,
            currents=(
                AccessCurrent(
                    process_id=process_id,
                    agency=("actor:redteam_pub", "tool:pub_xray"),
                    surface=("pub_windows_hardcore",),
                    effects=effects,
                    target_refs=targets,
                    source_adapter="pytest_pub",
                    tool_name="pub_xray",
                    proposal_id=f"{process_id}-proposal",
                ),
            ),
            boundary=boundary or BoundaryMetric(boundary_id="workspace"),
            auth=AuthPotential(
                process_id=process_id,
                authorized_actors=("benign_pub_observer",),
                authorized_tools=("metadata_sampler",),
                authorized_effects=("read",),
                authorized_targets=("not-this-case",),
                details={"authority": "witness_only_no_execution_grant"},
            ),
            observation=observation
            or ObservationMask(
                ObservationState.COMPLETE,
                observed_fields=(
                    "state_hash",
                    "metadata_vector_hash",
                    "resolved_path",
                    "file_id",
                    "nlink",
                    "boundary",
                ),
            ),
            metadata_change_tokens=metadata_change_tokens,
        )
    )


def _single_residual(result, residual_type: str):
    payload = result.to_dict()
    _assert_witness_payload_has_no_execution_authority(payload)
    _assert_legacy_finding_labels_absent(payload)
    assert result.minimum_action == "HOLD"
    matches = [
        residual
        for residual in payload["residuals"]
        if residual["residual_type"] == residual_type
    ]
    assert matches, payload
    assert matches[0]["requires_action"] is True
    return payload, matches[0]


def _pointer_observed_state(
    pointer: Path,
    *,
    boundary_root: Path,
    sampled_at_ns: int,
) -> XrayObjectState:
    target = Path(pointer.read_text(encoding="utf-8").strip())
    target_sample = sample_xray_object_state(
        target,
        raw_ref=str(pointer),
        boundary_root=boundary_root,
        sampled_at_ns=sampled_at_ns,
    )
    pointer_sample = sample_xray_object_state(
        pointer,
        raw_ref=str(pointer),
        boundary_root=boundary_root,
        sampled_at_ns=sampled_at_ns,
    )
    return replace(
        target_sample.state,
        object_ref="pointer:current_skill",
        raw_path=str(pointer),
        details={
            **target_sample.state.details,
            "pointer_file_metadata_sha256": pointer_sample.metadata_vector_hash,
            "pointer_payload_sha256": _sha256(pointer.read_bytes()),
            "pointer_observation_semantics": "raw_pointer_file_resolves_to_target_path",
        },
    )


def _with_skill_identity(state: XrayObjectState, capsule: Path) -> XrayObjectState:
    manifest = _read_manifest(capsule)
    return replace(
        state,
        details={
            **state.details,
            "skill_id": manifest["skill_id"],
            "skill_manifest_sha256": _sha256(json.dumps(manifest, sort_keys=True).encode()),
        },
    )


def _write_skill_capsule(path: Path, skill_id: str, hidden_payload: bytes) -> None:
    fixed_date = (2026, 5, 31, 0, 0, 0)
    entries = (
        ("SKILL.md", f"name: {skill_id}\ninstructions: read-only\n".encode()),
        ("manifest.json", json.dumps({"skill_id": skill_id, "version": 1}).encode()),
        ("hidden_audit.pad", hidden_payload),
    )
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in entries:
            info = zipfile.ZipInfo(name, fixed_date)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, payload)


def _skill_capsule_bytes(skill_id: str, hidden_payload: bytes) -> bytes:
    from io import BytesIO

    handle = BytesIO()
    fixed_date = (2026, 5, 31, 0, 0, 0)
    with zipfile.ZipFile(handle, "w") as archive:
        for name, payload in (
            ("SKILL.md", f"name: {skill_id}\ninstructions: read-only\n".encode()),
            ("manifest.json", json.dumps({"skill_id": skill_id, "version": 1}).encode()),
            ("hidden_audit.pad", hidden_payload),
        ):
            info = zipfile.ZipInfo(name, fixed_date)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, payload)
    return handle.getvalue()


def _read_manifest(capsule: Path) -> dict[str, Any]:
    with zipfile.ZipFile(capsule, "r") as archive:
        return json.loads(archive.read("manifest.json").decode("utf-8"))


def _archive_escaped_refs(capsule: Path, extraction_root: Path) -> tuple[str, ...]:
    root = extraction_root.resolve(strict=False)
    escaped: list[str] = []
    with zipfile.ZipFile(capsule, "r") as archive:
        for name in archive.namelist():
            candidate = (root / name).resolve(strict=False)
            try:
                candidate.relative_to(root)
            except ValueError:
                escaped.append(
                    f"archive_entry:{capsule.resolve(strict=False)}:{name}->{candidate}"
                )
    return tuple(escaped)


def _sha256(payload: bytes) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _assert_witness_payload_has_no_execution_authority(payload: Any) -> None:
    encoded = repr(payload)
    assert "can_execute" not in encoded
    assert "can_grant_permission" not in encoded
    if isinstance(payload, dict):
        assert "can_execute" not in payload
        assert "can_grant_permission" not in payload
        for value in payload.values():
            _assert_witness_payload_has_no_execution_authority(value)
    elif isinstance(payload, (list, tuple)):
        for value in payload:
            _assert_witness_payload_has_no_execution_authority(value)


def _assert_legacy_finding_labels_absent(payload: Any) -> None:
    encoded = repr(payload)
    for label in LEGACY_FINDING_LABELS:
        assert label not in encoded
