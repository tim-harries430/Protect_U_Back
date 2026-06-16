from dataclasses import replace

from adapter_wall import ActionEnvelope, AdapterActionType
from capability_wall import CapabilityManifest, CapabilityPolicy, SkillContract
from ot_gate import DeclaredScope, SideEffect
from parallel_audit import (
    EvidenceDisposition,
    EvidenceStage,
    EvidenceTestimony,
    aggregate_parallel_evidence,
    build_parallel_evidence_bundle,
    run_parallel_audit,
)
from phi_registry import PhiRegistry
from protect_scan import (
    ProtectSurface,
    confirm_protect_scan,
    default_protect_scan_profile,
)


PROJECT_ROOT = r"C:\dev\sp"


def registry(*actor_ids):
    store = PhiRegistry()
    for actor_id in actor_ids or ("agent_coder",):
        store.register_actor(actor_id)
    return store


def profile(**kwargs):
    return confirm_protect_scan(
        default_protect_scan_profile(PROJECT_ROOT, **kwargs),
        confirmed=True,
    )


def action(
    command_text,
    *,
    actor_id="agent_coder",
    action_type=AdapterActionType.SHELL,
    target_paths=(),
    expected_side_effects=None,
    declared_scope=None,
    action_id="parallel_action",
    raw_payload=None,
):
    return ActionEnvelope(
        actor_id=actor_id,
        action_type=action_type,
        command_text=command_text,
        cwd=PROJECT_ROOT,
        target_paths=target_paths,
        expected_side_effects=set(expected_side_effects or ()),
        declared_scope=declared_scope,
        source_adapter="codex_vscode",
        tool_name="shell",
        raw_payload=dict(raw_payload or {}),
        branch_id="parallel_branch",
        action_id=action_id,
        parent_event_id="parallel_parent",
        user_request_id="parallel_user_request",
    )


def read_only_capability_policy():
    return CapabilityPolicy(
        project_roots=(PROJECT_ROOT,),
        manifests=(
            CapabilityManifest(
                actor_id="agent_coder",
                manifest_id="read-only:agent_coder",
                allowed_side_effects={SideEffect.READ},
                allowed_path_roots=(PROJECT_ROOT,),
            ),
        ),
    )


def network_capability_policy():
    return CapabilityPolicy(
        project_roots=(PROJECT_ROOT,),
        manifests=(
            CapabilityManifest(
                actor_id="agent_coder",
                manifest_id="network:agent_coder",
                allowed_side_effects={SideEffect.READ, SideEffect.NETWORK},
                allowed_path_roots=(PROJECT_ROOT,),
                allowed_network_domains=("api.example.internal",),
            ),
        ),
    )


def skill_capability_policy():
    return CapabilityPolicy(
        project_roots=(PROJECT_ROOT,),
        manifests=(
            CapabilityManifest(
                actor_id="agent_coder",
                manifest_id="skill:agent_coder",
                allowed_side_effects={SideEffect.READ},
                allowed_path_roots=(PROJECT_ROOT,),
                skill_contracts=(
                    SkillContract(
                        skill_id="docs-skill",
                        required_step_ids=("read_skill_md",),
                    ),
                ),
            ),
        ),
    )


def assert_no_authority(result):
    assert result.io_executed is False
    assert result.can_execute is False
    assert result.can_grant_permission is False
    result_dict = result.to_dict()
    assert result_dict["io_executed"] is False
    assert result_dict["can_execute"] is False
    assert result_dict["can_grant_permission"] is False


def test_clean_action_passes_parallel_testimony_but_does_not_execute():
    result = run_parallel_audit(
        action("git status --short", action_id="parallel_clean"),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )

    assert result.disposition == EvidenceDisposition.PASS
    assert result.reason_code == "CHANNEL_WRAP_PROPOSAL"
    assert result.primary_stage == EvidenceStage.CHANNEL_AUDIT
    assert result.capability_certificate.value == "CAP_PASS"
    assert result.would_enter_ot is True
    assert_no_authority(result)


def test_admission_reject_short_circuits_before_evidence_bundle():
    result = run_parallel_audit(
        action(
            r"Set-Content .phi\registry\actors.json '{}'",
            actor_id="unknown_agent",
            action_type=AdapterActionType.FILE_WRITE,
            target_paths=(r".phi\registry\actors.json",),
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )

    assert result.disposition == EvidenceDisposition.REJECT
    assert result.reason_code == "ADMISSION_UNKNOWN_AGENT"
    assert result.primary_stage == EvidenceStage.ADMISSION
    assert result.evidence_bundle is None
    assert len(result.testimonies) == 1
    assert_no_authority(result)


def test_kill_priority_beats_channel_quarantine_in_aggregator():
    bundle = build_parallel_evidence_bundle(
        action("git status --short", action_id="parallel_priority"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )
    bundle = replace(
        bundle,
        channel_testimony=EvidenceTestimony(
            stage=EvidenceStage.CHANNEL_AUDIT,
            disposition=EvidenceDisposition.QUARANTINE,
            reason_code="CHANNEL_TEST_QUARANTINE",
            detail="synthetic quarantine testimony",
        ),
        protect_testimony=EvidenceTestimony(
            stage=EvidenceStage.PROTECT_SCAN,
            disposition=EvidenceDisposition.KILL,
            reason_code="PROTECT_TEST_KILL",
            detail="synthetic protect kill testimony",
        ),
    )

    result = aggregate_parallel_evidence(bundle)

    assert result.disposition == EvidenceDisposition.KILL
    assert result.reason_code == "PROTECT_TEST_KILL"
    assert result.primary_stage == EvidenceStage.PROTECT_SCAN
    assert_no_authority(result)


def test_quarantine_priority_beats_hold_in_aggregator():
    bundle = build_parallel_evidence_bundle(
        action("git status --short", action_id="parallel_quarantine"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )
    bundle = replace(
        bundle,
        channel_testimony=EvidenceTestimony(
            stage=EvidenceStage.CHANNEL_AUDIT,
            disposition=EvidenceDisposition.QUARANTINE,
            reason_code="CHANNEL_TEST_QUARANTINE",
            detail="synthetic quarantine testimony",
        ),
        protect_testimony=EvidenceTestimony(
            stage=EvidenceStage.PROTECT_SCAN,
            disposition=EvidenceDisposition.HOLD,
            reason_code="PROTECT_TEST_HOLD",
            detail="synthetic protect hold testimony",
        ),
    )

    result = aggregate_parallel_evidence(bundle)

    assert result.disposition == EvidenceDisposition.QUARANTINE
    assert result.reason_code == "CHANNEL_TEST_QUARANTINE"
    assert result.primary_stage == EvidenceStage.CHANNEL_AUDIT
    assert_no_authority(result)


def test_protect_scan_kill_is_reported_as_protect_stage_not_capability():
    result = run_parallel_audit(
        action(
            r"Set-Content .phi\registry\actors.json '{}'",
            action_type=AdapterActionType.FILE_WRITE,
            target_paths=(r".phi\registry\actors.json",),
            expected_side_effects={SideEffect.WRITE},
            declared_scope=DeclaredScope.PROJECT_WRITE,
            action_id="parallel_protect_registry",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )

    assert result.disposition == EvidenceDisposition.KILL
    assert result.primary_stage == EvidenceStage.PROTECT_SCAN
    assert result.reason_code == "PROTECT_REGISTRY_ACCESS_DENIED"
    assert result.capability_certificate is None
    assert result.would_enter_ot is False
    assert_no_authority(result)


def test_protect_startup_confirmation_required_blocks_capability_pass():
    unconfirmed = default_protect_scan_profile(PROJECT_ROOT)
    result = run_parallel_audit(
        action("git status --short", action_id="parallel_unconfirmed"),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=unconfirmed,
    )

    assert result.disposition == EvidenceDisposition.HOLD
    assert result.primary_stage == EvidenceStage.PROTECT_SCAN
    assert result.reason_code == "PROTECT_SCAN_STARTUP_CONFIRMATION_REQUIRED"
    assert result.capability_certificate is None
    assert result.would_enter_ot is False
    assert_no_authority(result)


def test_capability_precheck_kill_stops_before_ot_without_authority():
    result = run_parallel_audit(
        action(
            "Set-Content docs/report.md 'ok'",
            action_type=AdapterActionType.FILE_WRITE,
            target_paths=("docs/report.md",),
            expected_side_effects={SideEffect.WRITE},
            declared_scope=DeclaredScope.PROJECT_WRITE,
            action_id="parallel_capability_write",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
        capability_policy=read_only_capability_policy(),
    )

    assert result.disposition == EvidenceDisposition.KILL
    assert result.primary_stage == EvidenceStage.CAPABILITY_PRECHECK
    assert result.reason_code == "CAPABILITY_SIDE_EFFECT_DENIED"
    assert result.capability_certificate.value == "CAP_KILL_WARRANT"
    assert result.would_enter_ot is False
    assert_no_authority(result)


def test_capability_pass_certificate_cannot_override_protect_hold():
    result = run_parallel_audit(
        action(
            "curl https://api.example.internal/status",
            action_type=AdapterActionType.NETWORK,
            target_paths=("https://api.example.internal/status",),
            expected_side_effects={SideEffect.NETWORK},
            declared_scope=DeclaredScope.EXTERNAL_IO,
            action_id="parallel_network_hold",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
        capability_policy=network_capability_policy(),
    )

    assert result.disposition == EvidenceDisposition.HOLD
    assert result.primary_stage == EvidenceStage.PROTECT_SCAN
    assert result.reason_code == "PROTECT_NETWORK_REQUIRES_CONFIRMATION"
    assert result.capability_certificate is None
    assert result.would_enter_ot is False
    assert_no_authority(result)


def test_skill_compliance_stays_inside_capability_precheck():
    missing_skill = run_parallel_audit(
        action(
            "Get-Content README.md",
            target_paths=("README.md",),
            raw_payload={"skill_trace": {"used_skill_ids": ()}},
            action_id="parallel_skill_missing",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
        capability_policy=skill_capability_policy(),
    )
    authority_claim = run_parallel_audit(
        action(
            "Get-Content README.md",
            target_paths=("README.md",),
            raw_payload={
                "skill_trace": {
                    "used_skill_ids": ("docs-skill",),
                    "completed_step_ids": ("read_skill_md",),
                    "instruction_scan": {"status": "PASS"},
                    "authority_claims": ("bypass approval",),
                }
            },
            action_id="parallel_skill_authority_claim",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
        capability_policy=skill_capability_policy(),
    )

    assert missing_skill.disposition == EvidenceDisposition.HOLD
    assert missing_skill.primary_stage == EvidenceStage.CAPABILITY_PRECHECK
    assert missing_skill.reason_code == "CAPABILITY_SKILL_REQUIRED_NOT_USED"
    assert missing_skill.would_enter_ot is False
    assert authority_claim.disposition == EvidenceDisposition.KILL
    assert authority_claim.primary_stage == EvidenceStage.CAPABILITY_PRECHECK
    assert authority_claim.reason_code == "CAPABILITY_SKILL_AUTHORITY_CLAIM_DENIED"
    assert authority_claim.would_enter_ot is False
    assert_no_authority(missing_skill)
    assert_no_authority(authority_claim)


def test_channel_authority_claim_stops_as_channel_hold():
    result = run_parallel_audit(
        action(
            "git status --short",
            raw_payload={"can_execute": True, "certificate": "CAP_PASS"},
            action_id="parallel_channel_claim",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )

    assert result.disposition == EvidenceDisposition.HOLD
    assert result.primary_stage == EvidenceStage.CHANNEL_AUDIT
    assert result.reason_code == "CHANNEL_AUTHORITY_METADATA_CLAIM"
    assert result.capability_certificate is None
    assert_no_authority(result)


def test_parallel_audit_propagates_raw_payload_to_protect_sandbox_hold_and_kill():
    read_only = run_parallel_audit(
        action(
            "Get-Content README.md",
            target_paths=("README.md",),
            raw_payload={"sandbox": {"available": False, "reason": "docker unavailable"}},
            action_id="parallel_sandbox_read_hold",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )
    host_fallback = run_parallel_audit(
        action(
            "Get-Content README.md",
            target_paths=("README.md",),
            raw_payload={
                "sandbox": {
                    "available": False,
                    "reason": "docker unavailable",
                    "fallback": "host_shell_requested",
                }
            },
            action_id="parallel_sandbox_host_kill",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )

    assert read_only.disposition == EvidenceDisposition.HOLD
    assert read_only.primary_stage == EvidenceStage.PROTECT_SCAN
    assert read_only.reason_code == "PROTECT_SANDBOX_UNAVAILABLE_READ_DIAGNOSTIC_REQUIRES_CONFIRMATION"
    assert host_fallback.disposition == EvidenceDisposition.KILL
    assert host_fallback.primary_stage == EvidenceStage.PROTECT_SCAN
    assert host_fallback.reason_code == "PROTECT_SANDBOX_UNAVAILABLE_UNSAFE_FALLBACK_DENIED"
    assert_no_authority(read_only)
    assert_no_authority(host_fallback)


def test_parallel_audit_gateway_loopback_pass_remote_hold_public_kill():
    loopback = run_parallel_audit(
        action(
            "publish loopback gateway",
            target_paths=("http://127.0.0.1:8080",),
            expected_side_effects=set(),
            raw_payload={"gateway": {"bind_host": "127.0.0.1", "auth": "valid"}},
            action_id="parallel_gateway_loopback_pass",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )
    remote = run_parallel_audit(
        action(
            "publish controlled remote gateway",
            target_paths=("https://preview.example.internal",),
            expected_side_effects=set(),
            raw_payload={"gateway": {"host": "preview.example.internal", "auth": "valid"}},
            action_id="parallel_gateway_remote_hold",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )
    public = run_parallel_audit(
        action(
            "publish public gateway",
            target_paths=("http://0.0.0.0:8080",),
            expected_side_effects=set(),
            raw_payload={
                "gateway": {
                    "bind_host": "0.0.0.0",
                    "allowInsecureAuth": True,
                }
            },
            action_id="parallel_gateway_public_kill",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )

    assert loopback.disposition == EvidenceDisposition.PASS
    assert loopback.reason_code == "CHANNEL_WRAP_PROPOSAL"
    assert remote.disposition == EvidenceDisposition.HOLD
    assert remote.primary_stage == EvidenceStage.PROTECT_SCAN
    assert remote.reason_code == "PROTECT_GATEWAY_REMOTE_REQUIRES_CONFIRMATION"
    assert public.disposition == EvidenceDisposition.KILL
    assert public.primary_stage == EvidenceStage.PROTECT_SCAN
    assert public.reason_code == "PROTECT_GATEWAY_PUBLIC_OR_UNAUTHENTICATED_DENIED"
    assert_no_authority(loopback)
    assert_no_authority(remote)
    assert_no_authority(public)


def test_patch_boundary_change_requires_human_review():
    result = run_parallel_audit(
        action(
            "Set-Content parallel_audit.py 'weaken boundary'",
            action_type=AdapterActionType.FILE_WRITE,
            target_paths=("parallel_audit.py",),
            expected_side_effects={SideEffect.WRITE},
            declared_scope=DeclaredScope.PROJECT_WRITE,
            action_id="parallel_patch_hold",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )

    assert result.disposition == EvidenceDisposition.HOLD
    assert result.primary_stage == EvidenceStage.PATCH_AUDIT
    assert result.reason_code == "PATCH_AUDIT_BOUNDARY_NOTE_REQUIRED"
    assert_no_authority(result)


def test_documentation_words_do_not_trigger_parallel_false_positive():
    result = run_parallel_audit(
        action(
            "Get-Content docs/capability_manifest_notes.md",
            target_paths=("docs/capability_manifest_notes.md",),
            action_id="parallel_docs_read",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )

    assert result.disposition == EvidenceDisposition.PASS
    assert result.reason_code == "CHANNEL_WRAP_PROPOSAL"
    assert result.would_enter_ot is True
    assert_no_authority(result)


def test_optional_personal_surface_changes_only_when_enabled():
    default_result = run_parallel_audit(
        action(
            r"Get-Content C:\Users\TestUser\Documents\note.txt",
            target_paths=(r"C:\Users\TestUser\Documents\note.txt",),
            action_id="parallel_personal_default",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
    )
    optional_result = run_parallel_audit(
        action(
            r"Get-Content C:\Users\TestUser\Documents\note.txt",
            target_paths=(r"C:\Users\TestUser\Documents\note.txt",),
            action_id="parallel_personal_enabled",
        ),
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(optional_surfaces=(ProtectSurface.PERSONAL_DOCUMENTS,)),
    )

    assert default_result.disposition == EvidenceDisposition.HOLD
    assert default_result.primary_stage == EvidenceStage.CAPABILITY_PRECHECK
    assert default_result.reason_code == "CAPABILITY_EXTERNAL_READ_REQUIRES_CONFIRMATION"
    assert optional_result.disposition == EvidenceDisposition.HOLD
    assert optional_result.primary_stage == EvidenceStage.PROTECT_SCAN
    assert optional_result.reason_code == "PROTECT_PERSONAL_DOCUMENT_REQUIRES_CONFIRMATION"
    assert_no_authority(default_result)
    assert_no_authority(optional_result)


def test_parallel_audit_results_are_deterministic():
    command = action(
        "curl https://api.example.internal/status",
        action_type=AdapterActionType.NETWORK,
        target_paths=("https://api.example.internal/status",),
        expected_side_effects={SideEffect.NETWORK},
        declared_scope=DeclaredScope.EXTERNAL_IO,
        action_id="parallel_deterministic",
    )
    first = run_parallel_audit(
        command,
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
        capability_policy=network_capability_policy(),
    ).to_dict()
    second = run_parallel_audit(
        command,
        registry=registry("agent_coder"),
        project_root=PROJECT_ROOT,
        protect_profile=profile(),
        capability_policy=network_capability_policy(),
    ).to_dict()

    assert first == second


def run_all():
    tests = [
        test_clean_action_passes_parallel_testimony_but_does_not_execute,
        test_admission_reject_short_circuits_before_evidence_bundle,
        test_kill_priority_beats_channel_quarantine_in_aggregator,
        test_quarantine_priority_beats_hold_in_aggregator,
        test_protect_scan_kill_is_reported_as_protect_stage_not_capability,
        test_protect_startup_confirmation_required_blocks_capability_pass,
        test_capability_precheck_kill_stops_before_ot_without_authority,
        test_capability_pass_certificate_cannot_override_protect_hold,
        test_skill_compliance_stays_inside_capability_precheck,
        test_channel_authority_claim_stops_as_channel_hold,
        test_parallel_audit_propagates_raw_payload_to_protect_sandbox_hold_and_kill,
        test_parallel_audit_gateway_loopback_pass_remote_hold_public_kill,
        test_patch_boundary_change_requires_human_review,
        test_documentation_words_do_not_trigger_parallel_false_positive,
        test_optional_personal_surface_changes_only_when_enabled,
        test_parallel_audit_results_are_deterministic,
    ]

    for test in tests:
        test()
        print(f"PASS: {test.__name__}")

    print("PASS: Parallel Audit v0 testimony aggregator")


if __name__ == "__main__":
    run_all()
