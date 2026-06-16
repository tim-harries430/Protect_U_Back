from capability_wall import (
    CapabilityDisposition,
    CapabilityManifest,
    CapabilityPolicy,
    SkillContract,
    audit_capability,
    default_agent_capability_manifest,
)
from ot_gate import CommandProposal, DeclaredScope, SideEffect


PROJECT_ROOT = r"C:\dev\sp"


def proposal(
    command_text,
    *,
    actor_id="agent_coder",
    declared_scope=DeclaredScope.READ_ONLY,
    target_paths=(),
    expected_side_effects=frozenset({SideEffect.READ}),
    raw_payload=None,
):
    payload = {
        "pub_process": {
            "actor_id": actor_id,
            "action_id": "proposal_capability",
            "channel_type": "AGENT_PROPOSAL",
            "cwd": PROJECT_ROOT,
            "target_paths": tuple(target_paths),
            "expected_side_effects": tuple(
                sorted(effect.value for effect in expected_side_effects)
            ),
            "created_at": 1.0,
            "source_adapter": "test_capability_wall",
        }
    }
    payload.update(dict(raw_payload or {}))
    return CommandProposal(
        command_text=command_text,
        actor_id=actor_id,
        cwd=PROJECT_ROOT,
        declared_scope=declared_scope,
        target_paths=target_paths,
        expected_side_effects=set(expected_side_effects),
        parent_event_id="event_parent_capability",
        user_request_id="user_request_capability",
        proposal_id="proposal_capability",
        raw_payload=payload,
    )


def policy(*manifests):
    return CapabilityPolicy(
        project_roots=(PROJECT_ROOT,),
        manifests=manifests,
    )


def default_policy(actor_id="agent_coder"):
    return policy(default_agent_capability_manifest(actor_id, (PROJECT_ROOT,)))


def read_only_manifest(actor_id="agent_coder"):
    return CapabilityManifest(
        actor_id=actor_id,
        manifest_id=f"read-only:{actor_id}",
        allowed_side_effects={SideEffect.READ},
        allowed_path_roots=(PROJECT_ROOT,),
    )


def network_manifest(actor_id="agent_coder"):
    return CapabilityManifest(
        actor_id=actor_id,
        manifest_id=f"network:{actor_id}",
        allowed_side_effects={SideEffect.READ, SideEffect.NETWORK},
        allowed_path_roots=(PROJECT_ROOT,),
        allowed_network_domains=("api.example.internal",),
    )


def skill_manifest(actor_id="agent_coder"):
    return CapabilityManifest(
        actor_id=actor_id,
        manifest_id=f"skill:{actor_id}",
        allowed_side_effects={SideEffect.READ},
        allowed_path_roots=(PROJECT_ROOT,),
        skill_contracts=(
            SkillContract(
                skill_id="docs-skill",
                manifest_sha256="abc123",
                required_step_ids=("read_skill_md", "apply_skill_rules"),
            ),
        ),
    )


def skill_trace(**overrides):
    trace = {
        "used_skill_ids": ("docs-skill",),
        "completed_step_ids": ("read_skill_md", "apply_skill_rules"),
        "manifest_hashes": {"docs-skill": "abc123"},
        "instruction_scan": {"status": "PASS"},
        "authority_claims": (),
    }
    trace.update(overrides)
    return {"skill_trace": trace}


def assert_decision(command, expected_disposition, expected_reason=None, **kwargs):
    result = audit_capability(
        proposal(command, **kwargs),
        default_policy(kwargs.get("actor_id", "agent_coder")),
    )
    assert result.can_execute is False
    assert result.can_grant_permission is False
    assert result.disposition == expected_disposition
    if expected_reason is not None:
        assert result.reason_code == expected_reason
    return result


def test_allows_workspace_read_with_cap_pass():
    result = assert_decision(
        "Get-Content README.md",
        CapabilityDisposition.ALLOW,
        "CAPABILITY_PASS",
        target_paths=("README.md",),
    )

    assert result.certificate.value == "CAP_PASS"
    assert result.matched_side_effects == (SideEffect.READ,)


def test_allows_read_only_workspace_command_without_target_paths():
    result = assert_decision(
        "git status --short",
        CapabilityDisposition.ALLOW,
        "CAPABILITY_PASS",
        target_paths=(),
    )

    assert result.certificate.value == "CAP_PASS"


def test_holds_when_process_equation_metadata_is_missing():
    result = audit_capability(
        proposal(
            "Get-Content README.md",
            target_paths=("README.md",),
            raw_payload={"pub_process": {}},
        ),
        default_policy(),
    )

    assert result.disposition == CapabilityDisposition.HOLD
    assert result.reason_code == "CAPABILITY_PROCESS_EQUATION_INCOMPLETE"
    assert set(result.evidence) == {"channel_type", "process_time"}


def test_allows_workspace_write_but_does_not_execute():
    result = assert_decision(
        "Set-Content docs/report.md 'ok'",
        CapabilityDisposition.ALLOW,
        "CAPABILITY_PASS",
        declared_scope=DeclaredScope.PROJECT_WRITE,
        target_paths=("docs/report.md",),
        expected_side_effects={SideEffect.WRITE},
    )

    assert result.can_execute is False
    assert result.matched_side_effects == (SideEffect.WRITE,)


def test_missing_manifest_holds_instead_of_killing():
    result = audit_capability(
        proposal("Get-Content README.md", target_paths=("README.md",)),
        policy(),
    )

    assert result.disposition == CapabilityDisposition.HOLD
    assert result.certificate.value == "CAP_HOLD_TICKET"
    assert result.reason_code == "CAPABILITY_MANIFEST_MISSING"


def test_incomplete_manifest_holds():
    manifest = CapabilityManifest(
        actor_id="agent_coder",
        manifest_id="incomplete:agent_coder",
        allowed_side_effects=(),
        allowed_path_roots=(PROJECT_ROOT,),
    )

    result = audit_capability(
        proposal("Get-Content README.md", target_paths=("README.md",)),
        policy(manifest),
    )

    assert result.disposition == CapabilityDisposition.HOLD
    assert result.reason_code == "CAPABILITY_MANIFEST_INCOMPLETE"


def test_read_only_manifest_kills_write_side_effect():
    result = audit_capability(
        proposal(
            "Set-Content cache.json 'x'",
            declared_scope=DeclaredScope.PROJECT_WRITE,
            target_paths=("cache.json",),
            expected_side_effects={SideEffect.WRITE},
        ),
        policy(read_only_manifest()),
    )

    assert result.disposition == CapabilityDisposition.KILL
    assert result.certificate.value == "CAP_KILL_WARRANT"
    assert result.reason_code == "CAPABILITY_SIDE_EFFECT_DENIED"
    assert result.rejected_side_effects == (SideEffect.WRITE,)


def test_project_outside_read_holds_to_reduce_false_positive():
    result = assert_decision(
        r"Get-Content C:\Users\TestUser\Desktop\note.txt",
        CapabilityDisposition.HOLD,
        "CAPABILITY_EXTERNAL_READ_REQUIRES_CONFIRMATION",
        target_paths=(r"C:\Users\TestUser\Desktop\note.txt",),
    )

    assert result.rejected_targets


def test_project_outside_write_kills():
    result = assert_decision(
        r"Set-Content C:\Users\TestUser\Desktop\out.txt 'x'",
        CapabilityDisposition.KILL,
        "CAPABILITY_PATH_DENIED",
        declared_scope=DeclaredScope.PROJECT_WRITE,
        target_paths=(r"C:\Users\TestUser\Desktop\out.txt",),
        expected_side_effects={SideEffect.WRITE},
    )

    assert result.rejected_targets


def test_path_traversal_is_resolved_before_boundary_decision():
    result = assert_decision(
        r"Set-Content docs\..\..\outside.txt 'x'",
        CapabilityDisposition.KILL,
        "CAPABILITY_PATH_DENIED",
        declared_scope=DeclaredScope.PROJECT_WRITE,
        target_paths=(r"docs\..\..\outside.txt",),
        expected_side_effects={SideEffect.WRITE},
    )

    assert result.rejected_targets


def test_protected_phi_target_kills_even_when_inside_project():
    result = assert_decision(
        r"Set-Content .phi\registry\actors.json '{}'",
        CapabilityDisposition.KILL,
        "CAPABILITY_AUDIT_MUTATION_DENIED",
        declared_scope=DeclaredScope.PROJECT_WRITE,
        target_paths=(r".phi\registry\actors.json",),
        expected_side_effects={SideEffect.WRITE},
    )

    assert SideEffect.AUDIT_CHANGE in result.rejected_side_effects


def test_network_domain_allowlist_passes_capability_only():
    result = audit_capability(
        proposal(
            "curl https://api.example.internal/status",
            declared_scope=DeclaredScope.EXTERNAL_IO,
            target_paths=("https://api.example.internal/status",),
            expected_side_effects={SideEffect.NETWORK},
        ),
        policy(network_manifest()),
    )

    assert result.disposition == CapabilityDisposition.ALLOW
    assert result.reason_code == "CAPABILITY_PASS"
    assert result.can_execute is False


def test_network_domain_outside_allowlist_kills():
    result = audit_capability(
        proposal(
            "curl https://api.example.internal.evil.invalid/status",
            declared_scope=DeclaredScope.EXTERNAL_IO,
            target_paths=("https://api.example.internal.evil.invalid/status",),
            expected_side_effects={SideEffect.NETWORK},
        ),
        policy(network_manifest()),
    )

    assert result.disposition == CapabilityDisposition.KILL
    assert result.reason_code == "CAPABILITY_NETWORK_DOMAIN_DENIED"


def test_network_without_target_domain_holds():
    result = audit_capability(
        proposal(
            "curl $TARGET_URL",
            declared_scope=DeclaredScope.EXTERNAL_IO,
            expected_side_effects={SideEffect.NETWORK},
        ),
        policy(network_manifest()),
    )

    assert result.disposition == CapabilityDisposition.HOLD
    assert result.reason_code == "CAPABILITY_PROCESS_EQUATION_INCOMPLETE"
    assert result.evidence == ("target",)


def test_permission_mutation_kills():
    manifest = CapabilityManifest(
        actor_id="agent_coder",
        manifest_id="privilege-test",
        allowed_side_effects={SideEffect.READ, SideEffect.WRITE},
        allowed_path_roots=(PROJECT_ROOT,),
    )

    result = audit_capability(
        proposal(
            "runas /user:Administrator powershell",
            declared_scope=DeclaredScope.ADMIN,
            target_paths=("README.md",),
            expected_side_effects={SideEffect.PRIVILEGE},
        ),
        policy(manifest),
    )

    assert result.disposition == CapabilityDisposition.KILL
    assert result.reason_code == "CAPABILITY_PERMISSION_MUTATION_DENIED"


def test_capability_words_in_documentation_do_not_self_grant_or_kill():
    result = assert_decision(
        "Get-Content docs/capability_manifest_notes.md",
        CapabilityDisposition.ALLOW,
        "CAPABILITY_PASS",
        target_paths=("docs/capability_manifest_notes.md",),
    )

    assert result.certificate.value == "CAP_PASS"


def test_skill_contract_missing_required_skill_holds():
    result = audit_capability(
        proposal(
            "Get-Content README.md",
            target_paths=("README.md",),
            raw_payload=skill_trace(used_skill_ids=()),
        ),
        policy(skill_manifest()),
    )

    assert result.disposition == CapabilityDisposition.HOLD
    assert result.reason_code == "CAPABILITY_SKILL_REQUIRED_NOT_USED"
    assert result.evidence == ("docs-skill",)


def test_skill_contract_missing_required_step_holds():
    result = audit_capability(
        proposal(
            "Get-Content README.md",
            target_paths=("README.md",),
            raw_payload=skill_trace(completed_step_ids=("read_skill_md",)),
        ),
        policy(skill_manifest()),
    )

    assert result.disposition == CapabilityDisposition.HOLD
    assert result.reason_code == "CAPABILITY_SKILL_REQUIRED_STEP_SKIPPED"
    assert "apply_skill_rules" in result.evidence


def test_skill_contract_instruction_outside_manifest_holds():
    result = audit_capability(
        proposal(
            "Get-Content README.md",
            target_paths=("README.md",),
            raw_payload=skill_trace(
                instruction_scan={
                    "status": "HOLD",
                    "reason_code": "CAPABILITY_SKILL_INSTRUCTION_NOT_ALLOWED",
                    "evidence": ("improvise",),
                }
            ),
        ),
        policy(skill_manifest()),
    )

    assert result.disposition == CapabilityDisposition.HOLD
    assert result.reason_code == "CAPABILITY_SKILL_INSTRUCTION_NOT_ALLOWED"
    assert result.evidence == ("improvise",)


def test_skill_contract_manifest_hash_mismatch_holds():
    result = audit_capability(
        proposal(
            "Get-Content README.md",
            target_paths=("README.md",),
            raw_payload=skill_trace(manifest_hashes={"docs-skill": "bad"}),
        ),
        policy(skill_manifest()),
    )

    assert result.disposition == CapabilityDisposition.HOLD
    assert result.reason_code == "CAPABILITY_SKILL_MANIFEST_HASH_MISMATCH"
    assert result.evidence == ("docs-skill", "bad", "abc123")


def test_skill_contract_authority_claim_kills():
    result = audit_capability(
        proposal(
            "Get-Content README.md",
            target_paths=("README.md",),
            raw_payload=skill_trace(authority_claims=("can_execute",)),
        ),
        policy(skill_manifest()),
    )

    assert result.disposition == CapabilityDisposition.KILL
    assert result.reason_code == "CAPABILITY_SKILL_AUTHORITY_CLAIM_DENIED"
    assert result.can_execute is False
    assert result.can_grant_permission is False


def test_skill_contract_valid_trace_passes():
    result = audit_capability(
        proposal(
            "Get-Content README.md",
            target_paths=("README.md",),
            raw_payload=skill_trace(),
        ),
        policy(skill_manifest()),
    )

    assert result.disposition == CapabilityDisposition.ALLOW
    assert result.reason_code == "CAPABILITY_PASS"
    assert result.can_execute is False
    assert result.can_grant_permission is False


def run_all():
    tests = [
        test_allows_workspace_read_with_cap_pass,
        test_allows_read_only_workspace_command_without_target_paths,
        test_allows_workspace_write_but_does_not_execute,
        test_missing_manifest_holds_instead_of_killing,
        test_incomplete_manifest_holds,
        test_read_only_manifest_kills_write_side_effect,
        test_project_outside_read_holds_to_reduce_false_positive,
        test_project_outside_write_kills,
        test_path_traversal_is_resolved_before_boundary_decision,
        test_protected_phi_target_kills_even_when_inside_project,
        test_network_domain_allowlist_passes_capability_only,
        test_network_domain_outside_allowlist_kills,
        test_network_without_target_domain_holds,
        test_permission_mutation_kills,
        test_capability_words_in_documentation_do_not_self_grant_or_kill,
        test_skill_contract_missing_required_skill_holds,
        test_skill_contract_missing_required_step_holds,
        test_skill_contract_instruction_outside_manifest_holds,
        test_skill_contract_manifest_hash_mismatch_holds,
        test_skill_contract_authority_claim_kills,
        test_skill_contract_valid_trace_passes,
    ]

    for test in tests:
        test()
        print(f"PASS: {test.__name__}")

    print("PASS: Capability wall v0 strict audit")


if __name__ == "__main__":
    run_all()
