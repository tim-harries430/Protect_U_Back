import json
from pathlib import Path

import claude_code_connector


def read_settings(project: Path) -> dict:
    return json.loads((project / ".claude" / "settings.local.json").read_text(encoding="utf-8"))


def test_verify_warns_on_acceptEdits_default_mode(tmp_path):
    settings_path = tmp_path / ".claude" / "settings.local.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps({"permissions": {"defaultMode": "acceptEdits"}}),
        encoding="utf-8",
    )

    result = claude_code_connector.verify_claude_code(tmp_path)

    assert result["permission_unsafe"] is True
    assert any("acceptEdits" in item for item in result["permission_warnings"])
    assert result["permission_posture_ok"] is False


def test_verify_warns_on_bash_python3_star_allow(tmp_path):
    settings_path = tmp_path / ".claude" / "settings.local.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps({"permissions": {"allow": ["Bash(python3 *)"]}}),
        encoding="utf-8",
    )

    result = claude_code_connector.verify_claude_code(tmp_path)

    assert result["permission_unsafe"] is True
    assert any("dangerous_allow_rule:Bash(python3 *)" in item for item in result["permission_warnings"])


def test_verify_clean_default_settings(tmp_path):
    settings_path = tmp_path / ".claude" / "settings.local.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({"model": "test-model"}), encoding="utf-8")

    result = claude_code_connector.status_claude_code(tmp_path)

    assert result["permission_unsafe"] is False
    assert result["permission_warnings"] == ()


def test_status_includes_permission_audit(tmp_path):
    settings_path = tmp_path / ".claude" / "settings.local.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}),
        encoding="utf-8",
    )

    result = claude_code_connector.status_claude_code(tmp_path)

    assert result["permission_unsafe"] is True
    assert any("bypassPermissions" in item for item in result["permission_warnings"])


def test_verify_flags_acceptEdits_and_opaque_allow_together(tmp_path):
    settings_path = tmp_path / ".claude" / "settings.local.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps(
            {
                "permissions": {
                    "defaultMode": "acceptEdits",
                    "allow": ["Bash(python3 *)", "Bash(*)"],
                }
            }
        ),
        encoding="utf-8",
    )

    result = claude_code_connector.verify_claude_code(tmp_path)

    assert result["permission_unsafe"] is True
    assert len(result["permission_warnings"]) >= 2
