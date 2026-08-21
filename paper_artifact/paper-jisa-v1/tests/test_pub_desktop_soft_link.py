from __future__ import annotations

import json

from pub_desktop_soft_link import connect_soft, preflight, witness


def test_connect_soft_writes_desktop_state(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_THREAD_ID", "thread-123")

    state = connect_soft(tmp_path)
    saved = json.loads((tmp_path / ".pub_codex_guard" / "desktop_soft_start.json").read_text(encoding="utf-8"))

    assert state["schema_version"] == "pub_desktop_soft_link:v1"
    assert saved["thread_id"] == "thread-123"
    assert saved["mode"] == "soft_preflight"
    assert saved["connected"] is False
    assert saved["soft_link_active"] is True
    assert saved["managed_by_pub_runner"] is False
    assert saved["supervision_state"] == "UNMANAGED"
    assert saved["reason_code"] == "DESKTOP_RUNNER_NOT_ATTACHED"
    assert saved["hard_desktop_runner_attached"] is False
    assert saved["limits"]["auto_intercepts_desktop_tools"] is False
    assert saved["limits"]["executes_commands"] is False


def test_preflight_logs_without_execution(tmp_path):
    row = preflight("rg --files", tmp_path)
    log = tmp_path / ".pub_codex_guard" / "logs" / "pub_codex_guard.jsonl"
    entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]

    assert row["phase"] == "soft_preflight"
    assert row["actor_id"] == "codex_desktop_soft"
    assert row["executed"] is False
    assert entries[-1]["connection_adapter"] == "pub_desktop_soft_link"
    assert entries[-1]["executed"] is False


def test_witness_has_pass_hold_kill_without_execution(tmp_path):
    result = witness(tmp_path)
    rows = {row["case_id"]: row for row in result["rows"]}

    assert rows["pass_read"]["disposition"] == "PASS"
    assert rows["hold_opaque"]["disposition"] == "HOLD"
    assert rows["kill_delete"]["disposition"] == "KILL"
    assert all(row["executed"] is False for row in rows.values())
    assert result["connected"] is False
    assert result["soft_link_active"] is True
    assert result["managed_by_pub_runner"] is False
    assert result["supervision_state"] == "UNMANAGED"
    assert result["reason_code"] == "DESKTOP_RUNNER_NOT_ATTACHED"
    assert result["hard_desktop_runner_attached"] is False
