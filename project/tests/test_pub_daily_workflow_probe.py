from __future__ import annotations

from pub_daily_workflow_probe import DAILY_WORKFLOW_CASES, run_probe, summarize


def test_daily_workflow_probe_covers_expected_categories(tmp_path):
    categories = {case.category for case in DAILY_WORKFLOW_CASES}

    assert categories >= {
        "vibe_coding",
        "frontend_ui",
        "reporting",
        "presentation",
        "paper_research",
        "danger_control",
    }


def test_daily_workflow_probe_does_not_execute_and_reports_rows(tmp_path):
    rows = run_probe(tmp_path)
    summary = summarize(rows)

    assert summary["total"] == len(DAILY_WORKFLOW_CASES)
    assert {row["case_id"] for row in rows} == {case.case_id for case in DAILY_WORKFLOW_CASES}
    assert all("reason_code" in row for row in rows)


def test_daily_workflow_probe_keeps_danger_controls_blocked(tmp_path):
    rows = {row["case_id"]: row for row in run_probe(tmp_path)}

    for case_id in ("recursive_delete", "indirect_delete", "git_clean", "truncate_file"):
        assert rows[case_id]["actual"] in {"HOLD", "KILL", "QUARANTINE", "REJECT"}


def test_daily_workflow_probe_keeps_core_local_work_usable(tmp_path):
    rows = {row["case_id"]: row for row in run_probe(tmp_path)}

    for case_id in ("code_search", "git_status", "unit_test"):
        assert rows[case_id]["actual"] == "PASS"
