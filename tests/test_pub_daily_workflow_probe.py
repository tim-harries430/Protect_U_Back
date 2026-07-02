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
        "notebook_analysis",
        "eval_benchmark",
        "prompt_policy",
        "dataset_build",
        "dependency_management",
        "git_workflow",
        "secrets",
        "sre_ops",
        "customer_data",
        "security_redteam",
    }


def test_daily_workflow_probe_does_not_execute_and_reports_rows(tmp_path):
    rows = run_probe(tmp_path)
    summary = summarize(rows)

    assert summary["total"] == len(DAILY_WORKFLOW_CASES)
    assert {row["case_id"] for row in rows} == {case.case_id for case in DAILY_WORKFLOW_CASES}
    assert all("reason_code" in row for row in rows)
    assert len({case.case_id for case in DAILY_WORKFLOW_CASES}) == len(DAILY_WORKFLOW_CASES)


def test_daily_workflow_probe_keeps_danger_controls_blocked(tmp_path):
    rows = {row["case_id"]: row for row in run_probe(tmp_path)}

    for case_id in ("recursive_delete", "indirect_delete", "git_clean", "truncate_file"):
        assert rows[case_id]["actual"] in {"HOLD", "KILL", "QUARANTINE", "REJECT"}


def test_daily_workflow_probe_keeps_core_local_work_usable(tmp_path):
    rows = {row["case_id"]: row for row in run_probe(tmp_path)}

    # Read-only, modellable surface stays PASS (low friction).
    for case_id in ("code_search", "git_status"):
        assert rows[case_id]["actual"] == "PASS"

    # (v1) `unit_test` runs `python -m pytest ...` -- an opaque executor now, so
    # the eye SEES it and the gate HOLDs rather than silently passing it. This is
    # the accepted phase-1 friction; phase 2 (approve-by-hash) buys it back.
    assert rows["unit_test"]["actual"] in {"HOLD", "KILL", "QUARANTINE", "REJECT"}


def test_daily_workflow_probe_reconstructs_ai_company_workflows(tmp_path):
    rows = {row["case_id"]: row for row in run_probe(tmp_path)}

    for case_id in (
        "notebook_export_html",
        "eval_run_jsonl",
        "prompt_policy_edit",
        "dataset_from_desktop",
        "dependency_pip_install",
        "git_commit",
        "secret_env_read",
        "docker_compose_up",
        "customer_ticket_summary",
    ):
        assert case_id in rows
        assert rows[case_id]["preferred"] in {"HOLD", "KILL"}
        assert rows[case_id]["classification"] in {
            "OK",
            "UNDERMODEL",
            "HARD_BLOCK",
            "SOFT_BLOCK",
            "DRIFT",
        }

    assert rows["sre_log_tail"]["actual"] == "PASS"
