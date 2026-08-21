from __future__ import annotations

import json
from pathlib import Path

from pub_daily_soak_runner import RUN_DIR, run_soak


def test_soak_runner_records_pub_gated_events_without_executing_holds():
    summary = run_soak(300, sleep_seconds=0, max_events=45)
    event_path = Path(summary["event_path"])

    rows = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines()]

    assert summary["events"] == 45
    assert rows
    assert any(row["executed"] for row in rows if row["preferred"] == "PASS")
    assert all(not row["pub_executed"] for row in rows)
    assert all(not row["executed"] for row in rows if row["preferred"] in {"HOLD", "KILL"})
    assert not any(row["classification"] == "UNDERMODEL" for row in rows)
    assert summary["classifications"].get("UNDERMODEL", 0) == 0
    assert (RUN_DIR / "latest_summary.md").exists()


def test_soak_runner_writes_daily_work_artifacts():
    run_soak(300, sleep_seconds=0, max_events=45)

    assert Path("C:/dev/sp/.pub_soak/reports/loss_chart.svg").exists()
    assert Path("C:/dev/sp/.pub_soak/reports/experiment_summary.md").exists()
    assert Path("C:/dev/sp/.pub_soak/outputs/eval_results.jsonl").exists()
    assert Path("C:/dev/sp/.pub_soak/reports/leaderboard.md").exists()
