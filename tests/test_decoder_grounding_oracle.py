"""Grounding oracle: every X-ray verdict over the whole case corpus must be able
to justify itself from the scan's facts.

For each command in the probe + soak corpus we rebuild the proposal, re-scan the
X-ray frame, recompute the review, and `ground` it. A GROUNDED or UNVERIFIABLE
result is fine; a VERDICT_UNGROUNDED / REASON_UNGROUNDED / OBSERVATION_IGNORED is
a leak -- a verdict the decoder's own facts do not support. This welds the
QUARANTINE-class regression shut permanently.

Run as a script for an ad-hoc scan:  python test_decoder_grounding_oracle.py
"""

from __future__ import annotations

import os
from pathlib import Path

from claude_code_hooks import action_from_claude_event, proposal_from_action
from decoder_grounding import GroundingReport, ground_review
from transition_xray import scan_transition_xray
from xray_review import review_from_frame
from xray_transport import close_xray_transport, open_xray_transport

ROOT = str(Path(__file__).resolve().parent)


def _corpus() -> list[tuple[str, str]]:
    """(case_id, command) from both the probe and the soak case lists, deduped."""
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()

    from pub_daily_workflow_probe import DAILY_WORKFLOW_CASES

    for case in DAILY_WORKFLOW_CASES:
        if case.command not in seen:
            seen.add(case.command)
            pairs.append((f"probe:{case.case_id}", case.command))

    from pub_daily_soak_runner import CASES as SOAK_CASES

    for case in SOAK_CASES:
        if case.command not in seen:
            seen.add(case.command)
            pairs.append((f"soak:{case.case_id}", case.command))

    return pairs


def _ground_command(command: str, cwd: str = ROOT) -> GroundingReport:
    event = {
        "session_id": "grounding_oracle",
        "transcript_path": "grounding_oracle",
        "cwd": cwd,
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": "grounding_oracle",
    }
    action = action_from_claude_event(event, environ={"CLAUDE_PROJECT_DIR": cwd})
    proposal = proposal_from_action(action)
    frame = scan_transition_xray(proposal, phase="enter")
    seal = close_xray_transport(open_xray_transport(proposal), proposal)
    review = review_from_frame(frame, seal=seal)
    return ground_review(frame, review, seal=seal)


def scan_for_leaks(cwd: str = ROOT) -> list[tuple[str, str, GroundingReport]]:
    leaks: list[tuple[str, str, GroundingReport]] = []
    for case_id, command in _corpus():
        report = _ground_command(command, cwd)
        if not report.ok:
            leaks.append((case_id, command, report))
    return leaks


def test_every_xray_verdict_is_grounded():
    leaks = scan_for_leaks()
    assert not leaks, "ungrounded X-ray verdicts (decoder facts do not support them):\n" + "\n".join(
        f"  {case_id}: {report.status.value} :: {report.reason_code} :: {report.detail}"
        for case_id, _command, report in leaks
    )


def main() -> int:
    corpus = _corpus()
    leaks = scan_for_leaks()
    print(f"grounding oracle: {len(corpus)} commands scanned")
    if not leaks:
        print("OK -- every X-ray verdict is grounded (GROUNDED or UNVERIFIABLE)")
        return 0
    print(f"LEAKS: {len(leaks)} verdict(s) the decoder's facts do not support")
    for case_id, command, report in leaks:
        print(f"  [{report.status.value}] {case_id}")
        print(f"      reason : {report.reason_code}")
        print(f"      detail : {report.detail}")
        print(f"      facts  : {sorted(f.value for f in report.ledger.facts)}")
        print(f"      cmd    : {command.splitlines()[0][:90]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
