from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


CODE_ROOT = Path(__file__).resolve().parent
PACKAGE_ROOT = CODE_ROOT.parent if CODE_ROOT.name.lower() == "project" else CODE_ROOT
TEST_DIR = PACKAGE_ROOT / "test"
REPORTS_DIR = PACKAGE_ROOT / "reports"

EVIDENCE_BUNDLES = (
    {
        "label": "ALLOW",
        "input": "allow_install_file_cases.json",
        "output": "reports/demo_allow_report.json",
        "expected": "PASS",
    },
    {
        "label": "HOLD",
        "input": "hold_install_file_cases.json",
        "output": "reports/demo_hold_report.json",
        "expected": "HOLD",
    },
    {
        "label": "KILL",
        "input": "live_openclaw_dirty_cases.json",
        "output": "reports/demo_kill_report.json",
        "expected": "KILL",
    },
)


def main() -> int:
    print_header()
    REPORTS_DIR.mkdir(exist_ok=True)

    reports = []
    for bundle in EVIDENCE_BUNDLES:
        report = run_bundle(bundle)
        reports.append((bundle, report))

    print_summary(reports)
    autopsy = build_readable_autopsy(reports)
    write_json_report(reports, autopsy)
    write_markdown_autopsy(autopsy)
    print_autopsy(autopsy)

    print("\nGenerated:")
    print("  reports/demo_allow_report.json")
    print("  reports/demo_hold_report.json")
    print("  reports/demo_kill_report.json")
    print("  reports/demo_evidence_summary.json")
    print("  reports/readable_autopsy_report.md")
    print("\nBoundary statement:")
    print("  No real tool I/O is executed by this demo.")
    print("  The reports audit action proposals before commit.")
    return 0


def print_header() -> None:
    print("Protect U Back 60s Demo")
    print("Local pre-commit audit gate for AI agents.")
    print("ALLOW safe actions, HOLD ambiguous actions, KILL dangerous side effects.")
    print()


def run_bundle(bundle: dict[str, str]) -> dict[str, Any]:
    input_path = resolve_case_path(bundle["input"])
    output_path = PACKAGE_ROOT / bundle["output"]
    if not input_path.exists():
        raise FileNotFoundError(f"missing evidence corpus: {input_path}")

    command = (
        sys.executable,
        str(CODE_ROOT / "protect_u_back.py"),
        "--project-root",
        str(PACKAGE_ROOT),
        "agent-audit",
        "--input",
        str(input_path),
        "--confirm-protect",
        "--output",
        str(output_path),
    )
    subprocess.run(command, cwd=PACKAGE_ROOT, check=True)
    return load_json(output_path)


def resolve_case_path(name: str) -> Path:
    test_path = TEST_DIR / name
    if test_path.exists():
        return test_path
    return PACKAGE_ROOT / name


def print_summary(reports: list[tuple[dict[str, str], dict[str, Any]]]) -> None:
    print("Evidence summary:")
    for bundle, report in reports:
        label = bundle["label"]
        checked = report.get("expectation_checked", 0)
        passed = report.get("expectation_passed", 0)
        case_count = report.get("case_count", 0)
        summary = report.get("summary", {})
        print(f"  {label:<5} {passed}/{checked} matched, cases={case_count}, summary={summary}")

    print("\nCase decisions:")
    for _, report in reports:
        for result in report.get("results", ()):
            decision = result.get("decision", {})
            print(
                "  "
                + str(result.get("case_id"))
                + " "
                + str(decision.get("disposition"))
                + " "
                + str(decision.get("reason_code"))
            )


def build_readable_autopsy(
    reports: list[tuple[dict[str, str], dict[str, Any]]],
) -> dict[str, Any]:
    kill_report = next(report for bundle, report in reports if bundle["label"] == "KILL")
    kill_result = next(
        result
        for result in kill_report.get("results", ())
        if result.get("decision", {}).get("disposition") == "KILL"
    )

    action = kill_result.get("action", {})
    decision = kill_result.get("decision", {})
    bundle = decision.get("evidence_bundle", {})
    capability = bundle.get("capability_precheck", {})
    testimonies = decision.get("testimonies", ())

    return {
        "case_id": kill_result.get("case_id"),
        "description": kill_result.get("description"),
        "source_id": action.get("actor_id"),
        "proposal": action.get("command_text"),
        "decision": decision.get("disposition"),
        "primary_stage": decision.get("primary_stage"),
        "reason_code": decision.get("reason_code"),
        "capability_certificate": decision.get("capability_certificate"),
        "matched_side_effects": capability.get("matched_side_effects", ()),
        "rejected_side_effects": capability.get("rejected_side_effects", ()),
        "rejected_targets": capability.get("rejected_targets", ()),
        "would_enter_ot": decision.get("would_enter_ot"),
        "io_executed": decision.get("io_executed"),
        "can_execute": decision.get("can_execute"),
        "can_grant_permission": decision.get("can_grant_permission"),
        "trace": tuple(
            {
                "stage": testimony.get("stage"),
                "disposition": testimony.get("disposition"),
                "reason_code": testimony.get("reason_code"),
                "evidence": testimony.get("evidence", ()),
            }
            for testimony in testimonies
        ),
    }


def write_json_report(
    reports: list[tuple[dict[str, str], dict[str, Any]]],
    autopsy: dict[str, Any],
) -> None:
    payload = {
        "product": "Protect U Back",
        "mode": "demo_60s",
        "boundary": "proposal-level pre-commit audit",
        "io_executed": False,
        "bundles": tuple(
            {
                "label": bundle["label"],
                "input": bundle["input"],
                "output": bundle["output"],
                "summary": report.get("summary", {}),
                "expectation_checked": report.get("expectation_checked", 0),
                "expectation_passed": report.get("expectation_passed", 0),
                "case_count": report.get("case_count", 0),
            }
            for bundle, report in reports
        ),
        "selected_autopsy": autopsy,
    }
    (REPORTS_DIR / "demo_evidence_summary.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def write_markdown_autopsy(autopsy: dict[str, Any]) -> None:
    lines = [
        "# Protect U Back - Readable Autopsy Report",
        "",
        "## Selected Case",
        "",
        f"- Case: `{autopsy['case_id']}`",
        f"- Source: `{autopsy['source_id']}`",
        f"- Decision: `{autopsy['decision']}`",
        f"- Primary stage: `{autopsy['primary_stage']}`",
        f"- Reason: `{autopsy['reason_code']}`",
        f"- Certificate: `{autopsy['capability_certificate']}`",
        f"- Would enter OT: `{autopsy['would_enter_ot']}`",
        f"- I/O executed: `{autopsy['io_executed']}`",
        f"- Can execute: `{autopsy['can_execute']}`",
        f"- Can grant permission: `{autopsy['can_grant_permission']}`",
        "",
        "## Proposal",
        "",
        "```text",
        str(autopsy["proposal"]),
        "```",
        "",
        "## Side Effects",
        "",
        f"- Matched: `{tuple(autopsy['matched_side_effects'])}`",
        f"- Rejected: `{tuple(autopsy['rejected_side_effects'])}`",
        "",
        "## Stage Trace",
        "",
        "| Stage | Disposition | Reason | Evidence |",
        "| --- | --- | --- | --- |",
    ]
    for item in autopsy["trace"]:
        lines.append(
            "| "
            + str(item["stage"])
            + " | "
            + str(item["disposition"])
            + " | "
            + str(item["reason_code"])
            + " | "
            + str(tuple(item["evidence"]))
            + " |"
        )
    lines.extend(
        [
            "",
            "## Boundary Statement",
            "",
            "This report is generated from proposal-level audit evidence. No real tool I/O is executed by the demo.",
            "",
        ]
    )
    (REPORTS_DIR / "readable_autopsy_report.md").write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def print_autopsy(autopsy: dict[str, Any]) -> None:
    print("\nSelected autopsy:")
    print(f"  Case: {autopsy['case_id']}")
    print(f"  Decision: {autopsy['decision']}")
    print(f"  Primary stage: {autopsy['primary_stage']}")
    print(f"  Reason: {autopsy['reason_code']}")
    print(f"  Certificate: {autopsy['capability_certificate']}")
    print(f"  Rejected side effects: {tuple(autopsy['rejected_side_effects'])}")
    print(f"  Would enter OT: {autopsy['would_enter_ot']}")
    print(f"  I/O executed: {autopsy['io_executed']}")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())
