# Reviewer Flow

This flow is for a professional reviewer evaluating the local offline release
package. Run it in a clean working directory with Python available.

## 1. Unzip

If you received the release zip directly:

```powershell
Get-FileHash .\ProtectUBack_early_access_1.3_local.zip -Algorithm SHA256
Get-Content .\ProtectUBack_early_access_1.3_local.zip.sha256.txt
Expand-Archive .\ProtectUBack_early_access_1.3_local.zip -DestinationPath .\review
cd .\review\ProtectUBack_early_access_1.3_local
```

If you are starting from the repository, use the zip in `dist/` and extract it
the same way.

## 2. Doctor

```powershell
python project\protect_launcher.py doctor
```

Confirm that the local modules load and that the launcher reports the expected
proposal-level boundary fields, including `io_executed=false`,
`can_execute=false`, and `can_grant_permission=false`.

## 3. Smoke

```powershell
python project\protect_launcher.py smoke
```

Use this as the fastest single-case check. It performs a local dry-run audit of
a proposed action and prints the decision evidence. It should not require a
network account, daemon, telemetry service, or auto-update channel.

## 4. Demo

```powershell
python project\protect_launcher.py demo
```

The demo generates representative local evidence files:

```text
reports/demo_allow_report.json
reports/demo_hold_report.json
reports/demo_kill_report.json
reports/demo_evidence_summary.json
reports/readable_autopsy_report.md
```

Review the summary first, then spot-check the three disposition reports.

## 5. Audit A Case

```powershell
python project\protect_launcher.py audit test\sandbox_gateway_cases.json
```

By default, the launcher writes the audit output to:

```text
reports/sandbox_gateway_cases.audit.report.json
```

You can also provide your own local JSON, JSONL, or `cases[]` file:

```powershell
python project\protect_launcher.py audit .\my_cases.json --output .\reports\my_cases.audit.report.json
```

## 6. Inspect Reports

For each generated report, inspect:

- `summary`: counts by PASS, HOLD, KILL, or QUARANTINE.
- `expectation_checked` and `expectation_passed`: expected outcome coverage.
- Per-case decision reason and primary stage.
- Evidence showing whether proposed I/O was executed.
- Any HOLD result, which means more scope, target, permission, sandbox,
  gateway, or side-effect evidence is needed.

`PASS` means audit pass, not execution permission. `KILL` means the proposed
action is stopped before commit. `QUARANTINE` means the proposal or actor state
is isolated from the normal commit flow.

## 7. Boundaries

Protect U Back is a local, offline, proposal-level pre-commit audit gate. It
normalizes proposed agent actions, audits them before commit, and writes local
evidence reports.

It is not a cloud service, malware scanner, OS sandbox, packet filter, endpoint
security replacement, arbitrary runtime interception layer, or tool executor.
No launcher command executes proposed shell, file, or network actions.
