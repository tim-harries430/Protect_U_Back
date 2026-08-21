# Submission-closure evidence

This directory covers the final focused-regression and entrypoint-integrity
evidence that was recorded after the main `paper-jisa-v1` artifact was frozen.

## Focused regression

The recorded command was:

```powershell
python -m pytest `
  .\tests\test_sci_baseline_benchmark.py `
  .\tests\test_xray_transport.py `
  .\tests\test_redteam_hardcore_windows_pub.py `
  -q -p no:cacheprovider
```

Recorded result: `24 passed in 0.79s`.

The complete terminal transcript is not public because it contains workstation
account metadata. Its immutable SHA-256 commitment is recorded in
`focused_regression_summary.json`. The test sources themselves are published
inside `paper_artifact/paper-jisa-v1/tests/`.

## Historical product checksum

The captured 1.2 session reported `SHA256SUMS verified: 231/231` before the
Doctor/Smoke/Gateway entrypoint checks. The historical checksum list and
release manifest are included for provenance.

The old unpacked product directory was subsequently used by the capture and
four mutable state/log files changed. It is therefore not republished as if it
were still the untouched 231-file state. The current 1.3 ZIP and its 191-file
checksum closure are published under `releases/`.

## Gateway and authority boundary

`gateway_report_20260820_125401.json` is the raw seven-case report:

```text
case_count:          7
expectation_checked: 7
expectation_passed:  7
PASS/HOLD/KILL:      2/2/3
allowed_to_execute:  false
io_executed:         false
```

`sandbox_gateway_cases.json` contains the corresponding input cases.

