# Paper experiments and reproducibility map

This repository publishes the product snapshot and the evidence used by the
Protect U Back manuscript as separate objects. Product fixes are not silently
substituted into the frozen paper runs.

## Current product release

- Release: [`ProtectUBack_early_access_1.3_local.zip`](releases/ProtectUBack_early_access_1.3_local.zip)
- ZIP SHA-256: `6186cb4f643707aaa99a91607ad0a20b788c72e6d2f6cfe93fbbbed69bb12329`
- Sidecar: [`ProtectUBack_early_access_1.3_local.zip.sha256.txt`](releases/ProtectUBack_early_access_1.3_local.zip.sha256.txt)
- Feature wiring status: [`FEATURE_REACHABILITY.json`](FEATURE_REACHABILITY.json)

The scalar X-ray field is proven `OUTCOME_AFFECTING` through the formal local
CLI. It is intentionally marked `ACTIVE_PARTIAL`, not `RUNTIME_PROVEN`, because
the outer Claude PreTool/PostTool path remains endpoint-only.

## Frozen paper artifact

The complete frozen experiment package is under
[`paper_artifact/paper-jisa-v1`](paper_artifact/paper-jisa-v1/).

It contains 152 files sealed by its outer `SHA256SUMS` and includes:

| Manuscript evidence | Published material | Recomputed result |
| --- | --- | --- |
| Windows physical red team | one production harness, oracle v1/v2/v3, smoke/v2-fix/v3 runs | v3 micro P/R/F1 `0.950/0.864/0.905`; attack capture `1.000` |
| Paired controls | 10 attacks and 10 controls | benign completion `0.000`; false-HOLD `1.000` |
| Daily workflow probe | 79 raw cases and frozen runner | 67 exact preferred-verdict matches; benign completion `0.800` |
| Long-running soak | 49,806 raw JSONL records and frozen counter | PASS `19,237`; HOLD `17,568`; KILL `12,811`; QUARANTINE `190`; authority leak `0` |
| Baseline and ablations | eight methods over the same 10+10 paired cases | Full PUB capture `1.000`; benign completion `0.000`; binary F1 `0.667` |
| Figure 11 | source PNG, deterministic SVG and authoring source | byte-for-byte SVG comparison |

### Reproduce

Run from `paper_artifact/paper-jisa-v1`:

```powershell
python .\scripts\verify_artifact.py
python .\scripts\reproduce_all.py
```

Expected terminal results:

```text
[verify] RESULT: PASS
"all_expected_results_match": true
```

The generated `_recomputed/` directory is ignored and is not part of the
frozen checksum closure.

## Submission-closure evidence

Evidence used by the manuscript's final focused-regression and product-entry
figures is under [`paper_experiments/submission_closure`](paper_experiments/submission_closure/).

It records:

- the focused 24-test command over baseline, X-ray transport and Windows red-team tests;
- the historical 1.2 `231/231` product checksum observation;
- all seven Gateway cases and their raw report (`2 PASS / 2 HOLD / 3 KILL`);
- `expectation_passed=7`, `allowed_to_execute=false`, and `io_executed=false`;
- the current 1.3 package's independently verified checksum closure.

## Evidence boundaries

- X-ray output is testimony and does not grant execution authority.
- The frozen controls remain false-HOLDed; the paper does not claim a
  safety-utility advantage over deny-all behavior.
- The 49,806-row soak is deterministically recountable, not byte-identically
  re-executable as the original desktop session.
- Raw frozen red-team and soak records retain local temporary-path metadata so
  that manuscript hashes remain verifiable. A credential scan found no API
  token, private key, bearer credential or email address in the published
  frozen closure.
- The private full terminal transcript is not published because it contains
  workstation account metadata. Its SHA-256 commitment is published in the
  submission-closure summary.
