# Reproducing the PUB paper results

Run commands from the artifact root. The score-reproduction path uses Python's standard library. `pytest` is only needed for the optional unit-test step; Pillow is only needed to execute the historical PNG authoring source.

## 1. Verify the frozen package

```powershell
python .\scripts\verify_artifact.py
```

Expected terminal line:

```text
[verify] RESULT: PASS
```

The verifier checks every outer SHA-256 entry, rejects unlisted payload files, rejects nested ZIP/cache/runtime state, verifies the unique production harness identity, verifies the v3 oracle commitment, and checks the frozen DUT modules against the baseline manifest.

## 2. Recompute scores, summaries, and Figure 11

```powershell
python .\scripts\reproduce_all.py
```

Generated files are written under `_recomputed/`, which is deliberately outside the frozen payload closure. Expected result:

```text
"all_expected_results_match": true
```

The command performs semantic JSON comparison for the three red-team scores, daily summary, soak summary, and baseline score. The deterministic Figure 11 SVG is compared byte-for-byte.

## 3. Optional focused tests

```powershell
$env:PYTHONPATH="$PWD\src;$PWD\baseline"
python -m pytest .\tests\test_sci_baseline_benchmark.py .\tests\test_xray_transport.py .\tests\test_redteam_hardcore_windows_pub.py -q --basetemp "$PWD\_recomputed\pytest"
```

These tests exercise the frozen code. They must not be described as a new run of the paper experiment.

## 4. Optional new physical paired run (Windows)

The original 20 records remain under `baseline/run_v3/`. To create an independent new run without modifying them:

```powershell
$oracle = "3b137f19121f761b26b363c6f0f1e2b516975ccdfc640abafce1e972a3938bda"
python .\baseline\sci_baseline_benchmark.py run `
  --harness .\redteam\harness\reeeal_hardcore_production.py `
  --pub-root .\src `
  --out .\_recomputed\new_baseline_run `
  --oracle-commitment "sha256:$oracle" `
  --variant both --repeat 1 --seed 20260819
python .\baseline\sci_baseline_benchmark.py score `
  --run .\_recomputed\new_baseline_run `
  --oracle .\redteam\oracles\oracle_v3.json `
  --out .\_recomputed\new_baseline_run\baseline_score.json
```

The run requires Windows, an NTFS-capable filesystem, and permission to create the tested file primitives. A `SKIP_ENVIRONMENT` is an environment result, not a captured attack. File ids, temporary paths, and timestamps are expected to differ; compare metrics and case outcomes, not raw bytes.

## Known fail-closed gap

The raw 49,806-row soak evidence is fully recountable. The artifact does not offer a byte-identical re-execution of that historical desktop session because its original mutable soft-link adapter and wall-clock state were not part of the frozen source bundle. `scripts/recompute_paper_results.py` therefore limits the soak claim to deterministic recounting of the hashed JSONL.
