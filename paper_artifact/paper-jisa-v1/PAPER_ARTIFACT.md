# Protect_U_Back paper artifact: JISA snapshot v1

This directory is the paper-specific evidence package for the Protect_U_Back (PUB) manuscript. It is intentionally separate from the product release. Its purpose is to bind the paper's reported values to immutable source files, raw evidence, scoring code, and figures.

## Snapshot identity

- Artifact id: `paper-jisa-v1`
- Frozen experiment dates: 2026-08-18 and 2026-08-19
- Production red-team harness SHA-256: `dabc774416ae7f324d3a3fb2cf0fc18ac8f86f69f73ffb7b5d2b52be15866748`
- Baseline scorer SHA-256: `156c845ab1f6bd0478b71599462ec216118637eb31470721aa30e792662f5080`
- Baseline oracle v3 SHA-256: `3b137f19121f761b26b363c6f0f1e2b516975ccdfc640abafce1e972a3938bda`
- Baseline score SHA-256: `d86ba3e3ddc2c82001bdd8ebe5f24a9004a504a37ab1ea927167c0da15f84e98`

The files under `src/` are the DUT source snapshot that matched every `production_module_hashes` entry in `baseline/run_v3/run_manifest.json` when this artifact was assembled. Later product fixes are not silently substituted into this experiment snapshot.

## Directory map

- `src/`: frozen production DUT modules used by the baseline/red-team run.
- `tests/`: release tests plus the baseline protocol test.
- `redteam/harness/`: the single production physical-injection harness.
- `redteam/oracles/`: independently committed oracle lineages v1, v2, and v3.
- `redteam/runs/`: raw manifests, JSONL records, scores, and local checksums for three recorded runs.
- `baseline/`: paired baseline/ablation scorer and the frozen v3 baseline run.
- `daily/`: 79-case raw daily probe and its frozen runner.
- `soak/`: 49,806-row raw audit log and its frozen runner.
- `scripts/`: fail-closed artifact verification, raw-evidence recomputation, and Figure 11 rendering.
- `figures/`: the PNG embedded in the manuscript, its original authoring source, and a deterministic SVG rebuilt from `baseline_score.json`.
- `paper_results/`: compact expected summaries used by the paper.
- `release_snapshot/`: historical product-release manifest copied from the original evidence bundle; it is provenance, not this artifact's manifest.

## What this artifact reproduces

`scripts/reproduce_all.py` verifies every file in the outer `SHA256SUMS`, re-scores all three red-team runs against their committed oracles, recomputes the 79-case daily summary, streams and recounts all 49,806 soak records, recomputes every baseline/ablation metric from the raw paired JSONL, and regenerates the Figure 11 SVG.

The expected verified values include:

- Red-team v3 residual micro P/R/F1: 0.950 / 0.864 / 0.905.
- Red-team attack capture: 1.000; benign completion: 0.000.
- Daily probe: 79 rows, 67 exact preferred-verdict matches.
- Soak: 49,806 records; PASS 19,237, HOLD 17,568, KILL 12,811, QUARANTINE 190; no record grants execution or permission authority.
- Full PUB baseline reference: attack capture 1.000, benign completion 0.000, binary F1 0.667.
- Endpoint-only and access-only variants miss the transient RT09 case; process-only and Full PUB capture it.

## Claim and authority boundaries

The X-ray records in this artifact are testimony. They do not grant permission and do not execute tools. A reproduced score is evidence about this frozen dataset, not authority to claim universal protection.

The following limitations are deliberately preserved rather than hidden:

1. Full PUB false-HOLDs all ten control cases in the frozen v3 run. The artifact supports the narrower claim that process observation closes the RT09 endpoint blind spot; it does not establish a safety-utility advantage over deny-all behavior.
2. `P_auth` was not closed in this experiment snapshot. In particular, the legacy authorization explanation around `expected_mutation` was not fully sealed into the transport evidence. This artifact reproduces that historical result; it does not certify the flaw as fixed.
3. The Windows physical TTP suite is the supported red-team environment. Linux or macOS may skip Windows ADS, junction, hardlink, or ReplaceFileW cases and must not be reported as equivalent coverage.
4. The recorded RT09 result demonstrates the persistent sampler used by the production transport harness. It does not prove that a separated Claude PreTool/PostTool hook process observes the same live window.
5. The product Warden in this snapshot provides logical component separation. This artifact does not claim independent compromise isolation or an asymmetric trust domain.
6. Residual labels with zero positive oracle support cannot receive an empirical recall claim. See `redteam/runs/oracle_v3/score.json` for exact support.
7. The frozen 49,806-row soak log can be fully recounted from raw JSONL. A byte-identical physical re-run is not claimed: the original soft-link adapter dependency and mutable desktop timing state were not included in the 2026-08-18 evidence bundle.

Missing or ambiguous evidence must be reported as unavailable. It must never be converted to PASS.
