from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, *, encoding: str = "utf-8") -> Any:
    return json.loads(path.read_text(encoding=encoding))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def compare_json(actual_path: Path, expected_path: Path) -> bool:
    return expected_path.is_file() and load_json(actual_path) == load_json(expected_path)


def recompute_redteam(root: Path, out: Path) -> dict[str, Any]:
    harness = root / "redteam" / "harness" / "reeeal_hardcore_production.py"
    mapping = {
        "smoke_v1": "oracle_v1.json",
        "oracle_v2_rt05fix": "oracle_v2.json",
        "oracle_v3": "oracle_v3.json",
    }
    status: dict[str, Any] = {}
    for run_name, oracle_name in mapping.items():
        run_dir = root / "redteam" / "runs" / run_name
        target = out / "redteam" / f"{run_name}_score.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        command = [
            sys.executable, str(harness), "score", "--run", str(run_dir),
            "--oracle", str(root / "redteam" / "oracles" / oracle_name), "--out", str(target),
        ]
        result = subprocess.run(command, text=True, capture_output=True)
        match = result.returncode == 0 and compare_json(target, run_dir / "score.json")
        status[run_name] = {
            "returncode": result.returncode,
            "semantic_match": match,
            "recomputed_sha256": sha256_file(target) if target.exists() else None,
            "expected_sha256": sha256_file(run_dir / "score.json"),
            "stderr": result.stderr.strip(),
        }
    return status


def recompute_daily(root: Path, out: Path) -> dict[str, Any]:
    source = root / "daily" / "benign_probe_v1.json"
    data = load_json(source, encoding="utf-16")
    rows = data["rows"]
    categories: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        categories[str(row["category"])][str(row["actual"])] += 1
    summary = {
        "schema": "pub.paper.daily_recomputed.v1",
        "source_sha256": sha256_file(source),
        "rows": len(rows),
        "exact_matches": sum(row.get("actual") == row.get("preferred") for row in rows),
        "dispositions": dict(sorted(Counter(str(row["actual"]) for row in rows).items())),
        "preferred_dispositions": dict(sorted(Counter(str(row["preferred"]) for row in rows).items())),
        "classifications": dict(sorted(Counter(str(row["classification"]) for row in rows).items())),
        "categories": {key: dict(sorted(value.items())) for key, value in sorted(categories.items())},
    }
    target = out / "daily_summary.json"
    write_json(target, summary)
    return {"semantic_match": compare_json(target, root / "paper_results" / "daily_summary.json"), **summary}


def recompute_soak(root: Path, out: Path) -> dict[str, Any]:
    source = root / "soak" / "pub_codex_guard_49806.jsonl"
    dispositions: Counter[str] = Counter()
    phases: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    actors: Counter[str] = Counter()
    rows = 0
    authority_leak = 0
    can_execute_true = 0
    can_grant_permission_true = 0
    with source.open("r", encoding="utf-8") as handle:
        for number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"soak JSONL line {number} invalid: {exc}") from exc
            rows += 1
            dispositions[str(row.get("disposition"))] += 1
            phases[str(row.get("phase"))] += 1
            reasons[str(row.get("reason_code"))] += 1
            actors[str(row.get("actor_id"))] += 1
            authority_leak += bool(row.get("authority_leak", False))
            can_execute_true += bool(row.get("can_execute", False))
            can_grant_permission_true += bool(row.get("can_grant_permission", False))
    summary = {
        "schema": "pub.paper.soak_recomputed.v1",
        "source_sha256": sha256_file(source),
        "rows": rows,
        "dispositions": dict(sorted(dispositions.items())),
        "phases": dict(sorted(phases.items())),
        "reason_codes": dict(sorted(reasons.items())),
        "actors": dict(sorted(actors.items())),
        "authority_leak_true": authority_leak,
        "can_execute_true": can_execute_true,
        "can_grant_permission_true": can_grant_permission_true,
    }
    target = out / "soak_summary.json"
    write_json(target, summary)
    return {"semantic_match": compare_json(target, root / "paper_results" / "soak_summary.json"), **summary}


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("paper_jisa_baseline", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def recompute_baseline(root: Path, out: Path) -> dict[str, Any]:
    script = root / "baseline" / "sci_baseline_benchmark.py"
    run_dir = root / "baseline" / "run_v3"
    oracle_path = root / "redteam" / "oracles" / "oracle_v3.json"
    module = load_module(script)
    manifest = load_json(run_dir / "run_manifest.json")
    oracle_sha = sha256_file(oracle_path)
    commitment = str(manifest.get("oracle_sha256_commitment", "")).removeprefix("sha256:")
    if commitment != oracle_sha:
        raise RuntimeError("baseline oracle commitment mismatch")
    records = load_jsonl(run_dir / "results.jsonl")
    oracle = load_json(oracle_path)
    metrics, per_case, excluded = module.score_records(records, oracle)
    provenance = load_json(run_dir / "baseline_run_provenance.json")
    report = {
        "schema": module.SCHEMA,
        "suite_id": oracle.get("suite_id"),
        "oracle_sha256": oracle_sha,
        "run_manifest_sha256": sha256_file(run_dir / "run_manifest.json"),
        "results_jsonl_sha256": sha256_file(run_dir / "results.jsonl"),
        "harness_sha256": provenance.get("harness_sha256"),
        "baseline_script_sha256": sha256_file(script),
        "baseline_ablation_recorded": True,
        "taxonomy_metrics_applicable": False,
        "taxonomy_note": "Binary baselines emit stop/detection only; residual labels remain PUB evidence.",
        "excluded": excluded,
        "detectors": metrics,
        "per_case": per_case,
    }
    target = out / "baseline_score.json"
    write_json(target, report)
    return {
        "semantic_match": compare_json(target, run_dir / "baseline_score.json"),
        "recomputed_sha256": sha256_file(target),
        "expected_sha256": sha256_file(run_dir / "baseline_score.json"),
        "detectors": metrics,
    }


def recompute_figure(root: Path, out: Path) -> dict[str, Any]:
    module = load_module(root / "scripts" / "render_figure11_svg.py")
    target = out / "figure11_baseline_security_utility.svg"
    module.render(root / "baseline" / "run_v3" / "baseline_score.json", target)
    expected = root / "figures" / "figure11_baseline_security_utility.svg"
    return {
        "byte_match": target.read_bytes() == expected.read_bytes(),
        "recomputed_sha256": sha256_file(target),
        "expected_sha256": sha256_file(expected),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Recompute paper tables and Figure 11 from frozen raw evidence")
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--root", default=str(root))
    parser.add_argument("--output", default=str(root / "_recomputed"))
    args = parser.parse_args()
    root = Path(args.root).resolve()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    status = {
        "schema": "pub.paper.reproduction_status.v1",
        "redteam": recompute_redteam(root, out),
        "daily": recompute_daily(root, out),
        "soak": recompute_soak(root, out),
        "baseline": recompute_baseline(root, out),
        "figure11": recompute_figure(root, out),
    }
    checks = [
        *(entry["semantic_match"] for entry in status["redteam"].values()),
        status["daily"]["semantic_match"],
        status["soak"]["semantic_match"],
        status["baseline"]["semantic_match"],
        status["figure11"]["byte_match"],
    ]
    status["all_expected_results_match"] = all(checks)
    write_json(out / "reproduction_status.json", status)
    print(json.dumps({"all_expected_results_match": status["all_expected_results_match"]}, indent=2))
    return 0 if status["all_expected_results_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
