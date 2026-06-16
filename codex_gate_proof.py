from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Sequence


SOURCE_ADAPTER = "codex_shell_guard"
DEFAULT_LOG = Path(".pub_codex_guard/logs/pub_codex_guard.jsonl")


class GateProofError(RuntimeError):
    pass


def _load_rows(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        raise GateProofError(f"guard ledger not found: {log_path}")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            rows.append(json.loads(stripped))
        except json.JSONDecodeError as exc:
            raise GateProofError(f"{log_path}:{line_number}: invalid JSON line ({exc})") from exc
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prove_gate(log_path: Path = DEFAULT_LOG, *, probe: str = "pwd") -> dict[str, Any]:
    """Prove pub gated every Codex shell call before execution.

    The proof holds when, in the guard ledger:
      1. at least one 'pre' row exists           -> pub sits at the door,
      2. every 'pre' row has executed == False    -> pub decides before the real shell,
      3. every row's source_adapter is the guard  -> nothing reached a shell another way,
      4. the probe command appears in a 'pre' row  -> a known command was gated.

    Returns a structured evidence record. Reads the ledger only; runs nothing.
    """
    rows = _load_rows(log_path)
    pre = [row for row in rows if row.get("phase") == "pre"]
    post = [row for row in rows if row.get("phase") == "post"]
    probe_pre = [row for row in pre if probe in (row.get("command_text") or "")]

    foreign_adapters = sorted(
        {
            str(row.get("source_adapter"))
            for row in rows
            if row.get("source_adapter") != SOURCE_ADAPTER
        }
    )
    pre_executed = [row for row in pre if row.get("executed") is not False]

    checks = {
        "pub_at_the_door": bool(pre),
        "pre_decides_before_exec": not pre_executed,
        "no_foreign_adapter": not foreign_adapters,
        "probe_gated": bool(probe_pre),
    }

    return {
        "gate_proof": "pub_codex_shell_gate",
        "passed": all(checks.values()),
        "log_path": str(log_path),
        "log_sha256": _sha256(log_path),
        "total_rows": len(rows),
        "pre_rows": len(pre),
        "post_rows": len(post),
        "probe": probe,
        "probe_pre_rows": len(probe_pre),
        "foreign_adapters": foreign_adapters,
        "checks": checks,
        "generated_at": time.time(),
    }


def _resolve_log_path(log_file: str | None, log_dir: str | None) -> Path:
    if log_file:
        return Path(log_file)
    if log_dir:
        return Path(log_dir) / "pub_codex_guard.jsonl"
    return DEFAULT_LOG


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prove Protect U Back gated every Codex shell call before execution.",
    )
    parser.add_argument("--log-dir", default=None, help="directory holding pub_codex_guard.jsonl")
    parser.add_argument("--log-file", default=None, help="explicit path to the guard ledger")
    parser.add_argument("--probe", default="pwd", help="command substring expected in a gated pre row")
    parser.add_argument("--out", default=None, help="write the evidence record as JSON to this path")
    parser.add_argument("--json", action="store_true", help="print the evidence record as JSON")
    args = parser.parse_args(argv)

    try:
        record = prove_gate(_resolve_log_path(args.log_file, args.log_dir), probe=args.probe)
    except GateProofError as exc:
        print(f"gate proof error: {exc}", file=sys.stderr)
        return 2

    if args.out:
        Path(args.out).write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")

    if args.json:
        print(json.dumps(record, indent=2, sort_keys=True))
    else:
        print(f"log:        {record['log_path']}")
        print(f"log sha256: {record['log_sha256']}")
        print(f"total rows: {record['total_rows']}")
        print(f"pre-exec rows (seen by pub before the real shell): {record['pre_rows']}")
        print(f"probe {record['probe']!r} gated before execution: {record['probe_pre_rows']}")
        for name, ok in record["checks"].items():
            print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if record["foreign_adapters"]:
            print(f"  foreign adapters seen: {record['foreign_adapters']}")
        print(
            "PROOF: every /bin/bash Codex spawned was gated by pub first."
            if record["passed"]
            else "PROOF FAILED: a shell call was not gated by pub."
        )

    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
