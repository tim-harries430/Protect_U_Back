from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run(command: list[str]) -> int:
    print("[reproduce]", " ".join(command))
    return subprocess.run(command).returncode


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    verify = [sys.executable, str(root / "scripts" / "verify_artifact.py"), "--root", str(root)]
    if run(verify):
        return 1
    recompute = [
        sys.executable,
        str(root / "scripts" / "recompute_paper_results.py"),
        "--root", str(root),
        "--output", str(root / "_recomputed"),
    ]
    return run(recompute)


if __name__ == "__main__":
    raise SystemExit(main())
