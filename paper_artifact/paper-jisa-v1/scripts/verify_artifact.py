from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


EXPECTED_HARNESS_SHA256 = "dabc774416ae7f324d3a3fb2cf0fc18ac8f86f69f73ffb7b5d2b52be15866748"
IGNORED_TOP_LEVEL = {"_recomputed"}
FORBIDDEN_PARTS = {"__pycache__", ".pytest_cache", ".pub_codex_guard", ".pub_soak"}
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".zip"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_sums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        digest, separator, rel = line.partition("  ")
        if not separator or len(digest) != 64 or not rel.strip():
            raise ValueError(f"malformed SHA256SUMS line {number}: {raw!r}")
        key = rel.strip().replace("\\", "/")
        if key in entries:
            raise ValueError(f"duplicate SHA256SUMS entry: {key}")
        entries[key] = digest.lower()
    return entries


def iter_payload_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if rel.as_posix() == "SHA256SUMS":
            continue
        if rel.parts and rel.parts[0] in IGNORED_TOP_LEVEL:
            continue
        yield path, rel.as_posix()


def verify(root: Path, *, strict: bool = True) -> int:
    errors: list[str] = []
    sums_path = root / "SHA256SUMS"
    if not sums_path.is_file():
        print("[verify] FAIL: missing SHA256SUMS", file=sys.stderr)
        return 2
    try:
        entries = load_sums(sums_path)
    except (OSError, ValueError) as exc:
        print(f"[verify] FAIL: {exc}", file=sys.stderr)
        return 2

    actual_files = {rel: path for path, rel in iter_payload_files(root)}
    for rel, expected in entries.items():
        path = root / Path(rel)
        if not path.is_file():
            errors.append(f"missing listed file: {rel}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(f"hash mismatch: {rel} expected={expected} actual={actual}")
    if strict:
        unlisted = sorted(set(actual_files) - set(entries))
        if unlisted:
            errors.append("unlisted payload files: " + ", ".join(unlisted))

    for rel in sorted(actual_files):
        parts = set(Path(rel).parts)
        suffix = Path(rel).suffix.lower()
        if parts & FORBIDDEN_PARTS:
            errors.append(f"forbidden runtime/cache path: {rel}")
        if suffix in FORBIDDEN_SUFFIXES:
            errors.append(f"forbidden nested artifact type: {rel}")

    harness_rel = "redteam/harness/reeeal_hardcore_production.py"
    harness = root / harness_rel
    if not harness.is_file():
        errors.append(f"production harness missing: {harness_rel}")
    elif sha256_file(harness) != EXPECTED_HARNESS_SHA256:
        errors.append("production harness identity mismatch")
    hardcore_files = [
        rel for rel in actual_files
        if rel.startswith("redteam/harness/") and "hardcore" in Path(rel).name.lower()
    ]
    if hardcore_files != [harness_rel]:
        errors.append(f"ambiguous hardcore harness set: {hardcore_files}")

    manifest_path = root / "baseline" / "run_v3" / "run_manifest.json"
    oracle_path = root / "redteam" / "oracles" / "oracle_v3.json"
    if manifest_path.is_file() and oracle_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        commitment = str(manifest.get("oracle_sha256_commitment", "")).removeprefix("sha256:")
        if commitment != sha256_file(oracle_path):
            errors.append("baseline oracle commitment mismatch")
        for name, expected in manifest.get("production_module_hashes", {}).items():
            path = root / "src" / name
            digest = str(expected).removeprefix("sha256:")
            if not path.is_file():
                errors.append(f"baseline DUT source missing: src/{name}")
            elif sha256_file(path) != digest:
                errors.append(f"baseline DUT source drift: src/{name}")
    else:
        errors.append("baseline manifest or v3 oracle missing")

    if errors:
        print("[verify] RESULT: FAIL", file=sys.stderr)
        for error in errors:
            print(f"[verify] {error}", file=sys.stderr)
        return 1
    print(f"[verify] {len(entries)} listed files checked")
    print(f"[verify] production harness sha256={EXPECTED_HARNESS_SHA256}")
    print("[verify] baseline oracle commitment and DUT module hashes checked")
    print("[verify] RESULT: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed verification of paper-jisa-v1")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--no-strict", action="store_true", help="allow unlisted payload files")
    args = parser.parse_args()
    return verify(Path(args.root).resolve(), strict=not args.no_strict)


if __name__ == "__main__":
    raise SystemExit(main())
