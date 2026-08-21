from __future__ import annotations

import argparse
import hashlib
import importlib.util
import sys
import zipfile
from pathlib import Path


FIXED_ZIP_TIME = (2026, 8, 20, 0, 0, 0)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_verifier(root: Path):
    sys.dont_write_bytecode = True
    path = root / "scripts" / "verify_artifact.py"
    spec = importlib.util.spec_from_file_location("paper_artifact_verify", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load artifact verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package(root: Path, out: Path) -> None:
    verifier = load_verifier(root)
    if verifier.verify(root, strict=True):
        raise RuntimeError("artifact verification failed; refusing to package")
    if out.is_relative_to(root):
        raise RuntimeError("ZIP must be outside the artifact root")
    out.parent.mkdir(parents=True, exist_ok=True)
    prefix = root.name + "/"
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(root)
            if rel.parts and rel.parts[0] == "_recomputed":
                continue
            info = zipfile.ZipInfo(prefix + rel.as_posix(), date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    digest = sha256_file(out)
    sha_path = out.with_suffix(out.suffix + ".sha256.txt")
    sha_path.write_text(f"{digest}  {out.name}\n", encoding="ascii", newline="\n")
    print(f"[package] zip={out}")
    print(f"[package] sha256={digest}")
    print(f"[package] checksum={sha_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create deterministic paper-jisa-v1 ZIP")
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--root", default=str(root))
    parser.add_argument("--out", default=str(root.parent / (root.name + ".zip")))
    args = parser.parse_args()
    package(Path(args.root).resolve(), Path(args.out).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
