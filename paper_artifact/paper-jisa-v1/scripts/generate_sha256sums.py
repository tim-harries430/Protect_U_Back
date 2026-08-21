from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


IGNORED_TOP_LEVEL = {"_recomputed"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate(root: Path) -> Path:
    output = root / "SHA256SUMS"
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path == output:
            continue
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] in IGNORED_TOP_LEVEL:
            continue
        lines.append(f"{sha256_file(path)}  {rel.as_posix()}")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"[sha256] wrote {len(lines)} entries to {output}")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the outer paper artifact SHA256SUMS")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    generate(Path(args.root).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
