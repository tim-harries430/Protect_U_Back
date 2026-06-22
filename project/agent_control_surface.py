from __future__ import annotations

from os.path import normcase, normpath
from pathlib import Path
from typing import Iterable, Sequence


AGENT_CONTROL_DIR_NAMES = frozenset({".claude", ".codex"})


def agent_control_roots(project_roots: Sequence[str | Path]) -> tuple[Path, ...]:
    roots: list[Path] = []
    for root in project_roots:
        base = Path(root).resolve(strict=False)
        roots.extend(base / name for name in AGENT_CONTROL_DIR_NAMES)
    roots.extend(_home_control_roots())
    return tuple(_dedupe_paths(roots))


def is_agent_control_surface_path(
    path: str | Path,
    *,
    project_roots: Sequence[str | Path] = (),
) -> bool:
    resolved = Path(path).resolve(strict=False)
    if any(_is_within(resolved, root) for root in agent_control_roots(project_roots)):
        return True

    # Fail closed for mirrored or non-native home paths that safe_resolve cannot
    # anchor under Path.home() on this platform (for example WSL /mnt/c paths).
    return any(part.casefold() in AGENT_CONTROL_DIR_NAMES for part in resolved.parts)


def _home_control_roots() -> tuple[Path, ...]:
    candidates = []
    try:
        candidates.append(Path.home())
    except RuntimeError:
        pass
    return tuple(
        root / name
        for root in _dedupe_paths(candidates)
        for name in AGENT_CONTROL_DIR_NAMES
    )


def _dedupe_paths(paths: Iterable[Path]) -> tuple[Path, ...]:
    seen: set[str] = set()
    out: list[Path] = []
    for path in paths:
        key = _norm(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return tuple(out)


def _is_within(path: Path, root: Path) -> bool:
    path_text = _norm(path)
    root_text = _norm(root).rstrip("\\/")
    return (
        path_text == root_text
        or path_text.startswith(root_text + "\\")
        or path_text.startswith(root_text + "/")
    )


def _norm(path: str | Path) -> str:
    return normcase(normpath(str(path))).casefold()
