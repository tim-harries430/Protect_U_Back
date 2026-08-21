from __future__ import annotations

from os.path import normcase, normpath
from pathlib import Path
from typing import Iterable, Sequence


PROBE_CONTROL_DIR_NAMES = frozenset(
    {
        ".pub_codex_guard",
        ".pub_guard",
        ".pub_os",
    }
)

PROBE_AUTHORITY_NAME_PREFIXES = (
    "pub_",
    "pub-",
    "pubos",
    "protect_u_back",
    "protectuback",
)

PROBE_AUTHORITY_NAME_MARKERS = (
    "admission",
    "approval",
    "authority",
    "broker",
    "connected",
    "credential",
    "heartbeat",
    "ledger",
    "lease",
    "receipt",
    "runner",
    "session",
    "supervised",
    "supervision",
    "witness",
)

PROBE_AUTHORITY_SUFFIXES = frozenset(
    {
        ".admission",
        ".heartbeat",
        ".json",
        ".jsonl",
        ".lease",
        ".lock",
        ".pid",
        ".receipt",
        ".session",
        ".toml",
        ".yaml",
        ".yml",
    }
)

PROBE_AUTHORITY_FIELD_TOKENS = (
    "admitted",
    "approval_hash",
    "can_execute",
    "can_grant_permission",
    "connected",
    "expires_at",
    "expires_at_ns",
    "heartbeat",
    "lease_id",
    "permission_granted",
    "receipt_hash",
    "root_pid",
    "runner_attached",
    "runner_pid",
    "session_id",
    "supervised",
    "supervision_state",
)


def probe_control_roots(project_roots: Sequence[str | Path]) -> tuple[Path, ...]:
    roots: list[Path] = []
    for root in project_roots:
        base = Path(root).resolve(strict=False)
        roots.extend(base / name for name in PROBE_CONTROL_DIR_NAMES)
    return tuple(_dedupe_paths(roots))


def is_internal_probe_artifact_path(
    path: str | Path,
    *,
    project_roots: Sequence[str | Path] = (),
) -> bool:
    resolved = Path(path).resolve(strict=False)
    if any(_is_within(resolved, root) for root in probe_control_roots(project_roots)):
        return True

    # Fail closed for WSL/mirrored paths that cannot be anchored under the
    # native project root but still expose a PUB control directory by name.
    if any(part.casefold() in PROBE_CONTROL_DIR_NAMES for part in resolved.parts):
        return True

    return _looks_like_pub_authority_artifact(resolved.name)


def probe_authority_field_evidence(text: str) -> tuple[str, ...]:
    lowered = str(text).casefold()
    return tuple(token for token in PROBE_AUTHORITY_FIELD_TOKENS if token in lowered)


def probe_authority_text_evidence(text: str) -> tuple[str, ...]:
    lowered = str(text).casefold().replace("\\", "/")
    normalized = lowered.replace("-", "_")
    evidence: list[str] = []
    for token in sorted(PROBE_CONTROL_DIR_NAMES):
        if token in lowered:
            evidence.append(token)
    if (
        any(prefix in normalized for prefix in PROBE_AUTHORITY_NAME_PREFIXES)
        and any(marker in normalized for marker in PROBE_AUTHORITY_NAME_MARKERS)
        and any(suffix in lowered for suffix in PROBE_AUTHORITY_SUFFIXES)
    ):
        evidence.append("pub_probe_authority_name")
    return tuple(dict.fromkeys(evidence))


def internal_probe_path_evidence(path: str | Path) -> tuple[str, ...]:
    resolved = Path(path).resolve(strict=False)
    evidence: list[str] = []
    if any(part.casefold() in PROBE_CONTROL_DIR_NAMES for part in resolved.parts):
        evidence.append("pub_probe_control_path")
    if _looks_like_pub_authority_artifact(resolved.name):
        evidence.append("pub_probe_authority_name")
    return tuple(evidence)


def _looks_like_pub_authority_artifact(name: str) -> bool:
    lowered = name.casefold()
    normalized = lowered.replace("-", "_")
    if Path(lowered).suffix not in PROBE_AUTHORITY_SUFFIXES:
        return False
    if not any(prefix in normalized for prefix in PROBE_AUTHORITY_NAME_PREFIXES):
        return False
    return any(marker in normalized for marker in PROBE_AUTHORITY_NAME_MARKERS)


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
