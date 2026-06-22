"""Real-time scene continuity -- the surroundings judge.

Per action, the SURROUNDINGS that must stay continuous within a session -- pub's
own integrity anchors (its top-level modules) plus the project skeleton (the
project root's top-level entries) -- are captured and compared to the PREVIOUS
action's capture for the same session branch. An anchor whose content hash moved,
or that vanished/changed type, is a DISCONTINUITY (HOLD); an anchor that was
observable before but is not now is a BLINDSPOT (HOLD, fail-closed). The first
action of a branch establishes the baseline (PASS).

This complements A2: A2 blocks the AGENT writing pub code; scene catches a
non-agent side-channel / race that mutates an anchor BETWEEN actions -- the
"non-continuity" class. The detector re-baselines every action, so a single
legitimate change costs one HOLD (ask), not a permanent stall.

Properties (mirrors the temporal 4th judge):
  * branch keyed on HOST-injected provenance only (never a self-reported field);
  * reads only physical FS content hashes;
  * ADDITIVE / tighten-only -- it can raise a HOLD, never loosen a verdict;
  * FAILS CLOSED -- on any error the caller simply adds no tightening;
  * carries NO authority -- the witness is a summary (counts + state), never a
    grant.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from scene_seed import build_scene_seed, capture_surroundings

SCENE_CONTINUITY_SCHEMA = "scene_continuity_v0"
DEFAULT_MAX_ANCHOR_BYTES = 1_000_000
# Bounded so the per-action capture stays cheap; the project skeleton is the
# stable top-level, not a deep walk.
MAX_PUB_ANCHORS = 80
MAX_PROJECT_SKELETON = 32
MAX_TOTAL_ANCHORS = 128
_PUB_ROOT = Path(__file__).resolve().parent
# pub files that are NOT gate code (tests, probes, scratch) -- excluded from the
# integrity anchors so the watched set is pub's actual runtime modules.
_PUB_ANCHOR_SKIP_PREFIXES = ("test_", "conftest", "pub_rt", "_")
# Top-level entries that churn by nature -- excluded from the skeleton so normal
# work does not flap the continuity verdict. Hidden (dot) entries are excluded too.
_SKELETON_EXCLUDE = frozenset(
    {"node_modules", "dist", "releases", "build", "__pycache__", "venv", "target"}
)


class SceneContinuityState(str, Enum):
    BASELINE = "BASELINE"            # first observation; nothing to compare yet
    CONTINUOUS = "CONTINUOUS"        # every anchor unchanged
    DISCONTINUOUS = "DISCONTINUOUS"  # an anchor changed out-of-band -> HOLD
    BLINDSPOT = "BLINDSPOT"          # an anchor became unobservable -> HOLD


@dataclass(frozen=True)
class SceneContinuityReport:
    state: SceneContinuityState
    branch_id: str
    changed: tuple[str, ...]
    unobserved: tuple[str, ...]
    anchor_count: int

    @property
    def requires_hold(self) -> bool:
        return self.state in (
            SceneContinuityState.DISCONTINUOUS,
            SceneContinuityState.BLINDSPOT,
        )

    @property
    def reason_code(self) -> str:
        return f"SCENE_{self.state.value}"

    def witness(self) -> dict[str, Any]:
        # Summary only -- no path payload beyond the changed/blindspot anchor set,
        # which is itself just observed file paths. Carries no authority.
        return {
            "schema": SCENE_CONTINUITY_SCHEMA,
            "state": self.state.value,
            "requires_hold": self.requires_hold,
            "anchor_count": self.anchor_count,
            "changed_count": len(self.changed),
            "unobserved_count": len(self.unobserved),
        }


def _branch_of(proposal: Any) -> str:
    # Host-injected provenance only (same anchor as the temporal judge): the hook
    # stamps user_request_id (transcript) / parent_event_id (session); never a
    # self-reported raw_payload field.
    return (
        getattr(proposal, "user_request_id", "")
        or getattr(proposal, "parent_event_id", "")
        or "default_branch"
    )


def _scene_anchors(project_root: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    # Two anchor classes with DIFFERENT continuity semantics:
    #   content  = pub's own runtime modules -- they must NOT change (A2 protects
    #              them), so we content-hash them; a hash move = tampering.
    #   structure = the project skeleton -- its files' CONTENT churns during normal
    #              work, so watching content would HOLD every legit top-level edit.
    #              We watch existence/type ONLY: a top-level file vanishing or
    #              flipping to a symlink/dir is suspicious; an ordinary edit is not.
    content: list[str] = []
    structure: list[str] = []
    try:
        pub = sorted(
            path
            for path in _PUB_ROOT.glob("*.py")
            if not path.name.startswith(_PUB_ANCHOR_SKIP_PREFIXES)
        )
        content.extend(str(path) for path in pub[:MAX_PUB_ANCHORS])
    except OSError:
        pass
    try:
        skeleton = sorted(
            path
            for path in Path(project_root).iterdir()
            if not path.name.startswith(".") and path.name not in _SKELETON_EXCLUDE
        )[:MAX_PROJECT_SKELETON]
        structure.extend(str(path) for path in skeleton)
    except OSError:
        pass
    return tuple(dict.fromkeys(content)), tuple(dict.fromkeys(structure))


def _content_token(state: Any) -> str:
    if not state.exists:
        return "ABSENT"
    if state.object_type != "file":
        return f"TYPE:{state.object_type}"
    if state.content_hash_skipped or state.content_hash_error or not state.content_sha256:
        return "UNOBSERVED"
    return str(state.content_sha256)


def _structure_token(state: Any) -> str:
    # existence + object type only -- content is deliberately ignored.
    return "S:ABSENT" if not state.exists else f"S:{state.object_type}"


def _capture(project_root: str, paths: tuple[str, ...], max_file_bytes: int) -> dict[str, Any]:
    if not paths:
        return {}
    seed = build_scene_seed(
        seed_id="scene_continuity",
        boundary_root=project_root,
        untouched_paths=paths,
    )
    return dict(capture_surroundings(seed, max_file_bytes=max_file_bytes).states)


def _anchor_state_map(
    project_root: str,
    content_paths: tuple[str, ...],
    structure_paths: tuple[str, ...],
    max_file_bytes: int,
) -> dict[str, str]:
    states: dict[str, str] = {}
    for path, state in _capture(project_root, content_paths, max_file_bytes).items():
        states[path] = _content_token(state)
    # content wins on overlap (e.g. self-guard: a pub .py is also a top-level entry).
    for path, state in _capture(project_root, structure_paths, max_file_bytes).items():
        states.setdefault(path, _structure_token(state))
    return states


def _diff(previous: Mapping[str, str], current: Mapping[str, str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    changed: list[str] = []
    unobserved: list[str] = []
    for path, prior in previous.items():
        now = current.get(path, "ABSENT")
        if now == prior:
            continue
        # An anchor that was observable (a real hash) and is now UNOBSERVED is a
        # blindspot, not a content change -- separate so the reason is honest.
        if now == "UNOBSERVED" and prior not in ("UNOBSERVED", "ABSENT"):
            unobserved.append(path)
        else:
            changed.append(path)
    return tuple(sorted(changed)), tuple(sorted(unobserved))


class SceneContinuityLedger:
    """IO shell: the per-branch baseline snapshot of the watched anchors. Stored
    OUTSIDE the protected surface so recording it is not itself an audited write.
    Re-baselines every action (consecutive-action continuity)."""

    def __init__(self, state_dir: str | Path, *, max_file_bytes: int = DEFAULT_MAX_ANCHOR_BYTES):
        self.state_dir = Path(state_dir)
        self.max_file_bytes = max_file_bytes
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, branch_id: str) -> Path:
        digest = hashlib.sha256(branch_id.encode("utf-8")).hexdigest()[:32]
        return self.state_dir / f"scene_{digest}.json"

    def _load(self, branch_id: str) -> dict[str, str] | None:
        path = self._path(branch_id)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        states = payload.get("states")
        return {str(k): str(v) for k, v in states.items()} if isinstance(states, Mapping) else None

    def _save(self, branch_id: str, states: Mapping[str, str]) -> None:
        self._path(branch_id).write_text(
            json.dumps(
                {"schema": SCENE_CONTINUITY_SCHEMA, "branch_id": branch_id, "states": dict(states)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def evaluate(self, proposal: Any, project_root: str) -> SceneContinuityReport:
        branch_id = _branch_of(proposal)
        content_paths, structure_paths = _scene_anchors(project_root)
        current = _anchor_state_map(
            project_root, content_paths, structure_paths, self.max_file_bytes
        )
        previous = self._load(branch_id)
        # Re-baseline every action: a single legit change costs one HOLD, not a stall.
        self._save(branch_id, current)
        if previous is None:
            return SceneContinuityReport(
                state=SceneContinuityState.BASELINE,
                branch_id=branch_id,
                changed=(),
                unobserved=(),
                anchor_count=len(current),
            )
        changed, unobserved = _diff(previous, current)
        if changed:
            state = SceneContinuityState.DISCONTINUOUS
        elif unobserved:
            state = SceneContinuityState.BLINDSPOT
        else:
            state = SceneContinuityState.CONTINUOUS
        return SceneContinuityReport(
            state=state,
            branch_id=branch_id,
            changed=changed,
            unobserved=unobserved,
            anchor_count=len(current),
        )
