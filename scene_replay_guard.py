from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from scene_seed import SceneSeed, SurroundingsGuardFinding, SurroundingsSnapshot, capture_surroundings


SCENE_REPLAY_GUARD_SCHEMA = "scene_replay_guard_v0"

FORBIDDEN_GUARD_FIELDS = frozenset(
    {
        "attack",
        "attack_recipe",
        "can_execute",
        "can_kill",
        "can_grant_permission",
        "decision",
        "permission_granted",
        "autopsy",
        "autopsy_report",
        "evidence",
        "verdict",
        "xray_evidence",
        "p_enter",
        "p_exit",
        "omega",
        "omega_process",
    }
)


class SceneReplayState(str, Enum):
    CLEAN = "CLEAN"
    CONTAMINATED = "CONTAMINATED"
    UNOBSERVED = "UNOBSERVED"
    SEED_MISMATCH = "SEED_MISMATCH"


@dataclass(frozen=True)
class SceneReplayGuardFinding:
    finding_type: str
    detail: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "finding_type": self.finding_type,
            "detail": _plain_data(self.detail),
        }
        _assert_no_guard_forbidden_fields(payload)
        return payload


@dataclass(frozen=True)
class SceneReplaySession:
    session_id: str
    seed_id: str
    seed_hash: str
    opened_at_ns: int
    before_snapshot: SurroundingsSnapshot

    @property
    def observed(self) -> bool:
        return bool(self.before_snapshot.states)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": SCENE_REPLAY_GUARD_SCHEMA,
            "session_id": self.session_id,
            "seed_id": self.seed_id,
            "seed_hash": self.seed_hash,
            "opened_at_ns": self.opened_at_ns,
            "observed": self.observed,
            "before_snapshot": self.before_snapshot.to_dict(),
        }
        _assert_no_guard_forbidden_fields(payload)
        return payload


@dataclass(frozen=True)
class SceneReplayGuardReport:
    session_id: str
    seed_id: str
    seed_hash: str
    current_seed_hash: str
    opened_at_ns: int
    closed_at_ns: int
    state: SceneReplayState
    findings: tuple[SceneReplayGuardFinding | SurroundingsGuardFinding, ...]
    before_snapshot: SurroundingsSnapshot
    after_snapshot: SurroundingsSnapshot | None

    @property
    def requires_hold(self) -> bool:
        return self.state is not SceneReplayState.CLEAN

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": SCENE_REPLAY_GUARD_SCHEMA,
            "session_id": self.session_id,
            "seed_id": self.seed_id,
            "seed_hash": self.seed_hash,
            "current_seed_hash": self.current_seed_hash,
            "opened_at_ns": self.opened_at_ns,
            "closed_at_ns": self.closed_at_ns,
            "state": self.state.value,
            "requires_hold": self.requires_hold,
            "findings": tuple(finding.to_dict() for finding in self.findings),
            "before_snapshot": self.before_snapshot.to_dict(),
            "after_snapshot": self.after_snapshot.to_dict() if self.after_snapshot else None,
        }
        _assert_no_guard_forbidden_fields(payload)
        return payload


def open_scene(
    seed: SceneSeed,
    *,
    session_id: str | None = None,
    max_file_bytes: int | None = None,
) -> SceneReplaySession:
    sid = session_id or f"scene-replay:{uuid.uuid4()}"
    before = capture_surroundings(seed, max_file_bytes=max_file_bytes)
    return SceneReplaySession(
        session_id=sid,
        seed_id=seed.seed_id,
        seed_hash=seed.seed_hash,
        opened_at_ns=time.time_ns(),
        before_snapshot=before,
    )


def close_scene(
    session: SceneReplaySession,
    seed: SceneSeed,
    *,
    max_file_bytes: int | None = None,
) -> SceneReplayGuardReport:
    closed_at = time.time_ns()
    current_seed_hash = seed.seed_hash

    if current_seed_hash != session.seed_hash:
        finding = SceneReplayGuardFinding(
            "SCENE_SEED_MISMATCH",
            {
                "opened_seed_hash": session.seed_hash,
                "current_seed_hash": current_seed_hash,
            },
        )
        return SceneReplayGuardReport(
            session_id=session.session_id,
            seed_id=session.seed_id,
            seed_hash=session.seed_hash,
            current_seed_hash=current_seed_hash,
            opened_at_ns=session.opened_at_ns,
            closed_at_ns=closed_at,
            state=SceneReplayState.SEED_MISMATCH,
            findings=(finding,),
            before_snapshot=session.before_snapshot,
            after_snapshot=None,
        )

    after = capture_surroundings(seed, max_file_bytes=max_file_bytes)

    if not session.observed:
        finding = SceneReplayGuardFinding(
            "SCENE_SURROUNDINGS_UNOBSERVED",
            {"reason": "seed.untouched_paths is empty"},
        )
        return SceneReplayGuardReport(
            session_id=session.session_id,
            seed_id=session.seed_id,
            seed_hash=session.seed_hash,
            current_seed_hash=current_seed_hash,
            opened_at_ns=session.opened_at_ns,
            closed_at_ns=closed_at,
            state=SceneReplayState.UNOBSERVED,
            findings=(finding,),
            before_snapshot=session.before_snapshot,
            after_snapshot=after,
        )

    hash_findings = _hash_observation_findings(session.before_snapshot, phase="before") + _hash_observation_findings(
        after,
        phase="after",
    )
    if hash_findings:
        return SceneReplayGuardReport(
            session_id=session.session_id,
            seed_id=session.seed_id,
            seed_hash=session.seed_hash,
            current_seed_hash=current_seed_hash,
            opened_at_ns=session.opened_at_ns,
            closed_at_ns=closed_at,
            state=SceneReplayState.UNOBSERVED,
            findings=hash_findings,
            before_snapshot=session.before_snapshot,
            after_snapshot=after,
        )

    surroundings = session.before_snapshot.compare(after)
    state = SceneReplayState.CONTAMINATED if surroundings.requires_hold else SceneReplayState.CLEAN
    return SceneReplayGuardReport(
        session_id=session.session_id,
        seed_id=session.seed_id,
        seed_hash=session.seed_hash,
        current_seed_hash=current_seed_hash,
        opened_at_ns=session.opened_at_ns,
        closed_at_ns=closed_at,
        state=state,
        findings=tuple(surroundings.findings),
        before_snapshot=session.before_snapshot,
        after_snapshot=after,
    )


def _hash_observation_findings(snapshot: SurroundingsSnapshot, *, phase: str) -> tuple[SceneReplayGuardFinding, ...]:
    findings: list[SceneReplayGuardFinding] = []
    for path_key, state in sorted(snapshot.states.items()):
        if not state.exists or state.object_type != "file":
            continue
        if state.content_sha256 and not state.content_hash_skipped and not state.content_hash_error:
            continue
        findings.append(
            SceneReplayGuardFinding(
                "SCENE_HASH_UNOBSERVED",
                {
                    "phase": phase,
                    "path": path_key,
                    "content_hash_skipped": state.content_hash_skipped,
                    "content_hash_error": state.content_hash_error,
                },
            )
        )
    return tuple(findings)


def _assert_no_guard_forbidden_fields(value: Any, path: str = "scene_replay_guard") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in FORBIDDEN_GUARD_FIELDS:
                raise ValueError(f"Scene replay guard cannot emit authority/evidence/autopsy field: {path}.{key_text}")
            _assert_no_guard_forbidden_fields(item, f"{path}.{key_text}")
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, item in enumerate(value):
            _assert_no_guard_forbidden_fields(item, f"{path}[{index}]")


def _plain_data(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _plain_data(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(_plain_data(item) for item in value)
    return value
