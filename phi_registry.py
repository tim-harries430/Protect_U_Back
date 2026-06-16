from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional


class ActorState(str, Enum):
    ACTIVE = "ACTIVE"
    WARNING = "WARNING"
    FROZEN = "FROZEN"
    BUGCHECK = "BUGCHECK"


class ActorType(str, Enum):
    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    MODULE = "module"
    SYSTEM = "system"


class TrustLevel(str, Enum):
    USER_ROOT = "user_root"
    TRUSTED = "trusted"
    LIMITED = "limited"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ActorRecord:
    """
    Registered actor identity.

    This is the v0 identity record for agent audit. It is not a process handle
    and does not grant OS-level permission by itself.
    """

    actor_id: str
    actor_type: ActorType
    trust_level: TrustLevel = TrustLevel.LIMITED
    state: ActorState = ActorState.ACTIVE
    created_at_utc: str = ""
    updated_at_utc: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.actor_id.strip():
            raise ValueError("actor_id must be non-empty.")

        if isinstance(self.actor_type, str):
            object.__setattr__(self, "actor_type", ActorType(self.actor_type))

        if isinstance(self.trust_level, str):
            object.__setattr__(self, "trust_level", TrustLevel(self.trust_level))

        if isinstance(self.state, str):
            object.__setattr__(self, "state", ActorState(self.state))

        now = _utc_now()
        if not self.created_at_utc:
            object.__setattr__(self, "created_at_utc", now)

        if not self.updated_at_utc:
            object.__setattr__(self, "updated_at_utc", self.created_at_utc)


@dataclass(frozen=True)
class PhiStoreLayout:
    """
    Project-local Phi control space.

    v0 only models the paths. It does not create directories or apply OS ACLs.
    """

    project_root: str
    store_name: str = ".phi"

    @property
    def store_root(self) -> Path:
        return Path(self.project_root).resolve(strict=False) / self.store_name

    @property
    def registry_dir(self) -> Path:
        return self.store_root / "registry"

    @property
    def ledger_dir(self) -> Path:
        return self.store_root / "ledger"

    @property
    def quarantine_dir(self) -> Path:
        return self.store_root / "quarantine"

    @property
    def backups_dir(self) -> Path:
        return self.store_root / "backups"


class PhiRegistry:
    """
    In-memory v0 registry.

    The registry is the identity source for actors. Later versions may persist
    this into .phi/registry, but v0 keeps it in memory for deterministic tests.
    """

    def __init__(self, layout: Optional[PhiStoreLayout] = None):
        self.layout = layout
        self._actors: Dict[str, ActorRecord] = {}

    def register_actor(
        self,
        actor_id: str,
        actor_type: ActorType = ActorType.AGENT,
        trust_level: TrustLevel = TrustLevel.LIMITED,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ActorRecord:
        actor_id = actor_id.strip()
        if not actor_id:
            raise ValueError("actor_id must be non-empty.")

        if actor_id in self._actors:
            raise ValueError(f"actor already registered: {actor_id}")

        record = ActorRecord(
            actor_id=actor_id,
            actor_type=actor_type,
            trust_level=trust_level,
            metadata=dict(metadata or {}),
        )
        self._actors[actor_id] = record
        return record

    def get_actor(self, actor_id: str) -> Optional[ActorRecord]:
        return self._actors.get(actor_id)

    def require_actor(self, actor_id: str) -> ActorRecord:
        if not actor_id.strip():
            raise ValueError("actor_id must be non-empty.")

        record = self.get_actor(actor_id)
        if record is None:
            raise KeyError(f"unknown actor: {actor_id}")

        return record

    def is_registered_actor(self, actor_id: str) -> bool:
        return self.get_actor(actor_id) is not None

    def actor_can_propose(self, actor_id: str) -> bool:
        record = self.require_actor(actor_id)
        return record.state not in {ActorState.FROZEN, ActorState.BUGCHECK}

    def set_actor_state(
        self,
        actor_id: str,
        state: ActorState,
        *,
        reason_code: str = "",
    ) -> ActorRecord:
        record = self.require_actor(actor_id)
        if isinstance(state, str):
            state = ActorState(state)

        metadata = dict(record.metadata)
        if reason_code:
            metadata["last_state_reason"] = reason_code

        updated = replace(
            record,
            state=state,
            updated_at_utc=_utc_now(),
            metadata=metadata,
        )
        self._actors[actor_id] = updated
        return updated

    def actor_ids(self):
        return tuple(self._actors.keys())


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

