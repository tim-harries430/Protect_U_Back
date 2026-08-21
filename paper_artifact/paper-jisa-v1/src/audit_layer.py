from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Sequence


class AuditLayer(str, Enum):
    USER = "USER"
    SOURCE = "SOURCE"
    MOTION = "MOTION"
    REGISTRY = "REGISTRY"
    COMMIT = "COMMIT"
    LEDGER = "LEDGER"
    AUTOPSY = "AUTOPSY"


class KillScope(str, Enum):
    USER_CLAIM = "USER_CLAIM"
    SOURCE_OBJECT = "SOURCE_OBJECT"
    MOTION_BRANCH = "MOTION_BRANCH"
    REGISTRY_IDENTITY = "REGISTRY_IDENTITY"
    COMMIT_IO = "COMMIT_IO"
    LEDGER_ESCALATION = "LEDGER_ESCALATION"
    AUTOPSY_INTEGRITY = "AUTOPSY_INTEGRITY"
    PROTECTED_PHI_STORE = "PROTECTED_PHI_STORE"


@dataclass(frozen=True)
class LayerAuthority:
    layer: AuditLayer
    kill_scopes: Sequence[KillScope]
    can_kill: bool = True

    def __post_init__(self):
        if isinstance(self.layer, str):
            object.__setattr__(self, "layer", AuditLayer(self.layer))

        object.__setattr__(
            self,
            "kill_scopes",
            tuple(
                scope if isinstance(scope, KillScope) else KillScope(scope)
                for scope in self.kill_scopes
            ),
        )

    def owns_scope(self, scope: KillScope) -> bool:
        if isinstance(scope, str):
            scope = KillScope(scope)

        return self.can_kill and scope in self.kill_scopes


@dataclass(frozen=True)
class LayeredObjectRef:
    object_id: str
    phi_id: str
    layer: AuditLayer
    branch_id: str
    object_type: str = "proposal"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.object_id.strip():
            raise ValueError("object_id must be non-empty.")

        if not self.phi_id.strip():
            raise ValueError("phi_id must be non-empty.")

        if not self.branch_id.strip():
            raise ValueError("branch_id must be non-empty.")

        if isinstance(self.layer, str):
            object.__setattr__(self, "layer", AuditLayer(self.layer))

        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_id": self.object_id,
            "phi_id": self.phi_id,
            "layer": self.layer.value,
            "branch_id": self.branch_id,
            "object_type": self.object_type,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class LayerKillRequest:
    layer: AuditLayer
    scope: KillScope
    branch_id: str
    reason_code: str
    object_ref: Optional[LayeredObjectRef] = None
    critical: bool = False
    protected: bool = False

    def __post_init__(self):
        if isinstance(self.layer, str):
            object.__setattr__(self, "layer", AuditLayer(self.layer))

        if isinstance(self.scope, str):
            object.__setattr__(self, "scope", KillScope(self.scope))

        if not self.branch_id.strip():
            raise ValueError("branch_id must be non-empty.")

        if not self.reason_code.strip():
            raise ValueError("reason_code must be non-empty.")

        if self.object_ref is not None and self.object_ref.branch_id != self.branch_id:
            raise ValueError("object_ref branch_id must match request branch_id.")


@dataclass(frozen=True)
class LayerKillDecision:
    allowed: bool
    layer: AuditLayer
    scope: KillScope
    branch_id: str
    reason_code: str
    cooldown_applied: bool
    protected_bypass: bool
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "layer": self.layer.value,
            "scope": self.scope.value,
            "branch_id": self.branch_id,
            "reason_code": self.reason_code,
            "cooldown_applied": self.cooldown_applied,
            "protected_bypass": self.protected_bypass,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class LayerKillEvent:
    event_id: str
    layer: AuditLayer
    scope: KillScope
    branch_id: str
    reason_code: str
    critical: bool
    protected: bool
    protected_bypass: bool
    object_id: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "layer": self.layer.value,
            "scope": self.scope.value,
            "branch_id": self.branch_id,
            "reason_code": self.reason_code,
            "critical": self.critical,
            "protected": self.protected,
            "protected_bypass": self.protected_bypass,
            "object_id": self.object_id,
        }


def default_layer_authorities() -> Dict[AuditLayer, LayerAuthority]:
    return {
        AuditLayer.USER: LayerAuthority(
            layer=AuditLayer.USER,
            kill_scopes=(KillScope.USER_CLAIM,),
        ),
        AuditLayer.SOURCE: LayerAuthority(
            layer=AuditLayer.SOURCE,
            kill_scopes=(KillScope.SOURCE_OBJECT,),
        ),
        AuditLayer.MOTION: LayerAuthority(
            layer=AuditLayer.MOTION,
            kill_scopes=(KillScope.MOTION_BRANCH,),
        ),
        AuditLayer.REGISTRY: LayerAuthority(
            layer=AuditLayer.REGISTRY,
            kill_scopes=(
                KillScope.REGISTRY_IDENTITY,
                KillScope.PROTECTED_PHI_STORE,
            ),
        ),
        AuditLayer.COMMIT: LayerAuthority(
            layer=AuditLayer.COMMIT,
            kill_scopes=(
                KillScope.COMMIT_IO,
                KillScope.PROTECTED_PHI_STORE,
            ),
        ),
        AuditLayer.LEDGER: LayerAuthority(
            layer=AuditLayer.LEDGER,
            kill_scopes=(
                KillScope.LEDGER_ESCALATION,
                KillScope.PROTECTED_PHI_STORE,
            ),
        ),
        AuditLayer.AUTOPSY: LayerAuthority(
            layer=AuditLayer.AUTOPSY,
            kill_scopes=(KillScope.AUTOPSY_INTEGRITY,),
            can_kill=False,
        ),
    }


class LayerKillCooldown:
    """
    Branch-local kill cooldown.

    Each authority layer may issue one normal kill per branch. A protected
    critical kill may bypass cooldown, but it still must belong to a scope
    owned by that layer.
    """

    def __init__(
        self,
        authorities: Optional[Dict[AuditLayer, LayerAuthority]] = None,
    ):
        self.authorities = authorities or default_layer_authorities()
        self._cooldown_by_branch: Dict[str, set[AuditLayer]] = {}
        self._events: list[LayerKillEvent] = []
        self._next_event_index = 1

    def can_issue_kill(self, request: LayerKillRequest) -> LayerKillDecision:
        authority = self.authorities.get(request.layer)
        protected_bypass = request.protected and request.critical

        if authority is None:
            return _decision(
                request,
                allowed=False,
                cooldown_applied=False,
                protected_bypass=False,
                detail="layer has no registered authority",
                reason_code="UNKNOWN_LAYER_AUTHORITY",
            )

        if not authority.can_kill:
            return _decision(
                request,
                allowed=False,
                cooldown_applied=False,
                protected_bypass=False,
                detail="layer is report-only and cannot issue kills",
                reason_code="LAYER_HAS_NO_KILL_AUTHORITY",
            )

        if not authority.owns_scope(request.scope):
            return _decision(
                request,
                allowed=False,
                cooldown_applied=False,
                protected_bypass=False,
                detail="layer cannot kill outside its local scope",
                reason_code="LAYER_SCOPE_MISMATCH",
            )

        if (
            request.object_ref is not None
            and request.scope != KillScope.PROTECTED_PHI_STORE
            and request.object_ref.layer != request.layer
        ):
            return _decision(
                request,
                allowed=False,
                cooldown_applied=False,
                protected_bypass=False,
                detail="local kill cannot target another layer's object",
                reason_code="LAYER_OBJECT_MISMATCH",
            )

        if (
            request.object_ref is not None
            and request.scope == KillScope.PROTECTED_PHI_STORE
            and request.object_ref.layer
            not in {AuditLayer.REGISTRY, AuditLayer.COMMIT, AuditLayer.LEDGER}
        ):
            return _decision(
                request,
                allowed=False,
                cooldown_applied=False,
                protected_bypass=False,
                detail="protected Phi store object must belong to an authority layer",
                reason_code="PROTECTED_OBJECT_LAYER_MISMATCH",
            )

        cooldown_layers = self._cooldown_by_branch.get(request.branch_id, set())
        if request.layer in cooldown_layers and not protected_bypass:
            return _decision(
                request,
                allowed=False,
                cooldown_applied=True,
                protected_bypass=False,
                detail="layer kill authority is cooling down for this branch",
                reason_code="LAYER_KILL_COOLDOWN",
            )

        return _decision(
            request,
            allowed=True,
            cooldown_applied=request.layer in cooldown_layers,
            protected_bypass=protected_bypass and request.layer in cooldown_layers,
            detail=(
                "protected critical kill bypassed cooldown"
                if protected_bypass and request.layer in cooldown_layers
                else "layer-local kill authority accepted"
            ),
            reason_code=request.reason_code,
        )

    def record_layer_kill(self, request: LayerKillRequest) -> LayerKillDecision:
        decision = self.can_issue_kill(request)
        if not decision.allowed:
            return decision

        branch_layers = self._cooldown_by_branch.setdefault(request.branch_id, set())
        branch_layers.add(request.layer)
        self._events.append(
            LayerKillEvent(
                event_id=self._new_event_id(),
                layer=request.layer,
                scope=request.scope,
                branch_id=request.branch_id,
                reason_code=request.reason_code,
                critical=request.critical,
                protected=request.protected,
                protected_bypass=decision.protected_bypass,
                object_id=(
                    request.object_ref.object_id
                    if request.object_ref is not None
                    else None
                ),
            )
        )
        return decision

    def cooldown_layers(self, branch_id: str) -> Sequence[AuditLayer]:
        return tuple(sorted(
            self._cooldown_by_branch.get(branch_id, set()),
            key=lambda layer: layer.value,
        ))

    def events_for_branch(self, branch_id: str) -> Sequence[LayerKillEvent]:
        return tuple(event for event in self._events if event.branch_id == branch_id)

    def all_events(self) -> Sequence[LayerKillEvent]:
        return tuple(self._events)

    def reset_branch(self, branch_id: str) -> None:
        self._cooldown_by_branch.pop(branch_id, None)

    def _new_event_id(self) -> str:
        event_id = f"layer_kill_{self._next_event_index:06d}"
        self._next_event_index += 1
        return event_id


def can_issue_kill(
    request: LayerKillRequest,
    cooldown: Optional[LayerKillCooldown] = None,
) -> LayerKillDecision:
    state = cooldown if cooldown is not None else LayerKillCooldown()
    return state.can_issue_kill(request)


def _decision(
    request: LayerKillRequest,
    *,
    allowed: bool,
    cooldown_applied: bool,
    protected_bypass: bool,
    detail: str,
    reason_code: str,
) -> LayerKillDecision:
    return LayerKillDecision(
        allowed=allowed,
        layer=request.layer,
        scope=request.scope,
        branch_id=request.branch_id,
        reason_code=reason_code,
        cooldown_applied=cooldown_applied,
        protected_bypass=protected_bypass,
        detail=detail,
    )
