from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping, Sequence

from access_sampler import MetadataSampleProfile, sample_xray_object_state
from access_time_grid import (
    DEFAULT_BEAT_INTERVAL_NS,
    PlatformBeatPolicy,
    TimeGridCell,
    TimeGridSpec,
    TimeGridTrace,
    build_time_grid_trace,
    platform_beat_policy,
)
from ot_gate import CommandProposal
from transition_xray import (
    DEFAULT_MAX_HASH_BYTES,
    TransitionXrayFrame,
    build_transition_access_witness,
    build_transition_process_witness,
    compare_transition_xray,
    scan_transition_xray,
    transition_access_witness_evidence,
    transition_process_witness_evidence,
)
from xray_field import XrayFieldComparison, sample_xray_potential_pair
from xray_prison import XrayPrisonBoundary, XrayPrisonCustody, admit_xray_frame, seal_xray_pair


TRANSPORT_ID = "sealed_xray_transport:v0"
TRANSPORT_AUTHORITY = "observe_seal_attach_only"
DEFAULT_MAX_BEAT_CELLS = 16_384
AUTHORIZATION_MATCH_SCHEMA = "xray_authorization_match_v1"
AUTHORIZATION_MATCH_POLICY = "exact_target_effect_finding"
AUTHORIZATION_MATCH_POLICY_VERSION = "1"


class _XrayBeatMonitor:
    """Read-only, bounded metadata sampler spanning the real tool window."""

    def __init__(
        self,
        proposal: CommandProposal,
        *,
        interval_ns: int,
        max_cells: int,
    ) -> None:
        self.policy: PlatformBeatPolicy = platform_beat_policy(interval_ns=interval_ns)
        self.max_cells = max(2, int(max_cells))
        self.cwd = str(proposal.cwd)
        self.targets = tuple(
            dict.fromkeys(
                str(target)
                for target in proposal.target_paths
                if str(target).strip() and "://" not in str(target)
            )
        )
        self.started_at_ns = time.time_ns()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._samples: dict[str, dict[int, Any]] = {
            target: {} for target in self.targets
        }
        self._errors: dict[str, set[int]] = {target: set() for target in self.targets}
        self._thread: threading.Thread | None = None
        self._traces: tuple[TimeGridTrace, ...] | None = None
        self._next_index = 1
        self._sampling_exhausted = False

    def start(self) -> None:
        if not self.targets:
            return
        self._capture(0)
        self._thread = threading.Thread(
            target=self._run,
            name=f"pub-xray-beat-{self.policy.time_signature}",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        while self._next_index < self.max_cells:
            if self._stop.wait(self.policy.interval_ns / 1_000_000_000):
                return
            index = self._next_index
            self._capture(index)
            self._next_index += 1
        self._sampling_exhausted = True

    def _capture(self, index: int) -> None:
        sampled_at_ns = time.time_ns()
        for target in self.targets:
            try:
                sample = sample_xray_object_state(
                    target,
                    raw_ref=target,
                    cwd=self.cwd,
                    boundary_root=self.cwd,
                    sampled_at_ns=sampled_at_ns,
                    profile=MetadataSampleProfile.FULL,
                )
            except Exception:
                with self._lock:
                    self._errors[target].add(index)
                continue
            with self._lock:
                self._samples[target][index] = sample

    def close(self) -> tuple[TimeGridTrace, ...]:
        if self._traces is not None:
            return self._traces
        ended_at_ns = max(time.time_ns(), self.started_at_ns)
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

        sampling_truncated = self._sampling_exhausted
        final_index = min(self._next_index, self.max_cells - 1)
        if not sampling_truncated and self.targets:
            self._capture(final_index)
            self._next_index = final_index + 1
        grid_end_ns = self.started_at_ns + final_index * self.policy.interval_ns
        spec = TimeGridSpec(
            enter_ts_ns=self.started_at_ns,
            exit_ts_ns=grid_end_ns,
            step_ns=self.policy.interval_ns,
            # sampled_at_ns preserves the real clock. The meter grid is a
            # logical snare/kick cadence, not a scheduler-latency verdict.
            max_sample_drift_ns=None,
        )

        traces: list[TimeGridTrace] = []
        with self._lock:
            sample_snapshot = {
                target: dict(samples) for target, samples in self._samples.items()
            }
            error_snapshot = {
                target: set(indices) for target, indices in self._errors.items()
            }
        for target in self.targets:
            samples = sample_snapshot[target]
            errors = error_snapshot[target]
            any_present = any(
                bool(getattr(getattr(sample, "state", None), "exists", False))
                for sample in samples.values()
            )
            if not any_present and not errors:
                continue
            cells: list[TimeGridCell] = []
            for index, sample in sorted(samples.items()):
                if index >= len(spec.expected_timestamps):
                    continue
                cells.append(
                    replace(
                        TimeGridCell.from_sample(
                            index=index,
                            expected_ts_ns=spec.expected_timestamps[index],
                            sample=sample,
                        ),
                        beat_name=self.policy.beat_name(index),
                        beat_index=self.policy.beat_index(index),
                        bar_index=self.policy.bar_index(index),
                    )
                )
            traces.append(
                build_time_grid_trace(
                    spec=spec,
                    cells=tuple(cells),
                    object_ref=target,
                    details={
                        "source": "xray_transport_live_beat_sampler",
                        "sampling": self.policy.to_dict(),
                        "sampling_error_count": len(errors),
                        "sampling_truncated": sampling_truncated,
                        "ended_at_ns": ended_at_ns,
                        "authority": "observe_metadata_only",
                    },
                )
            )
        self._traces = tuple(traces)
        return self._traces


@dataclass(frozen=True)
class XrayTransportHandle:
    proposal_id: str
    boundary: XrayPrisonBoundary
    enter_frame: TransitionXrayFrame
    beat_monitor: _XrayBeatMonitor | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    transport_id: str = TRANSPORT_ID
    authority: str = TRANSPORT_AUTHORITY
    sealed: bool = True
    testimony_only: bool = True

    @property
    def boundary_hash(self) -> str:
        return self.boundary.boundary_hash

    @property
    def enter_frame_hash(self) -> str:
        return self.enter_frame.frame_hash

    @property
    def enter_admission_hash(self) -> str:
        return admit_xray_frame(self.enter_frame, boundary=self.boundary).admission_hash

    @property
    def handle_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "transport_id": self.transport_id,
            "proposal_id": self.proposal_id,
            "boundary_hash": self.boundary_hash,
            "enter_frame_hash": self.enter_frame_hash,
            "enter_admission_hash": self.enter_admission_hash,
            "authority": self.authority,
            "sealed": self.sealed,
            "testimony_only": self.testimony_only,
            "route": "main_process_pre_admission",
            "time_sampling": (
                self.beat_monitor.policy.to_dict()
                if self.beat_monitor is not None
                else None
            ),
        }
        if include_hash:
            payload["handle_hash"] = self.handle_hash
        return payload


@dataclass(frozen=True)
class AuthorizationFindingWitness:
    """One observed finding compared with one declared target/effect pair."""

    finding_type: str
    piece_key: str
    matched: bool
    matched_target: str | None = None
    matched_effect: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "piece_key": self.piece_key,
            "matched": self.matched,
            "matched_target": self.matched_target,
            "matched_effect": self.matched_effect,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class AuthorizationMatchWitness:
    """Hashed testimony explaining which observed deltas match declarations.

    This observes a proposal/finding relationship. It is testimony only and
    neither grants permission nor executes an operation.
    """

    declared_targets: Sequence[str] = field(default_factory=tuple)
    declared_effects: Sequence[str] = field(default_factory=tuple)
    finding_matches: Sequence[AuthorizationFindingWitness] = field(default_factory=tuple)
    authorized_delta_digest: str = ""
    schema: str = AUTHORIZATION_MATCH_SCHEMA
    match_policy: str = AUTHORIZATION_MATCH_POLICY
    policy_version: str = AUTHORIZATION_MATCH_POLICY_VERSION
    testimony_only: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "declared_targets", tuple(str(item) for item in self.declared_targets))
        object.__setattr__(self, "declared_effects", tuple(str(item) for item in self.declared_effects))
        object.__setattr__(self, "finding_matches", tuple(self.finding_matches))

    @property
    def matched_findings(self) -> tuple[AuthorizationFindingWitness, ...]:
        return tuple(item for item in self.finding_matches if item.matched)

    @property
    def unmatched_findings(self) -> tuple[AuthorizationFindingWitness, ...]:
        return tuple(item for item in self.finding_matches if not item.matched)

    @property
    def fully_matched(self) -> bool:
        return bool(self.finding_matches) and not self.unmatched_findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "match_policy": self.match_policy,
            "policy_version": self.policy_version,
            "declared_targets": tuple(self.declared_targets),
            "declared_effects": tuple(self.declared_effects),
            "finding_matches": tuple(item.to_dict() for item in self.finding_matches),
            "matched_targets": tuple(
                sorted({item.matched_target for item in self.matched_findings if item.matched_target})
            ),
            "matched_effects": tuple(
                sorted({item.matched_effect for item in self.matched_findings if item.matched_effect})
            ),
            "matched_finding_types": tuple(
                sorted({item.finding_type for item in self.matched_findings})
            ),
            "matched_count": len(self.matched_findings),
            "unmatched_count": len(self.unmatched_findings),
            "fully_matched": self.fully_matched,
            "authorized_delta_digest": self.authorized_delta_digest,
            "testimony_only": self.testimony_only,
        }

    def to_evidence(self) -> tuple[str, ...]:
        summary = (
            f"xray_authorization.schema:{self.schema}",
            f"xray_authorization.match_policy:{self.match_policy}",
            f"xray_authorization.policy_version:{self.policy_version}",
            f"xray_authorization.matched_count:{len(self.matched_findings)}",
            f"xray_authorization.unmatched_count:{len(self.unmatched_findings)}",
            f"xray_authorization.fully_matched:{str(self.fully_matched).lower()}",
            f"xray_authorization.authorized_delta_digest:{self.authorized_delta_digest}",
            f"xray_authorization.testimony_only:{str(self.testimony_only).lower()}",
        )
        matched_dimensions = (
            *(f"xray_authorization.matched_target:{target}" for target in sorted(
                {item.matched_target for item in self.matched_findings if item.matched_target}
            )),
            *(f"xray_authorization.matched_effect:{effect}" for effect in sorted(
                {item.matched_effect for item in self.matched_findings if item.matched_effect}
            )),
            *(f"xray_authorization.matched_finding_type:{finding_type}" for finding_type in sorted(
                {item.finding_type for item in self.matched_findings}
            )),
        )
        finding_evidence = tuple(
            "xray_authorization.finding:"
            f"{'matched' if item.matched else 'unmatched'}:"
            f"{item.finding_type}:{item.piece_key}:"
            f"{item.matched_target or '-'}:{item.matched_effect or '-'}:{item.reason}"
            for item in self.finding_matches
        )
        return summary + matched_dimensions + finding_evidence


@dataclass(frozen=True)
class XrayTransportSeal:
    proposal_id: str
    custody: XrayPrisonCustody
    field: XrayFieldComparison
    transition_evidence: Sequence[str] = field(default_factory=tuple)
    access_witness: Mapping[str, Any] = field(default_factory=dict)
    process_witness: Mapping[str, Any] = field(default_factory=dict)
    authorization_match: AuthorizationMatchWitness = field(
        default_factory=AuthorizationMatchWitness
    )
    transport_id: str = TRANSPORT_ID
    authority: str = TRANSPORT_AUTHORITY
    sealed: bool = True
    testimony_only: bool = True
    def __post_init__(self):
        object.__setattr__(
            self,
            "transition_evidence",
            tuple(str(item) for item in self.transition_evidence),
        )
        object.__setattr__(self, "access_witness", dict(self.access_witness))
        object.__setattr__(self, "process_witness", dict(self.process_witness))

    @property
    def expected_mutation(self) -> bool:
        """Compatibility view; the hashed structured witness is authoritative."""

        return self.authorization_match.fully_matched

    @property
    def boundary_hash(self) -> str:
        return self.custody.boundary.boundary_hash

    @property
    def pair_hash(self) -> str:
        return self.custody.pair_hash

    @property
    def mutation_state(self) -> str:
        return self.custody.mutation_state

    @property
    def continuity_state(self) -> str:
        return self.custody.continuity_state

    @property
    def witness_count(self) -> int:
        return self.custody.witness_count

    @property
    def field_state(self) -> str:
        return self.field.state.value

    @property
    def field_hash(self) -> str:
        return self.field.field_hash

    @property
    def transport_hash(self) -> str:
        return _sha256_canonical(self.to_dict(include_hash=False))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload = {
            "transport_id": self.transport_id,
            "proposal_id": self.proposal_id,
            "boundary_hash": self.boundary_hash,
            "pair_hash": self.pair_hash,
            "mutation_state": self.mutation_state,
            "continuity_state": self.continuity_state,
            "witness_count": self.witness_count,
            "field_state": self.field_state,
            "field_hash": self.field_hash,
            "authority": self.authority,
            "sealed": self.sealed,
            "testimony_only": self.testimony_only,
            "route": "main_process_observation_channel",
            "custody": self.custody.to_dict(),
            "field": self.field.to_dict(),
            "access_witness": dict(self.access_witness),
            "process_witness": dict(self.process_witness),
            "authorization_match": self.authorization_match.to_dict(),
            "evidence": self.to_evidence(include_hash=False),
        }
        if include_hash:
            payload["transport_hash"] = self.transport_hash
        return payload

    def to_evidence(self, *, include_hash: bool = True) -> tuple[str, ...]:
        evidence = (
            f"xray_transport.id:{self.transport_id}",
            f"xray_transport.boundary_hash:{self.boundary_hash}",
            f"xray_transport.pair_hash:{self.pair_hash}",
            f"xray_transport.mutation_state:{self.mutation_state}",
            f"xray_transport.continuity_state:{self.continuity_state}",
            f"xray_transport.witness_count:{self.witness_count}",
            f"xray_transport.field_state:{self.field_state}",
            f"xray_transport.testimony_only:{str(self.testimony_only).lower()}",
            f"xray_transport.sealed:{str(self.sealed).lower()}",
        )
        if include_hash:
            evidence = evidence + (f"xray_transport.transport_hash:{self.transport_hash}",)
        return (
            evidence
            + tuple(self.transition_evidence)
            + self.authorization_match.to_evidence()
            + transition_access_witness_evidence(self.access_witness)
            + transition_process_witness_evidence(self.process_witness)
            + tuple(self.custody.to_evidence())
            + tuple(self.field.to_evidence())
        )


def open_xray_transport(
    proposal: CommandProposal,
    *,
    boundary: XrayPrisonBoundary | None = None,
    max_file_bytes: int = DEFAULT_MAX_HASH_BYTES,
    beat_interval_ns: int = DEFAULT_BEAT_INTERVAL_NS,
    max_beat_cells: int = DEFAULT_MAX_BEAT_CELLS,
    enable_beat_sampling: bool = True,
) -> XrayTransportHandle:
    boundary = boundary or XrayPrisonBoundary()
    enter_frame = scan_transition_xray(
        proposal,
        phase="enter",
        max_file_bytes=max_file_bytes,
    )
    beat_monitor = None
    if enable_beat_sampling:
        beat_monitor = _XrayBeatMonitor(
            proposal,
            interval_ns=beat_interval_ns,
            max_cells=max_beat_cells,
        )
        beat_monitor.start()
    return XrayTransportHandle(
        proposal_id=proposal.proposal_id,
        boundary=boundary,
        enter_frame=enter_frame,
        beat_monitor=beat_monitor,
    )


def _authorization_match_witness(
    pair: Any,
    proposal: CommandProposal,
) -> AuthorizationMatchWitness:
    """Compare every observed finding with an exact declared target/effect."""

    declared_targets = tuple(dict.fromkeys(str(target) for target in proposal.target_paths))
    declared_effects = tuple(
        sorted(
            str(getattr(effect, "value", effect)).lower()
            for effect in proposal.expected_side_effects
        )
    )
    target_by_piece_key = {
        f"target_path:{target}": target for target in declared_targets
    }
    enter_by_key = {piece.key: piece for piece in getattr(pair.enter, "pieces", ())}
    exit_by_key = {piece.key: piece for piece in getattr(pair.exit, "pieces", ())}
    matches: list[AuthorizationFindingWitness] = []

    for finding in tuple(getattr(pair, "findings", ()) or ()):
        finding_type = str(getattr(finding, "finding_type", ""))
        piece_key = str(getattr(finding, "piece_key", ""))
        target = target_by_piece_key.get(piece_key)
        effect = _finding_effect(finding)
        reason = "exact_target_effect_finding_match"
        matched = True
        if target is None:
            matched = False
            reason = "finding_target_not_declared"
        elif effect is None:
            matched = False
            reason = "finding_type_or_state_not_authorizable"
        elif effect not in declared_effects:
            matched = False
            reason = "finding_effect_not_declared"
        else:
            identity_reason = _identity_movement_reason(
                enter_by_key.get(piece_key),
                exit_by_key.get(piece_key),
                finding_type=finding_type,
            )
            if identity_reason:
                matched = False
                reason = identity_reason
        matches.append(
            AuthorizationFindingWitness(
                finding_type=finding_type,
                piece_key=piece_key,
                matched=matched,
                matched_target=target if matched else None,
                matched_effect=effect if matched else None,
                reason=reason,
            )
        )

    digest_payload = {
        "schema": AUTHORIZATION_MATCH_SCHEMA,
        "match_policy": AUTHORIZATION_MATCH_POLICY,
        "policy_version": AUTHORIZATION_MATCH_POLICY_VERSION,
        "proposal_id": proposal.proposal_id,
        "declared_targets": declared_targets,
        "declared_effects": declared_effects,
        "finding_matches": tuple(item.to_dict() for item in matches),
    }
    return AuthorizationMatchWitness(
        declared_targets=declared_targets,
        declared_effects=declared_effects,
        finding_matches=tuple(matches),
        authorized_delta_digest=_sha256_canonical(digest_payload),
    )


def _finding_effect(finding: Any) -> str | None:
    finding_type = str(getattr(finding, "finding_type", ""))
    if finding_type == "CREATED_DURING_WINDOW":
        return "write"
    if finding_type == "DELETED_DURING_WINDOW":
        return "delete"
    if finding_type != "HASH_MUTATED":
        return None
    details = getattr(finding, "details", {}) or {}
    before_tags = set(details.get("before_tags") or ())
    after_tags = set(details.get("after_tags") or ())
    before_missing = "missing" in before_tags
    after_missing = "missing" in after_tags
    if before_missing and not after_missing:
        return "write"
    if not before_missing and after_missing:
        return "delete"
    if not before_missing and not after_missing:
        return "write"
    return None


def _identity_movement_reason(
    before: Any,
    after: Any,
    *,
    finding_type: str,
) -> str | None:
    """Keep pointer/alias/object identity changes outside content authorization."""

    if finding_type != "HASH_MUTATED" or before is None or after is None:
        return None
    if getattr(before, "exists", None) is not getattr(after, "exists", None):
        return None
    before_details = getattr(before, "details", {}) or {}
    after_details = getattr(after, "details", {}) or {}
    if getattr(before, "type", None) != getattr(after, "type", None):
        return "resource_type_movement_not_authorized"
    for key in ("file_id", "resolved_path", "symlink_target", "nlink"):
        if before_details.get(key) != after_details.get(key):
            return f"resource_identity_{key}_movement_not_authorized"
    for key in ("archive_escape_entries", "ads_streams"):
        if before_details.get(key) != after_details.get(key):
            return f"resource_surface_{key}_movement_not_authorized"
    return None


def close_xray_transport(
    handle: XrayTransportHandle,
    proposal: CommandProposal,
    *,
    max_file_bytes: int = DEFAULT_MAX_HASH_BYTES,
) -> XrayTransportSeal:
    time_grid_traces = (
        handle.beat_monitor.close()
        if handle.beat_monitor is not None
        else None
    )
    exit_frame = scan_transition_xray(
        proposal,
        phase="exit",
        max_file_bytes=max_file_bytes,
    )
    pair = compare_transition_xray(handle.enter_frame, exit_frame)
    custody = seal_xray_pair(pair, boundary=handle.boundary)
    field = sample_xray_potential_pair(pair, boundary=handle.boundary)
    access_witness = build_transition_access_witness(pair, proposal)
    process_witness = build_transition_process_witness(
        pair,
        proposal,
        time_grid_traces=time_grid_traces,
    )
    return XrayTransportSeal(
        proposal_id=handle.proposal_id,
        custody=custody,
        field=field,
        transition_evidence=pair.to_evidence(),
        access_witness=access_witness,
        process_witness=process_witness,
        authorization_match=_authorization_match_witness(pair, proposal),
    )


def _sha256_canonical(value: Any) -> str:
    canonical = json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _canonicalize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _canonicalize(child) for key, child in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return tuple(_canonicalize(item) for item in value)
    if isinstance(value, set):
        return tuple(sorted(_canonicalize(item) for item in value))
    if hasattr(value, "to_dict"):
        return _canonicalize(value.to_dict())
    return value
