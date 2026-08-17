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
class XrayTransportSeal:
    proposal_id: str
    custody: XrayPrisonCustody
    field: XrayFieldComparison
    transition_evidence: Sequence[str] = field(default_factory=tuple)
    access_witness: Mapping[str, Any] = field(default_factory=dict)
    process_witness: Mapping[str, Any] = field(default_factory=dict)
    transport_id: str = TRANSPORT_ID
    authority: str = TRANSPORT_AUTHORITY
    sealed: bool = True
    testimony_only: bool = True
    # True iff every mutation finding is exactly what the proposal DECLARED it would
    # do (a write/delete changing its declared targets = the job, not a substitution).
    # Read by xray_review.seal_disguise to stop a benign write from quarantining
    # itself. Deliberately NOT serialised into to_dict/to_evidence, so transport_hash
    # is unchanged. Default False = conservative (treat as before) when uncomputed.
    expected_mutation: bool = False

    def __post_init__(self):
        object.__setattr__(
            self,
            "transition_evidence",
            tuple(str(item) for item in self.transition_evidence),
        )
        object.__setattr__(self, "access_witness", dict(self.access_witness))
        object.__setattr__(self, "process_witness", dict(self.process_witness))

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


# A mutating effect (write/delete) DECLARED by the proposal vouches for the
# transition's content findings: the targets changing IS the job. A delete shows up
# as HASH_MUTATED (the hash goes to a missing sentinel), not a distinct DELETED
# finding, so we do NOT match finding type to effect -- declaring ANY mutating effect
# is enough. ACTION_ID_MISMATCH (a torn observation window) is never vouched. A
# declared-READ op that mutated has no mutating effect -> unexpected -> the seal still
# quarantines. Identity swaps (pointer/alias/container-escape) ride a SEPARATE review
# axis (single_frame_disguise on the enter frame), unaffected by this.
_MUTATING_EFFECTS = frozenset({"write", "delete"})


def _mutation_is_declared(pair: Any, proposal: CommandProposal) -> bool:
    findings = tuple(getattr(pair, "findings", ()) or ())
    if not findings:
        return False
    if any(
        str(getattr(finding, "finding_type", "")) == "ACTION_ID_MISMATCH"
        for finding in findings
    ):
        return False
    declared = {
        str(getattr(effect, "value", effect)).lower()
        for effect in getattr(proposal, "expected_side_effects", ()) or ()
    }
    return bool(declared & _MUTATING_EFFECTS)


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
        expected_mutation=_mutation_is_declared(pair, proposal),
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
