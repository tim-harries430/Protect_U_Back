from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from audit_layer import (
    KillScope,
    LayerKillCooldown,
    LayerKillDecision,
    LayerKillRequest,
)
from autopsy_report import (
    AutopsyReport,
    build_autopsy_report,
    build_capability_autopsy_report,
)
from baseline_guards import BaselineGuard, BaselineResult, default_baselines
from capability_wall import (
    CapabilityDecision,
    CapabilityDisposition,
    CapabilityPolicy,
    audit_capability,
    default_capability_policy,
)
from event_ledger import AuditEvent, EventLedger
from llm_channel import (
    ChannelAuditResult,
    ChannelDisposition,
    ChannelEnvelope,
    ChannelFinding,
    ChannelPolicy,
    ChannelSeverity,
    ChannelType,
    audit_channel_batch,
)
from ot_gate import (
    ExecutionDecision,
    OTGateResult,
    OTPolicy,
    audit_command_proposal,
)
from phi_registry import ActorState, PhiRegistry, PhiStoreLayout
from registry_admission import (
    AdmissionDisposition,
    AdmissionPolicy,
    AdmissionTicket,
    admitted_envelopes,
    issue_admission_batch,
)
from task_guard import (
    TaskGuard,
    TaskGuardPolicy,
    TaskIncidentSummary,
    TaskStopEvent,
    TaskStopSeverity,
)


PROJECT_ROOT = str(Path(__file__).resolve().parent)
DEFAULT_CASES_PATH = Path(__file__).with_name("redteam_cases.jsonl")


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    description: str
    should_stop: bool
    envelopes: Sequence[ChannelEnvelope]
    registered_actors: Sequence[str] = ("agent_coder",)

    def __post_init__(self):
        if not self.case_id.strip():
            raise ValueError("case_id must be non-empty.")

        if not self.envelopes:
            raise ValueError("benchmark case must contain at least one envelope.")

        object.__setattr__(self, "envelopes", tuple(self.envelopes))
        object.__setattr__(
            self,
            "registered_actors",
            tuple(str(actor) for actor in self.registered_actors),
        )


@dataclass(frozen=True)
class PhiBenchmarkOutcome:
    stopped: bool
    stop_stage: str
    reason_code: str
    channel_results: Sequence[ChannelAuditResult]
    admission_tickets: Sequence[AdmissionTicket] = field(default_factory=tuple)
    capability_decisions: Sequence[CapabilityDecision] = field(default_factory=tuple)
    task_incidents: Sequence[TaskIncidentSummary] = field(default_factory=tuple)
    layer_decisions: Sequence[LayerKillDecision] = field(default_factory=tuple)
    ot_results: Sequence[OTGateResult] = field(default_factory=tuple)
    ledger_events: Sequence[AuditEvent] = field(default_factory=tuple)
    autopsy_reports: Sequence[AutopsyReport] = field(default_factory=tuple)
    registry_states_after: Dict[str, Optional[ActorState]] = field(default_factory=dict)
    io_executed: bool = False

    def __post_init__(self):
        object.__setattr__(self, "admission_tickets", tuple(self.admission_tickets))
        object.__setattr__(self, "channel_results", tuple(self.channel_results))
        object.__setattr__(self, "capability_decisions", tuple(self.capability_decisions))
        object.__setattr__(self, "task_incidents", tuple(self.task_incidents))
        object.__setattr__(self, "layer_decisions", tuple(self.layer_decisions))
        object.__setattr__(self, "ot_results", tuple(self.ot_results))
        object.__setattr__(self, "ledger_events", tuple(self.ledger_events))
        object.__setattr__(self, "autopsy_reports", tuple(self.autopsy_reports))
        object.__setattr__(self, "registry_states_after", dict(self.registry_states_after))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stopped": self.stopped,
            "stop_stage": self.stop_stage,
            "reason_code": self.reason_code,
            "io_executed": self.io_executed,
            "admission_reason_codes": tuple(
                ticket.reason_code for ticket in self.admission_tickets
            ),
            "admission_rejections": sum(
                1
                for ticket in self.admission_tickets
                if ticket.disposition == AdmissionDisposition.REJECT
            ),
            "admission_holds": sum(
                1
                for ticket in self.admission_tickets
                if ticket.disposition == AdmissionDisposition.HOLD
            ),
            "channel_envelopes_audited": len(self.channel_results),
            "channel_reason_codes": tuple(
                reason
                for result in self.channel_results
                for reason in result.to_dict()["finding_reason_codes"]
            ),
            "capability_reason_codes": tuple(
                decision.reason_code for decision in self.capability_decisions
            ),
            "capability_certificates": tuple(
                decision.certificate.value for decision in self.capability_decisions
            ),
            "task_incidents": tuple(
                incident.to_dict() for incident in self.task_incidents
            ),
            "ot_reason_codes": tuple(
                result.reason_code for result in self.ot_results
            ),
            "autopsy_reasons": tuple(
                report.death_reason for report in self.autopsy_reports
            ),
            "registry_states_after": {
                actor_id: state.value if state is not None else None
                for actor_id, state in self.registry_states_after.items()
            },
        }


@dataclass(frozen=True)
class BenchmarkResult:
    case_id: str
    should_stop: bool
    phi: PhiBenchmarkOutcome
    baselines: Sequence[BaselineResult]

    @property
    def phi_passed_expectation(self) -> bool:
        return self.phi.stopped == self.should_stop

    @property
    def baseline_failures(self) -> int:
        return sum(
            baseline.stopped != self.should_stop
            for baseline in self.baselines
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "should_stop": self.should_stop,
            "phi": self.phi.to_dict(),
            "phi_passed_expectation": self.phi_passed_expectation,
            "baseline_failures": self.baseline_failures,
            "baselines": tuple(
                baseline.to_dict() for baseline in self.baselines
            ),
        }


@dataclass(frozen=True)
class BenchmarkSummary:
    results: Sequence[BenchmarkResult]

    @property
    def total_cases(self) -> int:
        return len(self.results)

    @property
    def phi_pass_count(self) -> int:
        return sum(result.phi_passed_expectation for result in self.results)

    @property
    def phi_fail_count(self) -> int:
        return self.total_cases - self.phi_pass_count

    @property
    def baseline_failure_count(self) -> int:
        return sum(result.baseline_failures for result in self.results)

    @property
    def io_executed(self) -> bool:
        return any(result.phi.io_executed for result in self.results)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_cases": self.total_cases,
            "phi_pass_count": self.phi_pass_count,
            "phi_fail_count": self.phi_fail_count,
            "baseline_failure_count": self.baseline_failure_count,
            "io_executed": self.io_executed,
            "results": tuple(result.to_dict() for result in self.results),
        }


class PhiBenchmarkRunner:
    def __init__(
        self,
        project_root: str = PROJECT_ROOT,
        baselines: Sequence[BaselineGuard] = (),
        use_admission: bool = True,
        admission_policy: AdmissionPolicy = AdmissionPolicy(),
        use_capability_wall: bool = True,
        capability_policy: CapabilityPolicy | None = None,
        use_task_guard: bool = True,
        task_guard_policy: TaskGuardPolicy = TaskGuardPolicy(),
    ):
        self.project_root = project_root
        self.baselines = tuple(baselines) if baselines else tuple(default_baselines())
        self.use_admission = use_admission
        self.admission_policy = admission_policy
        self.use_capability_wall = use_capability_wall
        self.capability_policy = capability_policy
        self.use_task_guard = use_task_guard
        self.task_guard_policy = task_guard_policy

    def run_cases(self, cases: Sequence[BenchmarkCase]) -> BenchmarkSummary:
        return BenchmarkSummary(
            results=tuple(self.run_case(case) for case in cases)
        )

    def run_case(self, case: BenchmarkCase) -> BenchmarkResult:
        phi = self._run_phi(case)
        baselines = tuple(
            baseline.evaluate(case.envelopes) for baseline in self.baselines
        )
        return BenchmarkResult(
            case_id=case.case_id,
            should_stop=case.should_stop,
            phi=phi,
            baselines=baselines,
        )

    def _run_phi(self, case: BenchmarkCase) -> PhiBenchmarkOutcome:
        registry = PhiRegistry(
            layout=PhiStoreLayout(project_root=self.project_root)
        )
        for actor_id in case.registered_actors:
            if actor_id.startswith("user"):
                continue

            registry.register_actor(actor_id)

        channel_policy = ChannelPolicy(project_root=self.project_root)
        ot_policy = OTPolicy(
            project_roots=(self.project_root,),
            registry=registry,
        )
        ledger = EventLedger(registry=registry)
        layer_cooldown = LayerKillCooldown()

        admission_tickets = ()
        envelopes_for_channel = tuple(case.envelopes)
        if self.use_admission:
            admission_tickets = issue_admission_batch(
                envelopes_for_channel,
                registry,
                self.admission_policy,
            )
            envelopes_for_channel = admitted_envelopes(
                envelopes_for_channel,
                admission_tickets,
            )

        channel_results = audit_channel_batch(envelopes_for_channel, channel_policy)
        capability_policy = self.capability_policy or default_capability_policy(
            self.project_root,
            case.registered_actors,
        )
        layer_decisions = []
        capability_decisions = []
        task_incidents = []
        ot_results = []
        ledger_events = []
        autopsy_reports = []
        task_guard = TaskGuard(self.task_guard_policy)

        for channel_result in channel_results:
            if self.use_task_guard and task_guard.is_terminated(
                channel_result.envelope.user_request_id,
                channel_result.envelope.branch_id,
            ):
                task_incidents.append(
                    task_guard.summary_for(
                        channel_result.envelope.user_request_id,
                        channel_result.envelope.branch_id,
                    )
                )
                continue

            layer_decision = _maybe_record_layer_decision(
                channel_result,
                layer_cooldown,
            )
            if layer_decision is not None:
                layer_decisions.append(layer_decision)

            task_incident = _record_channel_stop_if_needed(
                task_guard,
                channel_result,
                enabled=self.use_task_guard,
            )
            if task_incident is not None:
                task_incidents.append(task_incident)

            proposal = channel_result.command_proposal
            if proposal is None:
                continue

            if self.use_capability_wall:
                capability_decision = audit_capability(proposal, capability_policy)
                capability_decisions.append(capability_decision)
                if capability_decision.disposition == CapabilityDisposition.KILL:
                    autopsy_reports.append(
                        build_capability_autopsy_report(
                            proposal,
                            capability_decision,
                            registry=registry,
                            registry_state_before=_actor_state(
                                registry,
                                proposal.actor_id,
                            ),
                        )
                    )
                    task_incident = _record_capability_stop_if_needed(
                        task_guard,
                        proposal,
                        capability_decision,
                        channel_result.envelope.branch_id,
                        enabled=self.use_task_guard,
                    )
                    if task_incident is not None:
                        task_incidents.append(task_incident)
                    continue

                if capability_decision.disposition == CapabilityDisposition.HOLD:
                    task_incident = _record_capability_stop_if_needed(
                        task_guard,
                        proposal,
                        capability_decision,
                        channel_result.envelope.branch_id,
                        enabled=self.use_task_guard,
                    )
                    if task_incident is not None:
                        task_incidents.append(task_incident)
                    continue

            registry_state_before = _actor_state(registry, proposal.actor_id)
            ot_result = audit_command_proposal(proposal, ot_policy)
            ot_results.append(ot_result)

            ledger_event = _record_if_possible(ledger, proposal, ot_result)
            if ledger_event is not None:
                ledger_events.append(ledger_event)

            if ot_result.decision == ExecutionDecision.KILL:
                autopsy_reports.append(
                    build_autopsy_report(
                        proposal,
                        ot_result,
                        ledger_event=ledger_event,
                        registry=registry,
                        registry_state_before=registry_state_before,
                    )
                )
                task_incident = _record_ot_stop_if_needed(
                    task_guard,
                    proposal,
                    ot_result,
                    channel_result.envelope.branch_id,
                    enabled=self.use_task_guard,
                )
                if task_incident is not None:
                    task_incidents.append(task_incident)

        stopped, stop_stage, reason_code = _phi_stop_summary(
            admission_tickets,
            channel_results,
            capability_decisions,
            task_incidents,
            ot_results,
            autopsy_reports,
        )
        registry_states = {
            actor_id: _actor_state(registry, actor_id)
            for actor_id in _case_actor_ids(case)
        }

        return PhiBenchmarkOutcome(
            stopped=stopped,
            stop_stage=stop_stage,
            reason_code=reason_code,
            admission_tickets=admission_tickets,
            channel_results=channel_results,
            capability_decisions=tuple(capability_decisions),
            task_incidents=tuple(task_incidents),
            layer_decisions=tuple(layer_decisions),
            ot_results=tuple(ot_results),
            ledger_events=tuple(ledger_events),
            autopsy_reports=tuple(autopsy_reports),
            registry_states_after=registry_states,
            io_executed=False,
        )


def load_benchmark_cases(
    path: str | Path = DEFAULT_CASES_PATH,
    project_root: str = PROJECT_ROOT,
) -> Sequence[BenchmarkCase]:
    cases = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_number}") from exc

            cases.append(_case_from_dict(raw, project_root=project_root))

    return tuple(cases)


def run_benchmark(
    path: str | Path = DEFAULT_CASES_PATH,
    project_root: str = PROJECT_ROOT,
) -> BenchmarkSummary:
    cases = load_benchmark_cases(path=path, project_root=project_root)
    return PhiBenchmarkRunner(project_root=project_root).run_cases(cases)


def print_benchmark_summary(summary: BenchmarkSummary) -> None:
    print(
        f"Phi Benchmark: cases={summary.total_cases} "
        f"phi_pass={summary.phi_pass_count} "
        f"phi_fail={summary.phi_fail_count} "
        f"baseline_failures={summary.baseline_failure_count} "
        f"io_executed={summary.io_executed}"
    )
    for result in summary.results:
        baseline_status = ", ".join(
            f"{baseline.baseline_name}:{baseline.verdict.value}"
            for baseline in result.baselines
        )
        print(
            f"{result.case_id}: "
            f"should_stop={result.should_stop} "
            f"phi={result.phi.stop_stage}/{result.phi.reason_code} "
            f"baselines=[{baseline_status}]"
        )


def _case_from_dict(raw: Dict[str, Any], project_root: str) -> BenchmarkCase:
    envelopes = tuple(
        _envelope_from_dict(item, project_root=project_root)
        for item in raw.get("envelopes", ())
    )
    return BenchmarkCase(
        case_id=str(raw["case_id"]),
        description=str(raw.get("description", "")),
        should_stop=bool(raw["should_stop"]),
        envelopes=envelopes,
        registered_actors=tuple(raw.get("registered_actors", ("agent_coder",))),
    )


def _envelope_from_dict(raw: Dict[str, Any], project_root: str) -> ChannelEnvelope:
    metadata = _replace_project_root(raw.get("metadata", {}), project_root)
    return ChannelEnvelope(
        channel_type=ChannelType(raw["channel_type"]),
        source_id=str(raw["source_id"]),
        content=str(raw["content"]),
        branch_id=str(raw["branch_id"]),
        envelope_id=str(raw.get("envelope_id", "unknown_envelope")),
        parent_event_id=str(raw.get("parent_event_id", "")),
        user_request_id=str(raw.get("user_request_id", "")),
        metadata=metadata,
    )


def _replace_project_root(value: Any, project_root: str) -> Any:
    if isinstance(value, dict):
        return {
            key: _replace_project_root(child, project_root)
            for key, child in value.items()
        }

    if isinstance(value, list):
        return tuple(_replace_project_root(item, project_root) for item in value)

    if isinstance(value, str):
        return value.replace("{project_root}", project_root)

    return value


def _maybe_record_layer_decision(
    channel_result: ChannelAuditResult,
    layer_cooldown: LayerKillCooldown,
) -> Optional[LayerKillDecision]:
    if channel_result.disposition not in {
        ChannelDisposition.HOLD,
        ChannelDisposition.QUARANTINE,
    }:
        return None

    finding = _primary_channel_finding(channel_result.findings)
    if finding is None:
        return None

    request = LayerKillRequest(
        layer=channel_result.layer_ref.layer,
        scope=_scope_for_channel(channel_result.envelope.channel_type),
        branch_id=channel_result.envelope.branch_id,
        reason_code=finding.reason_code,
        object_ref=channel_result.layer_ref,
        critical=finding.severity == ChannelSeverity.CONTAMINATED,
        protected=False,
    )
    return layer_cooldown.record_layer_kill(request)


def _record_if_possible(
    ledger: EventLedger,
    proposal,
    ot_result: OTGateResult,
) -> Optional[AuditEvent]:
    try:
        return ledger.record(proposal, ot_result)
    except KeyError:
        return None


def _record_channel_stop_if_needed(
    task_guard: TaskGuard,
    channel_result: ChannelAuditResult,
    *,
    enabled: bool,
) -> Optional[TaskIncidentSummary]:
    if not enabled:
        return None

    if channel_result.disposition not in {
        ChannelDisposition.HOLD,
        ChannelDisposition.QUARANTINE,
    }:
        return None

    finding = _primary_channel_finding(channel_result.findings)
    reason_code = (
        finding.reason_code
        if finding is not None
        else channel_result.disposition.value
    )
    severity = (
        TaskStopSeverity.KILL
        if channel_result.disposition == ChannelDisposition.QUARANTINE
        else TaskStopSeverity.HOLD
    )
    return task_guard.record(
        TaskStopEvent(
            user_request_id=channel_result.envelope.user_request_id,
            branch_id=channel_result.envelope.branch_id,
            actor_id=channel_result.envelope.source_id,
            stage=f"CHANNEL_{channel_result.disposition.value}",
            reason_code=reason_code,
            severity=severity,
        )
    )


def _record_capability_stop_if_needed(
    task_guard: TaskGuard,
    proposal,
    capability_decision: CapabilityDecision,
    branch_id: str,
    *,
    enabled: bool,
) -> Optional[TaskIncidentSummary]:
    if not enabled:
        return None

    if capability_decision.disposition not in {
        CapabilityDisposition.HOLD,
        CapabilityDisposition.KILL,
    }:
        return None

    severity = (
        TaskStopSeverity.KILL
        if capability_decision.disposition == CapabilityDisposition.KILL
        else TaskStopSeverity.HOLD
    )
    return task_guard.record(
        TaskStopEvent(
            user_request_id=proposal.user_request_id,
            branch_id=branch_id,
            actor_id=proposal.actor_id,
            stage=f"CAPABILITY_{capability_decision.disposition.value}",
            reason_code=capability_decision.reason_code,
            severity=severity,
        )
    )


def _record_ot_stop_if_needed(
    task_guard: TaskGuard,
    proposal,
    ot_result: OTGateResult,
    branch_id: str,
    *,
    enabled: bool,
) -> Optional[TaskIncidentSummary]:
    if not enabled:
        return None

    if ot_result.decision != ExecutionDecision.KILL:
        return None

    return task_guard.record(
        TaskStopEvent(
            user_request_id=proposal.user_request_id,
            branch_id=branch_id,
            actor_id=proposal.actor_id,
            stage="OT_KILL",
            reason_code=ot_result.reason_code,
            severity=(
                TaskStopSeverity.CRITICAL
                if ot_result.critical
                else TaskStopSeverity.KILL
            ),
        )
    )
def _phi_stop_summary(
    admission_tickets: Sequence[AdmissionTicket],
    channel_results: Sequence[ChannelAuditResult],
    capability_decisions: Sequence[CapabilityDecision],
    task_incidents: Sequence[TaskIncidentSummary],
    ot_results: Sequence[OTGateResult],
    autopsy_reports: Sequence[AutopsyReport],
) -> tuple[bool, str, str]:
    task_stop = next(
        (incident for incident in task_incidents if incident.terminated),
        None,
    )
    if task_stop is not None:
        return True, "TASK_TERMINATED", "TASK_TERMINATED"

    admission_stop = next(
        (
            ticket
            for ticket in admission_tickets
            if ticket.disposition in {
                AdmissionDisposition.HOLD,
                AdmissionDisposition.REJECT,
            }
        ),
        None,
    )
    if admission_stop is not None:
        return (
            True,
            f"ADMISSION_{admission_stop.disposition.value}",
            admission_stop.reason_code,
        )

    channel_stop = next(
        (
            result
            for result in channel_results
            if result.disposition in {
                ChannelDisposition.HOLD,
                ChannelDisposition.QUARANTINE,
            }
        ),
        None,
    )
    if channel_stop is not None:
        finding = _primary_channel_finding(channel_stop.findings)
        return (
            True,
            f"CHANNEL_{channel_stop.disposition.value}",
            finding.reason_code if finding is not None else channel_stop.disposition.value,
        )

    capability_stop = next(
        (
            decision
            for decision in capability_decisions
            if decision.disposition in {
                CapabilityDisposition.HOLD,
                CapabilityDisposition.KILL,
            }
        ),
        None,
    )
    if capability_stop is not None:
        return (
            True,
            f"CAPABILITY_{capability_stop.disposition.value}",
            capability_stop.reason_code,
        )

    ot_stop = next(
        (
            result
            for result in ot_results
            if result.decision == ExecutionDecision.KILL
        ),
        None,
    )
    if ot_stop is not None:
        if autopsy_reports:
            return True, "OT_AUTOPSY", autopsy_reports[0].death_reason
        return True, "OT_GATE", ot_stop.reason_code

    return False, "ALLOW", "ALLOW"


def _primary_channel_finding(
    findings: Sequence[ChannelFinding],
) -> Optional[ChannelFinding]:
    for finding in findings:
        if finding.severity == ChannelSeverity.CONTAMINATED:
            return finding

    for finding in findings:
        if finding.severity == ChannelSeverity.SUSPECT:
            return finding

    return findings[0] if findings else None


def _scope_for_channel(channel_type: ChannelType) -> KillScope:
    mapping = {
        ChannelType.USER_REQUEST: KillScope.USER_CLAIM,
        ChannelType.TOOL_METADATA: KillScope.SOURCE_OBJECT,
        ChannelType.AGENT_PROPOSAL: KillScope.MOTION_BRANCH,
        ChannelType.REJECTED_FEEDBACK: KillScope.MOTION_BRANCH,
    }
    return mapping[channel_type]


def _case_actor_ids(case: BenchmarkCase) -> Sequence[str]:
    return tuple(
        dict.fromkeys(
            tuple(case.registered_actors)
            + tuple(envelope.source_id for envelope in case.envelopes)
        )
    )


def _actor_state(registry: PhiRegistry, actor_id: str) -> Optional[ActorState]:
    actor = registry.get_actor(actor_id)
    return actor.state if actor is not None else None


if __name__ == "__main__":
    print_benchmark_summary(run_benchmark())
