"""Form-1 grounding: the decoded observation ledger vs the judge's verdict.

Architecture seam (prototype). pub keeps the DECODER and the JUDGE separate:

  * DECODER  -- the X-ray SCAN (a `TransitionXrayFrame` of physical pieces). It
                reports only FACTS: exists / sha256 / type / disguise indicators
                (symlink, hardlink, archive-escape, out-of-boundary, sensitive
                marker, opaque executor). It never decides.
  * JUDGE    -- the verdict (disposition + reason_code) produced from those facts.

This module makes the seam ENFORCEABLE. `ObservationLedger` normalises the scan
into atomic facts; `ground()` checks the verdict and the ledger GROUND each other,
both directions:

  * over-reaction  -- a verdict stronger than any fact can justify, or a reason
                      whose required physical evidence is absent, is a PHANTOM
                      verdict / side-path leak (e.g. SUBSTITUTION claimed with no
                      pointer/alias/mutation fact -- the QUARANTINE regression).
  * under-reaction -- a fact that demands action while the verdict is weaker means
                      the judge dropped an observation.

It is a SELF-CONSISTENCY check: it makes the gate HONEST (it will not decide what
it cannot justify from what it saw), NOT OMNISCIENT (it cannot catch what the eye
never observed -- two eyes that agree-while-blind still pass; that perception gap
is Form 2's job, an independent decode). Use as a corpus test oracle and/or a
cheap always-on runtime invariant.

Scope (prototype): grounds verdicts SOURCED FROM the X-ray decoder. Reasons from
other eyes (protect_scan, capability_wall) return UNVERIFIABLE -- each such eye
gets its own observation extractor later, widening what is grounded. Channel
audit is now the second installed eye: its findings are decoded as channel facts,
not as execution authority.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Mapping

from transition_xray import TransitionXrayFrame, XrayPiece, hash_unavailable


class Severity(enum.IntEnum):
    PASS = 0
    HOLD = 1
    QUARANTINE = 2
    KILL = 3


_SEVERITY_BY_NAME = {
    "PASS": Severity.PASS,
    "HOLD": Severity.HOLD,
    "QUARANTINE": Severity.QUARANTINE,
    "KILL": Severity.KILL,
    "REJECT": Severity.KILL,
}


def severity_of(disposition: Any) -> Severity:
    name = getattr(disposition, "value", disposition)
    return _SEVERITY_BY_NAME.get(str(name).upper(), Severity.PASS)


class Fact(str, enum.Enum):
    """Atomic physical observations the SCAN can witness on the surface."""

    OUT_OF_BOUNDARY = "out_of_boundary"
    UNOBSERVED_CONTENT = "unobserved_content"
    MISSING = "missing"
    UNHASHABLE = "unhashable"
    POINTER = "pointer"
    ALIAS = "alias"
    CONTAINER_ESCAPE = "container_escape"
    SENSITIVE_MARKER = "sensitive_marker"
    OPAQUE_EXECUTOR = "opaque_executor"
    MUTATION = "mutation"
    CONTINUITY_BREAK = "continuity_break"
    FIELD_DISTORTION = "field_distortion"
    RESPONSIBILITY_GAP = "responsibility_gap"
    CHANNEL_CONTENT_TOO_LARGE = "channel_content_too_large"
    CHANNEL_EXECUTION_CLAIM = "channel_execution_claim"
    CHANNEL_PERMISSION_GRANT_CLAIM = "channel_permission_grant_claim"
    CHANNEL_AUTHORITY_METADATA_CLAIM = "channel_authority_metadata_claim"
    CHANNEL_FALSE_PERMISSION_CLAIM = "channel_false_permission_claim"
    CHANNEL_SENSITIVE_TARGET = "channel_sensitive_target"
    CHANNEL_TOOL_POISONING = "channel_tool_poisoning"
    CHANNEL_TOOL_EXECUTION_CAPABILITY = "channel_tool_execution_capability"
    CHANNEL_TOOL_PERMISSION_CLAIM = "channel_tool_permission_claim"
    CHANNEL_AGENT_PERMISSION_CLAIM = "channel_agent_permission_claim"
    CHANNEL_EMPTY_AGENT_PROPOSAL = "channel_empty_agent_proposal"
    CHANNEL_REJECTED_STATE_LINK = "channel_rejected_state_link"
    CHANNEL_REJECTED_FEEDBACK = "channel_rejected_feedback"
    CHANNEL_REJECTED_STATE_POLLUTION = "channel_rejected_state_pollution"
    CHANNEL_REJECTED_AUTHORITY_MUTATION = "channel_rejected_authority_mutation"
    CHANNEL_BRANCH_CONTAMINATION = "channel_branch_contamination"
    CHANNEL_NULL_BYTE_PATH = "channel_null_byte_path"
    CHANNEL_EXECUTION_PATH_DIVERGENCE = "channel_execution_path_divergence"
    CHANNEL_AMBIENT_CAPABILITY_CLAIM = "channel_ambient_capability_claim"
    CHANNEL_ENCODED_OR_CONDITIONAL_PAYLOAD = "channel_encoded_or_conditional_payload"
    CHANNEL_MULTI_STEP_COMPOSITION = "channel_multi_step_composition"


# the strongest verdict each physical fact can, on its own, justify.
_FACT_CEILING: dict[Fact, Severity] = {
    Fact.POINTER: Severity.QUARANTINE,
    Fact.ALIAS: Severity.QUARANTINE,
    Fact.CONTAINER_ESCAPE: Severity.QUARANTINE,
    Fact.MUTATION: Severity.QUARANTINE,
    Fact.CONTINUITY_BREAK: Severity.QUARANTINE,
    Fact.OUT_OF_BOUNDARY: Severity.HOLD,
    Fact.UNOBSERVED_CONTENT: Severity.HOLD,
    # A missing target is benign on its own -- creating a new file or deleting a
    # gone one. xray_review does not blindspot on exists=False, so neither do we.
    Fact.MISSING: Severity.PASS,
    Fact.UNHASHABLE: Severity.HOLD,
    Fact.OPAQUE_EXECUTOR: Severity.HOLD,
    Fact.FIELD_DISTORTION: Severity.HOLD,
    Fact.SENSITIVE_MARKER: Severity.HOLD,
    Fact.RESPONSIBILITY_GAP: Severity.HOLD,
    Fact.CHANNEL_CONTENT_TOO_LARGE: Severity.HOLD,
    Fact.CHANNEL_EXECUTION_CLAIM: Severity.HOLD,
    Fact.CHANNEL_PERMISSION_GRANT_CLAIM: Severity.HOLD,
    Fact.CHANNEL_AUTHORITY_METADATA_CLAIM: Severity.HOLD,
    Fact.CHANNEL_FALSE_PERMISSION_CLAIM: Severity.HOLD,
    Fact.CHANNEL_SENSITIVE_TARGET: Severity.HOLD,
    Fact.CHANNEL_TOOL_POISONING: Severity.QUARANTINE,
    Fact.CHANNEL_TOOL_EXECUTION_CAPABILITY: Severity.QUARANTINE,
    Fact.CHANNEL_TOOL_PERMISSION_CLAIM: Severity.QUARANTINE,
    Fact.CHANNEL_AGENT_PERMISSION_CLAIM: Severity.HOLD,
    Fact.CHANNEL_EMPTY_AGENT_PROPOSAL: Severity.HOLD,
    Fact.CHANNEL_REJECTED_STATE_LINK: Severity.HOLD,
    Fact.CHANNEL_REJECTED_FEEDBACK: Severity.QUARANTINE,
    Fact.CHANNEL_REJECTED_STATE_POLLUTION: Severity.QUARANTINE,
    Fact.CHANNEL_REJECTED_AUTHORITY_MUTATION: Severity.QUARANTINE,
    Fact.CHANNEL_BRANCH_CONTAMINATION: Severity.QUARANTINE,
    Fact.CHANNEL_NULL_BYTE_PATH: Severity.HOLD,
    Fact.CHANNEL_EXECUTION_PATH_DIVERGENCE: Severity.HOLD,
    Fact.CHANNEL_AMBIENT_CAPABILITY_CLAIM: Severity.HOLD,
    Fact.CHANNEL_ENCODED_OR_CONDITIONAL_PAYLOAD: Severity.HOLD,
    Fact.CHANNEL_MULTI_STEP_COMPOSITION: Severity.HOLD,
}


# which physical facts can GROUND each X-ray verdict reason. A reason whose facts
# are all absent from the ledger is a phantom verdict. Note: FIELD_DISTORTION
# (a blindspot symptom) grounds OBSERVATION_BLINDSPOT, NOT SUBSTITUTION -- the
# exact conflation that turned a benign out-of-boundary read into a QUARANTINE.
REASON_REQUIRES: dict[str, frozenset[Fact]] = {
    "XRAY_CLEAR": frozenset(),
    "XRAY_REVIEW_SUBSTITUTION": frozenset(
        {Fact.POINTER, Fact.ALIAS, Fact.CONTAINER_ESCAPE, Fact.MUTATION, Fact.CONTINUITY_BREAK}
    ),
    "XRAY_REVIEW_POINTER": frozenset({Fact.POINTER}),
    "XRAY_REVIEW_ALIAS": frozenset({Fact.ALIAS}),
    "XRAY_REVIEW_CONTAINER_ESCAPE": frozenset({Fact.CONTAINER_ESCAPE}),
    "XRAY_REVIEW_OBSERVATION_BLINDSPOT": frozenset(
        {
            Fact.OUT_OF_BOUNDARY,
            Fact.UNOBSERVED_CONTENT,
            Fact.UNHASHABLE,
            Fact.OPAQUE_EXECUTOR,
            Fact.FIELD_DISTORTION,
        }
    ),
    "XRAY_REVIEW_SENSITIVE_SURFACE": frozenset({Fact.SENSITIVE_MARKER}),
    "XRAY_REVIEW_RESPONSIBILITY_GAP": frozenset({Fact.RESPONSIBILITY_GAP}),
    "CHANNEL_ACCEPT": frozenset(),
    "CHANNEL_WRAP_PROPOSAL": frozenset(),
    "CHANNEL_CONTENT_TOO_LARGE": frozenset({Fact.CHANNEL_CONTENT_TOO_LARGE}),
    "CHANNEL_EXECUTION_CLAIM_STRIPPED": frozenset({Fact.CHANNEL_EXECUTION_CLAIM}),
    "CHANNEL_PERMISSION_GRANT_CLAIM_STRIPPED": frozenset(
        {Fact.CHANNEL_PERMISSION_GRANT_CLAIM}
    ),
    "CHANNEL_AUTHORITY_METADATA_CLAIM": frozenset(
        {Fact.CHANNEL_AUTHORITY_METADATA_CLAIM}
    ),
    "FALSE_PERMISSION_CLAIM": frozenset({Fact.CHANNEL_FALSE_PERMISSION_CLAIM}),
    "USER_REQUEST_SENSITIVE_TARGET": frozenset({Fact.CHANNEL_SENSITIVE_TARGET}),
    "TOOL_METADATA_POISONING": frozenset({Fact.CHANNEL_TOOL_POISONING}),
    "TOOL_METADATA_EXECUTION_CAPABILITY": frozenset(
        {Fact.CHANNEL_TOOL_EXECUTION_CAPABILITY}
    ),
    "TOOL_METADATA_PERMISSION_CLAIM": frozenset(
        {Fact.CHANNEL_TOOL_PERMISSION_CLAIM}
    ),
    "AGENT_PROPOSAL_PERMISSION_CLAIM": frozenset(
        {Fact.CHANNEL_AGENT_PERMISSION_CLAIM}
    ),
    "EMPTY_AGENT_PROPOSAL": frozenset({Fact.CHANNEL_EMPTY_AGENT_PROPOSAL}),
    "AGENT_PROPOSAL_FROM_REJECTED_STATE": frozenset(
        {Fact.CHANNEL_REJECTED_STATE_LINK}
    ),
    "REJECTED_FEEDBACK_QUARANTINED": frozenset({Fact.CHANNEL_REJECTED_FEEDBACK}),
    "REJECTED_STATE_POLLUTION": frozenset({Fact.CHANNEL_REJECTED_STATE_POLLUTION}),
    "REJECTED_FEEDBACK_AUTHORITY_MUTATION": frozenset(
        {Fact.CHANNEL_REJECTED_AUTHORITY_MUTATION}
    ),
    "BRANCH_CONTAMINATION_INHERITED": frozenset(
        {Fact.CHANNEL_BRANCH_CONTAMINATION}
    ),
    "CHANNEL_NULL_BYTE_PATH": frozenset({Fact.CHANNEL_NULL_BYTE_PATH}),
    "CHANNEL_EXECUTION_PATH_DIVERGENCE": frozenset(
        {Fact.CHANNEL_EXECUTION_PATH_DIVERGENCE}
    ),
    "CHANNEL_AMBIENT_CAPABILITY_CLAIM": frozenset(
        {Fact.CHANNEL_AMBIENT_CAPABILITY_CLAIM}
    ),
    "CHANNEL_ENCODED_OR_CONDITIONAL_PAYLOAD": frozenset(
        {Fact.CHANNEL_ENCODED_OR_CONDITIONAL_PAYLOAD}
    ),
    "CHANNEL_MULTI_STEP_COMPOSITION": frozenset(
        {Fact.CHANNEL_MULTI_STEP_COMPOSITION}
    ),
}

CHANNEL_REASON_FACTS: dict[str, Fact] = {
    reason: next(iter(facts))
    for reason, facts in REASON_REQUIRES.items()
    if reason.startswith("CHANNEL_")
    and facts
} | {
    "FALSE_PERMISSION_CLAIM": Fact.CHANNEL_FALSE_PERMISSION_CLAIM,
    "USER_REQUEST_SENSITIVE_TARGET": Fact.CHANNEL_SENSITIVE_TARGET,
    "TOOL_METADATA_POISONING": Fact.CHANNEL_TOOL_POISONING,
    "TOOL_METADATA_EXECUTION_CAPABILITY": Fact.CHANNEL_TOOL_EXECUTION_CAPABILITY,
    "TOOL_METADATA_PERMISSION_CLAIM": Fact.CHANNEL_TOOL_PERMISSION_CLAIM,
    "AGENT_PROPOSAL_PERMISSION_CLAIM": Fact.CHANNEL_AGENT_PERMISSION_CLAIM,
    "EMPTY_AGENT_PROPOSAL": Fact.CHANNEL_EMPTY_AGENT_PROPOSAL,
    "AGENT_PROPOSAL_FROM_REJECTED_STATE": Fact.CHANNEL_REJECTED_STATE_LINK,
    "REJECTED_FEEDBACK_QUARANTINED": Fact.CHANNEL_REJECTED_FEEDBACK,
    "REJECTED_STATE_POLLUTION": Fact.CHANNEL_REJECTED_STATE_POLLUTION,
    "REJECTED_FEEDBACK_AUTHORITY_MUTATION": Fact.CHANNEL_REJECTED_AUTHORITY_MUTATION,
    "BRANCH_CONTAMINATION_INHERITED": Fact.CHANNEL_BRANCH_CONTAMINATION,
}


@dataclass(frozen=True)
class Observation:
    fact: Fact
    ref: str
    detail: str = ""

    @property
    def ceiling(self) -> Severity:
        return _FACT_CEILING[self.fact]

    def to_dict(self) -> dict[str, Any]:
        return {"fact": self.fact.value, "ref": self.ref, "detail": self.detail}


@dataclass(frozen=True)
class ObservationLedger:
    observations: tuple[Observation, ...] = ()

    @property
    def facts(self) -> frozenset[Fact]:
        return frozenset(observation.fact for observation in self.observations)

    @property
    def ceiling(self) -> Severity:
        return max(
            (observation.ceiling for observation in self.observations),
            default=Severity.PASS,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ceiling": self.ceiling.name,
            "facts": sorted(fact.value for fact in self.facts),
            "observations": [observation.to_dict() for observation in self.observations],
        }

    @classmethod
    def from_frame(
        cls,
        frame: TransitionXrayFrame,
        *,
        seal: Any = None,
    ) -> "ObservationLedger":
        observations: list[Observation] = []
        for piece in frame.pieces:
            observations.extend(_facts_from_piece(piece))
        if seal is not None:
            observations.extend(_facts_from_seal(seal))
        return cls(tuple(observations))

    @classmethod
    def from_channel_result(cls, result: Any) -> "ObservationLedger":
        return cls(tuple(_facts_from_channel_result(result)))


# Mirror of xray_review._ARCHIVE_BLINDSPOT_STATUSES: a zip-magic file we could
# not fully read/scan grounds UNOBSERVED_CONTENT (a blindspot), not a pass.
_ARCHIVE_BLINDSPOT_STATUSES = frozenset(
    {"archive_unreadable", "archive_resource_limit", "archive_truncated"}
)


def _facts_from_piece(piece: XrayPiece) -> list[Observation]:
    details = piece.details if isinstance(piece.details, Mapping) else {}
    tags = tuple(str(tag) for tag in details.get("xray_tags", ()))
    ref = piece.key
    out: list[Observation] = []

    if details.get("observation_boundary") == "outside_project_root":
        out.append(Observation(Fact.OUT_OF_BOUNDARY, ref))
    elif piece.exists is None:
        out.append(Observation(Fact.UNOBSERVED_CONTENT, ref, "exists=None"))
    elif piece.exists is False:
        out.append(Observation(Fact.MISSING, ref))
    elif piece.kind == "target_path" and piece.exists is True and piece.sha256 is None:
        out.append(Observation(Fact.UNOBSERVED_CONTENT, ref))

    if (
        hash_unavailable(details)
        and details.get("observation_boundary") != "outside_project_root"
    ):
        out.append(Observation(Fact.UNHASHABLE, ref, str(details.get("hash_status"))))
    if piece.type == "symlink" or details.get("symlink_target"):
        out.append(Observation(Fact.POINTER, ref))
    nlink = details.get("nlink")
    if isinstance(nlink, int) and not isinstance(nlink, bool) and nlink > 1:
        out.append(Observation(Fact.ALIAS, ref, f"nlink={nlink}"))
    if details.get("archive_escape_entries"):
        out.append(Observation(Fact.CONTAINER_ESCAPE, ref))
    if details.get("archive_sensitive_entries"):
        out.append(Observation(Fact.SENSITIVE_MARKER, ref, "archive_sensitive_entry"))
    if details.get("archive_observation_status") in _ARCHIVE_BLINDSPOT_STATUSES:
        out.append(
            Observation(
                Fact.UNOBSERVED_CONTENT,
                ref,
                str(details.get("archive_observation_status")),
            )
        )
    if "sensitive_marker" in tags:
        out.append(Observation(Fact.SENSITIVE_MARKER, ref))
    if piece.kind == "registered_action" and details.get("effect_modellable") is False:
        out.append(Observation(Fact.OPAQUE_EXECUTOR, ref, str(details.get("opaque_executor", ""))))
    if piece.kind == "skill_responsibility" and str(details.get("state", "")) in {
        "required_but_missing",
        "trace_present_no_id",
    }:
        out.append(Observation(Fact.RESPONSIBILITY_GAP, ref, str(details.get("state"))))
    return out


def _facts_from_seal(seal: Any) -> list[Observation]:
    ref = f"seal:{getattr(seal, 'proposal_id', '?')}"
    out: list[Observation] = []
    if getattr(seal, "mutation_state", "STABLE") != "STABLE":
        out.append(Observation(Fact.MUTATION, ref, seal.mutation_state))
    if getattr(seal, "continuity_state", "CONTINUOUS") != "CONTINUOUS":
        out.append(Observation(Fact.CONTINUITY_BREAK, ref, seal.continuity_state))
    if getattr(seal, "field_state", "STABLE") != "STABLE":
        out.append(Observation(Fact.FIELD_DISTORTION, ref, seal.field_state))
    return out


def _facts_from_channel_result(result: Any) -> list[Observation]:
    envelope = getattr(result, "envelope", None)
    ref = str(getattr(envelope, "envelope_id", "") or "channel")
    observations: list[Observation] = []
    for finding in getattr(result, "findings", ()) or ():
        reason = str(getattr(finding, "reason_code", ""))
        fact = CHANNEL_REASON_FACTS.get(reason)
        if fact is None:
            continue
        evidence = tuple(str(item) for item in getattr(finding, "evidence", ()) or ())
        detail = ",".join(evidence) if evidence else str(getattr(finding, "detail", ""))
        observations.append(Observation(fact, ref, detail))
    return observations


class GroundingStatus(str, enum.Enum):
    GROUNDED = "GROUNDED"                       # verdict justified by the observation
    VERDICT_UNGROUNDED = "VERDICT_UNGROUNDED"   # verdict stronger than any fact supports
    REASON_UNGROUNDED = "REASON_UNGROUNDED"     # reason lacks its required physical fact
    OBSERVATION_IGNORED = "OBSERVATION_IGNORED" # a fact demanded more than the verdict gave
    UNVERIFIABLE = "UNVERIFIABLE"               # reason not sourced from the x-ray decoder


@dataclass(frozen=True)
class GroundingReport:
    status: GroundingStatus
    verdict_severity: Severity
    ledger_ceiling: Severity
    reason_code: str
    detail: str
    ledger: ObservationLedger

    @property
    def ok(self) -> bool:
        return self.status in {GroundingStatus.GROUNDED, GroundingStatus.UNVERIFIABLE}

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "ok": self.ok,
            "verdict_severity": self.verdict_severity.name,
            "ledger_ceiling": self.ledger_ceiling.name,
            "reason_code": self.reason_code,
            "detail": self.detail,
            "ledger": self.ledger.to_dict(),
        }


def ground(
    ledger: ObservationLedger,
    disposition: Any,
    reason_code: str,
) -> GroundingReport:
    vsev = severity_of(disposition)
    reason = str(reason_code)
    required = REASON_REQUIRES.get(reason)
    facts = ledger.facts

    def report(status: GroundingStatus, detail: str) -> GroundingReport:
        return GroundingReport(status, vsev, ledger.ceiling, reason, detail, ledger)

    # under-reaction: an observed fact demands more than the verdict gave.
    if ledger.ceiling > vsev:
        return report(
            GroundingStatus.OBSERVATION_IGNORED,
            f"verdict {vsev.name} below ledger ceiling {ledger.ceiling.name} "
            f"(facts {sorted(f.value for f in facts)})",
        )
    # reason produced by a different eye -> this ledger cannot verify it.
    if required is None:
        return report(
            GroundingStatus.UNVERIFIABLE,
            "reason not sourced from the x-ray decoder; needs that eye's ledger",
        )
    # over-reaction: verdict stronger than the strongest fact can justify.
    if vsev > ledger.ceiling:
        return report(
            GroundingStatus.VERDICT_UNGROUNDED,
            f"verdict {vsev.name} exceeds what any observed fact justifies "
            f"({ledger.ceiling.name})",
        )
    if vsev <= Severity.PASS:
        return report(GroundingStatus.GROUNDED, "clear: no action, no high facts")
    # the reason must point at a physical fact that actually warrants it.
    grounding_facts = facts & required
    if not grounding_facts:
        return report(
            GroundingStatus.REASON_UNGROUNDED,
            f"reason {reason} requires one of {sorted(f.value for f in required)}; "
            f"ledger has {sorted(f.value for f in facts)}",
        )
    reason_ceiling = max(_FACT_CEILING[fact] for fact in grounding_facts)
    if reason_ceiling < vsev:
        return report(
            GroundingStatus.REASON_UNGROUNDED,
            f"reason {reason} only supports {reason_ceiling.name}, below verdict {vsev.name}",
        )
    return report(GroundingStatus.GROUNDED, "verdict grounded in observation")


def ground_review(
    frame: TransitionXrayFrame,
    review: Any,
    *,
    seal: Any = None,
) -> GroundingReport:
    """Convenience: ground an XrayReview against the frame it claims to summarise."""
    ledger = ObservationLedger.from_frame(frame, seal=seal)
    return ground(ledger, review.disposition, review.reason_code)


def ground_channel_result(result: Any) -> GroundingReport:
    """Ground a ChannelAuditResult against the facts decoded from its findings."""
    ledger = ObservationLedger.from_channel_result(result)
    disposition = getattr(result, "disposition", "")
    findings = tuple(getattr(result, "findings", ()) or ())
    # Ground against the finding that DROVE the aggregate disposition -- the
    # highest-severity one -- not findings[0]. The disposition is max() over the
    # findings; a weaker finding listed first would otherwise fail the
    # reason-ceiling check against the stronger aggregate verdict.
    driver: str | None = None
    driver_severity = -1
    for finding in findings:
        reason_code = str(getattr(finding, "reason_code", ""))
        fact = CHANNEL_REASON_FACTS.get(reason_code)
        severity = int(_FACT_CEILING[fact]) if fact is not None else 0
        if severity >= driver_severity:
            driver_severity = severity
            driver = reason_code
    reason = driver or f"CHANNEL_{getattr(disposition, 'value', disposition)}"
    return ground(ledger, disposition, reason)
