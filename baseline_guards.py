from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Sequence

from llm_channel import ChannelEnvelope, ChannelType


class BaselineVerdict(str, Enum):
    COMMIT = "COMMIT"
    ACCEPT_CONTEXT = "ACCEPT_CONTEXT"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class BaselineResult:
    baseline_name: str
    verdict: BaselineVerdict
    reason_code: str
    evidence: Sequence[str] = ()

    @property
    def stopped(self) -> bool:
        return self.verdict in {BaselineVerdict.HOLD, BaselineVerdict.BLOCK}

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_name": self.baseline_name,
            "verdict": self.verdict.value,
            "reason_code": self.reason_code,
            "evidence": tuple(self.evidence),
            "stopped": self.stopped,
        }


class BaselineGuard:
    name = "baseline"

    def evaluate(self, envelopes: Sequence[ChannelEnvelope]) -> BaselineResult:
        raise NotImplementedError


class NakedAgentBaseline(BaselineGuard):
    """
    No audit boundary.

    This models a harness where agent output is treated as executable intent.
    Non-proposal channels are simply admitted into context.
    """

    name = "naked_agent"

    def evaluate(self, envelopes: Sequence[ChannelEnvelope]) -> BaselineResult:
        if _has_agent_proposal(envelopes):
            return BaselineResult(
                baseline_name=self.name,
                verdict=BaselineVerdict.COMMIT,
                reason_code="NO_AUDIT_COMMIT",
            )

        return BaselineResult(
            baseline_name=self.name,
            verdict=BaselineVerdict.ACCEPT_CONTEXT,
            reason_code="NO_AUDIT_ACCEPT_CONTEXT",
        )


class PromptGuardrailBaseline(BaselineGuard):
    """
    A lightweight prompt-only control.

    It checks only visible text, not structured metadata, branch history,
    actor identity, protected stores, or declared side effects.
    """

    name = "prompt_guardrail"

    suspicious_text_tokens = (
        "highest permission",
        "admin permission",
        "root permission",
        "ignore previous",
        "bypass audit",
        "without approval",
        "run without approval",
        "delete",
        "remove-item",
        "secret",
    )

    def evaluate(self, envelopes: Sequence[ChannelEnvelope]) -> BaselineResult:
        hits = _token_hits(_joined_content(envelopes), self.suspicious_text_tokens)
        if hits:
            return BaselineResult(
                baseline_name=self.name,
                verdict=BaselineVerdict.HOLD,
                reason_code="PROMPT_GUARDRAIL_TEXT_HIT",
                evidence=hits,
            )

        return _default_pass_result(self.name, envelopes)


class KeywordGuardrailBaseline(BaselineGuard):
    """
    A shallow static keyword filter.

    This is intentionally stronger than a prompt-only control because it also
    scans metadata. It still has no identity model, branch memory, vote system,
    protected-store semantics, or autopsy.
    """

    name = "keyword_guardrail"

    tokens = (
        "highest permission",
        "can_execute",
        "can_grant_permission",
        "ignore previous",
        "bypass audit",
        "without approval",
        "run without approval",
        "from_rejected_state",
        ".phi\\registry",
        ".phi/registry",
        ".phi\\ledger",
        ".phi/ledger",
        "c:\\users\\",
        "remove-item",
        " rm ",
        " del ",
        "set-content",
        "out-file",
        "add-content",
        "curl",
        "wget",
        "invoke-webrequest",
        "invoke-restmethod",
        "irm",
        "iex",
        "powershell -",
        "secret",
        ".env",
        "id_rsa",
    )

    def evaluate(self, envelopes: Sequence[ChannelEnvelope]) -> BaselineResult:
        hits = _token_hits(_joined_content_with_metadata(envelopes), self.tokens)
        if hits:
            return BaselineResult(
                baseline_name=self.name,
                verdict=BaselineVerdict.BLOCK,
                reason_code="KEYWORD_GUARDRAIL_TEXT_HIT",
                evidence=hits,
            )

        return _default_pass_result(self.name, envelopes)


def default_baselines() -> Sequence[BaselineGuard]:
    return (
        NakedAgentBaseline(),
        PromptGuardrailBaseline(),
        KeywordGuardrailBaseline(),
    )


def _default_pass_result(
    baseline_name: str,
    envelopes: Sequence[ChannelEnvelope],
) -> BaselineResult:
    if _has_agent_proposal(envelopes):
        return BaselineResult(
            baseline_name=baseline_name,
            verdict=BaselineVerdict.COMMIT,
            reason_code="BASELINE_COMMIT",
        )

    return BaselineResult(
        baseline_name=baseline_name,
        verdict=BaselineVerdict.ACCEPT_CONTEXT,
        reason_code="BASELINE_ACCEPT_CONTEXT",
    )


def _has_agent_proposal(envelopes: Sequence[ChannelEnvelope]) -> bool:
    return any(
        envelope.channel_type == ChannelType.AGENT_PROPOSAL
        for envelope in envelopes
    )


def _joined_content(envelopes: Sequence[ChannelEnvelope]) -> str:
    return "\n".join(envelope.content for envelope in envelopes)


def _joined_content_with_metadata(envelopes: Sequence[ChannelEnvelope]) -> str:
    chunks = []
    for envelope in envelopes:
        chunks.append(envelope.content)
        chunks.append(_flatten_metadata(envelope.metadata))

    return "\n".join(chunks)


def _flatten_metadata(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(
            f"{key} {_flatten_metadata(child)}"
            for key, child in sorted(value.items(), key=lambda item: str(item[0]))
        )

    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_metadata(item) for item in value)

    return str(value)


def _token_hits(content: str, tokens: Iterable[str]) -> tuple[str, ...]:
    text = content.lower()
    return tuple(token for token in tokens if token in text)
