from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Sequence

from benchmark_runner import BenchmarkCase, PROJECT_ROOT
from llm_channel import ChannelEnvelope, ChannelType
from ot_gate import DeclaredScope, SideEffect


DEFAULT_EXTERNAL_CASES_PATH = Path(__file__).with_name("external_redteam_cases.json")


def load_external_redteam_cases(
    path: str | Path = DEFAULT_EXTERNAL_CASES_PATH,
    project_root: str = PROJECT_ROOT,
) -> Sequence[BenchmarkCase]:
    raw_cases = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw_cases, list):
        raise ValueError("external red-team case file must contain a JSON array.")

    return tuple(
        external_case_to_benchmark_case(raw, project_root=project_root)
        for raw in raw_cases
    )


def external_case_to_benchmark_case(
    raw: Dict[str, Any],
    project_root: str = PROJECT_ROOT,
) -> BenchmarkCase:
    if "envelopes" in raw:
        envelopes = tuple(
            _envelope_from_external_envelope(
                raw,
                raw_envelope,
                index=index,
                project_root=project_root,
            )
            for index, raw_envelope in enumerate(raw["envelopes"], start=1)
        )
    else:
        envelopes = (_envelope_from_external_case(raw, project_root=project_root),)

    return BenchmarkCase(
        case_id=str(raw["case_id"]),
        description=str(raw.get("description", "")),
        should_stop=bool(raw.get("should_stop", True)),
        envelopes=envelopes,
        registered_actors=_registered_actors_for(envelopes),
    )


def _envelope_from_external_case(
    raw: Dict[str, Any],
    project_root: str,
) -> ChannelEnvelope:
    return _envelope_from_external_envelope(
        raw,
        raw,
        index=1,
        project_root=project_root,
    )


def _envelope_from_external_envelope(
    raw_case: Dict[str, Any],
    raw_envelope: Dict[str, Any],
    *,
    index: int,
    project_root: str,
) -> ChannelEnvelope:
    metadata = dict(raw_envelope.get("metadata") or {})
    content = _stringify_content(raw_envelope.get("content", ""))
    target_paths = tuple(str(path) for path in metadata.get("target_paths", ()))
    raw_effects = tuple(str(effect) for effect in metadata.get("expected_side_effects", ()))

    normalized_effects = _normalize_side_effects(
        raw_effects,
        content=content,
        target_paths=target_paths,
    )
    metadata.update(
        {
            "cwd": str(metadata.get("cwd") or project_root),
            "declared_scope": _normalize_declared_scope(
                str(metadata.get("declared_scope", "")),
                content=content,
                raw_effects=raw_effects,
                normalized_effects=normalized_effects,
            ),
            "target_paths": target_paths,
            "expected_side_effects": normalized_effects,
            "external_case_id": str(raw_case["case_id"]),
            "raw_declared_scope": str(metadata.get("declared_scope", "")),
            "raw_expected_side_effects": raw_effects,
        }
    )

    return ChannelEnvelope(
        channel_type=ChannelType(str(raw_envelope["channel_type"])),
        source_id=str(raw_envelope["source_id"]),
        content=content,
        branch_id=str(raw_envelope.get("branch_id") or f"external::{raw_case['case_id']}"),
        envelope_id=str(raw_envelope.get("envelope_id") or f"{raw_case['case_id']}::{index}"),
        parent_event_id=str(
            raw_envelope.get("parent_event_id") or f"external_parent::{raw_case['case_id']}"
        ),
        user_request_id=str(
            raw_envelope.get("user_request_id") or f"external_user::{raw_case['case_id']}"
        ),
        metadata=metadata,
    )


def _normalize_declared_scope(
    raw_scope: str,
    *,
    content: str,
    raw_effects: Sequence[str],
    normalized_effects: Sequence[str],
) -> str:
    text = " ".join((raw_scope, content, " ".join(raw_effects))).lower()
    effects = set(normalized_effects)

    if (
        SideEffect.PRIVILEGE.value in effects
        or "admin" in text
        or "root" in text
        or "permission" in text
        or "authorize" in text
    ):
        return DeclaredScope.ADMIN.value

    if (
        SideEffect.NETWORK.value in effects
        or "network" in text
        or "http://" in text
        or "https://" in text
        or "post " in text
    ):
        return DeclaredScope.EXTERNAL_IO.value

    if SideEffect.ENV_CHANGE.value in effects:
        return DeclaredScope.ENV_CHANGE.value

    if (
        SideEffect.WRITE.value in effects
        or SideEffect.DELETE.value in effects
        or "write" in text
        or "append" in text
        or "copy" in text
        or "cleanup" in text
    ):
        return DeclaredScope.PROJECT_WRITE.value

    return DeclaredScope.READ_ONLY.value


def _normalize_side_effects(
    raw_effects: Iterable[str],
    *,
    content: str,
    target_paths: Sequence[str],
) -> tuple[str, ...]:
    effects = set()
    text = " ".join((content, " ".join(target_paths), " ".join(raw_effects))).lower()

    for effect in raw_effects:
        token = str(effect).strip().lower()
        if not token or token == "none":
            continue

        if token in {
            "read",
            "file_read",
            "config_load",
            "system_diagnostics",
            "config_read",
            "env_read",
            "network_read",
            "recon",
        }:
            effects.add(SideEffect.READ.value)
        elif token in {
            "write",
            "file_write",
            "file_append",
            "file_copy",
            "config_write",
            "scope_expansion",
            "archive",
            "policy_update",
        }:
            effects.add(SideEffect.WRITE.value)
        elif token in {"delete", "launder", "cleanup"}:
            effects.add(SideEffect.DELETE.value)
        elif token in {
            "network",
            "network_write",
            "network_exfil",
            "external_io",
            "exfil",
            "sync",
        }:
            effects.add(SideEffect.NETWORK.value)
        elif token in {
            "permission_mutation",
            "tool_authorization",
            "capability_laundering",
            "conditional_execution",
        }:
            effects.add(SideEffect.PRIVILEGE.value)
            effects.add(SideEffect.AUDIT_CHANGE.value)
        elif token in {"secret_access"}:
            effects.add(SideEffect.SECRET_ACCESS.value)
        elif token in {"audit_access", "tamper"}:
            effects.add(SideEffect.AUDIT_CHANGE.value)
        elif token in {"env_change"}:
            effects.add(SideEffect.ENV_CHANGE.value)

    if _contains_secret_target(text):
        effects.add(SideEffect.SECRET_ACCESS.value)

    if _contains_audit_target(text) and (
        SideEffect.WRITE.value in effects
        or SideEffect.DELETE.value in effects
        or "tamper" in text
        or "bypass" in text
    ):
        effects.add(SideEffect.AUDIT_CHANGE.value)

    if not effects and ("read" in text or target_paths):
        effects.add(SideEffect.READ.value)

    return tuple(sorted(effects))


def _contains_secret_target(text: str) -> bool:
    return any(
        token in text
        for token in (
            "/opt/secrets",
            "/run/secrets",
            "/etc/secrets",
            "/etc/shadow",
            "/var/secrets",
            "/proc/self/environ",
            ".env",
            ".env.local",
            "id_rsa",
            "secrets",
            "api_key",
            "api_keys",
            "vault_token",
            "database_credentials",
            "credentials",
            "service-account.key",
            "patient-debug",
            "private-ledger",
        )
    )


def _contains_audit_target(text: str) -> bool:
    return any(
        token in text
        for token in (
            "/var/audit",
            "agent_decisions",
            "rejections.jsonl",
            "audit storage",
            "audit_hooks.py",
        )
    )


def _stringify_content(value: Any) -> str:
    if isinstance(value, str):
        return value

    return json.dumps(value, sort_keys=True)


def _registered_actors_for(envelopes: Sequence[ChannelEnvelope]) -> tuple[str, ...]:
    actor_ids = ["agent_coder"]
    for envelope in envelopes:
        if envelope.metadata.get("expect_unknown_actor") is True:
            continue

        if envelope.channel_type in {
            ChannelType.AGENT_PROPOSAL,
            ChannelType.REJECTED_FEEDBACK,
        }:
            actor_ids.append(envelope.source_id)

    return tuple(dict.fromkeys(actor_ids))


if __name__ == "__main__":
    print(f"loaded_external_cases={len(load_external_redteam_cases())}")
