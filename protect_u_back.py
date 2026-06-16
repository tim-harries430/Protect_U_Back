from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Sequence

from adapter_wall import ActionDomain, ActionEnvelope, AdapterActionType
from harness_adapter import normalize_harness_event
from llm_channel import ChannelType
from ot_gate import DeclaredScope, SideEffect
from parallel_audit import EvidenceDisposition
from phi_registry import ActorType, PhiRegistry
from protect_scan import (
    ProtectSurface,
    build_startup_notice,
    confirm_protect_scan,
    default_protect_scan_profile,
)
from xray_review import audit_with_xray_review


PRODUCT_NAME = "Protect U Back"
INTERFACE_VERSION = "agent_interface_v0"


@dataclass(frozen=True)
class AgentCase:
    case_id: str
    description: str
    should_stop: bool | None
    action: ActionEnvelope
    channel_type: ChannelType


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "doctor":
        return _emit(_doctor(args))

    if args.command == "schema":
        return _emit(_schema(args))

    if args.command == "smoke":
        return _emit(_smoke(args))

    if args.command == "agent-audit":
        return _emit(_agent_audit(args), output_path=args.output)

    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protect_u_back.py",
        description="Protect U Back launcher and dry-run agent audit interface.",
    )
    parser.add_argument(
        "--project-root",
        default=str(Path.cwd()),
        help="Project root used for path/capability/protect audit.",
    )

    subparsers = parser.add_subparsers(dest="command")

    doctor = subparsers.add_parser("doctor", help="Check imports and launcher wiring.")
    _add_project_root_override(doctor)

    schema = subparsers.add_parser("schema", help="Print the agent-audit input schema.")
    _add_project_root_override(schema)

    smoke = subparsers.add_parser("smoke", help="Run one local dry-run audit.")
    _add_project_root_override(smoke)
    smoke.add_argument(
        "--confirm-protect",
        action="store_true",
        help="Confirm metadata-only Protect Scan for the smoke run.",
    )

    agent = subparsers.add_parser(
        "agent-audit",
        help="Audit one agent proposal file, JSON array, or JSONL corpus.",
    )
    _add_project_root_override(agent)
    agent.add_argument("--input", required=True, help="JSON, JSONL, or '-' for stdin.")
    agent.add_argument("--output", help="Optional JSON output path.")
    agent.add_argument(
        "--input-format",
        choices=("auto", "agent", "harness"),
        default="auto",
        help="Input normalizer. auto accepts both Protect U Back and harness-style events.",
    )
    agent.add_argument(
        "--confirm-protect",
        action="store_true",
        help="Confirm metadata-only Protect Scan before running evidence bundle.",
    )
    agent.add_argument(
        "--strict-registry",
        action="store_true",
        help="Do not auto-register sources from the input corpus.",
    )
    agent.add_argument(
        "--registered-actor",
        action="append",
        default=[],
        help="Actor id allowed through Registry Admission. Repeatable.",
    )
    agent.add_argument(
        "--optional-surface",
        action="append",
        default=[],
        choices=[surface.value for surface in ProtectSurface],
        help="Optional Protect Scan surface to enable. Repeatable.",
    )
    agent.add_argument(
        "--custom-path",
        action="append",
        default=[],
        help="Extra metadata-only protected path. Repeatable.",
    )
    agent.add_argument(
        "--source-adapter",
        default="dirty_test",
        help="Adapter label stamped into ActionEnvelope testimony.",
    )

    return parser


def _add_project_root_override(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--project-root",
        default=argparse.SUPPRESS,
        help="Project root used for path/capability/protect audit.",
    )


def _doctor(args: argparse.Namespace) -> Dict[str, Any]:
    project_root = str(Path(args.project_root).resolve(strict=False))
    return {
        "product": PRODUCT_NAME,
        "interface_version": INTERFACE_VERSION,
        "status": "OK",
        "project_root": project_root,
        "modules": {
            "adapter_wall": "OK",
            "harness_adapter": "OK",
            "parallel_audit": "OK",
            "phi_registry": "OK",
            "protect_scan": "OK",
        },
        "commands": ("doctor", "schema", "smoke", "agent-audit"),
        "schema": _interface_schema(summary_only=True),
        "io_executed": False,
        "can_execute": False,
        "can_grant_permission": False,
    }


def _schema(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "product": PRODUCT_NAME,
        "interface_version": INTERFACE_VERSION,
        "mode": "schema",
        "project_root": str(Path(args.project_root).resolve(strict=False)),
        "schema": _interface_schema(summary_only=False),
        "io_executed": False,
        "can_execute": False,
        "can_grant_permission": False,
    }


def _smoke(args: argparse.Namespace) -> Dict[str, Any]:
    project_root = str(Path(args.project_root).resolve(strict=False))
    action = ActionEnvelope(
        actor_id="agent_smoke",
        action_type=AdapterActionType.SHELL,
        channel_type=ChannelType.AGENT_PROPOSAL,
        command_text="git status --short",
        cwd=project_root,
        target_paths=(),
        expected_side_effects={SideEffect.READ},
        declared_scope=DeclaredScope.READ_ONLY,
        source_adapter="launcher_smoke",
        tool_name="shell",
        branch_id="smoke_branch",
        action_id="smoke_action",
        parent_event_id="smoke_parent",
        user_request_id="smoke_user_request",
    )
    registry = PhiRegistry()
    registry.register_actor("agent_smoke", ActorType.AGENT)
    profile = _protect_profile(
        project_root,
        confirmed=bool(args.confirm_protect),
        optional_surfaces=(),
        custom_paths=(),
    )
    decision = audit_with_xray_review(
        action,
        registry=registry,
        project_root=project_root,
        protect_profile=profile,
    )
    return {
        "product": PRODUCT_NAME,
        "interface_version": INTERFACE_VERSION,
        "mode": "smoke",
        "profile_notice": build_startup_notice(profile).to_dict(),
        "action": action.to_dict(),
        "decision": decision.to_dict(),
        "allowed_to_execute": False,
        "io_executed": False,
    }


def _agent_audit(args: argparse.Namespace) -> Dict[str, Any]:
    project_root = str(Path(args.project_root).resolve(strict=False))
    raw_cases = load_agent_payloads(args.input)
    cases = [
        normalize_input_case(
            payload,
            project_root=project_root,
            source_adapter=args.source_adapter,
            index=index,
            input_format=args.input_format,
        )
        for index, payload in enumerate(raw_cases, start=1)
    ]
    profile = _protect_profile(
        project_root,
        confirmed=bool(args.confirm_protect),
        optional_surfaces=args.optional_surface,
        custom_paths=args.custom_path,
    )
    registry = _build_registry(
        cases,
        strict=bool(args.strict_registry),
        registered_actor_ids=tuple(args.registered_actor),
    )

    results = []
    summary: Dict[str, int] = {}
    expectation_passed = 0
    expectation_checked = 0

    for case in cases:
        decision = audit_with_xray_review(
            case.action,
            registry=registry,
            project_root=project_root,
            protect_profile=profile,
        )
        stopped = decision.disposition != EvidenceDisposition.PASS
        matched_expectation = None
        if case.should_stop is not None:
            expectation_checked += 1
            matched_expectation = stopped == case.should_stop
            if matched_expectation:
                expectation_passed += 1

        summary[decision.disposition.value] = summary.get(decision.disposition.value, 0) + 1
        results.append(
            {
                "case_id": case.case_id,
                "description": case.description,
                "should_stop": case.should_stop,
                "stopped": stopped,
                "matched_expectation": matched_expectation,
                "action": case.action.to_dict(),
                "decision": decision.to_dict(),
                "allowed_to_execute": False,
                "io_executed": False,
                "can_execute": False,
                "can_grant_permission": False,
            }
        )

    return {
        "product": PRODUCT_NAME,
        "interface_version": INTERFACE_VERSION,
        "mode": "agent-audit",
        "project_root": project_root,
        "case_count": len(cases),
        "summary": dict(sorted(summary.items())),
        "expectation_checked": expectation_checked,
        "expectation_passed": expectation_passed,
        "profile_notice": build_startup_notice(profile).to_dict(),
        "registered_actors": tuple(registry.actor_ids()),
        "results": tuple(results),
        "allowed_to_execute": False,
        "io_executed": False,
    }


def _interface_schema(*, summary_only: bool) -> Dict[str, Any]:
    schema = {
        "input_shapes": (
            "single JSON object",
            "JSON array of objects",
            "JSON object with cases[]",
            "JSONL",
            "stdin via --input -",
        ),
        "required_fields": ("content or command_text or proposal or description",),
        "recommended_fields": (
            "case_id",
            "channel_type",
            "action_domain",
            "source_id or actor_id",
            "metadata.declared_scope",
            "metadata.target_paths",
            "metadata.expected_side_effects",
        ),
        "channel_type": tuple(channel.value for channel in ChannelType),
        "action_domain": tuple(domain.value for domain in ActionDomain),
        "action_domain_compatibility": (
            "Top-level action_domain is accepted.",
            "metadata.action_domain is accepted.",
            "Explicit action_domain wins; otherwise a lightweight inference is used.",
            "Normalized action_domain is written back into metadata.action_domain testimony.",
        ),
    }
    if summary_only:
        return schema

    schema["example"] = {
        "case_id": "EXAMPLE-001",
        "channel_type": "AGENT_PROPOSAL",
        "action_domain": "SYSTEM_REMEDIATION",
        "source_id": "agent_core",
        "content": "Run a malware diagnostic plan without executing tools.",
        "metadata": {
            "action_domain": "SYSTEM_REMEDIATION",
            "declared_scope": "system_maintenance",
            "target_paths": ["/system/processes"],
            "expected_side_effects": ["read", "env_change"],
            "can_execute": False,
            "can_grant_permission": False,
            "from_rejected_state": False,
        },
    }
    return schema


def load_agent_payloads(input_path: str) -> Sequence[Dict[str, Any]]:
    if input_path == "-":
        text = sys.stdin.read()
        source_name = "stdin"
    else:
        source = Path(input_path)
        text = source.read_text(encoding="utf-8")
        source_name = source.name.lower()

    stripped = text.strip()
    if not stripped:
        return ()

    if source_name.endswith(".jsonl"):
        return tuple(json.loads(line) for line in stripped.splitlines() if line.strip())

    payload = json.loads(stripped)
    if isinstance(payload, list):
        return tuple(_require_object(item) for item in payload)

    if isinstance(payload, dict) and isinstance(payload.get("cases"), list):
        return tuple(_require_object(item) for item in payload["cases"])

    return (_require_object(payload),)


def normalize_input_case(
    payload: Dict[str, Any],
    *,
    project_root: str,
    source_adapter: str,
    index: int,
    input_format: str = "auto",
) -> AgentCase:
    normalized_format = str(input_format or "auto").strip().lower()
    if normalized_format not in {"auto", "agent", "harness"}:
        raise ValueError(f"unsupported input_format: {input_format}")

    if normalized_format == "agent":
        return normalize_agent_case(
            payload,
            project_root=project_root,
            source_adapter=source_adapter,
            index=index,
        )

    if normalized_format == "harness":
        return normalize_harness_case(
            payload,
            project_root=project_root,
            source_adapter=source_adapter,
            index=index,
        )

    if _looks_like_harness_payload(payload):
        try:
            return normalize_harness_case(
                payload,
                project_root=project_root,
                source_adapter=source_adapter,
                index=index,
            )
        except ValueError:
            return normalize_agent_case(
                payload,
                project_root=project_root,
                source_adapter=source_adapter,
                index=index,
            )

    try:
        return normalize_agent_case(
            payload,
            project_root=project_root,
            source_adapter=source_adapter,
            index=index,
        )
    except ValueError:
        return normalize_harness_case(
            payload,
            project_root=project_root,
            source_adapter=source_adapter,
            index=index,
        )


def normalize_agent_case(
    payload: Dict[str, Any],
    *,
    project_root: str,
    source_adapter: str,
    index: int,
) -> AgentCase:
    metadata = _object(payload.get("metadata"))
    case_id = str(payload.get("case_id") or payload.get("id") or f"case_{index:04d}")
    channel_type = _channel_type(payload.get("channel_type"))
    actor_id = str(
        payload.get("actor_id")
        or payload.get("source_id")
        or metadata.get("source_id")
        or "agent_unknown"
    )
    content = str(
        payload.get("content")
        or payload.get("command_text")
        or payload.get("proposal")
        or payload.get("description")
        or ""
    ).strip()
    if not content:
        raise ValueError(f"{case_id}: content/command_text must be non-empty.")

    target_paths = _sequence(payload.get("target_paths", metadata.get("target_paths", ())))
    raw_effects = _sequence(
        payload.get("expected_side_effects", metadata.get("expected_side_effects", ()))
    )
    effects = _side_effects(raw_effects)
    action_type = _action_type(
        payload.get("action_type"),
        metadata.get("declared_scope"),
        effects,
        content,
    )
    action_domain = _action_domain(
        payload.get("action_domain", metadata.get("action_domain")),
        metadata.get("declared_scope"),
        effects,
        content,
        target_paths,
        action_type,
    )
    declared_scope = _declared_scope(
        payload.get("declared_scope", metadata.get("declared_scope")),
        effects,
        action_type,
    )
    raw_payload = dict(payload)
    raw_metadata = _object(raw_payload.get("metadata"))
    raw_metadata["action_domain"] = action_domain.value
    raw_payload["metadata"] = raw_metadata
    raw_payload["normalized_action_domain"] = action_domain.value
    raw_payload["normalized_unknown_side_effects"] = tuple(_unknown_side_effects(raw_effects))

    action = ActionEnvelope(
        actor_id=actor_id,
        action_type=action_type,
        action_domain=action_domain,
        channel_type=channel_type,
        command_text=content,
        cwd=str(payload.get("cwd") or metadata.get("cwd") or project_root),
        target_paths=target_paths,
        expected_side_effects=effects,
        declared_scope=declared_scope,
        source_adapter=str(payload.get("source_adapter") or source_adapter),
        tool_name=str(payload.get("tool_name") or metadata.get("tool_name") or ""),
        raw_payload=raw_payload,
        branch_id=str(payload.get("branch_id") or metadata.get("branch_id") or f"{case_id}:branch"),
        action_id=str(payload.get("action_id") or metadata.get("action_id") or case_id),
        parent_event_id=str(
            payload.get("parent_event_id")
            or metadata.get("parent_event_id")
            or f"{case_id}:parent"
        ),
        user_request_id=str(
            payload.get("user_request_id")
            or metadata.get("user_request_id")
            or f"{case_id}:user_request"
        ),
    )
    should_stop = payload.get("should_stop")
    return AgentCase(
        case_id=case_id,
        description=str(payload.get("description") or ""),
        should_stop=bool(should_stop) if should_stop is not None else None,
        action=action,
        channel_type=channel_type,
    )


def normalize_harness_case(
    payload: Dict[str, Any],
    *,
    project_root: str,
    source_adapter: str,
    index: int,
) -> AgentCase:
    action = normalize_harness_event(
        payload,
        index=index,
        project_root=project_root,
        source_adapter=source_adapter,
    )
    metadata = _object(payload.get("metadata"))
    case_id = str(
        payload.get("case_id")
        or payload.get("id")
        or payload.get("event_id")
        or payload.get("tool_call_id")
        or metadata.get("case_id")
        or action.action_id
        or f"case_{index:04d}"
    )
    should_stop = payload.get("should_stop")
    return AgentCase(
        case_id=case_id,
        description=str(payload.get("description") or metadata.get("description") or ""),
        should_stop=bool(should_stop) if should_stop is not None else None,
        action=action,
        channel_type=action.channel_type,
    )


def _looks_like_harness_payload(payload: Dict[str, Any]) -> bool:
    if any(key in payload for key in ("payload", "arguments", "args", "parameters", "input")):
        return True
    if any(key in payload for key in ("action", "event", "tool_call", "tool_event")):
        return True
    if any(key in payload for key in ("tool", "tool_name", "name")) and not any(
        key in payload for key in ("content", "command_text", "proposal")
    ):
        return True
    return False


def _build_registry(
    cases: Sequence[AgentCase],
    *,
    strict: bool,
    registered_actor_ids: Sequence[str],
) -> PhiRegistry:
    registry = PhiRegistry()
    for actor_id in registered_actor_ids:
        _register_once(registry, actor_id, ActorType.AGENT)

    if strict:
        return registry

    for case in cases:
        _register_once(registry, case.action.actor_id, _actor_type(case.channel_type))

    return registry


def _protect_profile(
    project_root: str,
    *,
    confirmed: bool,
    optional_surfaces: Iterable[str],
    custom_paths: Sequence[str],
):
    profile = default_protect_scan_profile(
        project_root,
        optional_surfaces=tuple(optional_surfaces),
        custom_paths=tuple(custom_paths),
    )
    return confirm_protect_scan(profile, confirmed=confirmed)


def _register_once(registry: PhiRegistry, actor_id: str, actor_type: ActorType) -> None:
    if registry.get_actor(actor_id) is None:
        registry.register_actor(actor_id, actor_type)


def _actor_type(channel_type: ChannelType) -> ActorType:
    if channel_type == ChannelType.USER_REQUEST:
        return ActorType.USER
    if channel_type == ChannelType.TOOL_METADATA:
        return ActorType.TOOL
    return ActorType.AGENT


def _channel_type(value: object) -> ChannelType:
    if value is None:
        return ChannelType.AGENT_PROPOSAL
    text = str(value).strip()
    if not text:
        return ChannelType.AGENT_PROPOSAL
    return ChannelType(text.upper())


def _action_type(
    value: object,
    declared_scope: object,
    effects: set[SideEffect],
    content: str,
) -> AdapterActionType:
    if value:
        text = str(value).strip().lower()
        direct = {
            "file_read": AdapterActionType.FILE_READ,
            "file_write": AdapterActionType.FILE_WRITE,
            "file_append": AdapterActionType.FILE_WRITE,
            "file_copy": AdapterActionType.FILE_WRITE,
            "file_delete": AdapterActionType.FILE_DELETE,
            "shell": AdapterActionType.SHELL,
            "network": AdapterActionType.NETWORK,
            "registry": AdapterActionType.REGISTRY,
        }
        if text in direct:
            return direct[text]

    scope_text = str(declared_scope or "").strip().lower()
    content_text = content.lower()
    if SideEffect.DELETE in effects or "delete" in content_text or "rm -rf" in content_text:
        return AdapterActionType.FILE_DELETE
    if SideEffect.NETWORK in effects or "http://" in content_text or "https://" in content_text:
        return AdapterActionType.NETWORK
    if SideEffect.WRITE in effects or scope_text in {"file_write", "config_write", "file_append"}:
        return AdapterActionType.FILE_WRITE
    if SideEffect.READ in effects or scope_text in {"file_read", "config_load"}:
        return AdapterActionType.FILE_READ
    if SideEffect.AUDIT_CHANGE in effects or SideEffect.PRIVILEGE in effects:
        return AdapterActionType.REGISTRY
    return AdapterActionType.SHELL


def _action_domain(
    value: object,
    declared_scope: object,
    effects: set[SideEffect],
    content: str,
    target_paths: Sequence[str],
    action_type: AdapterActionType,
) -> ActionDomain:
    explicit = _action_domain_alias(value)
    if explicit is not None:
        return explicit

    scope_text = str(declared_scope or "").strip().lower()
    target_text = " ".join(str(path) for path in target_paths).lower()
    effect_text = " ".join(effect.value for effect in effects).lower()
    content_text = content.lower()
    audit_text = " ".join((scope_text, target_text, effect_text, content_text))

    if _contains_any(
        audit_text,
        (
            "audit",
            "ledger",
            "registry",
            ".phi",
            "agent_decisions",
            "permission_mutation",
            "scope_expansion",
            "grant_admin",
        ),
    ):
        return ActionDomain.AUDIT_OR_REGISTRY_CONTROL

    if _contains_any(
        audit_text,
        (
            "tool_authorization",
            "permission_request",
            "can_grant_permission",
            "authorize tool",
            "allowed_roles",
            "root-level",
            "admin",
        ),
    ):
        return ActionDomain.TOOL_OR_PERMISSION_AUTHORIZATION

    if _contains_any(
        audit_text,
        (
            "install",
            "setup",
            "configure",
            "configuration",
            "settings",
            "preferences",
            "accessibility",
            "password",
            "account",
            "beginner",
            "novice",
            "software",
        ),
    ):
        return ActionDomain.SYSTEM_CONFIGURATION_SETUP

    if _contains_any(
        audit_text,
        (
            "malware",
            "virus",
            "diagnostic",
            "diagnostics",
            "remediation",
            "quarantine",
            "stabilize",
            "system_maintenance",
            "system_diagnostics",
            "infection",
        ),
    ):
        return ActionDomain.SYSTEM_REMEDIATION

    if SideEffect.NETWORK in effects or _contains_any(
        audit_text,
        ("http://", "https://", "network", "external_io", "post ", "curl "),
    ):
        return ActionDomain.NETWORK_OR_EXTERNAL_IO

    if SideEffect.SECRET_ACCESS in effects or _contains_any(
        audit_text,
        ("api_key", "secret", "credential", ".env", "vault_token", "/etc/shadow"),
    ):
        return ActionDomain.SECRET_HANDLING

    if action_type in {
        AdapterActionType.FILE_READ,
        AdapterActionType.FILE_WRITE,
        AdapterActionType.FILE_DELETE,
    } or effects.intersection({SideEffect.READ, SideEffect.WRITE, SideEffect.DELETE}):
        return ActionDomain.FILE_SYSTEM_MANAGEMENT

    return ActionDomain.GENERAL


def _action_domain_alias(value: object) -> ActionDomain | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    normalized = text.upper().replace("-", "_").replace(" ", "_")
    direct = {domain.value: domain for domain in ActionDomain}
    aliases = {
        "FILE": ActionDomain.FILE_SYSTEM_MANAGEMENT,
        "FILES": ActionDomain.FILE_SYSTEM_MANAGEMENT,
        "FILE_SYSTEM": ActionDomain.FILE_SYSTEM_MANAGEMENT,
        "SYSTEM_REPAIR": ActionDomain.SYSTEM_REMEDIATION,
        "REMEDIATION": ActionDomain.SYSTEM_REMEDIATION,
        "SYSTEM_SETUP": ActionDomain.SYSTEM_CONFIGURATION_SETUP,
        "CONFIGURATION": ActionDomain.SYSTEM_CONFIGURATION_SETUP,
        "NETWORK": ActionDomain.NETWORK_OR_EXTERNAL_IO,
        "EXTERNAL_IO": ActionDomain.NETWORK_OR_EXTERNAL_IO,
        "SECRET": ActionDomain.SECRET_HANDLING,
        "SECRETS": ActionDomain.SECRET_HANDLING,
        "AUDIT": ActionDomain.AUDIT_OR_REGISTRY_CONTROL,
        "REGISTRY": ActionDomain.AUDIT_OR_REGISTRY_CONTROL,
        "PERMISSION": ActionDomain.TOOL_OR_PERMISSION_AUTHORIZATION,
        "TOOL_AUTHORIZATION": ActionDomain.TOOL_OR_PERMISSION_AUTHORIZATION,
    }
    return direct.get(normalized) or aliases.get(normalized)


def _declared_scope(
    value: object,
    effects: set[SideEffect],
    action_type: AdapterActionType,
) -> DeclaredScope:
    text = str(value or "").strip().lower()
    direct = {
        "read_only": DeclaredScope.READ_ONLY,
        "file_read": DeclaredScope.READ_ONLY,
        "config_load": DeclaredScope.READ_ONLY,
        "project_write": DeclaredScope.PROJECT_WRITE,
        "file_write": DeclaredScope.PROJECT_WRITE,
        "file_append": DeclaredScope.PROJECT_WRITE,
        "file_copy": DeclaredScope.PROJECT_WRITE,
        "config_write": DeclaredScope.PROJECT_WRITE,
        "system_maintenance": DeclaredScope.ENV_CHANGE,
        "env_change": DeclaredScope.ENV_CHANGE,
        "external_io": DeclaredScope.EXTERNAL_IO,
        "network_health_check": DeclaredScope.EXTERNAL_IO,
        "diagnostics": DeclaredScope.EXTERNAL_IO,
        "admin": DeclaredScope.ADMIN,
        "permission_request": DeclaredScope.ADMIN,
        "tool_authorization": DeclaredScope.ADMIN,
    }
    if text in direct:
        return direct[text]
    if SideEffect.PRIVILEGE in effects:
        return DeclaredScope.ADMIN
    if SideEffect.NETWORK in effects:
        return DeclaredScope.EXTERNAL_IO
    if SideEffect.ENV_CHANGE in effects:
        return DeclaredScope.ENV_CHANGE
    if action_type in {AdapterActionType.FILE_WRITE, AdapterActionType.FILE_DELETE}:
        return DeclaredScope.PROJECT_WRITE
    return DeclaredScope.READ_ONLY


def _contains_any(text: str, needles: Sequence[str]) -> bool:
    return any(needle in text for needle in needles)


def _side_effects(values: Sequence[object]) -> set[SideEffect]:
    effects: set[SideEffect] = set()
    for value in values:
        text = str(value).strip().lower().replace("-", "_")
        if not text or text == "none":
            continue
        effect = _effect_alias(text)
        if effect is not None:
            effects.add(effect)
    return effects


def _unknown_side_effects(values: Sequence[object]) -> Sequence[str]:
    unknown = []
    for value in values:
        text = str(value).strip().lower().replace("-", "_")
        if text and text != "none" and _effect_alias(text) is None:
            unknown.append(text)
    return tuple(unknown)


def _effect_alias(text: str) -> SideEffect | None:
    aliases = {
        "read": SideEffect.READ,
        "file_read": SideEffect.READ,
        "write": SideEffect.WRITE,
        "file_write": SideEffect.WRITE,
        "append": SideEffect.WRITE,
        "file_append": SideEffect.WRITE,
        "copy": SideEffect.WRITE,
        "file_copy": SideEffect.WRITE,
        "delete": SideEffect.DELETE,
        "remove": SideEffect.DELETE,
        "env_change": SideEffect.ENV_CHANGE,
        "network": SideEffect.NETWORK,
        "network_write": SideEffect.NETWORK,
        "network_exfil": SideEffect.NETWORK,
        "external_io": SideEffect.NETWORK,
        "privilege": SideEffect.PRIVILEGE,
        "permission_mutation": SideEffect.PRIVILEGE,
        "scope_expansion": SideEffect.PRIVILEGE,
        "secret_access": SideEffect.SECRET_ACCESS,
        "audit_change": SideEffect.AUDIT_CHANGE,
        "audit_access": SideEffect.AUDIT_CHANGE,
        "tamper": SideEffect.AUDIT_CHANGE,
    }
    return aliases.get(text)


def _sequence(value: object) -> Sequence[Any]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(value)
    return (value,)


def _object(value: object) -> Dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _require_object(value: object) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("agent audit input must contain JSON objects.")
    return dict(value)


def _emit(payload: Dict[str, Any], *, output_path: str | None = None) -> int:
    text = json.dumps(_jsonable(payload), indent=2, sort_keys=True)
    if output_path:
        Path(output_path).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


if __name__ == "__main__":
    raise SystemExit(main())
