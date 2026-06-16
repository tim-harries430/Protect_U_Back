from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from os import PathLike
from pathlib import Path
from typing import Any

from adapter_wall import ActionDomain, ActionEnvelope, AdapterActionType
from llm_channel import ChannelType
from ot_gate import DeclaredScope, SideEffect


DEFAULT_SOURCE_ADAPTER = "generic"
DEFAULT_ACTOR_ID = "harness_unknown"
DEFAULT_CWD = "."


@dataclass(frozen=True)
class HarnessAdapterDefaults:
    source_adapter: str = DEFAULT_SOURCE_ADAPTER
    actor_id: str = DEFAULT_ACTOR_ID
    cwd: str = DEFAULT_CWD
    channel_type: ChannelType | str = ChannelType.AGENT_PROPOSAL
    action_domain: ActionDomain | str = ActionDomain.GENERAL
    branch_id: str = "harness_branch"
    action_id_prefix: str = "harness_action"
    parent_event_id: str = "harness_parent"
    user_request_id: str = "harness_user_request"
    tool_name: str = ""


def load_harness_payloads(payload: Any) -> tuple[dict[str, Any], ...]:
    """
    Normalize JSON-like harness input into a tuple of event dictionaries.

    Accepts a single event dict, a list of event dicts, a wrapper object with
    common list keys such as cases/events/actions, JSON object/array text, or
    JSONL text. It does not read files or perform any external I/O.
    """

    if isinstance(payload, str):
        return _load_harness_text(payload)

    if isinstance(payload, Mapping):
        data = dict(payload)
        for key in ("cases", "events", "actions", "tool_calls", "items"):
            value = data.get(key)
            if _is_sequence(value):
                return tuple(_require_object(item) for item in value)
        return (data,)

    if _is_sequence(payload):
        return tuple(_require_object(item) for item in payload)

    raise ValueError("harness payload must be a dict, list, JSON string, or JSONL string.")


def load_harness_events(payload: Any) -> tuple[dict[str, Any], ...]:
    """
    Public loader for harness event corpora.

    Accepts the same JSON-like values as load_harness_payloads. If given a
    path-like value, it reads that file as JSON or JSONL. Reading an explicit
    caller-supplied corpus path is the only I/O this adapter performs.
    """

    if isinstance(payload, (Path, PathLike)):
        return _load_harness_text(payload.read_text(encoding="utf-8"))

    if isinstance(payload, str):
        stripped = payload.strip()
        if stripped and not stripped.startswith(("{", "[")) and "\n" not in stripped:
            path = Path(stripped)
            if path.is_file():
                return _load_harness_text(path.read_text(encoding="utf-8"))

    return load_harness_payloads(payload)


def normalize_harness_event(
    event: Mapping[str, Any],
    *,
    index: int = 1,
    defaults: HarnessAdapterDefaults | None = None,
    project_root: str | None = None,
    source_adapter: str | None = None,
) -> ActionEnvelope:
    """
    Normalize one raw harness/tool event into an ActionEnvelope.

    The returned envelope is testimony only. ActionEnvelope keeps can_execute
    and can_grant_permission false.
    """

    defaults = defaults or HarnessAdapterDefaults()
    payload = _event_payload(event)
    metadata = _object(payload.get("metadata"))
    arguments = _first_object(
        payload.get("arguments"),
        payload.get("args"),
        payload.get("parameters"),
        payload.get("input"),
    )
    context = _first_object(payload.get("context"), metadata.get("context"))

    action_id = _first_text(
        payload.get("action_id"),
        payload.get("event_id"),
        payload.get("id"),
        payload.get("case_id"),
        payload.get("tool_call_id"),
        metadata.get("action_id"),
        default=f"{defaults.action_id_prefix}_{index:04d}",
    )
    command_text = _command_text(payload, metadata, arguments)
    if not command_text.strip():
        raise ValueError(f"{action_id}: command/content text must be non-empty.")

    raw_effects = _sequence(
        _first_present(
            payload.get("expected_side_effects"),
            payload.get("side_effects"),
            metadata.get("expected_side_effects"),
            arguments.get("expected_side_effects"),
            default=(),
        )
    )
    effects = side_effects_from_aliases(raw_effects)
    action_type = infer_action_type(
        _first_present(payload.get("action_type"), metadata.get("action_type")),
        tool_name=_tool_name(payload, metadata, arguments, defaults),
        effects=effects,
        command_text=command_text,
    )
    declared_scope = infer_declared_scope(
        _first_present(
            payload.get("declared_scope"),
            payload.get("scope"),
            metadata.get("declared_scope"),
            arguments.get("declared_scope"),
        ),
        effects=effects,
        action_type=action_type,
    )
    target_paths = extract_target_paths(payload)
    action_domain = infer_action_domain(
        _first_present(
            payload.get("action_domain"),
            metadata.get("action_domain"),
            arguments.get("action_domain"),
        ),
        declared_scope=declared_scope,
        effects=effects,
        command_text=command_text,
        target_paths=target_paths,
        action_type=action_type,
        default=defaults.action_domain,
    )
    adapter_label = _first_text(
        payload.get("source_adapter"),
        payload.get("adapter"),
        payload.get("source"),
        metadata.get("source_adapter"),
        default=source_adapter or defaults.source_adapter,
    )

    return ActionEnvelope(
        actor_id=_actor_id(payload, metadata, context, defaults),
        action_type=action_type,
        action_domain=action_domain,
        channel_type=_channel_type(
            _first_present(payload.get("channel_type"), metadata.get("channel_type")),
            defaults.channel_type,
        ),
        command_text=command_text,
        cwd=_cwd(payload, metadata, arguments, context, project_root, defaults),
        target_paths=target_paths,
        expected_side_effects=effects,
        declared_scope=declared_scope,
        source_adapter=adapter_label,
        tool_name=_tool_name(payload, metadata, arguments, defaults),
        raw_payload=_raw_payload_with_evidence(payload, action_domain=action_domain),
        branch_id=_first_text(
            payload.get("branch_id"),
            payload.get("session_id"),
            metadata.get("branch_id"),
            context.get("branch_id"),
            default=defaults.branch_id,
        ),
        action_id=action_id,
        parent_event_id=_first_text(
            payload.get("parent_event_id"),
            metadata.get("parent_event_id"),
            context.get("parent_event_id"),
            default=defaults.parent_event_id,
        ),
        user_request_id=_first_text(
            payload.get("user_request_id"),
            payload.get("request_id"),
            metadata.get("user_request_id"),
            context.get("user_request_id"),
            default=defaults.user_request_id,
        ),
    )


def normalize_harness_events(
    payload: Any,
    *,
    defaults: HarnessAdapterDefaults | None = None,
    project_root: str | None = None,
    source_adapter: str | None = None,
) -> tuple[ActionEnvelope, ...]:
    events = load_harness_events(payload)
    return tuple(
        normalize_harness_event(
            event,
            index=index,
            defaults=defaults,
            project_root=project_root,
            source_adapter=source_adapter,
        )
        for index, event in enumerate(events, start=1)
    )


def side_effects_from_aliases(values: Any) -> set[SideEffect]:
    effects: set[SideEffect] = set()
    for value in _sequence(values):
        text = str(value).strip().lower().replace("-", "_")
        if not text or text == "none":
            continue
        effect = side_effect_alias(text)
        if effect is not None:
            effects.add(effect)
    return effects


def side_effect_alias(value: Any) -> SideEffect | None:
    text = str(value).strip().lower().replace("-", "_")
    aliases = {
        "read": SideEffect.READ,
        "file_read": SideEffect.READ,
        "read_file": SideEffect.READ,
        "filesystem_read": SideEffect.READ,
        "write": SideEffect.WRITE,
        "file_write": SideEffect.WRITE,
        "write_file": SideEffect.WRITE,
        "append": SideEffect.WRITE,
        "file_append": SideEffect.WRITE,
        "copy": SideEffect.WRITE,
        "file_copy": SideEffect.WRITE,
        "create": SideEffect.WRITE,
        "delete": SideEffect.DELETE,
        "remove": SideEffect.DELETE,
        "unlink": SideEffect.DELETE,
        "rm": SideEffect.DELETE,
        "env": SideEffect.ENV_CHANGE,
        "env_change": SideEffect.ENV_CHANGE,
        "environment": SideEffect.ENV_CHANGE,
        "install": SideEffect.ENV_CHANGE,
        "network": SideEffect.NETWORK,
        "http": SideEffect.NETWORK,
        "https": SideEffect.NETWORK,
        "network_write": SideEffect.NETWORK,
        "network_exfil": SideEffect.NETWORK,
        "external_io": SideEffect.NETWORK,
        "privilege": SideEffect.PRIVILEGE,
        "permission": SideEffect.PRIVILEGE,
        "permission_mutation": SideEffect.PRIVILEGE,
        "scope_expansion": SideEffect.PRIVILEGE,
        "secret": SideEffect.SECRET_ACCESS,
        "secret_access": SideEffect.SECRET_ACCESS,
        "credential": SideEffect.SECRET_ACCESS,
        "audit": SideEffect.AUDIT_CHANGE,
        "audit_change": SideEffect.AUDIT_CHANGE,
        "audit_access": SideEffect.AUDIT_CHANGE,
        "registry": SideEffect.AUDIT_CHANGE,
        "tamper": SideEffect.AUDIT_CHANGE,
    }
    return aliases.get(text)


def infer_action_type(
    value: Any = None,
    *,
    tool_name: str = "",
    effects: set[SideEffect] | None = None,
    command_text: str = "",
) -> AdapterActionType:
    effects = effects or set()
    direct = {
        "file_read": AdapterActionType.FILE_READ,
        "read": AdapterActionType.FILE_READ,
        "read_file": AdapterActionType.FILE_READ,
        "file_write": AdapterActionType.FILE_WRITE,
        "write": AdapterActionType.FILE_WRITE,
        "write_file": AdapterActionType.FILE_WRITE,
        "file_append": AdapterActionType.FILE_WRITE,
        "file_copy": AdapterActionType.FILE_WRITE,
        "file_delete": AdapterActionType.FILE_DELETE,
        "delete": AdapterActionType.FILE_DELETE,
        "remove": AdapterActionType.FILE_DELETE,
        "shell": AdapterActionType.SHELL,
        "bash": AdapterActionType.SHELL,
        "powershell": AdapterActionType.SHELL,
        "terminal": AdapterActionType.SHELL,
        "network": AdapterActionType.NETWORK,
        "http": AdapterActionType.NETWORK,
        "request": AdapterActionType.NETWORK,
        "registry": AdapterActionType.REGISTRY,
        "audit": AdapterActionType.REGISTRY,
    }
    for candidate in (value, tool_name):
        text = str(candidate or "").strip().lower().replace("-", "_")
        if text in direct:
            return direct[text]

    content = command_text.lower()
    if SideEffect.DELETE in effects or any(token in content for token in ("remove-item", "rm -", "delete", "unlink")):
        return AdapterActionType.FILE_DELETE
    if SideEffect.NETWORK in effects or "http://" in content or "https://" in content:
        return AdapterActionType.NETWORK
    if SideEffect.AUDIT_CHANGE in effects or SideEffect.PRIVILEGE in effects:
        return AdapterActionType.REGISTRY
    if SideEffect.WRITE in effects:
        return AdapterActionType.FILE_WRITE
    if SideEffect.READ in effects and tool_name.lower() in {"read", "file_read", "read_file"}:
        return AdapterActionType.FILE_READ
    return AdapterActionType.SHELL


def infer_declared_scope(
    value: Any = None,
    *,
    effects: set[SideEffect] | None = None,
    action_type: AdapterActionType = AdapterActionType.SHELL,
) -> DeclaredScope:
    effects = effects or set()
    text = str(value or "").strip().lower().replace("-", "_")
    direct = {
        "read_only": DeclaredScope.READ_ONLY,
        "readonly": DeclaredScope.READ_ONLY,
        "file_read": DeclaredScope.READ_ONLY,
        "config_load": DeclaredScope.READ_ONLY,
        "project_write": DeclaredScope.PROJECT_WRITE,
        "workspace_write": DeclaredScope.PROJECT_WRITE,
        "file_write": DeclaredScope.PROJECT_WRITE,
        "file_append": DeclaredScope.PROJECT_WRITE,
        "file_copy": DeclaredScope.PROJECT_WRITE,
        "file_delete": DeclaredScope.PROJECT_WRITE,
        "env_change": DeclaredScope.ENV_CHANGE,
        "environment": DeclaredScope.ENV_CHANGE,
        "system_maintenance": DeclaredScope.ENV_CHANGE,
        "external_io": DeclaredScope.EXTERNAL_IO,
        "network": DeclaredScope.EXTERNAL_IO,
        "network_health_check": DeclaredScope.EXTERNAL_IO,
        "diagnostics": DeclaredScope.EXTERNAL_IO,
        "admin": DeclaredScope.ADMIN,
        "permission_request": DeclaredScope.ADMIN,
        "tool_authorization": DeclaredScope.ADMIN,
    }
    if text in direct:
        return direct[text]
    if SideEffect.PRIVILEGE in effects or SideEffect.AUDIT_CHANGE in effects:
        return DeclaredScope.ADMIN
    if SideEffect.NETWORK in effects:
        return DeclaredScope.EXTERNAL_IO
    if SideEffect.ENV_CHANGE in effects:
        return DeclaredScope.ENV_CHANGE
    if action_type in {AdapterActionType.FILE_WRITE, AdapterActionType.FILE_DELETE}:
        return DeclaredScope.PROJECT_WRITE
    return DeclaredScope.READ_ONLY


def infer_action_domain(
    value: Any = None,
    *,
    declared_scope: DeclaredScope = DeclaredScope.READ_ONLY,
    effects: set[SideEffect] | None = None,
    command_text: str = "",
    target_paths: Sequence[str] = (),
    action_type: AdapterActionType = AdapterActionType.SHELL,
    default: ActionDomain | str = ActionDomain.GENERAL,
) -> ActionDomain:
    explicit = action_domain_alias(value)
    if explicit is not None:
        return explicit

    effects = effects or set()
    scope_text = declared_scope.value if isinstance(declared_scope, DeclaredScope) else str(declared_scope)
    target_text = " ".join(str(path) for path in target_paths)
    effect_text = " ".join(effect.value for effect in effects)
    audit_text = " ".join((scope_text, target_text, effect_text, command_text)).lower()

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
    return action_domain_alias(default) or ActionDomain.GENERAL


def action_domain_alias(value: Any) -> ActionDomain | None:
    if value is None:
        return None
    if isinstance(value, ActionDomain):
        return value
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


def extract_target_paths(event: Mapping[str, Any]) -> tuple[str, ...]:
    event = _event_payload(event)
    metadata = _object(event.get("metadata"))
    arguments = _first_object(
        event.get("arguments"),
        event.get("args"),
        event.get("parameters"),
        event.get("input"),
    )
    values: list[Any] = []
    for source in (event, metadata, arguments):
        for key in (
            "target_paths",
            "target_path",
            "path",
            "paths",
            "file",
            "files",
            "filepath",
            "file_path",
            "cwd_targets",
        ):
            values.extend(_sequence(source.get(key)))
    return tuple(dict.fromkeys(str(value) for value in values if str(value).strip()))


def _load_harness_text(text: str) -> tuple[dict[str, Any], ...]:
    stripped = text.strip()
    if not stripped:
        return ()
    try:
        return load_harness_payloads(json.loads(stripped))
    except json.JSONDecodeError:
        events = []
        for line in stripped.splitlines():
            if line.strip():
                events.append(_require_object(json.loads(line)))
        return tuple(events)


def _event_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(event)
    nested = _first_object(
        payload.get("action"),
        payload.get("event"),
        payload.get("tool_call"),
        payload.get("tool_event"),
    )
    if not nested:
        return payload

    merged = dict(nested)
    for key in (
        "case_id",
        "description",
        "should_stop",
        "source_adapter",
        "branch_id",
        "parent_event_id",
        "user_request_id",
        "channel_type",
    ):
        if key in payload and key not in merged:
            merged[key] = payload[key]
    if "metadata" in payload and "metadata" in merged:
        merged["metadata"] = {**_object(payload["metadata"]), **_object(merged["metadata"])}
    elif "metadata" in payload:
        merged["metadata"] = payload["metadata"]
    return merged


def _command_text(
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any],
    arguments: Mapping[str, Any],
) -> str:
    value = _first_present(
        payload.get("command_text"),
        payload.get("command"),
        payload.get("content"),
        payload.get("proposal"),
        payload.get("description"),
        payload.get("text"),
        metadata.get("command_text"),
        metadata.get("content"),
        arguments.get("command"),
        arguments.get("cmd"),
        arguments.get("query"),
        arguments.get("url"),
        arguments.get("path"),
        arguments.get("file_path"),
        default="",
    )
    if isinstance(value, (Mapping, list, tuple)):
        return json.dumps(_jsonable(value), sort_keys=True)
    return str(value)


def _raw_payload_with_evidence(
    payload: Mapping[str, Any],
    *,
    action_domain: ActionDomain,
) -> dict[str, Any]:
    raw = dict(payload)
    metadata = _object(raw.get("metadata"))
    metadata["action_domain"] = action_domain.value
    raw["metadata"] = metadata
    raw["normalized_action_domain"] = action_domain.value
    sandbox = _first_present(
        raw.get("sandbox"),
        raw.get("sandbox_evidence"),
        metadata.get("sandbox"),
        metadata.get("sandbox_evidence"),
        default=None,
    )
    gateway = _first_present(
        raw.get("gateway"),
        raw.get("gateway_evidence"),
        raw.get("permission_gateway"),
        metadata.get("gateway"),
        metadata.get("gateway_evidence"),
        metadata.get("permission_gateway"),
        default=None,
    )
    raw["harness_adapter"] = {
        "sandbox_evidence": _jsonable(sandbox),
        "gateway_evidence": _jsonable(gateway),
        "contract": "testimony_only_no_io_commit",
    }
    return raw


def _actor_id(
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any],
    context: Mapping[str, Any],
    defaults: HarnessAdapterDefaults,
) -> str:
    return _first_text(
        payload.get("actor_id"),
        payload.get("source_id"),
        payload.get("agent_id"),
        payload.get("model"),
        metadata.get("actor_id"),
        metadata.get("source_id"),
        context.get("actor_id"),
        context.get("agent_id"),
        default=defaults.actor_id,
    )


def _tool_name(
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any],
    arguments: Mapping[str, Any],
    defaults: HarnessAdapterDefaults,
) -> str:
    return _first_text(
        payload.get("tool_name"),
        payload.get("tool"),
        payload.get("name"),
        metadata.get("tool_name"),
        arguments.get("tool_name"),
        default=defaults.tool_name,
    )


def _cwd(
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any],
    arguments: Mapping[str, Any],
    context: Mapping[str, Any],
    project_root: str | None,
    defaults: HarnessAdapterDefaults,
) -> str:
    return _first_text(
        payload.get("cwd"),
        metadata.get("cwd"),
        arguments.get("cwd"),
        context.get("cwd"),
        default=project_root or defaults.cwd,
    )


def _channel_type(value: Any, default: ChannelType | str) -> ChannelType:
    if value is None or not str(value).strip():
        value = default
    if isinstance(value, ChannelType):
        return value
    return ChannelType(str(value).strip().upper())


def _contains_any(text: str, needles: Sequence[str]) -> bool:
    return any(needle in text for needle in needles)


def _first_present(*values: Any, default: Any = None) -> Any:
    for value in values:
        if value is not None:
            return value
    return default


def _first_text(*values: Any, default: str) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return default


def _first_object(*values: Any) -> dict[str, Any]:
    for value in values:
        if isinstance(value, Mapping):
            return dict(value)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, Mapping):
                return dict(parsed)
    return {}


def _object(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (value,)
    if isinstance(value, set):
        return tuple(value)
    if _is_sequence(value):
        return tuple(value)
    return (value,)


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _require_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("harness payload entries must be JSON objects.")
    return dict(value)


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


__all__ = (
    "HarnessAdapterDefaults",
    "load_harness_events",
    "load_harness_payloads",
    "normalize_harness_event",
    "normalize_harness_events",
    "side_effect_alias",
    "side_effects_from_aliases",
    "infer_action_type",
    "infer_declared_scope",
    "extract_target_paths",
)
