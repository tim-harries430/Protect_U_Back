from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Sequence


BACKUP_SUFFIX = ".protect_u_back.bak"
# Match ALL tools, not an allowlist. An 8-tool allowlist silently leaves every
# tool outside it -- WebFetch, WebSearch, Task subagents, NotebookEdit, and all
# mcp__* tools -- never routed through the hook: a default-allow front door on a
# default-deny gate. "*" fires the hook for every tool; the hook then decides
# per tool (recognized tools are classified, unknown ones are held for review).
TOOL_MATCHER = "*"
PRETOOL_SCRIPT = "pretool_admission.py"
POSTTOOL_SCRIPT = "posttool_autopsy.py"
MANAGED_SCRIPTS = (PRETOOL_SCRIPT, POSTTOOL_SCRIPT)
# Shared contract with claude_code_hooks.GATE_SWITCH_FILE_NAME: the hook reads
# this file fresh on every invocation, so flipping it here takes effect on the
# next tool call in every live session -- no restart, unlike connect/disconnect
# whose registration is cached per session.
GATE_SWITCH_FILE = "pub_gate_switch.json"
GATE_SWITCH_SCHEMA_VERSION = "pub_gate_switch:v0"

# Cross-platform connect. The hook command Claude Code stores is a single
# string handed to the OS shell, so it is platform-specific: a WSL-style
# `python3 /mnt/c/dev/sp/...` command does not resolve when Claude Code runs as
# a native Windows process, and a Windows `py -3 C:\dev\sp\...` command does not
# resolve under WSL/Linux. The platform mode picks the right interpreter and
# path style for wherever Claude Code actually runs.
#   * auto    -- match the OS this connector runs on (the common case: you run
#                the launcher on the same machine as Claude Code).
#   * windows -- `py -3` (or python/python3 if py is absent) and Windows paths;
#                normalize a /mnt/<d>/... root to <D>:\...
#   * posix   -- `python3` and POSIX paths; normalize <D>:\... to /mnt/<d>/...
# Explicit python_bin / protect_root arguments are always honored verbatim so a
# caller can pin an exact command; auto only fills in what was left blank and
# never rewrites an explicitly supplied path.
AUTO_PLATFORM = "auto"
WINDOWS_PLATFORM = "windows"
POSIX_PLATFORM = "posix"
PLATFORM_CHOICES = (AUTO_PLATFORM, WINDOWS_PLATFORM, POSIX_PLATFORM)
DEFAULT_PLATFORM = AUTO_PLATFORM

_WSL_MOUNT_RE = re.compile(r"^/mnt/([A-Za-z])(?:/(.*))?$")
_WINDOWS_DRIVE_RE = re.compile(r"^([A-Za-z]):[\\/](.*)$")


class ClaudeCodeConnectorError(RuntimeError):
    pass


def status_claude_code(
    claude_project: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
    python_bin: str | None = None,
    platform: str = DEFAULT_PLATFORM,
) -> dict[str, Any]:
    project_root = find_claude_project(claude_project)
    settings_path = _settings_path(project_root)
    settings = _read_settings(settings_path)
    resolved_python = _effective_python_bin(python_bin, platform)
    resolved_root = _effective_protect_root(protect_root, platform)
    commands = _managed_commands(protect_root=resolved_root, python_bin=resolved_python)
    pretool_hook = _has_hook_command(settings, "PreToolUse", commands["PreToolUse"])
    posttool_hook = _has_hook_command(settings, "PostToolUse", commands["PostToolUse"])
    switch_path = _gate_switch_path(project_root)
    return {
        "claude_project": str(project_root),
        "settings_path": str(settings_path),
        "settings_exists": settings_path.exists(),
        "connected": pretool_hook and posttool_hook,
        "gate_switch": "off" if _gate_switch_disarmed(switch_path) else "on",
        "gate_switch_path": str(switch_path),
        "pretool_hook": pretool_hook,
        "posttool_hook": posttool_hook,
        "managed_hook_count": _managed_hook_count(settings),
        "matcher": TOOL_MATCHER,
        "platform": _resolve_platform(platform),
        "python_bin": resolved_python,
        "protect_root": resolved_root,
        "pretool_command": commands["PreToolUse"],
        "posttool_command": commands["PostToolUse"],
        "backup_path": str(_backup_path(settings_path)),
        "sha256": _sha256(settings_path) if settings_path.exists() else None,
    }


def connect_claude_code(
    claude_project: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
    python_bin: str | None = None,
    platform: str = DEFAULT_PLATFORM,
) -> dict[str, Any]:
    project_root = find_claude_project(claude_project)
    settings_path = _settings_path(project_root)
    settings = _read_settings(settings_path)
    original = _canonical(settings)

    resolved_python = _effective_python_bin(python_bin, platform)
    resolved_root = _effective_protect_root(protect_root, platform)
    commands = _managed_commands(protect_root=resolved_root, python_bin=resolved_python)
    _remove_managed_hooks(settings)
    _append_hook_command(settings, "PreToolUse", commands["PreToolUse"])
    _append_hook_command(settings, "PostToolUse", commands["PostToolUse"])

    changed = _canonical(settings) != original
    if changed:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        if settings_path.exists():
            _backup_once(settings_path)
        _write_settings(settings_path, settings)

    result = status_claude_code(
        project_root,
        protect_root=protect_root,
        python_bin=python_bin,
        platform=platform,
    )
    result["changed"] = changed
    return result


def disconnect_claude_code(claude_project: str | Path | None = None) -> dict[str, Any]:
    project_root = find_claude_project(claude_project)
    settings_path = _settings_path(project_root)
    settings = _read_settings(settings_path)
    original = _canonical(settings)
    removed = _remove_managed_hooks(settings)
    changed = _canonical(settings) != original
    if changed:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        if settings_path.exists():
            _backup_once(settings_path)
        _write_settings(settings_path, settings)

    result = status_claude_code(project_root)
    result["changed"] = changed
    result["removed_hook_count"] = removed
    return result


def gate_claude_code(
    claude_project: str | Path | None = None,
    *,
    enabled: bool,
) -> dict[str, Any]:
    project_root = find_claude_project(claude_project)
    switch_path = _gate_switch_path(project_root)
    switch_path.parent.mkdir(parents=True, exist_ok=True)
    switch_path.write_text(
        json.dumps(
            {"schema_version": GATE_SWITCH_SCHEMA_VERSION, "enabled": enabled},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="",
    )
    result = status_claude_code(project_root)
    result["note"] = (
        "Gate ON: blocking re-armed. Effective on the next tool call in every "
        "live session of this project; no restart needed."
        if enabled
        else "Gate OFF: nothing is blocked or escalated, but hooks stay "
        "registered and the audit trail keeps recording. Effective on the "
        "next tool call; no restart needed. Re-arm with 'on'; remove hooks "
        "entirely with 'disconnect'."
    )
    return result


def verify_claude_code(
    claude_project: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
    python_bin: str | None = None,
    platform: str = DEFAULT_PLATFORM,
) -> dict[str, Any]:
    status = status_claude_code(
        claude_project,
        protect_root=protect_root,
        python_bin=python_bin,
        platform=platform,
    )
    project_root = Path(status["claude_project"])

    from claude_code_hooks import run_pretool_admission

    payload = {
        "session_id": "pub_claude_code_connector_verify",
        "transcript_path": str(project_root / ".claude" / "pub_verify_transcript.jsonl"),
        "cwd": str(project_root),
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf .", "description": "synthetic destructive probe"},
        "tool_use_id": "pub_claude_code_connector_verify",
    }
    verify_dir = project_root / ".claude" / "pub_verify_state"
    result = run_pretool_admission(
        json.dumps(payload),
        environ={
            "CLAUDE_PROJECT_DIR": str(project_root),
            "PUB_CLAUDE_HOOK_STATE_DIR": str(verify_dir),
            "PUB_CLAUDE_HOOK_LOG_DIR": str(verify_dir),
        },
    )
    hook_output = result.output.get("hookSpecificOutput") if result.output else None
    return {
        **status,
        "preflight_blocked": bool(
            isinstance(hook_output, dict) and hook_output.get("permissionDecision") == "deny"
        ),
        "disposition": result.disposition.value,
        "reason_code": result.reason_code,
        "io_executed": False,
        "can_execute": False,
        "can_grant_permission": False,
    }


def find_claude_project(claude_project: str | Path | None = None) -> Path:
    candidate = Path(claude_project or Path.cwd()).expanduser().resolve(strict=False)
    if candidate.name == "settings.local.json" and candidate.parent.name == ".claude":
        return candidate.parent.parent
    if candidate.name == ".claude":
        return candidate.parent
    return candidate


def _settings_path(project_root: Path) -> Path:
    return project_root / ".claude" / "settings.local.json"


def _gate_switch_path(project_root: Path) -> Path:
    return project_root / ".claude" / GATE_SWITCH_FILE


def _gate_switch_disarmed(switch_path: Path) -> bool:
    # Mirror of claude_code_hooks._gate_switch_off, fail closed the same way:
    # missing, unreadable, or malformed reads as armed.
    try:
        payload = json.loads(switch_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(payload, dict) and payload.get("enabled") is False


def _read_settings(settings_path: Path) -> dict[str, Any]:
    if not settings_path.exists():
        return {}
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise ClaudeCodeConnectorError(f"invalid Claude Code settings JSON: {settings_path}") from exc
    if not isinstance(data, dict):
        raise ClaudeCodeConnectorError("Claude Code settings root must be a JSON object.")
    return data


def _write_settings(settings_path: Path, settings: dict[str, Any]) -> None:
    settings_path.write_text(
        json.dumps(settings, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="",
    )


def _append_hook_command(settings: dict[str, Any], event_name: str, command: str) -> None:
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ClaudeCodeConnectorError("Claude Code settings hooks field must be a JSON object.")
    entries = hooks.setdefault(event_name, [])
    if not isinstance(entries, list):
        raise ClaudeCodeConnectorError(f"Claude Code hooks.{event_name} must be a JSON array.")
    entries.append(
        {
            "matcher": TOOL_MATCHER,
            "hooks": [{"type": "command", "command": command}],
        }
    )


def _remove_managed_hooks(settings: dict[str, Any]) -> int:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return 0

    removed = 0
    for event_name in ("PreToolUse", "PostToolUse"):
        entries = hooks.get(event_name)
        if not isinstance(entries, list):
            continue
        kept_entries = []
        for entry in entries:
            if not isinstance(entry, dict):
                kept_entries.append(entry)
                continue
            hook_items = entry.get("hooks")
            if not isinstance(hook_items, list):
                if _entry_mentions_managed_script(entry):
                    removed += 1
                else:
                    kept_entries.append(entry)
                continue
            kept_hooks = []
            for hook in hook_items:
                if _is_managed_hook(hook):
                    removed += 1
                else:
                    kept_hooks.append(hook)
            if kept_hooks:
                kept_entry = dict(entry)
                kept_entry["hooks"] = kept_hooks
                kept_entries.append(kept_entry)
        if kept_entries:
            hooks[event_name] = kept_entries
        else:
            hooks.pop(event_name, None)
    if not hooks:
        settings.pop("hooks", None)
    return removed


def _has_hook_command(settings: dict[str, Any], event_name: str, command: str) -> bool:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False
    entries = hooks.get(event_name)
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("matcher") != TOOL_MATCHER:
            continue
        hook_items = entry.get("hooks")
        if not isinstance(hook_items, list):
            continue
        for hook in hook_items:
            if isinstance(hook, dict) and hook.get("type") == "command" and hook.get("command") == command:
                return True
    return False


def _managed_hook_count(settings: dict[str, Any]) -> int:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return 0
    count = 0
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("hooks"), list):
                count += sum(1 for hook in entry["hooks"] if _is_managed_hook(hook))
    return count


def _is_managed_hook(hook: Any) -> bool:
    if not isinstance(hook, dict) or hook.get("type") != "command":
        return False
    command = hook.get("command")
    return isinstance(command, str) and any(script in command for script in MANAGED_SCRIPTS)


def _entry_mentions_managed_script(entry: dict[str, Any]) -> bool:
    return any(script in json.dumps(entry, sort_keys=True) for script in MANAGED_SCRIPTS)


def _managed_commands(*, protect_root: str | Path | None, python_bin: str) -> dict[str, str]:
    return {
        "PreToolUse": _hook_command(
            python_bin=python_bin,
            protect_root=protect_root,
            script_name=PRETOOL_SCRIPT,
        ),
        "PostToolUse": _hook_command(
            python_bin=python_bin,
            protect_root=protect_root,
            script_name=POSTTOOL_SCRIPT,
        ),
    }


def _hook_command(*, python_bin: str, protect_root: str | Path | None, script_name: str) -> str:
    return f"{python_bin} {_quote_if_needed(_script_path(_protect_root_literal(protect_root), script_name))}"


def _protect_root_literal(protect_root: str | Path | None) -> str:
    if protect_root is None:
        return str(Path(__file__).resolve(strict=False).parent)
    return str(protect_root).strip().strip('"').strip("'")


def _resolve_platform(platform: str | None) -> str:
    value = (platform or AUTO_PLATFORM).strip().lower()
    if value in (WINDOWS_PLATFORM, POSIX_PLATFORM):
        return value
    if value not in ("", AUTO_PLATFORM):
        raise ClaudeCodeConnectorError(
            f"unknown platform mode {platform!r}; choose one of {PLATFORM_CHOICES}."
        )
    return WINDOWS_PLATFORM if os.name == "nt" else POSIX_PLATFORM


def _effective_python_bin(python_bin: str | None, platform: str | None) -> str:
    # An explicit interpreter is honored verbatim; only a blank one is resolved
    # from the platform, so existing callers that pin "python3" are unaffected.
    if python_bin is not None and str(python_bin).strip():
        return str(python_bin).strip()
    return _default_python_bin(platform)


def _default_python_bin(platform: str | None) -> str:
    if _resolve_platform(platform) == WINDOWS_PLATFORM:
        if shutil.which("py"):
            # The Windows Python launcher; -3 pins Python 3 over any legacy 2.x.
            return "py -3"
        return "python" if shutil.which("python") else "python3"
    return "python3"


def _effective_protect_root(protect_root: str | Path | None, platform: str | None) -> str:
    literal = _protect_root_literal(protect_root)
    requested = (platform or AUTO_PLATFORM).strip().lower()
    if requested in (WINDOWS_PLATFORM, POSIX_PLATFORM):
        return _convert_path_for_platform(literal, requested)
    # auto: do not change the mount style (so an explicit /mnt or C: path keeps
    # its target), but still normalize backslashes to forward slashes. The path
    # is embedded in a shell command; a blank root resolves to this machine's
    # own path, which on Windows is C:\dev\sp -- and the shell that runs the
    # hook strips those backslashes (C:\dev\sp\pretool_admission.py collapses to
    # C:devsppretool_admission.py and fails to open). Forward slashes survive
    # every shell and Python on Windows accepts them.
    return literal.replace("\\", "/")


def _convert_path_for_platform(path: str, platform: str) -> str:
    if platform == WINDOWS_PLATFORM:
        return _to_windows_path(path)
    if platform == POSIX_PLATFORM:
        return _to_posix_path(path)
    return path


def _to_windows_path(path: str) -> str:
    # /mnt/c/dev/sp -> C:/dev/sp. Forward slashes on purpose: this path is
    # embedded in the hook command string, which Claude Code hands to a shell
    # before exec. Backslashes do not survive that shell -- bash/sh strip them
    # (C:\dev\sp\pretool_admission.py collapses to C:devsppretool_admission.py,
    # which then resolves against cwd and fails to open). Python on Windows
    # accepts '/' in paths and no shell treats '/' as an escape character, so
    # '/' is the portable choice for both cmd.exe and bash-run hooks.
    match = _WSL_MOUNT_RE.match(path)
    if not match:
        return path.replace("\\", "/")
    drive = match.group(1).upper()
    tail = match.group(2) or ""
    return f"{drive}:/{tail}" if tail else f"{drive}:/"


def _to_posix_path(path: str) -> str:
    # C:\dev\sp -> /mnt/c/dev/sp ; already-POSIX paths pass through unchanged.
    match = _WINDOWS_DRIVE_RE.match(path)
    if not match:
        return path
    drive = match.group(1).lower()
    tail = match.group(2).replace("\\", "/").rstrip("/")
    return f"/mnt/{drive}/{tail}" if tail else f"/mnt/{drive}"


def _script_path(root: str, script_name: str) -> str:
    root = root.rstrip("/\\")
    separator = "\\" if "\\" in root and "/" not in root else "/"
    return f"{root}{separator}{script_name}"


def _quote_if_needed(value: str) -> str:
    if not any(character.isspace() for character in value):
        return value
    return '"' + value.replace('"', '\\"') + '"'


def _canonical(settings: dict[str, Any]) -> str:
    return json.dumps(settings, sort_keys=True, separators=(",", ":"))


def _backup_path(path: Path) -> Path:
    return path.with_name(path.name + BACKUP_SUFFIX)


def _backup_once(path: Path) -> None:
    backup = _backup_path(path)
    if not backup.exists():
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8", newline="")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Connect Protect U Back to Claude Code hooks.")
    parser.add_argument("command", choices=("status", "connect", "disconnect", "verify", "on", "off"))
    parser.add_argument("--claude-project", default=".")
    parser.add_argument("--protect-root")
    parser.add_argument(
        "--python-bin",
        default=None,
        help="Python command as seen by Claude Code; blank auto-detects per --platform.",
    )
    parser.add_argument(
        "--platform",
        choices=PLATFORM_CHOICES,
        default=DEFAULT_PLATFORM,
        help="Target platform for the hook command (auto matches this machine).",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    operations = {
        "status": lambda: status_claude_code(
            args.claude_project,
            protect_root=args.protect_root,
            python_bin=args.python_bin,
            platform=args.platform,
        ),
        "connect": lambda: connect_claude_code(
            args.claude_project,
            protect_root=args.protect_root,
            python_bin=args.python_bin,
            platform=args.platform,
        ),
        "disconnect": lambda: disconnect_claude_code(args.claude_project),
        "on": lambda: gate_claude_code(args.claude_project, enabled=True),
        "off": lambda: gate_claude_code(args.claude_project, enabled=False),
        "verify": lambda: verify_claude_code(
            args.claude_project,
            protect_root=args.protect_root,
            python_bin=args.python_bin,
            platform=args.platform,
        ),
    }
    try:
        result = operations[args.command]()
    except Exception as exc:
        print(f"Claude Code connector error: {exc}")
        return 1
    _print_result(result, as_json=args.json)
    return 0


def _print_result(result: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    for key, value in result.items():
        if isinstance(value, dict):
            print(f"{key}:")
            for child_key, child_value in value.items():
                print(f"  {child_key}: {child_value}")
        else:
            print(f"{key}: {value}")


if __name__ == "__main__":
    raise SystemExit(main())
