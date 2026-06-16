from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Sequence

from harness_runtime_guard import ProtectPreflightBlocked, enforce_shell_subprocess_preflight


BLOCKED_EXIT = 23


def audit_openclaw_shell(payload: dict[str, Any]) -> dict[str, Any]:
    command = str(payload.get("command") or "")
    cwd = payload.get("cwd") or "."
    sandbox_available = bool(payload.get("sandbox_available", False))
    sandbox_fallback = str(
        payload.get("sandbox_fallback")
        or ("openclaw_sandbox" if sandbox_available else "openclaw_host_shell")
    )
    try:
        enforce_shell_subprocess_preflight(
            command,
            cwd=cwd,
            project_root=cwd,
            actor_id="openclaw_shell",
            source_adapter="openclaw",
            tool_name="bash",
            action_id="openclaw_run_exec_process",
            branch_id="openclaw_shell_branch",
            user_request_id="openclaw_shell_user_request",
            sandbox_available=sandbox_available,
            sandbox_reason="" if sandbox_available else "sandbox unavailable",
            sandbox_fallback=sandbox_fallback,
        )
    except ProtectPreflightBlocked as exc:
        return {
            "allowed": False,
            "message": str(exc),
            "metadata": exc.to_metadata(),
            "io_executed": False,
            "can_execute": False,
            "can_grant_permission": False,
        }
    return {
        "allowed": True,
        "io_executed": False,
        "can_execute": False,
        "can_grant_permission": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    _ = argv
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            raise ValueError("payload must be a JSON object")
        result = audit_openclaw_shell(payload)
    except Exception as exc:
        result = {
            "allowed": False,
            "message": f"Protect U Back OpenClaw guard failed closed: {exc}",
            "io_executed": False,
            "can_execute": False,
            "can_grant_permission": False,
        }
    sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    return 0 if result.get("allowed") is True else BLOCKED_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
