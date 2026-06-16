from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Sequence

from harness_runtime_guard import ProtectPreflightBlocked, enforce_shell_subprocess_preflight


BLOCKED_EXIT = 23


def audit_kimi_shell(payload: dict[str, Any]) -> dict[str, Any]:
    command = str(payload.get("command") or "")
    cwd = payload.get("cwd") or "."
    run_in_background = bool(payload.get("run_in_background", False))
    try:
        enforce_kimi_shell_preflight(
            command,
            cwd=cwd,
            run_in_background=run_in_background,
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


def enforce_kimi_shell_preflight(
    command: str,
    *,
    cwd: str | Path | None = None,
    run_in_background: bool = False,
) -> None:
    action_suffix = "background" if run_in_background else "foreground"
    enforce_shell_subprocess_preflight(
        command,
        cwd=cwd,
        project_root=cwd,
        actor_id="kimi_shell",
        source_adapter="kimi",
        tool_name="Shell",
        action_id=f"kimi_shell_{action_suffix}",
        branch_id="kimi_shell_branch",
        user_request_id="kimi_shell_user_request",
        sandbox_available=False,
        sandbox_reason="Kimi CLI Shell tool has no Protect U Back sandbox certificate",
        sandbox_fallback="kimi_shell",
        raw_payload={"run_in_background": run_in_background},
    )


def main(argv: Sequence[str] | None = None) -> int:
    _ = argv
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            raise ValueError("payload must be a JSON object")
        result = audit_kimi_shell(payload)
    except Exception as exc:
        result = {
            "allowed": False,
            "message": f"Protect U Back Kimi guard failed closed: {exc}",
            "io_executed": False,
            "can_execute": False,
            "can_grant_permission": False,
        }
    sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    return 0 if result.get("allowed") is True else BLOCKED_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
