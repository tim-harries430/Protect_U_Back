from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from codex_bash_guard import LOG_FILE_NAME, audit_shell_argv


SCHEMA_VERSION = "pub_desktop_soft_link:v1"
GUARD_DIR = ".pub_codex_guard"
STATE_NAME = "desktop_soft_start.json"
ACTOR_ID = "codex_desktop_soft"


def connect_soft(project_root: str | Path, *, thread_id: str | None = None) -> dict[str, Any]:
    root = Path(project_root).resolve(strict=False)
    guard_dir = root / GUARD_DIR
    guard_dir.mkdir(parents=True, exist_ok=True)
    (guard_dir / "logs").mkdir(parents=True, exist_ok=True)
    now = _now()
    state = {
        "schema_version": SCHEMA_VERSION,
        "created_at": _existing_created_at(guard_dir / STATE_NAME) or now,
        "updated_at": now,
        "mode": "soft_preflight",
        "scope": "current_codex_desktop_thread",
        "thread_id": thread_id or os.environ.get("CODEX_THREAD_ID", ""),
        "connected": False,
        "soft_link_active": True,
        "managed_by_pub_runner": False,
        "supervision_state": "UNMANAGED",
        "reason_code": "DESKTOP_RUNNER_NOT_ATTACHED",
        "boundary": "voluntary_pre_execution_audit_only",
        "hard_desktop_runner_attached": False,
        "adapter": "pub_desktop_soft_link.preflight",
        "preflight": {
            "adapter": "codex_bash_guard.audit_shell_argv",
            "pass": "execute_allowed_by_operator",
            "hold": "ask_or_stop",
            "kill": "stop",
        },
        "limits": {
            "auto_intercepts_desktop_tools": False,
            "executes_commands": False,
            "can_grant_permission": False,
        },
    }
    _write_json(guard_dir / STATE_NAME, state)
    return state


def preflight(command: str, project_root: str | Path) -> dict[str, Any]:
    root = Path(project_root).resolve(strict=False)
    state = connect_soft(root)
    env = {
        **os.environ,
        "PUB_CODEX_ACTOR_ID": ACTOR_ID,
        "PUB_CODEX_PROJECT_ROOT": str(root),
        "PUB_CODEX_SESSION_ID": state.get("thread_id") or "codex_desktop_soft_link",
        "PUB_CODEX_SANDBOX_AVAILABLE": "true",
        "PUB_CODEX_SANDBOX_MODE": "desktop_soft_preflight",
        "PUB_CODEX_LOG_DIR": str(root / GUARD_DIR / "logs"),
    }
    decision = audit_shell_argv(("-lc", command), cwd=str(root), environ=env)
    row = {
        "phase": "soft_preflight",
        "connection_adapter": "pub_desktop_soft_link",
        "soft_link_schema": SCHEMA_VERSION,
        "executed": False,
        **decision.to_dict(),
    }
    _append_log(root, row)
    return row


def witness(project_root: str | Path) -> dict[str, Any]:
    cases = (
        ("pass_read", "rg --files"),
        ("hold_opaque", "D=rm; $D -rf /tmp/pub_desktop_soft_link_probe"),
        ("kill_delete", "rm -rf ."),
    )
    rows = []
    for case_id, command in cases:
        row = preflight(command, project_root)
        rows.append(
            {
                "case_id": case_id,
                "command": command,
                "disposition": row["disposition"],
                "reason_code": row["reason_code"],
                "blocked": row["blocked"],
                "executed": row["executed"],
            }
        )
    return {
        "schema_version": "pub_desktop_soft_link_witness:v1",
        "project_root": str(Path(project_root).resolve(strict=False)),
        "rows": rows,
        "connected": False,
        "soft_link_active": True,
        "managed_by_pub_runner": False,
        "supervision_state": "UNMANAGED",
        "reason_code": "DESKTOP_RUNNER_NOT_ATTACHED",
        "hard_desktop_runner_attached": False,
    }


def _existing_created_at(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ""
    return str(existing.get("created_at") or "")


def _append_log(root: Path, row: dict[str, Any]) -> None:
    log_dir = root / GUARD_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    payload = {"ts": time.time(), **row}
    with (log_dir / LOG_FILE_NAME).open("a", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now().astimezone().isoformat()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Soft-connect Codex Desktop to PUB preflight audit.")
    parser.add_argument("command", choices=("connect", "preflight", "witness"))
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--shell-command", default="")
    args = parser.parse_args(argv)

    if args.command == "connect":
        payload = connect_soft(args.project_root)
    elif args.command == "preflight":
        if not args.shell_command:
            parser.error("--shell-command is required for preflight")
        payload = preflight(args.shell_command, args.project_root)
    else:
        payload = witness(args.project_root)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
