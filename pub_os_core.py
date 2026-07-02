"""PUB-OS core -- pub's house. The eyes + beast, behind the window.

A white, empty house. pub lives here and does exactly ONE thing: JUDGE. Its only
connection to the world is the window (the broker). A request frame comes in; a
verdict frame goes out. It NEVER executes, never touches a resource, never opens
another door -- execution is the warden's separate house; judgment is all that
happens here.

Minimalism (the fewest interface functions):
  * judge(command, cwd)      -- pure: run pub's existing eyes, return a verdict.
  * respond_to_frame(payload) -- the ONE intake: opaque request bytes -> verdict
                                 bytes. No state, no side effects, no execution.
  * serve_core(conn)          -- read request frames from the window, judge each,
                                 write a verdict frame back. Fail-closed.

The judging itself is NOT reimplemented here -- it is the audit pipeline this
whole project hardened (decoders + grounding + ot_gate). The house is empty; the
eyes are the only furniture, reached through a single call.

One-way mirror (I7 -- observation asymmetry): pub sees the agent's every move
(single egress -> every request reaches the eyes), but the agent sees NOTHING of
pub. pub's FULL verdict (disposition + reason_code + evidence) goes only to pub's
own record; the agent receives the MINIMUM -- allow/deny -- uniform across all
block reasons. The agent cannot read pub's reasons, cannot tell WHY it was
blocked, and so cannot probe pub to map its decision boundary. (Full invisibility
-- a denial indistinguishable from an ordinary OS failure -- arrives with the
warden / syscall layer; here, at the cooperative layer, we deny pub's LOGIC to
the agent.)
"""

from __future__ import annotations

import json
from os.path import normcase, normpath
from pathlib import Path
import re
import socket
import struct

from claude_code_hooks import action_from_claude_event, _audit_action
from pub_os_broker import HEADER_BYTES, MAX_FRAME_BYTES, read_frame
from pub_os_warden import sign_verdict


def _frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def judge(
    command: str,
    cwd: str,
    *,
    env_overrides: "Mapping[str, str] | None" = None,
) -> tuple[str, str]:
    """Pure judgment: a (disposition, reason_code) from pub's existing eyes.

    No file is written, nothing is executed -- the eyes only OBSERVE and decide.
    ``env_overrides`` forwards host-only knobs (notably the PUB_CLAUDE_*_STATE_DIR
    pointers) so the prison can keep the continuity judges' state OUTSIDE the
    box's RW bind. Default None preserves the legacy in-cwd state location.
    """
    environ = {"CLAUDE_PROJECT_DIR": cwd, **(env_overrides or {})}
    event = {
        "session_id": "pub_os_core",
        "transcript_path": "pub_os_core",
        "cwd": cwd,
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": "pub_os_core",
    }
    action = action_from_claude_event(event, environ=environ)
    decision = _audit_action(action)
    return decision.disposition.value, decision.reason_code


def judge_operation(
    command: str,
    cwd: str,
    op: dict,
    *,
    env_overrides: "Mapping[str, str] | None" = None,
) -> tuple[str, str]:
    """Judge the command and the structured operation before anything is sealed.

    The shell surface and the warden op are separate inputs. A PASS command may
    not smuggle a different op through the signing boundary.
    """
    disposition, reason_code = judge(command, cwd, env_overrides=env_overrides)
    if disposition != "PASS":
        return disposition, reason_code
    return _judge_op_bound_to_command(command, cwd, op, env_overrides=env_overrides)


def authorize(
    command: str,
    cwd: str,
    op: dict,
    *,
    key: bytes,
    env_overrides: "Mapping[str, str] | None" = None,
) -> bytes:
    """Beast -> warden: judge the request, then SEAL an order the warden can trust.

    The agent never sees this (one-way mirror); only the warden consumes it. `op`
    is the structured operation the eyes already extracted -- the warden will
    perform exactly it, and only if this seal says allow.
    """
    disposition, _reason = judge_operation(command, cwd, op, env_overrides=env_overrides)
    return sign_verdict({"allow": disposition == "PASS", "op": op}, key=key)


def _judge_op_bound_to_command(
    command: str,
    cwd: str,
    op: dict,
    *,
    env_overrides: "Mapping[str, str] | None" = None,
) -> tuple[str, str]:
    kind = str((op or {}).get("kind", ""))
    if kind != "read":
        return "HOLD", "OP_KIND_UNSUPPORTED"

    path = str(op.get("path", "")).strip()
    if not path:
        return "HOLD", "OP_TARGET_MISSING"

    if not _command_names_target(command, cwd, path, env_overrides=env_overrides):
        return "HOLD", "OP_COMMAND_TARGET_MISMATCH"

    op_action = _action_for_tool(
        "Read",
        {"file_path": path},
        cwd,
        tool_use_id="pub_os_op_read",
        env_overrides=env_overrides,
    )
    decision = _audit_action(op_action)
    return decision.disposition.value, decision.reason_code


def _command_names_target(
    command: str,
    cwd: str,
    target_path: str,
    *,
    env_overrides: "Mapping[str, str] | None" = None,
) -> bool:
    if _command_text_names_target(command, target_path):
        return True
    action = _action_for_tool(
        "Bash",
        {"command": command},
        cwd,
        tool_use_id="pub_os_command_binding",
        env_overrides=env_overrides,
    )
    return any(_same_target(cwd, target, target_path) for target in action.target_paths)


def _action_for_tool(
    tool_name: str,
    tool_input: dict,
    cwd: str,
    *,
    tool_use_id: str,
    env_overrides: "Mapping[str, str] | None" = None,
):
    environ = {"CLAUDE_PROJECT_DIR": cwd, **(env_overrides or {})}
    event = {
        "session_id": "pub_os_core",
        "transcript_path": "pub_os_core",
        "cwd": cwd,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": tool_use_id,
    }
    return action_from_claude_event(event, environ=environ)


def _same_target(cwd: str, left: str, right: str) -> bool:
    return _resolved_target(cwd, left) == _resolved_target(cwd, right)


def _command_text_names_target(command: str, target_path: str) -> bool:
    candidates = {
        str(target_path).strip(),
        str(target_path).strip().replace("\\", "/"),
    }
    normalized_command = str(command).replace("\\", "/")
    return any(
        _contains_complete_path_token(normalized_command, candidate.replace("\\", "/"))
        for candidate in candidates
        if candidate
    )


def _contains_complete_path_token(text: str, needle: str) -> bool:
    pattern = re.compile(r"(?<![A-Za-z0-9_./:\\-])" + re.escape(needle) + r"(?![A-Za-z0-9_./:\\-])")
    return bool(pattern.search(text))


def _resolved_target(cwd: str, target: str) -> str:
    path = Path(str(target))
    if not path.is_absolute():
        path = Path(cwd) / path
    return normcase(normpath(str(path.resolve(strict=False))))


def _agent_reply(disposition: str) -> bytes:
    """The one-way mirror: the agent learns only allow/deny -- no reason, no
    disposition granularity, no pub internals. Uniform across every block reason,
    so the agent cannot probe pub to map its decision boundary."""
    return json.dumps({"allow": disposition == "PASS"}).encode("utf-8")


def respond_to_frame(request_payload: bytes) -> bytes:
    """The one intake: opaque request bytes -> MINIMAL agent reply bytes.

    The agent receives only allow/deny. pub's full verdict (disposition + reason)
    is pub's own record and is NEVER returned through the window to the agent.
    """
    request = json.loads(request_payload.decode("utf-8"))
    disposition, _reason = judge(
        str(request.get("command", "")),
        str(request.get("cwd", ".")),
    )
    return _agent_reply(disposition)


def serve_core(core_conn: socket.socket, *, max_frame: int = MAX_FRAME_BYTES, record=None) -> None:
    """Read request frames from the window, JUDGE each, and reply asymmetrically.

    pub's FULL verdict (command + disposition + reason_code) goes to `record` --
    pub's own eyes / ledger, which the agent never sees. The agent gets back only
    the minimal allow/deny through the window. Fail-closed: a malformed frame, a
    parse error, or a write failure ends the loop and closes the door.
    """
    while True:
        request_frame = read_frame(core_conn, max_frame)
        if request_frame is None:
            break
        try:
            request = json.loads(request_frame[HEADER_BYTES:].decode("utf-8"))
            command = str(request.get("command", ""))
            cwd = str(request.get("cwd", "."))
            disposition, reason_code = judge(command, cwd)
        except Exception:
            break  # ambiguous request -> no verdict -> denied (the box gets EOF)
        if record is not None:  # pub sees all; this never reaches the agent
            record({"command": command, "disposition": disposition, "reason_code": reason_code})
        try:
            core_conn.sendall(_frame(_agent_reply(disposition)))
        except OSError:
            break
    try:
        core_conn.close()
    except OSError:
        pass


def serve(listener: socket.socket, *, max_frame: int = MAX_FRAME_BYTES) -> None:
    """Accept window connections and judge each. The house has ONE door: this."""
    while True:
        conn, _ = listener.accept()
        serve_core(conn, max_frame=max_frame)
