"""pub run -- the launcher that assembles the prison and runs an agent inside it.

It stands up, OUTSIDE the box, the four parts we built, and wires them into one
live loop:

    agent (in box) --window--> eyes (judge) --sealed verdict--> warden (execute)
                   <--window--            result / deny  <------

  * a fresh shared KEY is generated for the beast (sign) and the warden (verify);
    the window and the box never receive it (contract I3, unforgeability).
  * the EYES judge; on allow the beast SEALS the order and the WARDEN executes it
    -- the signature is the boundary between decision and action, so they stay
    separate even when co-hosted.
  * the AGENT only ever gets `ok`/`result` or a bare `ok:false` -- never a reason
    (the one-way mirror, I7).
  * the BOX confines: no network, fs = project root only, single egress = window.

On Windows the box needs Linux + bwrap, so the launcher runs this under WSL2.
"""

from __future__ import annotations

import json
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pub_os_box
import pub_os_core
import pub_os_warden
from pub_os_broker import HEADER_BYTES, MAX_FRAME_BYTES, make_listener, read_frame, serve
from pub_os_core import _frame


def mediate(conn: socket.socket, *, key: bytes, record=None, max_frame: int = MAX_FRAME_BYTES, env_overrides=None) -> None:
    """Eyes + warden behind the window. Judge each request; on allow, the beast
    SEALS and the warden EXECUTES (the signature is the eyes/warden boundary). The
    agent gets only `ok`/result or a bare `ok:false` -- never a reason."""
    while True:
        request_frame = read_frame(conn, max_frame)
        if request_frame is None:
            break
        try:
            request = json.loads(request_frame[HEADER_BYTES:].decode("utf-8"))
            command = str(request.get("command", ""))
            cwd = str(request.get("cwd", "."))
            op = request.get("op") or {}
            disposition, reason_code = pub_os_core.judge_operation(command, cwd, op, env_overrides=env_overrides)
        except Exception:
            break  # ambiguous request -> close (fail-closed)

        if record is not None:  # pub keeps the full verdict; the agent never sees it
            record({"command": command, "op": op, "disposition": disposition, "reason_code": reason_code})

        if disposition == "PASS":
            sealed = pub_os_warden.sign_verdict({"allow": True, "op": op}, key=key)
            result = pub_os_warden.execute(sealed, key=key)
            if result.get("executed"):
                data = result.get("result")
                payload = {"ok": True, "result": data.hex() if isinstance(data, bytes) else data}
            else:
                payload = {"ok": False}
        else:
            payload = {"ok": False}  # denied -- uniform, no reason (one-way mirror)

        try:
            conn.sendall(_frame(json.dumps(payload).encode("utf-8")))
        except OSError:
            break
    try:
        conn.close()
    except OSError:
        pass


def _serve_eyes_warden(listener: socket.socket, *, key: bytes, record=None, env_overrides=None) -> None:
    while True:
        conn, _ = listener.accept()
        mediate(conn, key=key, record=record, env_overrides=env_overrides)


def run(agent_argv, *, project_root, runtime_dir=None, record=None) -> int:
    """Assemble the prison and launch `agent_argv` inside the box. Returns the
    box process's exit code. Linux + bwrap only (on Windows, via WSL2)."""
    if not pub_os_box.box_available():
        raise RuntimeError("no box available: need Linux + bwrap (on Windows, run inside WSL2)")

    key = secrets.token_bytes(32)
    runtime = Path(runtime_dir or tempfile.mkdtemp(prefix="pub_run_"))
    runtime.mkdir(parents=True, exist_ok=True)
    box_socket = str(runtime / "box.sock")     # the box's single egress (bind-mounted in)
    core_socket = str(runtime / "core.sock")   # host-side: eyes + warden

    # The eyes' continuity judges (xray / temporal / scene) keep state on disk.
    # Default they land under <cwd>/.claude/ -- which is INSIDE the box's RW
    # project_root bind, so the agent could tamper with them and reset the next
    # verdict. Pin them to a host-only dir under `runtime` instead: `runtime` is
    # never bind-mounted into the box (the box gets project_root + broker_socket
    # only), so the agent cannot reach these files. Mirrors the ledger supervisor
    # discipline (single writer outside the cage).
    state_root = runtime / "pub_state"
    env_overrides = {
        "PUB_CLAUDE_HOOK_STATE_DIR": str(state_root / "xray"),
        "PUB_CLAUDE_TEMPORAL_STATE_DIR": str(state_root / "temporal"),
        "PUB_CLAUDE_SCENE_STATE_DIR": str(state_root / "scene"),
    }

    # 1. eyes + warden (the judge and the hands, sharing the key the box lacks)
    core_listener = make_listener(core_socket, family=socket.AF_UNIX)
    threading.Thread(
        target=_serve_eyes_warden, args=(core_listener,), kwargs={"key": key, "record": record, "env_overrides": env_overrides}, daemon=True
    ).start()
    # 2. the window (dumb relay between the box socket and the eyes)
    box_listener = make_listener(box_socket, family=socket.AF_UNIX)
    threading.Thread(
        target=serve, args=(box_listener, core_socket), kwargs={"family": socket.AF_UNIX}, daemon=True
    ).start()
    time.sleep(0.2)  # let the listeners settle before the box dials out

    # 3. the box: the agent inside, its only way out the broker socket.
    argv = pub_os_box.build_box_argv(agent_argv, project_root=str(project_root), broker_socket=box_socket)
    return subprocess.run(argv).returncode


def main(argv: "list[str] | None" = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        sys.stderr.write("usage: pub_run.py <project_root> <agent_cmd> [args...]\n")
        return 2
    project_root, *agent = args
    try:
        return run(agent, project_root=project_root)
    except RuntimeError as exc:
        sys.stderr.write(f"pub run: {exc}\n")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
