"""PUB-OS out-of-cage ledger (Task 3).

The audit ledger is pub's memory and evidence. If the thing that can write it
lives inside the agent cage, the agent can reach it -- so the witness must sit
OUTSIDE the cell. This module splits the ledger in two:

  * ``LedgerSupervisor`` runs OUTSIDE the cage and is the ONLY writer. The ledger
    file lives outside the cage and is never bind-mounted in, so no in-cage
    process can open, truncate, or rewrite it.
  * the in-cage hook calls ``emit_event`` to push an event over a unix-domain
    socket. Only the socket node is bind-mounted into the cage; connecting to it
    lets the hook DELIVER an event, never touch the ledger file. The supervisor
    validates every event (no payload, no authority claim), stamps a monotonic
    sequence and a hash-chain link, and appends.

The hash chain makes the ledger tamper-evident even against a writer bug: each
row commits to the previous row's hash, so altering or dropping any row breaks
every link after it.

Losing the witness must TIGHTEN, never loosen: ``emit_event`` fails closed
(raises) if it cannot reach the supervisor or get an ack. The in-cage hook is
expected to map that failure to HOLD (wiring that into the hook entry is a
separate, authorized step against the original framework).
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


GENESIS_HASH = "sha256:" + "0" * 64

# Fields a ledger event may never carry. Mirrors the discipline used across the
# pub_os_* surface: a witness records, it never conveys payload or authority.
_BLOCKED_FIELDS = frozenset(
    {
        "allow",
        "body",
        "can_execute",
        "can_grant_permission",
        "content",
        "execute",
        "grant",
        "kill",
        "payload",
        "permission_granted",
        "raw_bytes",
    }
)


class LedgerEventRejected(ValueError):
    """An emitted event carried a payload or authority field."""


class LedgerUnavailable(RuntimeError):
    """The in-cage emitter could not reach the out-of-cage supervisor."""


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _reject_unsafe(event: Mapping[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in dict(event).items():
        name = str(key)
        lowered = name.lower()
        if lowered in {"can_execute", "can_grant_permission"} and value is False:
            clean[name] = False
            continue
        if lowered in _BLOCKED_FIELDS:
            raise LedgerEventRejected(f"ledger event must not include authority or payload field: {name}")
        clean[name] = value
    return clean


@dataclass
class LedgerSupervisor:
    """Out-of-cage, single-writer, append-only, hash-chained ledger server."""

    ledger_path: str
    socket_path: str
    _seq: int = 0
    _prev_hash: str = GENESIS_HASH

    def __post_init__(self) -> None:
        self.ledger_path = str(Path(self.ledger_path))
        self.socket_path = str(Path(self.socket_path))
        self._server: socket.socket | None = None
        # Resume the chain if a ledger already exists, so a restart does not fork it.
        last = self._last_row()
        if last is not None:
            self._seq = int(last.get("seq", 0))
            self._prev_hash = str(last.get("row_hash", GENESIS_HASH))

    # -- recording (the only writer) -------------------------------------

    def record(self, event: Mapping[str, Any], *, source: str = "in_cage_hook") -> dict[str, Any]:
        clean = _reject_unsafe(event)
        self._seq += 1
        row = {
            "seq": self._seq,
            "ts": time.time(),
            "source": str(source),
            "prev_hash": self._prev_hash,
            "event": clean,
            "can_execute": False,
            "can_grant_permission": False,
        }
        row_hash = _sha256(self._prev_hash + _canonical(row))
        row["row_hash"] = row_hash
        self._prev_hash = row_hash
        target = Path(self.ledger_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8", newline="") as handle:
            handle.write(_canonical(row) + "\n")
        return {"seq": self._seq, "row_hash": row_hash}

    # -- socket transport (the only thing that crosses into the cage) ----

    def start(self) -> "LedgerSupervisor":
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass
        Path(self.socket_path).parent.mkdir(parents=True, exist_ok=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(8)
        self._server = server
        return self

    def _handle(self, conn: socket.socket) -> int:
        recorded = 0
        with conn:
            data = b""
            conn.settimeout(2.0)
            try:
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    while b"\n" in data:
                        line, data = data.split(b"\n", 1)
                        if not line.strip():
                            continue
                        try:
                            event = json.loads(line.decode("utf-8"))
                            ack = self.record(event)
                            conn.sendall((_canonical({"ack": ack}) + "\n").encode("utf-8"))
                            recorded += 1
                        except (LedgerEventRejected, ValueError) as exc:
                            conn.sendall((_canonical({"rejected": str(exc)}) + "\n").encode("utf-8"))
            except socket.timeout:
                pass
        return recorded

    def drain(self, max_events: int = 1, timeout: float = 5.0) -> int:
        """Accept connections and record until ``max_events`` rows or timeout.
        Returns the number of rows recorded. Useful for single-shot / tests."""
        assert self._server is not None, "call start() first"
        recorded = 0
        self._server.settimeout(timeout)
        while recorded < max_events:
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                break
            recorded += self._handle(conn)
        return recorded

    def serve_forever(self) -> None:  # pragma: no cover - long-running loop
        assert self._server is not None, "call start() first"
        while True:
            try:
                conn, _ = self._server.accept()
            except OSError:
                break
            self._handle(conn)

    def close(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

    def serve_in_thread(self, max_events: int, timeout: float = 5.0) -> threading.Thread:
        thread = threading.Thread(target=self.drain, kwargs={"max_events": max_events, "timeout": timeout})
        thread.daemon = True
        thread.start()
        return thread

    # -- verification ----------------------------------------------------

    def rows(self) -> list[dict[str, Any]]:
        path = Path(self.ledger_path)
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def _last_row(self) -> dict[str, Any] | None:
        rows = self.rows()
        return rows[-1] if rows else None


def verify_chain(rows: list[dict[str, Any]]) -> tuple[bool, str]:
    """Recompute the hash chain. Returns (ok, reason)."""
    prev = GENESIS_HASH
    for index, row in enumerate(rows, start=1):
        if int(row.get("seq", -1)) != index:
            return False, f"seq_gap_at_row_{index}"
        if row.get("prev_hash") != prev:
            return False, f"prev_hash_mismatch_at_seq_{row.get('seq')}"
        body = {k: v for k, v in row.items() if k != "row_hash"}
        expected = _sha256(prev + _canonical(body))
        if row.get("row_hash") != expected:
            return False, f"row_hash_mismatch_at_seq_{row.get('seq')}"
        prev = row["row_hash"]
    return True, "chain_intact"


def emit_event(socket_path: str, event: Mapping[str, Any], *, timeout: float = 2.0) -> dict[str, Any]:
    """In-cage client. Deliver one event to the supervisor and return its ack.
    Fails closed: raises ``LedgerUnavailable`` on any transport failure, and
    ``LedgerEventRejected`` if the supervisor refused the event."""
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect(socket_path)
    except OSError as exc:
        raise LedgerUnavailable(f"cannot reach ledger supervisor at {socket_path}: {exc}") from exc
    with client:
        client.sendall((_canonical(dict(event)) + "\n").encode("utf-8"))
        client.shutdown(socket.SHUT_WR)
        data = b""
        try:
            while b"\n" not in data:
                chunk = client.recv(65536)
                if not chunk:
                    break
                data += chunk
        except socket.timeout as exc:
            raise LedgerUnavailable(f"no ack from ledger supervisor: {exc}") from exc
    if not data.strip():
        raise LedgerUnavailable("ledger supervisor closed without ack")
    reply = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
    if "rejected" in reply:
        raise LedgerEventRejected(str(reply["rejected"]))
    return reply.get("ack", {})
