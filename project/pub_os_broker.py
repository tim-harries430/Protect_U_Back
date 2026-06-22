"""PUB-OS broker -- the prison-door window. Spec: PUB_OS_BROKER_CONTRACT.md.

This is the ONLY component the confined box can reach, so it holds ZERO
authority: a relay that forwards opaque, length-framed bytes between the box and
pub-core, and nothing else. It does NOT decode payloads, judge, execute, hold
keys, or keep state. On any doubt it drops the frame and tears the stream down
(fail-closed): a broken window seals the prison, it never opens it.

Action set of this whole file: {forward a frame, drop a frame}. Nothing in it can
cause or authorize an external effect. The judge (eyes + beast) and the warden
(executor) live BEHIND this window, unreachable from the box.

Audit notes (contract clauses, verifiable by reading):
  * Opaque framing only -- a frame is HEADER_BYTES of big-endian length + that
    many payload bytes. We read the length, validate it, read the payload, and
    forward `header + payload` VERBATIM. No branch below depends on payload
    content; only on the length and on I/O success.
  * Fail-closed -- bad length / short read / write error / EOF -> return -> the
    stream is closed -> the box's in-flight request never receives a verdict.
  * No resource access beyond the two socket endpoints; no keys; no state.
"""

from __future__ import annotations

import socket
import struct
import sys
import threading

HEADER_BYTES = 4
MAX_FRAME_BYTES = 1 << 20  # 1 MiB. A confinement bound, NOT a content rule.
_LENGTH = struct.Struct("!I")
# Production transport is AF_UNIX (filesystem-permissioned, Linux sandbox) or
# AF_VSOCK (VM boundary). On a dev host without AF_UNIX (Windows) fall back so the
# module still imports; the tests pin AF_INET loopback explicitly for portability.
_DEFAULT_FAMILY = getattr(socket, "AF_UNIX", socket.AF_INET)


def _read_exact(conn: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes, or None on EOF/error. Bytes are never interpreted."""
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        try:
            chunk = conn.recv(remaining)
        except OSError:
            return None
        if not chunk:  # peer closed mid-read
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(conn: socket.socket, max_frame: int = MAX_FRAME_BYTES) -> bytes | None:
    """Return one opaque frame (header + payload) verbatim, or None.

    None means EOF / malformed length / oversized / short read -- every one of
    which the caller turns into a stream teardown (fail-closed). The payload is
    read and returned but NEVER examined: this function does not parse content.
    """
    header = _read_exact(conn, HEADER_BYTES)
    if header is None:
        return None
    (length,) = _LENGTH.unpack(header)
    if length == 0 or length > max_frame:
        return None  # malformed / oversized -> fail-closed, payload not even read
    payload = _read_exact(conn, length)
    if payload is None:
        return None
    return header + payload  # forwarded as-is


def _write_all(conn: socket.socket, data: bytes) -> bool:
    try:
        conn.sendall(data)
        return True
    except OSError:
        return False


def _pump(src: socket.socket, dst: socket.socket, max_frame: int) -> None:
    """Relay frames src -> dst until EOF/error, then return so the window seals."""
    while True:
        frame = read_frame(src, max_frame)
        if frame is None:
            return
        if not _write_all(dst, frame):
            return


def relay(
    box_conn: socket.socket,
    core_conn: socket.socket,
    *,
    max_frame: int = MAX_FRAME_BYTES,
) -> None:
    """The window: a dumb bidirectional opaque-frame relay between the box and
    pub-core. Returns when EITHER direction ends; both sockets are then closed,
    so any in-flight request is denied (fail-closed). Holds no authority -- it
    cannot decode, judge, execute, or forge."""
    done = threading.Event()

    def run(src: socket.socket, dst: socket.socket) -> None:
        try:
            _pump(src, dst, max_frame)
        finally:
            done.set()

    threads = [
        threading.Thread(target=run, args=(box_conn, core_conn), daemon=True),
        threading.Thread(target=run, args=(core_conn, box_conn), daemon=True),
    ]
    for thread in threads:
        thread.start()
    done.wait()
    # One direction ended -> seal the window so the other side reads EOF too.
    for conn in (box_conn, core_conn):
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass
    for thread in threads:
        thread.join(timeout=1.0)


def make_listener(box_address, *, family: int = _DEFAULT_FAMILY) -> socket.socket:
    """Bind + listen the box-facing endpoint -- the box's ONLY egress.

    Production transport is AF_UNIX (filesystem-permissioned) or AF_VSOCK (VM
    boundary); AF_INET loopback is used only by the tests for portability.
    """
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.bind(box_address)
    listener.listen()
    return listener


def serve(
    listener: socket.socket,
    core_address,
    *,
    family: int = _DEFAULT_FAMILY,
    max_frame: int = MAX_FRAME_BYTES,
    accept_limit: int | None = None,
) -> None:
    """Wiring: accept a box connection (its only way out), open a FRESH connection
    to pub-core, and relay. Per-stream teardown: a bad frame seals that one
    request stream, not the listener. core_address is FIXED host-side config --
    never derived from box content."""
    served = 0
    while accept_limit is None or served < accept_limit:
        box_conn, _ = listener.accept()
        served += 1
        core_conn = socket.socket(family, socket.SOCK_STREAM)
        try:
            core_conn.connect(core_address)
        except OSError:
            box_conn.close()  # core unreachable -> seal this stream (fail-closed)
            core_conn.close()
            continue
        threading.Thread(
            target=relay,
            args=(box_conn, core_conn),
            kwargs={"max_frame": max_frame},
            daemon=True,
        ).start()


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        sys.stderr.write("usage: pub_os_broker.py <box_socket_path> <core_socket_path>\n")
        return 2
    box_path, core_path = args
    listener = make_listener(box_path, family=_DEFAULT_FAMILY)
    try:
        serve(listener, core_path, family=_DEFAULT_FAMILY)
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
