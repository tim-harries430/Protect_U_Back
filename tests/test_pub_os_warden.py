"""Contract tests for the warden (pub_os_warden) -- the verified executor.

The warden acts ONLY on a beast-signed verdict, performs exactly the sealed op,
and judges nothing. Forgery / tamper / a sealed deny -> it refuses to act.
"""

from __future__ import annotations

import json

from pub_os_core import authorize
from pub_os_warden import execute, sign_verdict

KEY = b"beast-and-warden-shared-secret"
OTHER = b"not-the-key"


def _read_op(path):
    return {"kind": "read", "path": str(path)}


# --- acts on a valid sealed allow ------------------------------------------- #

def test_warden_executes_a_sealed_allow(tmp_path):
    target = tmp_path / "data.txt"
    target.write_bytes(b"payload")
    sealed = sign_verdict({"allow": True, "op": _read_op(target)}, key=KEY)
    result = execute(sealed, key=KEY)
    assert result["executed"] is True
    assert result["result"] == b"payload"


# --- refuses anything it cannot verify -------------------------------------- #

def test_warden_refuses_unsigned_verdict(tmp_path):
    target = tmp_path / "x.txt"
    target.write_bytes(b"secret")
    raw = json.dumps({"verdict": {"allow": True, "op": _read_op(target)}, "mac": "deadbeef"}).encode()
    result = execute(raw, key=KEY)
    assert result["executed"] is False and result["error"] == "unverified"


def test_warden_refuses_forged_signature(tmp_path):
    target = tmp_path / "x.txt"
    target.write_bytes(b"secret")
    sealed = sign_verdict({"allow": True, "op": _read_op(target)}, key=OTHER)  # wrong key
    assert execute(sealed, key=KEY) == {"executed": False, "error": "unverified"}


def test_warden_refuses_tampered_op(tmp_path):
    allowed = tmp_path / "allowed.txt"; allowed.write_bytes(b"ok")
    forbidden = tmp_path / "forbidden.txt"; forbidden.write_bytes(b"DO_NOT_READ")
    sealed = sign_verdict({"allow": True, "op": _read_op(allowed)}, key=KEY)
    envelope = json.loads(sealed)
    envelope["verdict"]["op"]["path"] = str(forbidden)  # redirect the op, keep old mac
    tampered = json.dumps(envelope).encode()
    result = execute(tampered, key=KEY)
    assert result["executed"] is False  # the seal protects the op, not just allow


def test_warden_refuses_tampered_allow(tmp_path):
    target = tmp_path / "x.txt"; target.write_bytes(b"secret")
    sealed = sign_verdict({"allow": False, "op": _read_op(target)}, key=KEY)
    envelope = json.loads(sealed)
    envelope["verdict"]["allow"] = True  # flip deny -> allow, keep old mac
    tampered = json.dumps(envelope).encode()
    assert execute(tampered, key=KEY)["executed"] is False


def test_warden_refuses_sealed_deny(tmp_path):
    target = tmp_path / "x.txt"; target.write_bytes(b"secret")
    sealed = sign_verdict({"allow": False, "op": _read_op(target)}, key=KEY)
    assert execute(sealed, key=KEY) == {"executed": False, "error": "denied"}


# --- the warden does NOT judge (separation of decision and action) ---------- #

def test_warden_executes_a_dangerous_op_if_validly_sealed(tmp_path):
    # A dangerous-LOOKING op (a file named like a secret). The warden has NO
    # opinion: if the beast sealed allow, it acts. Safety is the beast's job.
    secretish = tmp_path / ".env"
    secretish.write_bytes(b"API_KEY=xyz")
    sealed = sign_verdict({"allow": True, "op": _read_op(secretish)}, key=KEY)
    assert execute(sealed, key=KEY)["result"] == b"API_KEY=xyz"


# --- the beast -> warden chain ---------------------------------------------- #

def test_beast_authorizes_benign_then_warden_executes(tmp_path):
    target = tmp_path / "report.md"; target.write_bytes(b"hello")
    sealed = authorize(f"cat {target}", str(tmp_path), _read_op(target), key=KEY)
    assert execute(sealed, key=KEY)["result"] == b"hello"


def test_beast_denies_dangerous_then_warden_refuses(tmp_path):
    target = tmp_path / "report.md"; target.write_bytes(b"hello")
    # the request is opaque/blocked -> beast seals a DENY -> warden never reads.
    sealed = authorize("python3.11 -c 'evil'", str(tmp_path), _read_op(target), key=KEY)
    assert execute(sealed, key=KEY) == {"executed": False, "error": "denied"}
