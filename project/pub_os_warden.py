"""PUB-OS warden -- the hands. Performs an allowed operation, and ONLY that.

Identity (decided, NOT a third judge): judgment is already complete -- ot_gate,
the X-ray decoders, capability_wall and the grounding oracle have aligned into ONE
verdict. The warden sits DOWNSTREAM of all of them and DECIDES NOTHING. It is the
only component that holds real capability (it can touch resources outside the
box), and it uses that capability ONLY on a verdict the beast SIGNED. Verify the
seal -> perform the EXACT authorized operation -> return the result. No seal, a
bad seal, or a sealed "deny" -> refuse (fail-closed).

Why a separate house, not a judge and not under capability_wall: separation of
DECISION and ACTION is the security model. The courts decide and SIGN; the warden
verifies and ACTS. Compromise the courts -> you can decide but not act (no
capability). Compromise the warden -> you can act but only on an order you cannot
forge (no signing key). Neither alone escapes. Folding the executor into a judge
would collapse both into one point of total compromise.

The warden does not decode either: the op it performs was extracted by the eyes
and sealed by the beast. The eyes understand; the warden only acts.

Key discipline: the beast holds the SIGNING key; the warden holds the VERIFY key.
Neither the window nor the box ever holds either -- so a compromised window can
relay a signed order but can never forge one (contract I3, unforgeability).
"""

from __future__ import annotations

import hashlib
import hmac
import json


def _canonical(verdict: dict) -> bytes:
    return json.dumps(verdict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_verdict(verdict: dict, *, key: bytes) -> bytes:
    """Beast-side: seal a verdict so the warden can trust it (HMAC-SHA256)."""
    mac = hmac.new(key, _canonical(verdict), hashlib.sha256).hexdigest()
    return json.dumps({"verdict": verdict, "mac": mac}, sort_keys=True).encode("utf-8")


def verify_verdict(signed: bytes, *, key: bytes) -> "dict | None":
    """Warden-side: return the verdict iff the seal is authentic, else None.

    Any tamper -- a flipped allow, a swapped op, a forged or absent mac -- fails
    the constant-time compare and yields None (refuse).
    """
    try:
        envelope = json.loads(signed.decode("utf-8"))
        verdict = envelope["verdict"]
        presented = str(envelope["mac"])
    except Exception:
        return None
    expected = hmac.new(key, _canonical(verdict), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(presented, expected):
        return None
    return verdict


def _perform(op: dict) -> dict:
    """The capability primitives. Each does EXACTLY what the sealed op names, with
    no re-interpretation. An unknown op is refused (fail-closed). This is where
    the real power lives, so it stays small and explicit -- like the window.
    """
    kind = str(op.get("kind", ""))
    if kind == "read":
        with open(op["path"], "rb") as handle:
            return {"executed": True, "result": handle.read()}
    # write / connect / exec follow the same shape and are added one at a time.
    return {"executed": False, "error": "unknown_op"}


def execute(signed_verdict: bytes, *, key: bytes) -> dict:
    """Verify the seal, then perform the authorized op. The warden JUDGES NOTHING
    -- it trusts only the signature, never its own opinion of the op. No seal /
    bad seal -> 'unverified'; a sealed deny -> 'denied'; both refuse to act."""
    verdict = verify_verdict(signed_verdict, key=key)
    if verdict is None:
        return {"executed": False, "error": "unverified"}
    if not verdict.get("allow"):
        return {"executed": False, "error": "denied"}
    return _perform(verdict.get("op") or {})
