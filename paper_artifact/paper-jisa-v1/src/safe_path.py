from __future__ import annotations

from pathlib import Path


def safe_resolve(path: str | Path) -> Path:
    """Canonical hardened path resolution for adversary-facing input.

    A hostile or malformed path (embedded null byte, symlink loop, OS error)
    must never crash the auditor. We fall back to a non-resolving absolute form
    so the caller's downstream observation (lstat / blindspot) turns the
    unresolved path into a HOLD instead of a raised exception.

    The closure rule: a path the auditor cannot resolve becomes an unobserved
    blindspot (2), never a crash into "no state".

    Use ONLY where the path originates from agent/proposal input. Trusted paths
    (project roots, ``__file__``, config) should keep raising so configuration
    errors stay loud.
    """
    candidate = Path(path)
    try:
        return candidate.resolve(strict=False)
    except (OSError, ValueError, RuntimeError):
        try:
            return candidate.absolute()
        except (OSError, ValueError, RuntimeError):
            return candidate
