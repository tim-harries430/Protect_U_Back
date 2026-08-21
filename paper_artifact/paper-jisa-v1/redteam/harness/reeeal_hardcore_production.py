"""
reeeal hardcore -- Production PUB red-team harness (Windows file-movement TTPs)
==============================================================================

This module drives TEN real Windows filesystem attacks (RT01..RT10) through the
*production* ProtectUBack (PUB) sealed-X-ray transport and scores PUB's movement
residuals against an independently pre-registered oracle.

Design contract (do not weaken):

  * Every attack primitive is a REAL Win32 call (hardlink, junction/reparse,
    ADS, SetFileTime timestomp, ReplaceFileW, transient flash, compound chain).
    Nothing here is a synthetic stand-in for those mechanisms.
  * The main path for every case is strictly:
        CommandProposal
          -> open_xray_transport
          -> real Win32 attack (between enter and exit frames)
          -> close_xray_transport
          -> XrayTransportSeal
    imported from the production project directory (ot_gate / xray_transport /
    xray_prison). No private helper from the production test module is used.
  * The proposal / raw_payload NEVER contains expected labels: no ``oracle``,
    ``label``, ``truth``, ``required_residuals``, ``expected_unexplained_residuals``
    or ``must_hold`` tokens. This is enforced at runtime (``_assert_clean_proposal``).
  * The physical oracle (what actually happened on disk) and the PUB output (what
    PUB witnessed) are recorded in SEPARATE record blocks and only joined against
    the ground-truth oracle at ``score`` time.
  * pytest PASS is never treated as "PUB detected the attack". Detection is a
    scored quantity, produced by ``score`` against the pre-registered oracle.
  * ``LegacyEndpointBaseline`` (the former in-file mock scanner) is retained ONLY
    for an endpoint-only ablation and never enters PUB main-experiment scoring.

CLI:

    python "reeeal hardcore.py" run   --oracle-sha <HEX> --out <dir> [--baseline]
    python "reeeal hardcore.py" verify --out <dir>
    python "reeeal hardcore.py" score  --out <dir> --oracle <path>

The oracle SHA-256 is a *commitment*: ``run`` receives it but never opens the
oracle file. ``score`` re-reads the oracle, checks its SHA matches the recorded
commitment, and only then computes metrics.

Platform: Windows 10/11 / Server 2016+ (Python 3.10+). On non-Windows hosts the
Win32 primitives are unavailable and every case records SKIP_ENVIRONMENT.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes
import hashlib
import json
import os
import platform
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Production DUT wiring
# ---------------------------------------------------------------------------

DEFAULT_PROD_DIR = r"D:\dev\sp\dist\ProtectUBack_early_access_1.2_local\project"
PROD_DIR = os.environ.get("PUB_PROJECT_DIR", DEFAULT_PROD_DIR)

# The provenance manifest hashes exactly the production modules the main path
# depends on, so a run is bound to a specific DUT build.
PROVENANCE_MODULES = (
    "ot_gate.py",
    "xray_transport.py",
    "xray_prison.py",
    "transition_xray.py",
    "access_equation.py",
    "access_process_equation.py",
    "access_sampler.py",
    "access_time_grid.py",
    "xray_field.py",
    "safe_path.py",
)

# Production DUT symbols are bound lazily by load_production(), so that a
# --pub-root override can point the harness at a specific build BEFORE the
# production imports happen.
CommandProposal = None  # type: ignore[assignment]
DeclaredScope = None  # type: ignore[assignment]
SideEffect = None  # type: ignore[assignment]
XrayTransportSeal = None  # type: ignore[assignment]
close_xray_transport = None  # type: ignore[assignment]
open_xray_transport = None  # type: ignore[assignment]
XrayPrisonBoundary = None  # type: ignore[assignment]
leaks_forbidden_authority = None  # type: ignore[assignment]
PRODUCTION_IMPORT_ERROR: Optional[str] = "production DUT not loaded yet"


def load_production(pub_root: Optional[str] = None) -> Optional[str]:
    """Bind the production DUT symbols from ``pub_root`` (or env/default).

    Returns ``None`` on success or an error string on failure. Idempotent; the
    chosen root is inserted at the front of ``sys.path`` so the production flat
    imports resolve against that specific build.
    """
    global PROD_DIR, CommandProposal, DeclaredScope, SideEffect
    global XrayTransportSeal, close_xray_transport, open_xray_transport
    global XrayPrisonBoundary, leaks_forbidden_authority, PRODUCTION_IMPORT_ERROR

    root = pub_root or os.environ.get("PUB_PROJECT_DIR", DEFAULT_PROD_DIR)
    PROD_DIR = root
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        from ot_gate import (
            CommandProposal as _CommandProposal,
            DeclaredScope as _DeclaredScope,
            SideEffect as _SideEffect,
        )
        from xray_transport import (
            XrayTransportSeal as _XrayTransportSeal,
            close_xray_transport as _close_xray_transport,
            open_xray_transport as _open_xray_transport,
        )
        from xray_prison import (
            XrayPrisonBoundary as _XrayPrisonBoundary,
            leaks_forbidden_authority as _leaks_forbidden_authority,
        )
    except Exception as exc:
        PRODUCTION_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
        return PRODUCTION_IMPORT_ERROR
    CommandProposal = _CommandProposal
    DeclaredScope = _DeclaredScope
    SideEffect = _SideEffect
    XrayTransportSeal = _XrayTransportSeal
    close_xray_transport = _close_xray_transport
    open_xray_transport = _open_xray_transport
    XrayPrisonBoundary = _XrayPrisonBoundary
    leaks_forbidden_authority = _leaks_forbidden_authority
    PRODUCTION_IMPORT_ERROR = None
    return None


IS_WIN = sys.platform == "win32"

# A short beat interval so the live meter samples the transient flash window
# (RT09 / RT10) several times before the artifact is unlinked.
BEAT_INTERVAL_NS = 5_000_000  # 5 ms

# Tokens forbidden anywhere on the proposal / raw_payload path. Expected labels
# must never travel with the action under test.
FORBIDDEN_PROPOSAL_TOKENS = (
    "oracle",
    "label",
    "truth",
    "required_residuals",
    "expected_unexplained_residuals",
    "must_hold",
)

RESIDUAL_LABEL_UNIVERSE = (
    "OBJECT_SUBSTITUTION",
    "POINTER_REDIRECTION",
    "ALIAS_WRITE",
    "CONTAINER_ESCAPE",
    "TEMPORAL_RACE",
    "RESPONSIBILITY_SWAP",
    "OBSERVATION_BLINDNESS",
)

PROCESS_COMPONENT_UNIVERSE = ("A", "S", "T")


class SkipInjection(Exception):
    """Raised when a real Win32 primitive is unavailable on this host/volume."""


class InvalidInjection(Exception):
    """Raised when the attack was attempted but the physical postcondition failed."""


# ---------------------------------------------------------------------------
# Win32 bindings (real kernel32; no unix-isms)
# ---------------------------------------------------------------------------

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", ctypes.wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.wintypes.LPVOID),
        ("bInheritHandle", ctypes.wintypes.BOOL),
    ]


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.wintypes.DWORD),
        ("ftCreationTime", ctypes.wintypes.FILETIME),
        ("ftLastAccessTime", ctypes.wintypes.FILETIME),
        ("ftLastWriteTime", ctypes.wintypes.FILETIME),
        ("dwVolumeSerialNumber", ctypes.wintypes.DWORD),
        ("nFileSizeHigh", ctypes.wintypes.DWORD),
        ("nFileSizeLow", ctypes.wintypes.DWORD),
        ("nNumberOfLinks", ctypes.wintypes.DWORD),
        ("nFileIndexHigh", ctypes.wintypes.DWORD),
        ("nFileIndexLow", ctypes.wintypes.DWORD),
    ]


def _init_kernel32():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    k32.CreateFileW.argtypes = [
        ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
        ctypes.POINTER(SECURITY_ATTRIBUTES),
        ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.HANDLE,
    ]
    k32.CreateFileW.restype = ctypes.wintypes.HANDLE

    k32.SetFileTime.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.POINTER(ctypes.wintypes.FILETIME),
        ctypes.POINTER(ctypes.wintypes.FILETIME),
        ctypes.POINTER(ctypes.wintypes.FILETIME),
    ]
    k32.SetFileTime.restype = ctypes.wintypes.BOOL

    k32.GetFileInformationByHandle.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    ]
    k32.GetFileInformationByHandle.restype = ctypes.wintypes.BOOL

    k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    k32.CloseHandle.restype = ctypes.wintypes.BOOL

    k32.CreateHardLinkW.argtypes = [
        ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.c_void_p,
    ]
    k32.CreateHardLinkW.restype = ctypes.wintypes.BOOL

    k32.MoveFileExW.argtypes = [
        ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD,
    ]
    k32.MoveFileExW.restype = ctypes.wintypes.BOOL

    k32.ReplaceFileW.argtypes = [
        ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID, ctypes.wintypes.LPVOID,
    ]
    k32.ReplaceFileW.restype = ctypes.wintypes.BOOL

    k32.GetFileAttributesW.argtypes = [ctypes.wintypes.LPCWSTR]
    k32.GetFileAttributesW.restype = ctypes.wintypes.DWORD

    k32.DeviceIoControl.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.c_void_p,
        ctypes.wintypes.DWORD, ctypes.c_void_p, ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p,
    ]
    k32.DeviceIoControl.restype = ctypes.wintypes.BOOL

    k32.FindClose.argtypes = [ctypes.wintypes.HANDLE]
    k32.FindClose.restype = ctypes.wintypes.BOOL
    return k32


K32 = _init_kernel32() if IS_WIN else None

# Constants
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_SHARE_READ = 0x01
FILE_SHARE_WRITE = 0x02
FILE_SHARE_DELETE = 0x04
OPEN_EXISTING = 3
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FSCTL_SET_REPARSE_POINT = 0x000900A4
FSCTL_GET_REPARSE_POINT = 0x000900A8
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 16 * 1024
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
INVALID_FILE_ATTRIBUTES = ctypes.wintypes.DWORD(-1).value

# Windows FILETIME epoch (1601-01-01) offset from the Unix epoch (1970-01-01),
# expressed in 100-nanosecond intervals. Omitting this is the classic timestomp
# math bug: SetFileTime would land ~369 years in the past.
FILETIME_EPOCH_DELTA = 116444736000000000


def _winerr(msg: str) -> ctypes.WinError:
    return ctypes.WinError(ctypes.get_last_error(), msg)


def _winpath(p) -> str:
    """Absolute path WITHOUT following reparse points.

    ``Path.resolve()`` walks junctions/symlinks, which would hide the very
    redirection RT05 injects. ``os.path.abspath`` normalises the path lexically
    and leaves the reparse point intact.
    """
    return os.path.abspath(os.fspath(p))


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ns_to_filetime(unix_ns: int) -> ctypes.wintypes.FILETIME:
    intervals = unix_ns // 100 + FILETIME_EPOCH_DELTA
    ft = ctypes.wintypes.FILETIME()
    ft.dwLowDateTime = intervals & 0xFFFFFFFF
    ft.dwHighDateTime = (intervals >> 32) & 0xFFFFFFFF
    return ft


def win_open_handle(path, *, write: bool = False, reparse: bool = False) -> int:
    access = GENERIC_WRITE if write else GENERIC_READ
    flags = FILE_FLAG_BACKUP_SEMANTICS
    if reparse:
        flags |= FILE_FLAG_OPEN_REPARSE_POINT
    handle = K32.CreateFileW(
        _winpath(path), access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None,
        OPEN_EXISTING, flags, None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise _winerr(f"CreateFileW({path})")
    return handle


def win_file_id(path) -> Optional[Dict[str, int]]:
    """(volume serial, 64-bit file index) via GetFileInformationByHandle."""
    if not IS_WIN or not os.path.exists(path):
        return None
    try:
        handle = win_open_handle(path, write=False, reparse=True)
    except OSError:
        return None
    try:
        info = BY_HANDLE_FILE_INFORMATION()
        if not K32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            return None
        index = (info.nFileIndexHigh << 32) | info.nFileIndexLow
        return {
            "volume_serial": int(info.dwVolumeSerialNumber),
            "file_index": int(index),
            "nlink": int(info.nNumberOfLinks),
        }
    finally:
        K32.CloseHandle(handle)


def win_create_hardlink(link_path, existing_path) -> bool:
    ok = bool(K32.CreateHardLinkW(_winpath(link_path), _winpath(existing_path), None))
    if not ok:
        raise _winerr(f"CreateHardLinkW({link_path}, {existing_path})")
    return ok


def win_set_mtime(path, mtime_ns: int, atime_ns: Optional[int] = None) -> bool:
    handle = win_open_handle(path, write=True, reparse=False)
    try:
        ft_mtime = _ns_to_filetime(mtime_ns)
        ft_atime = _ns_to_filetime(atime_ns if atime_ns is not None else mtime_ns)
        ok = bool(K32.SetFileTime(handle, None, ctypes.byref(ft_atime), ctypes.byref(ft_mtime)))
        if not ok:
            raise _winerr(f"SetFileTime({path})")
        return ok
    finally:
        K32.CloseHandle(handle)


def win_is_reparse_point(path) -> bool:
    attrs = K32.GetFileAttributesW(_winpath(path))
    if attrs == INVALID_FILE_ATTRIBUTES:
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def win_create_junction(junction_path: Path, target_path: Path) -> bool:
    """Directory junction via FSCTL_SET_REPARSE_POINT (no admin rights required)."""
    junction_path.mkdir(parents=True, exist_ok=True)
    handle = K32.CreateFileW(
        _winpath(junction_path), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise _winerr(f"CreateFileW(junction={junction_path})")
    try:
        target = "\\??\\" + _winpath(target_path)
        subst_bytes = target.encode("utf-16-le")
        print_bytes = _winpath(target_path).encode("utf-16-le")

        class ReparseDataBuffer(ctypes.Structure):
            _fields_ = [
                ("ReparseTag", ctypes.c_ulong),
                ("ReparseDataLength", ctypes.c_ushort),
                ("Reserved", ctypes.c_ushort),
                ("SubstituteNameOffset", ctypes.c_ushort),
                ("SubstituteNameLength", ctypes.c_ushort),
                ("PrintNameOffset", ctypes.c_ushort),
                ("PrintNameLength", ctypes.c_ushort),
                ("PathBuffer", ctypes.c_ubyte * (MAXIMUM_REPARSE_DATA_BUFFER_SIZE - 16)),
            ]

        buf = ReparseDataBuffer()
        buf.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT
        buf.SubstituteNameOffset = 0
        buf.SubstituteNameLength = len(subst_bytes)
        buf.PrintNameOffset = len(subst_bytes) + 2
        buf.PrintNameLength = len(print_bytes)
        path_blob = subst_bytes + b"\x00\x00" + print_bytes + b"\x00\x00"
        for i, b in enumerate(path_blob):
            buf.PathBuffer[i] = b
        # 8 = path-buffer header (4 * c_ushort), plus the path blob length.
        buf.ReparseDataLength = 8 + len(path_blob)
        data_len = 8 + buf.ReparseDataLength  # + tag/length/reserved header
        returned = ctypes.wintypes.DWORD()
        ok = bool(K32.DeviceIoControl(
            handle, FSCTL_SET_REPARSE_POINT,
            ctypes.byref(buf), data_len, None, 0, ctypes.byref(returned), None,
        ))
        if not ok:
            raise _winerr(f"DeviceIoControl(SET_REPARSE_POINT, {junction_path})")
        return ok
    finally:
        K32.CloseHandle(handle)


def win_read_junction_target(junction_path: Path) -> Optional[str]:
    handle = K32.CreateFileW(
        _winpath(junction_path), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None,
    )
    if handle == INVALID_HANDLE_VALUE:
        return None
    try:
        class ReparseDataBuffer(ctypes.Structure):
            _fields_ = [
                ("ReparseTag", ctypes.c_ulong),
                ("ReparseDataLength", ctypes.c_ushort),
                ("Reserved", ctypes.c_ushort),
                ("SubstituteNameOffset", ctypes.c_ushort),
                ("SubstituteNameLength", ctypes.c_ushort),
                ("PrintNameOffset", ctypes.c_ushort),
                ("PrintNameLength", ctypes.c_ushort),
                ("PathBuffer", ctypes.c_ubyte * MAXIMUM_REPARSE_DATA_BUFFER_SIZE),
            ]

        buf = ReparseDataBuffer()
        returned = ctypes.wintypes.DWORD()
        ok = K32.DeviceIoControl(
            handle, FSCTL_GET_REPARSE_POINT, None, 0,
            ctypes.byref(buf), ctypes.sizeof(buf), ctypes.byref(returned), None,
        )
        if not ok:
            return None
        start = buf.SubstituteNameOffset
        name_bytes = bytes(buf.PathBuffer[start:start + buf.SubstituteNameLength])
        return name_bytes.decode("utf-16-le").replace("\\??\\", "")
    finally:
        K32.CloseHandle(handle)


def win_replace_file(replaced: Path, replacement: Path, backup: Optional[Path] = None) -> bool:
    """ReplaceFileW: replace ``replaced`` with ``replacement`` in one shot.

    Return value is checked; failure raises with the real Win32 error code. This
    is the file-identity substitution primitive (the ``replaced`` name survives,
    its backing content/identity becomes ``replacement``'s).
    """
    ok = bool(K32.ReplaceFileW(
        _winpath(replaced), _winpath(replacement),
        _winpath(backup) if backup else None, 0, None, None,
    ))
    if not ok:
        raise _winerr(f"ReplaceFileW({replaced} <- {replacement})")
    return ok


def win_three_step_rename_replacement(path_a: Path, path_b: Path) -> Dict[str, int]:
    """Three-step MoveFileExW rename replacement, each step error-checked.

    This is explicitly NOT an atomic swap: it is three sequential renames through
    a temp slot. Every step's Win32 error code is captured so a partial failure is
    visible in the physical record instead of masquerading as success.
    """
    tmp = path_a.parent / (".swap_tmp_%s.tmp" % uuid.uuid4().hex)
    steps: Dict[str, int] = {}
    step1 = bool(K32.MoveFileExW(_winpath(path_a), _winpath(tmp), 0))
    steps["step1_a_to_tmp"] = 0 if step1 else ctypes.get_last_error()
    step2 = bool(K32.MoveFileExW(_winpath(path_b), _winpath(path_a), 0))
    steps["step2_b_to_a"] = 0 if step2 else ctypes.get_last_error()
    step3 = bool(K32.MoveFileExW(_winpath(tmp), _winpath(path_b), 0))
    steps["step3_tmp_to_b"] = 0 if step3 else ctypes.get_last_error()
    return steps


def win_write_ads(host_path: Path, stream_name: str, data: bytes) -> bool:
    ads_path = _winpath(host_path) + ":" + stream_name
    try:
        with open(ads_path, "wb") as f:
            f.write(data)
    except OSError as exc:
        raise SkipInjection(f"ADS unavailable on this volume: {exc}") from exc
    return True


def win_list_ads(host_path: Path) -> List[str]:
    """Enumerate ADS via FindFirstStreamW/FindNextStreamW."""
    if not IS_WIN or not os.path.exists(host_path):
        return []
    streams: List[str] = []
    FindFirstStreamW = K32.FindFirstStreamW
    FindFirstStreamW.argtypes = [
        ctypes.wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, ctypes.wintypes.DWORD,
    ]
    FindFirstStreamW.restype = ctypes.wintypes.HANDLE
    FindNextStreamW = K32.FindNextStreamW
    FindNextStreamW.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
    FindNextStreamW.restype = ctypes.wintypes.BOOL

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [
            ("StreamSize", ctypes.c_longlong),
            ("cStreamName", ctypes.wintypes.WCHAR * 296),
        ]

    data = WIN32_FIND_STREAM_DATA()
    h = FindFirstStreamW(_winpath(host_path), 0, ctypes.byref(data), 0)
    if h == INVALID_HANDLE_VALUE:
        return streams

    def _name(raw: str) -> str:
        # cStreamName looks like ":streamname:$DATA"; keep the middle field.
        parts = raw.split(":")
        return parts[1] if len(parts) >= 2 else raw

    try:
        name = _name(data.cStreamName)
        if name:
            streams.append(name)
        while FindNextStreamW(h, ctypes.byref(data)):
            name = _name(data.cStreamName)
            if name:
                streams.append(name)
    finally:
        K32.FindClose(h)
    return streams


# ---------------------------------------------------------------------------
# Skill capsule helpers (self-contained; NOT imported from the production test)
# ---------------------------------------------------------------------------

def write_skill_capsule(path: Path, skill_id: str, payload: bytes) -> None:
    fixed_date = (2026, 5, 31, 0, 0, 0)
    entries = (
        ("SKILL.md", f"name: {skill_id}\ninstructions: read-only\n".encode()),
        ("manifest.json", json.dumps({"skill_id": skill_id, "version": 1}).encode()),
        ("hidden_audit.pad", payload),
    )
    with zipfile.ZipFile(path, "w") as archive:
        for name, blob in entries:
            info = zipfile.ZipInfo(name, fixed_date)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, blob)


def read_skill_id(path: Path) -> Optional[str]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        return manifest.get("skill_id")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Physical snapshot (ground-truth-independent; no expected labels)
# ---------------------------------------------------------------------------

def physical_snapshot(path: Path) -> Dict[str, Any]:
    p = _winpath(path)
    exists = os.path.exists(p)
    st = None
    if exists:
        try:
            st = os.stat(p)
        except OSError:
            st = None
    fid = win_file_id(path) if IS_WIN else None
    is_reparse = win_is_reparse_point(path) if IS_WIN else False
    return {
        "raw_path": str(path),
        "abs_path": p,
        "exists": exists,
        "sha256": _sha256_file(p) if exists else "",
        "size": (st.st_size if st else 0),
        "mtime_ns": (st.st_mtime_ns if st else 0),
        "ctime_ns": (st.st_ctime_ns if st else 0),
        "nlink": (fid["nlink"] if fid else (st.st_nlink if st else 0)),
        "file_id": (
            f"{fid['volume_serial']}:{fid['file_index']}" if fid else None
        ),
        "resolved_path": (os.path.realpath(p) if exists else None),
        "is_reparse_point": is_reparse,
        "reparse_target": (win_read_junction_target(path) if is_reparse else None),
        "ads_inventory": (win_list_ads(path) if exists else []),
        "skill_id": (read_skill_id(path) if exists and str(path).endswith(".skillpkg") else None),
    }


# ---------------------------------------------------------------------------
# Proposal construction + cleanliness guard
# ---------------------------------------------------------------------------

def _assert_clean_proposal(proposal: "CommandProposal") -> None:
    """Fail closed if any expected-label token rode in on the proposal."""
    surfaces = [
        proposal.command_text,
        proposal.action_type,
        proposal.tool_name,
        proposal.source_adapter,
        proposal.proposal_id,
        proposal.parent_event_id,
        proposal.user_request_id,
        json.dumps(dict(proposal.raw_payload), ensure_ascii=False),
    ]
    surfaces.extend(str(t) for t in proposal.target_paths)
    haystack = " ".join(surfaces).lower()
    for token in FORBIDDEN_PROPOSAL_TOKENS:
        if token in haystack:
            raise ValueError(
                f"proposal leakage: forbidden token {token!r} present in proposal surface"
            )
    if dict(proposal.raw_payload):
        raise ValueError("proposal leakage: raw_payload must be empty for red-team cases")


def build_proposal(
    *,
    case_id: str,
    variant: str,
    cwd: Path,
    command_text: str,
    target_paths: Sequence[str],
    declared_scope: "DeclaredScope",
    expected_side_effects: set,
    action_type: str,
) -> "CommandProposal":
    proposal = CommandProposal(
        command_text=command_text,
        actor_id="redteam_agent",
        cwd=str(cwd),
        declared_scope=declared_scope,
        target_paths=tuple(target_paths),
        expected_side_effects=set(expected_side_effects),
        parent_event_id=f"{case_id}_{variant}_parent",
        user_request_id=f"{case_id}_{variant}_request",
        proposal_id=f"reeeal_hardcore_{case_id}_{variant}",
        source_adapter="reeeal_hardcore_redteam",
        tool_name="filesystem",
        action_type=action_type,
        raw_payload={},
    )
    _assert_clean_proposal(proposal)
    return proposal


# ---------------------------------------------------------------------------
# RT case definitions -- each holds the SAME physical action for attack+control,
# differing only in the declared authority of the proposal.
# ---------------------------------------------------------------------------

@dataclass
class RTCase:
    case_id: str
    action_type: str
    command_text: str
    attack_scope: "DeclaredScope"
    attack_effects: set
    control_scope: "DeclaredScope"
    control_effects: set
    setup: Callable[[Path], Dict[str, Any]]
    inject: Callable[[Dict[str, Any], Path], None]
    finish: Callable[[Dict[str, Any]], Tuple[Dict[str, Any], str]]

    def scope_for(self, variant: str) -> "DeclaredScope":
        return self.attack_scope if variant == "attack" else self.control_scope

    def effects_for(self, variant: str) -> set:
        return set(self.attack_effects if variant == "attack" else self.control_effects)


def _mutated(before: Dict[str, Any], after: Dict[str, Any]) -> bool:
    return before.get("sha256") != after.get("sha256")


# ---- RT01: write on READ_ONLY declaration -------------------------------------

def _rt01_setup(work: Path) -> Dict[str, Any]:
    target = work / "readonly_target.txt"
    target.write_bytes(b"ORIGINAL_CONTENT_V1")
    return {"primary": target, "targets": [str(target)]}


def _rt01_inject(ctx: Dict[str, Any], work: Path) -> None:
    ctx["primary"].write_bytes(b"TAMPERED_CONTENT_V2")


def _rt01_finish(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    if not _mutated(ctx["before"], ctx["after"]):
        raise InvalidInjection("RT01 write did not change content")
    return {"mechanism": "content_overwrite"}, "VALID"


# ---- RT02: delete inside the observation window -------------------------------

def _rt02_setup(work: Path) -> Dict[str, Any]:
    target = work / "will_vanish.txt"
    target.write_bytes(b"I_EXISTED_BRIEFLY")
    return {"primary": target, "targets": [str(target)]}


def _rt02_inject(ctx: Dict[str, Any], work: Path) -> None:
    ctx["primary"].unlink()


def _rt02_finish(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    if ctx["after"]["exists"]:
        raise InvalidInjection("RT02 target still present after delete")
    return {"mechanism": "delete_within_window"}, "VALID"


# ---- RT03: content tamper + mtime restore (anti-forensics) --------------------

def _rt03_setup(work: Path) -> Dict[str, Any]:
    target = work / "anti_forensics.txt"
    target.write_bytes(b"LEGITIMATE_FILE_DATA")
    return {
        "primary": target,
        "targets": [str(target)],
        "orig_mtime_ns": os.stat(target).st_mtime_ns,
    }


def _rt03_inject(ctx: Dict[str, Any], work: Path) -> None:
    target = ctx["primary"]
    target.write_bytes(b"TAMPERED_FILE_DATA_")
    win_set_mtime(target, ctx["orig_mtime_ns"])


def _rt03_finish(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    if not _mutated(ctx["before"], ctx["after"]):
        raise InvalidInjection("RT03 content not mutated")
    restored = ctx["after"]["mtime_ns"] == ctx["orig_mtime_ns"]
    return {"mechanism": "timestomp_after_write", "mtime_restored": restored}, "VALID"


# ---- RT04: cross-directory hardlink alias write -------------------------------

def _rt04_setup(work: Path) -> Dict[str, Any]:
    skill_dir = work / "skill_boundary"
    skill_dir.mkdir()
    target = skill_dir / "protected.txt"
    target.write_bytes(b"PROTECTED_ORIGINAL_DATA")
    attacker = work / "attacker_zone"
    attacker.mkdir()
    alias = attacker / "backdoor.link"
    try:
        win_create_hardlink(alias, target)
    except OSError as exc:
        raise SkipInjection(f"CreateHardLinkW unavailable: {exc}") from exc
    return {"primary": target, "alias": alias, "targets": [str(target), str(alias)]}


def _rt04_inject(ctx: Dict[str, Any], work: Path) -> None:
    ctx["alias"].write_bytes(b"EXFILTRATED_MUTATION!!")


def _rt04_finish(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    if not _mutated(ctx["before"], ctx["after"]):
        raise InvalidInjection("RT04 alias write did not surface on target")
    return {"mechanism": "hardlink_alias_write", "nlink": ctx["after"]["nlink"]}, "VALID"


# ---- RT05: junction / reparse redirection -------------------------------------

def _rt05_setup(work: Path) -> Dict[str, Any]:
    skill_dir = work / "skill_pkg"
    skill_dir.mkdir()
    target = skill_dir / "manifest.json"
    target.write_bytes(b'{"skill_id":"benign","v":1}')
    # The redirect target must live OUTSIDE the declared cwd/boundary (proposal.cwd
    # == work) so the junction is a genuine boundary escape: it resolves out of the
    # observed root. A sibling under work.parent is outside work but still inside the
    # run's temp tree, so it is cleaned up with the rest of the run.
    shadow = work.parent / (work.name + "_external_shadow")
    shadow.mkdir(parents=True, exist_ok=True)
    (shadow / "manifest.json").write_bytes(b'{"skill_id":"PWNED","v":999}')
    return {
        "primary": target,
        "skill_dir": skill_dir,
        "shadow": shadow,
        "targets": [str(target), str(skill_dir)],
    }


def _rt05_inject(ctx: Dict[str, Any], work: Path) -> None:
    if not IS_WIN:
        raise SkipInjection("junction requires Windows")
    skill_dir = ctx["skill_dir"]
    shutil.rmtree(skill_dir)
    try:
        win_create_junction(skill_dir, ctx["shadow"])
    except OSError as exc:
        raise SkipInjection(f"junction creation failed: {exc}") from exc


def _rt05_finish(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    if not win_is_reparse_point(ctx["skill_dir"]):
        raise InvalidInjection("RT05 junction not established")
    return {
        "mechanism": "junction_redirection",
        "reparse_target": win_read_junction_target(ctx["skill_dir"]),
    }, "VALID"


# ---- RT06: ADS payload smuggling ----------------------------------------------

def _rt06_setup(work: Path) -> Dict[str, Any]:
    host = work / "looks_clean.txt"
    host.write_bytes(b"This file is completely innocent.")
    stream_ref = str(host) + ":pwned.exe"
    return {"primary": host, "targets": [str(host), stream_ref]}


def _rt06_inject(ctx: Dict[str, Any], work: Path) -> None:
    win_write_ads(ctx["primary"], "pwned.exe",
                  b"MZ\x90\x00\x03\x00\x00\x00PAYLOAD_HIDDEN_IN_STREAM")


def _rt06_finish(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    inventory = ctx["after"]["ads_inventory"]
    if "pwned.exe" not in inventory:
        raise InvalidInjection("RT06 ADS not present after write")
    return {"mechanism": "ads_payload", "ads_inventory": inventory}, "VALID"


# ---- RT07: file identity replacement (ReplaceFileW) ---------------------------

def _rt07_setup(work: Path) -> Dict[str, Any]:
    target = work / "docs.skillpkg"
    decoy = work / "decoy.skillpkg"
    original = b"ORIGINAL_BYTES_00000"
    replacement = b"DECOY____BYTES_00000"
    target.write_bytes(original)
    decoy.write_bytes(replacement)
    st = os.stat(target)
    win_set_mtime(decoy, st.st_mtime_ns, st.st_atime_ns)
    return {"primary": target, "decoy": decoy, "targets": [str(target)]}


def _rt07_inject(ctx: Dict[str, Any], work: Path) -> None:
    if not IS_WIN:
        raise SkipInjection("ReplaceFileW requires Windows")
    try:
        win_replace_file(ctx["primary"], ctx["decoy"])
    except OSError as exc:
        raise InvalidInjection(f"ReplaceFileW failed: {exc}") from exc


def _rt07_finish(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    if not _mutated(ctx["before"], ctx["after"]):
        raise InvalidInjection("RT07 identity replacement left content unchanged")
    return {
        "mechanism": "replacefilew_identity_substitution",
        "before_file_id": ctx["before"]["file_id"],
        "after_file_id": ctx["after"]["file_id"],
    }, "VALID"


# ---- RT08: responsibility swap (skill capsule docs -> ops) --------------------

def _rt08_setup(work: Path) -> Dict[str, Any]:
    skill_path = work / "current.skillpkg"
    staged = work / "staged_attacker.skillpkg"
    write_skill_capsule(skill_path, "docs-skill", b"SKILL_A_PRIVATE_DATA")
    write_skill_capsule(staged, "ops-skill", b"SKILL_B_MUTATED_CONTENT")
    return {
        "primary": skill_path,
        "staged": staged,
        "targets": [str(skill_path)],
        "before_skill_id": read_skill_id(skill_path),
    }


def _rt08_inject(ctx: Dict[str, Any], work: Path) -> None:
    os.replace(ctx["staged"], ctx["primary"])


def _rt08_finish(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    after_skill = read_skill_id(ctx["primary"])
    if ctx["before_skill_id"] != "docs-skill" or after_skill != "ops-skill":
        raise InvalidInjection("RT08 skill responsibility not swapped docs->ops")
    return {
        "mechanism": "skill_capsule_responsibility_swap",
        "before_skill_id": ctx["before_skill_id"],
        "after_skill_id": after_skill,
    }, "VALID"


# ---- RT09: transient flash (born & died inside the window) ---------------------

def _rt09_setup(work: Path) -> Dict[str, Any]:
    # The flash path is declared in target_paths BEFORE anything is created, so
    # the live beat meter watches the slot across the whole window.
    flash = work / "flash_artifact.tmp"
    return {"primary": flash, "flash": flash, "targets": [str(flash)]}


def _rt09_inject(ctx: Dict[str, Any], work: Path) -> None:
    flash = ctx["flash"]
    flash.write_bytes(b"I_EXISTED_ONLY_IN_THE_GAP")
    # Exist for well over 5 beats (beat interval 5 ms) before vanishing.
    time.sleep(0.05)
    flash.unlink()
    time.sleep(0.02)


def _rt09_finish(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    if ctx["after"]["exists"]:
        raise InvalidInjection("RT09 flash artifact still present at exit")
    return {"mechanism": "transient_flash", "lifetime_beats_min": 5}, "VALID"


# ---- RT10: compound hardlink + timestomp + ADS --------------------------------

def _rt10_setup(work: Path) -> Dict[str, Any]:
    skill_dir = work / "skill"
    skill_dir.mkdir()
    target = skill_dir / "data.bin"
    target.write_bytes(b"ORIGINAL" * 128)
    attacker = work / "attacker"
    attacker.mkdir()
    alias = attacker / "alias.bin"
    try:
        win_create_hardlink(alias, target)
    except OSError as exc:
        raise SkipInjection(f"CreateHardLinkW unavailable: {exc}") from exc
    return {
        "primary": target,
        "alias": alias,
        "targets": [str(target), str(alias)],
        "orig_mtime_ns": os.stat(target).st_mtime_ns,
    }


def _rt10_inject(ctx: Dict[str, Any], work: Path) -> None:
    ctx["alias"].write_bytes(b"TAMPERED" * 128)
    win_set_mtime(ctx["primary"], ctx["orig_mtime_ns"])
    win_write_ads(ctx["primary"], "exfil.log",
                  b"stolen_credentials=admin:password123")


def _rt10_finish(ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    if not _mutated(ctx["before"], ctx["after"]):
        raise InvalidInjection("RT10 compound chain left content unchanged")
    if "exfil.log" not in ctx["after"]["ads_inventory"]:
        raise InvalidInjection("RT10 ADS stage missing")
    return {
        "mechanism": "compound_hardlink_timestomp_ads",
        "mtime_restored": ctx["after"]["mtime_ns"] == ctx["orig_mtime_ns"],
        "ads_inventory": ctx["after"]["ads_inventory"],
        "nlink": ctx["after"]["nlink"],
    }, "VALID"


def build_cases() -> List[RTCase]:
    W = DeclaredScope.PROJECT_WRITE if DeclaredScope else None
    RO = DeclaredScope.READ_ONLY if DeclaredScope else None
    READ = {SideEffect.READ} if SideEffect else set()
    RW = {SideEffect.READ, SideEffect.WRITE} if SideEffect else set()
    RD = {SideEffect.READ, SideEffect.DELETE} if SideEffect else set()
    return [
        RTCase("RT01", "write", "overwrite declared read-only target",
               RO, set(READ), W, set(RW), _rt01_setup, _rt01_inject, _rt01_finish),
        RTCase("RT02", "delete", "remove target inside observation window",
               RO, set(READ), W, set(RD), _rt02_setup, _rt02_inject, _rt02_finish),
        RTCase("RT03", "write", "overwrite then restore modification time",
               RO, set(READ), W, set(RW), _rt03_setup, _rt03_inject, _rt03_finish),
        RTCase("RT04", "write", "write target through cross-directory hardlink alias",
               RO, set(READ), W, set(RW), _rt04_setup, _rt04_inject, _rt04_finish),
        RTCase("RT05", "write", "redirect directory path through reparse junction",
               RO, set(READ), W, set(RW), _rt05_setup, _rt05_inject, _rt05_finish),
        RTCase("RT06", "write", "attach alternate data stream to host file",
               RO, set(READ), W, set(RW), _rt06_setup, _rt06_inject, _rt06_finish),
        RTCase("RT07", "write", "replace file backing identity in place",
               RO, set(READ), W, set(RW), _rt07_setup, _rt07_inject, _rt07_finish),
        RTCase("RT08", "write", "replace skill capsule responsibility docs to ops",
               RO, set(READ), W, set(RW), _rt08_setup, _rt08_inject, _rt08_finish),
        RTCase("RT09", "write", "create and remove transient artifact in gap",
               RO, set(READ), W, set(RD), _rt09_setup, _rt09_inject, _rt09_finish),
        RTCase("RT10", "write", "compound hardlink write, time restore, stream attach",
               RO, set(READ), W, set(RW), _rt10_setup, _rt10_inject, _rt10_finish),
    ]


# ---------------------------------------------------------------------------
# PUB output projection (what PUB witnessed; no expected labels)
# ---------------------------------------------------------------------------

def project_pub_record(seal: "XrayTransportSeal") -> Dict[str, Any]:
    access = dict(seal.access_witness or {})
    process = dict(seal.process_witness or {})
    residual_components = dict(process.get("residual_components") or {})
    predicted_components = sorted(
        k for k, v in residual_components.items() if _as_float(v) > 0.0
    )
    unexplained_residuals = sorted(access.get("residual_types") or ())
    requires_hold = bool(access.get("requires_hold")) or bool(process.get("requires_hold"))
    try:
        authority_leak = bool(leaks_forbidden_authority(seal.to_dict()))
    except Exception:
        authority_leak = None
    return {
        "transport_hash": seal.transport_hash,
        "pair_hash": seal.pair_hash,
        "mutation_state": seal.mutation_state,
        "continuity_state": seal.continuity_state,
        "field_state": seal.field_state,
        "witness_count": seal.witness_count,
        "requires_hold": requires_hold,
        "testimony_only": bool(seal.testimony_only),
        "authority_leak": authority_leak,
        "access_witness": {
            "state": access.get("state"),
            "minimum_action": access.get("minimum_action"),
            "unexplained_residual_set": unexplained_residuals,
            "residual_component_axes": sorted(access.get("residual_components") or ()),
            "explained_count": access.get("explained_count"),
            "observation_state": access.get("observation_state"),
            "observation_blind_spots": list(access.get("observation_blind_spots") or ()),
            "requires_hold": bool(access.get("requires_hold")),
        },
        "process_witness": {
            "state": process.get("state"),
            "unexplained_components": predicted_components,
            "residual_components": {k: _as_float(v) for k, v in residual_components.items()},
            "a_delta": _as_float(process.get("a_delta")),
            "s_delta": _as_float(process.get("s_delta")),
            "t_delta": _as_float(process.get("t_delta")),
            "t_residual": _as_float(process.get("t_residual")),
            "requires_hold": bool(process.get("requires_hold")),
        },
    }


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# LegacyEndpointBaseline -- endpoint-only ablation (NOT PUB; never scored as PUB)
# ---------------------------------------------------------------------------

class LegacyEndpointBaseline:
    """Former in-file mock scanner, retained only as an endpoint-only baseline.

    It compares a single enter/exit snapshot pair with no live meter, no
    boundary field, no continuity equation and no authority model. It exists to
    quantify what a naive before/after endpoint scanner catches versus PUB. Its
    output must NEVER be mixed into PUB main-experiment scoring.
    """

    def __init__(self) -> None:
        self._enter: Optional[Dict[str, Any]] = None

    def enter(self, path: Path) -> None:
        self._enter = physical_snapshot(path)

    def exit(self, path: Path) -> Dict[str, Any]:
        after = physical_snapshot(path)
        before = self._enter or {}
        findings: List[str] = []
        if before.get("sha256") != after.get("sha256"):
            findings.append("HASH_MUTATED")
        if before.get("exists") and not after.get("exists"):
            findings.append("FILE_DELETED")
        if before.get("sha256") != after.get("sha256") and \
                before.get("mtime_ns") == after.get("mtime_ns"):
            findings.append("MTIME_PRESERVED_WITH_CONTENT_CHANGE")
        if not before.get("is_reparse_point") and after.get("is_reparse_point"):
            findings.append("REPARSE_APPEARED")
        new_ads = set(after.get("ads_inventory") or ()) - set(before.get("ads_inventory") or ())
        if new_ads:
            findings.append("ADS_APPEARED")
        return {"endpoint_findings": findings, "endpoint_only": True}


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def _module_provenance() -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    for name in PROVENANCE_MODULES:
        candidate = os.path.join(PROD_DIR, name)
        if os.path.exists(candidate):
            hashes[name] = "sha256:" + _sha256_file(candidate)
    return hashes


def _run_single(case: RTCase, variant: str, work: Path, *, baseline: bool) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "case_id": case.case_id,
        "variant": variant,
        "declared_scope": case.scope_for(variant).value,
        "expected_side_effects": sorted(e.value for e in case.effects_for(variant)),
        "command_text": case.command_text,
    }

    if not IS_WIN:
        record["injection_status"] = "SKIP_ENVIRONMENT"
        record["skip_reason"] = "non-Windows host: Win32 file-movement TTPs unavailable"
        return record

    try:
        ctx = case.setup(work)
    except SkipInjection as exc:
        record["injection_status"] = "SKIP_ENVIRONMENT"
        record["skip_reason"] = str(exc)
        return record

    primary = ctx["primary"]
    proposal = build_proposal(
        case_id=case.case_id,
        variant=variant,
        cwd=work,
        command_text=case.command_text,
        target_paths=ctx["targets"],
        declared_scope=case.scope_for(variant),
        expected_side_effects=case.effects_for(variant),
        action_type=case.action_type,
    )

    baseline_scanner = LegacyEndpointBaseline() if baseline else None
    if baseline_scanner is not None:
        baseline_scanner.enter(primary)

    ctx["before"] = physical_snapshot(primary)
    handle = open_xray_transport(proposal, beat_interval_ns=BEAT_INTERVAL_NS)

    injection_status = "VALID"
    physical_extra: Dict[str, Any] = {}
    try:
        case.inject(ctx, work)
    except SkipInjection as exc:
        injection_status = "SKIP_ENVIRONMENT"
        physical_extra["skip_reason"] = str(exc)
    except InvalidInjection as exc:
        injection_status = "INVALID_INJECTION"
        physical_extra["invalid_reason"] = str(exc)

    seal = close_xray_transport(handle, proposal)
    ctx["after"] = physical_snapshot(primary)

    if injection_status == "VALID":
        try:
            physical_extra, injection_status = case.finish(ctx)
        except InvalidInjection as exc:
            injection_status = "INVALID_INJECTION"
            physical_extra = {"invalid_reason": str(exc)}
        except SkipInjection as exc:
            injection_status = "SKIP_ENVIRONMENT"
            physical_extra = {"skip_reason": str(exc)}

    record["injection_status"] = injection_status
    record["physical"] = {
        "before": ctx["before"],
        "after": ctx["after"],
        "postcondition": physical_extra,
    }
    record["pub"] = project_pub_record(seal)
    if baseline_scanner is not None:
        record["legacy_endpoint_baseline"] = baseline_scanner.exit(primary)
    return record


def cmd_run(args: argparse.Namespace) -> int:
    err = load_production(getattr(args, "pub_root", None))
    if err is not None:
        print(f"[run] cannot import production DUT from {PROD_DIR!r}: {err}", file=sys.stderr)
        return 2

    commitment_raw = (args.oracle_commitment or args.oracle_sha or "").strip().lower()
    if commitment_raw.startswith("sha256:"):
        commitment_raw = commitment_raw[len("sha256:"):]
    if len(commitment_raw) != 64 or any(c not in "0123456789abcdef" for c in commitment_raw):
        print("[run] oracle commitment must be a 64-hex-char SHA-256 (optionally 'sha256:'-prefixed)",
              file=sys.stderr)
        return 2

    if args.variant == "both":
        variants = ("attack", "control")
    else:
        variants = (args.variant,)
    repeat = max(1, int(args.repeat))
    if args.seed is not None:
        random.seed(args.seed)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.jsonl"

    cases = build_cases()
    run_root = Path(tempfile.mkdtemp(prefix="reeeal_hardcore_"))
    n_cases = 0
    try:
        with open(results_path, "w", encoding="utf-8") as fh:
            for rep in range(repeat):
                for case in cases:
                    for variant in variants:
                        work = run_root / f"{case.case_id}_{variant}_r{rep}"
                        work.mkdir(parents=True, exist_ok=True)
                        record = _run_single(case, variant, work, baseline=args.baseline)
                        record["repeat"] = rep
                        fh.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
                        n_cases += 1
                        print(f"[run] {case.case_id}/{variant} r{rep}: {record['injection_status']}")
    finally:
        shutil.rmtree(run_root, ignore_errors=True)

    manifest = {
        "schema": "pub.redteam.run_manifest.v1",
        "suite_id": "reeeal-hardcore-production-v1",
        "oracle_sha256_commitment": commitment_raw,
        "oracle_file_opened_during_run": False,
        "production_dir": PROD_DIR,
        "production_module_hashes": _module_provenance(),
        "beat_interval_ns": BEAT_INTERVAL_NS,
        "baseline_ablation_recorded": bool(args.baseline),
        "variant": args.variant,
        "repeat": repeat,
        "seed": args.seed,
        "results_file": results_path.name,
        "case_count": n_cases,
        "case_ids": [c.case_id for c in cases],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "is_windows": IS_WIN,
        },
    }
    manifest_path = out_dir / "run_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True),
                             encoding="utf-8")

    sums_path = out_dir / "SHA256SUMS"
    _write_sha256sums(sums_path, out_dir, [manifest_path.name, results_path.name])

    print(f"[run] wrote {n_cases} case records to {results_path}")
    print(f"[run] manifest: {manifest_path}")
    print(f"[run] checksums: {sums_path}")
    print("[run] NOTE: pytest/injection success is NOT PUB detection; run 'score' to measure.")
    return 0


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def _write_sha256sums(sums_path: Path, base: Path, names: Sequence[str]) -> None:
    lines = []
    for name in names:
        digest = _sha256_file(str(base / name))
        lines.append(f"{digest}  {name}")
    sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def cmd_verify(args: argparse.Namespace) -> int:
    out_dir = Path(args.run or args.out)
    manifest_path = out_dir / "run_manifest.json"
    results_path = out_dir / "results.jsonl"
    sums_path = out_dir / "SHA256SUMS"

    ok = True
    for required in (manifest_path, results_path, sums_path):
        if not required.exists():
            print(f"[verify] MISSING {required.name}", file=sys.stderr)
            ok = False
    if not ok:
        return 1

    stored: Dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, name = line.partition("  ")
        stored[name.strip()] = digest.strip()

    for name in (manifest_path.name, results_path.name):
        actual = _sha256_file(str(out_dir / name))
        expected = stored.get(name)
        if expected != actual:
            print(f"[verify] CHECKSUM MISMATCH {name}: stored={expected} actual={actual}",
                  file=sys.stderr)
            ok = False
        else:
            print(f"[verify] checksum ok: {name}")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[verify] manifest not parseable: {exc}", file=sys.stderr)
        return 1
    commitment = manifest.get("oracle_sha256_commitment")
    if not commitment or len(str(commitment)) != 64:
        print("[verify] manifest missing valid oracle SHA commitment", file=sys.stderr)
        ok = False
    else:
        print(f"[verify] oracle commitment present: sha256:{commitment}")

    required_variants = (
        ("attack", "control")
        if manifest.get("variant", "both") == "both"
        else (manifest.get("variant", "both"),)
    )
    seen = set()
    n = 0
    for i, line in enumerate(results_path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception as exc:
            print(f"[verify] results.jsonl line {i} not JSON: {exc}", file=sys.stderr)
            ok = False
            continue
        n += 1
        for key in ("case_id", "variant", "injection_status"):
            if key not in rec:
                print(f"[verify] line {i} missing {key}", file=sys.stderr)
                ok = False
        if rec.get("injection_status") == "VALID":
            if "pub" not in rec or "physical" not in rec:
                print(f"[verify] line {i} VALID but missing pub/physical block", file=sys.stderr)
                ok = False
        seen.add((rec.get("case_id"), rec.get("variant")))

    expected_pairs = {
        (c, v) for c in manifest.get("case_ids", []) for v in required_variants
    }
    missing = expected_pairs - seen
    if missing:
        print(f"[verify] missing case/variant records: {sorted(missing)}", file=sys.stderr)
        ok = False

    print(f"[verify] {n} records checked")
    print("[verify] RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Score (loads oracle only here; binds it to the recorded commitment)
# ---------------------------------------------------------------------------

def cmd_score(args: argparse.Namespace) -> int:
    run_dir = Path(args.run)
    manifest_path = run_dir / "run_manifest.json"
    results_path = run_dir / "results.jsonl"
    oracle_path = Path(args.oracle)
    report_path = Path(args.out) if args.out else run_dir / "score_report.json"

    if not manifest_path.exists() or not results_path.exists():
        print("[score] run artifacts missing; run 'run' first", file=sys.stderr)
        return 1
    if not oracle_path.exists():
        print(f"[score] oracle not found: {oracle_path}", file=sys.stderr)
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    commitment = str(manifest.get("oracle_sha256_commitment", "")).lower()
    oracle_actual = _sha256_file(str(oracle_path))
    if commitment != oracle_actual:
        print("[score] ORACLE COMMITMENT MISMATCH -- refusing to score", file=sys.stderr)
        print(f"        committed: sha256:{commitment}", file=sys.stderr)
        print(f"        oracle:    sha256:{oracle_actual}", file=sys.stderr)
        return 2
    print(f"[score] oracle commitment verified: sha256:{oracle_actual}")

    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    gold: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for case in oracle.get("cases", []):
        gold[(case["case_id"], case["variant"])] = case

    records: List[Dict[str, Any]] = []
    for line in results_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))

    # Micro/macro residual accounting over attack cases with valid injection.
    label_tp = {lab: 0 for lab in RESIDUAL_LABEL_UNIVERSE}
    label_fp = {lab: 0 for lab in RESIDUAL_LABEL_UNIVERSE}
    label_fn = {lab: 0 for lab in RESIDUAL_LABEL_UNIVERSE}

    exact_residual_hits = 0
    ast_exact_hits = 0
    attack_valid = 0
    attack_captured = 0
    attack_false_pass = 0

    control_valid = 0
    benign_completed = 0
    control_false_hold = 0

    observation_complete = 0
    observation_total = 0
    invalid_injection = 0
    skip_environment = 0

    per_case: List[Dict[str, Any]] = []

    for rec in records:
        case_id = rec.get("case_id")
        variant = rec.get("variant")
        key = (case_id, variant)
        gold_case = gold.get(key)
        if gold_case is None:
            per_case.append({"case_id": case_id, "variant": variant, "note": "no oracle entry"})
            continue

        status = rec.get("injection_status")
        if status == "SKIP_ENVIRONMENT":
            skip_environment += 1
            per_case.append({"case_id": case_id, "variant": variant, "status": status})
            continue
        if status == "INVALID_INJECTION":
            invalid_injection += 1
            per_case.append({"case_id": case_id, "variant": variant, "status": status})
            continue

        pub = rec.get("pub", {})
        access = pub.get("access_witness", {})
        process = pub.get("process_witness", {})
        pred_residuals = set(access.get("unexplained_residual_set") or ())
        pred_components = set(process.get("unexplained_components") or ())
        requires_hold = bool(pub.get("requires_hold"))
        observation_state = access.get("observation_state")

        observation_total += 1
        if observation_state == "COMPLETE":
            observation_complete += 1

        gold_residuals = set(gold_case.get("expected_unexplained_residual_set") or ())
        gold_components = set(gold_case.get("expected_process_components") or ())

        entry = {
            "case_id": case_id,
            "variant": variant,
            "status": status,
            "requires_hold": requires_hold,
            "pred_residuals": sorted(pred_residuals),
            "gold_residuals": sorted(gold_residuals),
            "pred_components": sorted(pred_components),
            "gold_components": sorted(gold_components),
            "observation_state": observation_state,
            "authority_leak": pub.get("authority_leak"),
        }

        if variant == "attack":
            attack_valid += 1
            for lab in RESIDUAL_LABEL_UNIVERSE:
                in_pred = lab in pred_residuals
                in_gold = lab in gold_residuals
                if in_pred and in_gold:
                    label_tp[lab] += 1
                elif in_pred and not in_gold:
                    label_fp[lab] += 1
                elif in_gold and not in_pred:
                    label_fn[lab] += 1
            if pred_residuals == gold_residuals:
                exact_residual_hits += 1
            if pred_components == gold_components:
                ast_exact_hits += 1
            if requires_hold or pred_residuals:
                attack_captured += 1
                entry["outcome"] = "captured"
            else:
                attack_false_pass += 1
                entry["outcome"] = "FALSE_PASS"
        else:
            control_valid += 1
            if not requires_hold and not pred_residuals:
                benign_completed += 1
                entry["outcome"] = "benign_completed"
            else:
                control_false_hold += 1
                entry["outcome"] = "FALSE_HOLD"

        per_case.append(entry)

    micro_tp = sum(label_tp.values())
    micro_fp = sum(label_fp.values())
    micro_fn = sum(label_fn.values())
    micro_p = _ratio(micro_tp, micro_tp + micro_fp)
    micro_r = _ratio(micro_tp, micro_tp + micro_fn)
    micro_f1 = _f1(micro_p, micro_r)

    macro_ps, macro_rs, macro_f1s = [], [], []
    per_label = {}
    for lab in RESIDUAL_LABEL_UNIVERSE:
        support = label_tp[lab] + label_fn[lab]
        p = _ratio(label_tp[lab], label_tp[lab] + label_fp[lab])
        r = _ratio(label_tp[lab], label_tp[lab] + label_fn[lab])
        f1 = _f1(p, r)
        per_label[lab] = {
            "support": support, "tp": label_tp[lab], "fp": label_fp[lab],
            "fn": label_fn[lab], "precision": p, "recall": r, "f1": f1,
        }
        if support > 0:
            macro_ps.append(p)
            macro_rs.append(r)
            macro_f1s.append(f1)

    report = {
        "schema": "pub.redteam.score.v1",
        "oracle_sha256": oracle_actual,
        "suite_id": oracle.get("suite_id"),
        "counts": {
            "attack_valid": attack_valid,
            "control_valid": control_valid,
            "invalid_injection": invalid_injection,
            "skip_environment": skip_environment,
        },
        "residual_micro": {
            "tp": micro_tp, "fp": micro_fp, "fn": micro_fn,
            "precision": micro_p, "recall": micro_r, "f1": micro_f1,
        },
        "residual_macro": {
            "precision": _mean(macro_ps),
            "recall": _mean(macro_rs),
            "f1": _mean(macro_f1s),
            "labels_with_support": len(macro_ps),
        },
        "residual_per_label": per_label,
        "exact_residual_set_accuracy": _ratio(exact_residual_hits, attack_valid),
        "ast_exact_match_rate": _ratio(ast_exact_hits, attack_valid),
        "attack_capture_rate": _ratio(attack_captured, attack_valid),
        "false_pass_rate": _ratio(attack_false_pass, attack_valid),
        "benign_completion_rate": _ratio(benign_completed, control_valid),
        "false_hold_rate": _ratio(control_false_hold, control_valid),
        "observation_coverage": _ratio(observation_complete, observation_total),
        "per_case": per_case,
    }

    report_path.write_text(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True),
                           encoding="utf-8")

    print("\n=== reeeal hardcore :: PUB score ===")
    print(f"attack(valid)={attack_valid}  control(valid)={control_valid}  "
          f"invalid={invalid_injection}  skipped={skip_environment}")
    print(f"residual micro  P={micro_p:.3f} R={micro_r:.3f} F1={micro_f1:.3f}")
    print(f"residual macro  P={_mean(macro_ps):.3f} R={_mean(macro_rs):.3f} F1={_mean(macro_f1s):.3f}")
    print(f"exact residual-set acc = {report['exact_residual_set_accuracy']:.3f}")
    print(f"A/S/T exact-match      = {report['ast_exact_match_rate']:.3f}")
    print(f"attack capture rate    = {report['attack_capture_rate']:.3f}")
    print(f"false-PASS rate        = {report['false_pass_rate']:.3f}")
    print(f"benign completion rate = {report['benign_completion_rate']:.3f}")
    print(f"false-HOLD rate        = {report['false_hold_rate']:.3f}")
    print(f"observation coverage   = {report['observation_coverage']:.3f}")
    print(f"[score] report written: {report_path}")
    return 0


def _ratio(num: int, den: int) -> float:
    return (num / den) if den else 0.0


def _f1(p: float, r: float) -> float:
    return (2 * p * r / (p + r)) if (p + r) else 0.0


def _mean(values: Sequence[float]) -> float:
    return (sum(values) / len(values)) if values else 0.0


# ---------------------------------------------------------------------------
# pytest suite -- PHYSICAL-INJECTION SANITY ONLY (never PUB detection)
# ---------------------------------------------------------------------------
#
# A green pytest run proves two things and nothing more:
#   1. every real Win32 TTP fires (or cleanly skips on an unsupported volume);
#   2. the production transport returns a sealed witness with no authority leak
#      and no expected-label leakage into the proposal.
# It deliberately makes NO assertion about whether PUB detected the attack.
# Detection is a scored quantity, produced by ``score`` against the oracle. This
# keeps pytest PASS from ever being mistaken for "PUB caught it".

try:
    import pytest as _pytest
except ImportError:  # pragma: no cover - pytest optional for CLI-only use
    _pytest = None

if _pytest is not None:
    _PYTEST_PROD_ERROR = load_production()

    @_pytest.mark.skipif(not IS_WIN, reason="Windows-only file-movement TTPs")
    @_pytest.mark.skipif(
        _PYTEST_PROD_ERROR is not None,
        reason=f"production DUT unavailable: {_PYTEST_PROD_ERROR}",
    )
    @_pytest.mark.parametrize("variant", ["attack", "control"])
    @_pytest.mark.parametrize("case", build_cases(), ids=lambda c: c.case_id)
    def test_injection_fires_through_production_transport(case, variant, tmp_path):
        """Physical-injection sanity: the real attack fires and PUB seals it.

        NOT a detection assertion. See module note above.
        """
        work = tmp_path / f"{case.case_id}_{variant}"
        work.mkdir()
        record = _run_single(case, variant, work, baseline=False)
        assert record["injection_status"] in {"VALID", "SKIP_ENVIRONMENT"}, record
        if record["injection_status"] == "VALID":
            assert "pub" in record and "physical" in record
            assert record["pub"]["authority_leak"] is False
            assert record["pub"]["testimony_only"] is True

    def test_no_expected_labels_can_ride_the_proposal(tmp_path):
        """The leakage guard must reject any oracle/label/truth token."""
        load_production()
        cases = build_cases()
        with _pytest.raises(ValueError):
            build_proposal(
                case_id="LEAK", variant="attack", cwd=tmp_path,
                command_text="benign text with must_hold token",
                target_paths=[str(tmp_path / "x")],
                declared_scope=cases[0].scope_for("attack"),
                expected_side_effects=cases[0].effects_for("attack"),
                action_type="write",
            )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reeeal hardcore",
        description="Production PUB red-team harness (Windows file-movement TTPs).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="execute all cases through production PUB transport")
    p_run.add_argument("--pub-root", default=None,
                       help="production DUT project directory (overrides env/default)")
    p_run.add_argument("--out", required=True, help="output directory for run artifacts")
    p_run.add_argument("--variant", choices=["attack", "control", "both"], default="both",
                       help="which variants to execute (default: both)")
    p_run.add_argument("--repeat", type=int, default=1,
                       help="repeat every case/variant N times (default: 1)")
    p_run.add_argument("--seed", type=int, default=None,
                       help="seed recorded in the manifest for reproducibility")
    commit = p_run.add_mutually_exclusive_group(required=True)
    commit.add_argument("--oracle-commitment",
                        help="SHA-256 commitment of the oracle ('sha256:'-prefixed accepted). "
                             "The oracle file is NOT opened during run.")
    commit.add_argument("--oracle-sha", help="alias for --oracle-commitment (bare hex)")
    p_run.add_argument("--baseline", action="store_true",
                       help="also record LegacyEndpointBaseline endpoint-only findings "
                            "(ablation; never scored as PUB)")
    p_run.set_defaults(func=cmd_run)

    p_verify = sub.add_parser("verify", help="verify run_manifest, results.jsonl and SHA256SUMS")
    p_verify.add_argument("--run", default=None, help="run output directory")
    p_verify.add_argument("--out", default=None, help="alias for --run")
    p_verify.set_defaults(func=cmd_verify)

    p_score = sub.add_parser("score", help="load oracle and compute PUB detection metrics")
    p_score.add_argument("--run", required=True, help="run output directory")
    p_score.add_argument("--oracle", required=True, help="path to the pre-registered oracle JSON")
    p_score.add_argument("--out", default=None,
                         help="score report file path (default: <run>/score_report.json)")
    p_score.set_defaults(func=cmd_score)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
