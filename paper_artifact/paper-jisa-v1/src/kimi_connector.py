from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Sequence


SHELL_REL = Path("src/kimi_cli/tools/shell/__init__.py")
BACKUP_SUFFIX = ".protect_u_back.bak"

IMPORT_BEGIN = "# Protect U Back / Kimi import bridge begin\n"
IMPORT_END = "# Protect U Back / Kimi import bridge end\n"
FOREGROUND_BEGIN = "            # Protect U Back / Kimi foreground gate begin\n"
FOREGROUND_END = "            # Protect U Back / Kimi foreground gate end\n"
BACKGROUND_BEGIN = "            # Protect U Back / Kimi background gate begin\n"
BACKGROUND_END = "            # Protect U Back / Kimi background gate end\n"
FOREGROUND_EXCEPT_BEGIN = "        # Protect U Back / Kimi foreground ToolReturn bridge begin\n"
FOREGROUND_EXCEPT_END = "        # Protect U Back / Kimi foreground ToolReturn bridge end\n"
BACKGROUND_EXCEPT_BEGIN = "        # Protect U Back / Kimi background ToolReturn bridge begin\n"
BACKGROUND_EXCEPT_END = "        # Protect U Back / Kimi background ToolReturn bridge end\n"


class KimiConnectorError(RuntimeError):
    pass


def status_kimi(root: str | Path | None = None) -> dict[str, Any]:
    package_root = find_kimi_root(root)
    shell_path = package_root / SHELL_REL
    text = shell_path.read_text(encoding="utf-8")
    connected = _has_import(text) and _has_foreground_gate(text) and _has_background_gate(text)
    return {
        "kimi_root": str(package_root),
        "shell_path": str(shell_path),
        "connected": connected,
        "patched": connected,
        "import_bridge": _has_import(text),
        "foreground_gate": _has_foreground_gate(text),
        "background_gate": _has_background_gate(text),
        "foreground_tool_result_bridge": _has_foreground_except(text),
        "background_tool_result_bridge": _has_background_except(text),
        "sha256": _sha256(shell_path),
    }


def connect_kimi(
    root: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
) -> dict[str, Any]:
    package_root = find_kimi_root(root)
    shell_path = package_root / SHELL_REL
    text = shell_path.read_text(encoding="utf-8")
    guard_root = Path(protect_root or Path(__file__).resolve().parent).resolve(strict=False)
    patched = _patch_shell_tool(text, protect_root=guard_root)
    changed = patched != text
    if changed:
        _backup_once(shell_path, text)
        shell_path.write_text(patched, encoding="utf-8", newline="")
    result = status_kimi(package_root)
    result["changed"] = changed
    result["protect_root"] = str(guard_root)
    return result


def disconnect_kimi(root: str | Path | None = None) -> dict[str, Any]:
    package_root = find_kimi_root(root)
    shell_path = package_root / SHELL_REL
    backup = _backup_path(shell_path)
    if backup.exists():
        shell_path.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8", newline="")
        restored = True
    else:
        shell_path.write_text(
            _strip_marked_blocks(shell_path.read_text(encoding="utf-8")),
            encoding="utf-8",
            newline="",
        )
        restored = False
    result = status_kimi(package_root)
    result["restored_from_backup"] = restored
    return result


def verify_kimi(root: str | Path | None = None) -> dict[str, Any]:
    status = status_kimi(root)
    from kimi_runtime_guard import audit_kimi_shell

    result = audit_kimi_shell(
        {
            "command": "rm -rf .",
            "cwd": ".",
            "run_in_background": False,
        }
    )
    return {
        **status,
        "preflight_blocked": result.get("allowed") is False,
        "disposition": _decision_field(result, "disposition"),
        "reason_code": _decision_field(result, "reason_code"),
        "io_executed": False,
        "can_execute": False,
        "can_grant_permission": False,
    }


def find_kimi_root(root: str | Path | None = None) -> Path:
    if root is None:
        raise KimiConnectorError("Kimi CLI repository root is required.")
    candidate = Path(root).expanduser().resolve(strict=False)
    if candidate.name == "__init__.py" and candidate.parent.name == "shell":
        return _require_kimi_root(candidate.parents[4])
    if candidate.name == "kimi_cli" and candidate.parent.name == "src":
        return _require_kimi_root(candidate.parent.parent)
    return _require_kimi_root(candidate)


def _patch_shell_tool(text: str, *, protect_root: Path) -> str:
    _raise_on_partial_patch(text)
    if not _has_import(text):
        needle = "from kimi_cli.utils.subprocess_env import get_noninteractive_env\n"
        if needle not in text:
            raise KimiConnectorError("could not find Kimi Shell import anchor")
        text = text.replace(needle, needle + _import_bridge(protect_root), 1)
    if not _has_foreground_gate(text):
        needle = "        try:\n            exitcode = await self._run_shell_command(command, stdout_cb, stderr_cb, params.timeout)\n"
        if needle not in text:
            raise KimiConnectorError("could not find Kimi foreground execution anchor")
        gate = (
            "        try:\n"
            + FOREGROUND_BEGIN
            + "            enforce_kimi_shell_preflight(\n"
            + "                command,\n"
            + "                cwd=str(self._runtime.session.work_dir),\n"
            + "                run_in_background=False,\n"
            + "            )\n"
            + FOREGROUND_END
            + "            exitcode = await self._run_shell_command(command, stdout_cb, stderr_cb, params.timeout)\n"
        )
        text = text.replace(needle, gate, 1)
    if not _has_foreground_except(text):
        needle = "        except TimeoutError:\n"
        if needle not in text:
            raise KimiConnectorError("could not find Kimi foreground exception anchor")
        bridge = (
            FOREGROUND_EXCEPT_BEGIN
            + "        except ProtectPreflightBlocked as exc:\n"
            + "            builder.extras(protect_u_back=exc.to_metadata())\n"
            + "            return builder.error(str(exc), brief=\"Blocked by Protect U Back\")\n"
            + FOREGROUND_EXCEPT_END
        )
        text = text.replace(needle, bridge + needle, 1)
    if not _has_background_gate(text):
        needle = "        try:\n            view = self._runtime.background_tasks.create_bash_task(\n"
        if needle not in text:
            raise KimiConnectorError("could not find Kimi background task anchor")
        gate = (
            "        try:\n"
            + BACKGROUND_BEGIN
            + "            enforce_kimi_shell_preflight(\n"
            + "                command,\n"
            + "                cwd=str(self._runtime.session.work_dir),\n"
            + "                run_in_background=True,\n"
            + "            )\n"
            + BACKGROUND_END
            + "            view = self._runtime.background_tasks.create_bash_task(\n"
        )
        text = text.replace(needle, gate, 1)
    if not _has_background_except(text):
        needle = (
            "        except Exception as exc:\n"
            "            logger.error(\n"
            "                \"Failed to start background shell task: {command}: {error}\",\n"
        )
        if needle not in text:
            raise KimiConnectorError("could not find Kimi background exception anchor")
        bridge = (
            BACKGROUND_EXCEPT_BEGIN
            + "        except ProtectPreflightBlocked as exc:\n"
            + "            builder = ToolResultBuilder()\n"
            + "            builder.extras(protect_u_back=exc.to_metadata())\n"
            + "            return builder.error(str(exc), brief=\"Blocked by Protect U Back\")\n"
            + BACKGROUND_EXCEPT_END
        )
        text = text.replace(needle, bridge + needle, 1)
    return text


def _import_bridge(protect_root: Path) -> str:
    root_literal = repr(str(protect_root))
    return (
        IMPORT_BEGIN
        + "import sys as _protect_u_back_sys\n"
        + f"_PROTECT_U_BACK_ROOT = Path({root_literal})\n"
        + "if str(_PROTECT_U_BACK_ROOT) not in _protect_u_back_sys.path:\n"
        + "    _protect_u_back_sys.path.insert(0, str(_PROTECT_U_BACK_ROOT))\n"
        + "from kimi_runtime_guard import ProtectPreflightBlocked, enforce_kimi_shell_preflight\n"
        + IMPORT_END
    )


def _require_kimi_root(path: Path) -> Path:
    if not (path / SHELL_REL).exists():
        raise KimiConnectorError(f"not a Kimi CLI repository root: {path}")
    return path


def _has_import(text: str) -> bool:
    return IMPORT_BEGIN in text and IMPORT_END in text


def _has_foreground_gate(text: str) -> bool:
    return FOREGROUND_BEGIN in text and FOREGROUND_END in text


def _has_background_gate(text: str) -> bool:
    return BACKGROUND_BEGIN in text and BACKGROUND_END in text


def _has_foreground_except(text: str) -> bool:
    return FOREGROUND_EXCEPT_BEGIN in text and FOREGROUND_EXCEPT_END in text


def _has_background_except(text: str) -> bool:
    return BACKGROUND_EXCEPT_BEGIN in text and BACKGROUND_EXCEPT_END in text


def _strip_marked_blocks(text: str) -> str:
    for begin, end in (
        (IMPORT_BEGIN, IMPORT_END),
        (FOREGROUND_BEGIN, FOREGROUND_END),
        (BACKGROUND_BEGIN, BACKGROUND_END),
        (FOREGROUND_EXCEPT_BEGIN, FOREGROUND_EXCEPT_END),
        (BACKGROUND_EXCEPT_BEGIN, BACKGROUND_EXCEPT_END),
    ):
        while begin in text:
            start = text.index(begin)
            finish = text.index(end, start) + len(end)
            text = text[:start] + text[finish:]
    return text


def _raise_on_partial_patch(text: str) -> None:
    for begin, end in (
        (IMPORT_BEGIN, IMPORT_END),
        (FOREGROUND_BEGIN, FOREGROUND_END),
        (BACKGROUND_BEGIN, BACKGROUND_END),
        (FOREGROUND_EXCEPT_BEGIN, FOREGROUND_EXCEPT_END),
        (BACKGROUND_EXCEPT_BEGIN, BACKGROUND_EXCEPT_END),
    ):
        if (begin in text) != (end in text):
            raise KimiConnectorError("found incomplete Protect U Back Kimi patch markers")


def _decision_field(result: dict[str, Any], field: str) -> str | None:
    metadata = result.get("metadata")
    if not isinstance(metadata, dict):
        return None
    protect = metadata.get("protect_u_back")
    if not isinstance(protect, dict):
        return None
    decision = protect.get("decision")
    if not isinstance(decision, dict):
        return None
    value = decision.get(field)
    return str(value) if value is not None else None


def _backup_path(path: Path) -> Path:
    return path.with_name(path.name + BACKUP_SUFFIX)


def _backup_once(path: Path, text: str) -> None:
    backup = _backup_path(path)
    if not backup.exists():
        backup.write_text(text, encoding="utf-8", newline="")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Connect Protect U Back to local Kimi CLI.")
    parser.add_argument("command", choices=("status", "connect", "disconnect", "verify"))
    parser.add_argument("--kimi-root", required=True)
    parser.add_argument("--protect-root")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    operations = {
        "status": lambda: status_kimi(args.kimi_root),
        "connect": lambda: connect_kimi(args.kimi_root, protect_root=args.protect_root),
        "disconnect": lambda: disconnect_kimi(args.kimi_root),
        "verify": lambda: verify_kimi(args.kimi_root),
    }
    try:
        result = operations[args.command]()
    except Exception as exc:
        print(f"Kimi connector error: {exc}")
        return 1
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else _format_result(result))
    return 0


def _format_result(result: dict[str, Any]) -> str:
    return "\n".join(f"{key}: {value}" for key, value in result.items())


if __name__ == "__main__":
    raise SystemExit(main())
