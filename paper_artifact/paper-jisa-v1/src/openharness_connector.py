from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Sequence


SHELL_REL = Path("utils/shell.py")
BASH_TOOL_REL = Path("tools/bash_tool.py")
BACKUP_SUFFIX = ".protect_u_back.bak"
PTH_NAME = "protect_u_back_local.pth"

SHELL_BEGIN = "    # Protect U Back / OpenHarness inline gate begin\n"
SHELL_END = "    # Protect U Back / OpenHarness inline gate end\n"
BASH_IMPORT_BEGIN = "# Protect U Back / OpenHarness import bridge begin\n"
BASH_IMPORT_END = "# Protect U Back / OpenHarness import bridge end\n"
BASH_EXCEPT_BEGIN = "        # Protect U Back / OpenHarness ToolResult bridge begin\n"
BASH_EXCEPT_END = "        # Protect U Back / OpenHarness ToolResult bridge end\n"


class OpenHarnessConnectorError(RuntimeError):
    pass


def status_openharness(root: str | Path | None = None) -> dict[str, Any]:
    package_root = find_openharness_root(root)
    shell_path = package_root / SHELL_REL
    bash_tool_path = package_root / BASH_TOOL_REL
    shell_text = _read(shell_path)
    bash_text = _read(bash_tool_path)
    connected = _has_shell_gate(shell_text) and _has_bash_import(bash_text)
    return {
        "openharness_root": str(package_root),
        "connected": connected,
        "patched": connected,
        "shell_patched": _has_shell_gate(shell_text),
        "bash_tool_patched": _has_bash_import(bash_text),
        "tool_result_bridge": _has_bash_except(bash_text),
        "import_path_file": str(_pth_path(package_root)),
        "import_path_present": _pth_path(package_root).exists(),
        "sha256": {
            "shell": _sha256(shell_path),
            "bash_tool": _sha256(bash_tool_path),
        },
    }


def connect_openharness(
    root: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
) -> dict[str, Any]:
    package_root = find_openharness_root(root)
    shell_path = package_root / SHELL_REL
    bash_tool_path = package_root / BASH_TOOL_REL
    shell_text = _read(shell_path)
    bash_text = _read(bash_tool_path)

    patched_shell = _patch_shell(shell_text)
    patched_bash = _patch_bash_tool(bash_text)
    changed = patched_shell != shell_text or patched_bash != bash_text

    if changed:
        _backup_once(shell_path, shell_text)
        _backup_once(bash_tool_path, bash_text)
        shell_path.write_text(patched_shell, encoding="utf-8", newline="")
        bash_tool_path.write_text(patched_bash, encoding="utf-8", newline="")

    import_root = Path(protect_root or Path(__file__).resolve().parent).resolve(strict=False)
    _write_pth(package_root, import_root)
    result = status_openharness(package_root)
    result["changed"] = changed
    result["protect_root"] = str(import_root)
    return result


def disconnect_openharness(root: str | Path | None = None) -> dict[str, Any]:
    package_root = find_openharness_root(root)
    restored = []
    for relative in (SHELL_REL, BASH_TOOL_REL):
        path = package_root / relative
        backup = _backup_path(path)
        if backup.exists():
            path.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8", newline="")
            restored.append(relative.as_posix())
        else:
            path.write_text(_strip_marked_blocks(_read(path)), encoding="utf-8", newline="")
    pth = _pth_path(package_root)
    if pth.exists():
        pth.unlink()
    result = status_openharness(package_root)
    result["restored"] = tuple(restored)
    return result


def verify_openharness(root: str | Path | None = None) -> dict[str, Any]:
    status = status_openharness(root)
    try:
        from harness_runtime_guard import ProtectPreflightBlocked, enforce_openharness_shell_preflight

        try:
            enforce_openharness_shell_preflight("rm -rf .", cwd=Path.cwd(), settings=None)
        except ProtectPreflightBlocked as exc:
            metadata = exc.to_metadata()
            return {
                **status,
                "preflight_blocked": True,
                "disposition": metadata["protect_u_back"]["decision"]["disposition"],
                "reason_code": metadata["protect_u_back"]["decision"]["reason_code"],
                "io_executed": False,
                "can_execute": False,
                "can_grant_permission": False,
            }
    except ImportError as exc:
        return {**status, "preflight_blocked": False, "error": str(exc)}
    return {**status, "preflight_blocked": False, "error": "synthetic destructive check passed"}


def find_openharness_root(root: str | Path | None = None) -> Path:
    if root is not None:
        candidate = Path(root).expanduser().resolve(strict=False)
        if candidate.name == "shell.py" and candidate.parent.name == "utils":
            candidate = candidate.parent.parent
        if (candidate / "openharness").is_dir():
            candidate = candidate / "openharness"
        return _require_package_root(candidate)

    try:
        import openharness
    except ImportError as exc:
        raise OpenHarnessConnectorError(
            "OpenHarness package root was not provided and openharness is not importable."
        ) from exc
    return _require_package_root(Path(openharness.__file__).resolve(strict=False).parent)


def _patch_shell(text: str) -> str:
    if _has_shell_gate(text):
        return text
    block = (
        SHELL_BEGIN
        + "    try:\n"
        + "        from harness_runtime_guard import enforce_openharness_shell_preflight\n"
        + "    except ImportError:\n"
        + "        enforce_openharness_shell_preflight = None\n"
        + "    if enforce_openharness_shell_preflight is not None:\n"
        + "        _pub_state = locals()\n"
        + "        enforce_openharness_shell_preflight(\n"
        + "            command,\n"
        + "            cwd=_pub_state.get(\"cwd\") or _pub_state.get(\"kwargs\", {}).get(\"cwd\"),\n"
        + "            settings=_pub_state.get(\"resolved_settings\") or _pub_state.get(\"settings\"),\n"
        + "        )\n"
        + SHELL_END
    )
    if "resolved_settings = settings or load_settings()\n" in text:
        return text.replace(
            "resolved_settings = settings or load_settings()\n",
            "resolved_settings = settings or load_settings()\n" + block,
            1,
        )
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith("async def create_shell_subprocess(") and line.rstrip().endswith(":"):
            return "".join(lines[: index + 1]) + block + "".join(lines[index + 1 :])
    raise OpenHarnessConnectorError("could not find OpenHarness create_shell_subprocess anchor")


def _patch_bash_tool(text: str) -> str:
    if not _has_bash_import(text):
        needle = "from openharness.utils.shell import create_shell_subprocess\n"
        if needle not in text:
            raise OpenHarnessConnectorError("could not find OpenHarness BashTool import anchor")
        import_block = (
            BASH_IMPORT_BEGIN
            + "try:\n"
            + "    from harness_runtime_guard import ProtectPreflightBlocked\n"
            + "except ImportError:\n"
            + "    class ProtectPreflightBlocked(RuntimeError):\n"
            + "        def to_metadata(self) -> dict[str, object]:\n"
            + "            return {\"io_executed\": False, \"can_execute\": False, \"can_grant_permission\": False}\n"
            + BASH_IMPORT_END
        )
        text = text.replace(needle, needle + import_block, 1)

    if not _has_bash_except(text) and "except SandboxUnavailableError as exc:" in text:
        except_block = (
            BASH_EXCEPT_BEGIN
            + "        except ProtectPreflightBlocked as exc:\n"
            + "            return ToolResult(output=str(exc), is_error=True, metadata=exc.to_metadata())\n"
            + BASH_EXCEPT_END
        )
        text = text.replace("        except SandboxUnavailableError as exc:\n", except_block + "        except SandboxUnavailableError as exc:\n", 1)
    return text


def _has_shell_gate(text: str) -> bool:
    return SHELL_BEGIN in text or (
        "harness_runtime_guard" in text
        and (
            "enforce_shell_subprocess_preflight" in text
            or "enforce_openharness_shell_preflight" in text
        )
    )


def _has_bash_import(text: str) -> bool:
    return BASH_IMPORT_BEGIN in text or (
        "harness_runtime_guard" in text and "ProtectPreflightBlocked" in text
    )


def _has_bash_except(text: str) -> bool:
    return BASH_EXCEPT_BEGIN in text or "except ProtectPreflightBlocked as exc:" in text


def _strip_marked_blocks(text: str) -> str:
    for begin, end in (
        (SHELL_BEGIN, SHELL_END),
        (BASH_IMPORT_BEGIN, BASH_IMPORT_END),
        (BASH_EXCEPT_BEGIN, BASH_EXCEPT_END),
    ):
        while begin in text:
            start = text.index(begin)
            finish = text.index(end, start) + len(end)
            text = text[:start] + text[finish:]
    return text


def _require_package_root(path: Path) -> Path:
    if not (path / SHELL_REL).exists() or not (path / BASH_TOOL_REL).exists():
        raise OpenHarnessConnectorError(f"not an OpenHarness package root: {path}")
    return path


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _backup_path(path: Path) -> Path:
    return path.with_name(path.name + BACKUP_SUFFIX)


def _backup_once(path: Path, text: str) -> None:
    backup = _backup_path(path)
    if not backup.exists():
        backup.write_text(text, encoding="utf-8", newline="")


def _pth_path(package_root: Path) -> Path:
    return package_root.parent / PTH_NAME


def _write_pth(package_root: Path, protect_root: Path) -> None:
    _pth_path(package_root).write_text(str(protect_root) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Connect Protect U Back to local OpenHarness.")
    parser.add_argument("command", choices=("status", "connect", "disconnect", "verify"))
    parser.add_argument("--openharness-root")
    parser.add_argument("--protect-root")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    operations = {
        "status": lambda: status_openharness(args.openharness_root),
        "connect": lambda: connect_openharness(args.openharness_root, protect_root=args.protect_root),
        "disconnect": lambda: disconnect_openharness(args.openharness_root),
        "verify": lambda: verify_openharness(args.openharness_root),
    }
    try:
        result = operations[args.command]()
    except Exception as exc:
        print(f"OpenHarness connector error: {exc}")
        return 1
    _print_result(result, as_json=args.json)
    return 0


def _print_result(result: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    for key, value in result.items():
        if isinstance(value, dict):
            print(f"{key}:")
            for child_key, child_value in value.items():
                print(f"  {child_key}: {child_value}")
        else:
            print(f"{key}: {value}")


if __name__ == "__main__":
    raise SystemExit(main())
