from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Sequence


BASH_RUNTIME_GLOB = "bash-tools.exec-runtime-*.js"
BACKUP_SUFFIX = ".protect_u_back.bak"
BLOCK_BEGIN = "  // Protect U Back / OpenClaw preflight begin\n"
BLOCK_END = "  // Protect U Back / OpenClaw preflight end\n"
CALL_BEGIN = "          // Protect U Back / OpenClaw gate begin\n"
CALL_END = "          // Protect U Back / OpenClaw gate end\n"


class OpenClawConnectorError(RuntimeError):
    pass


def status_openclaw(root: str | Path | None = None) -> dict[str, Any]:
    package_root = find_openclaw_root(root)
    runtime_path = _runtime_path(package_root)
    text = runtime_path.read_text(encoding="utf-8")
    connected = _has_guard(text) and _has_call(text)
    return {
        "openclaw_root": str(package_root),
        "runtime_path": str(runtime_path),
        "connected": connected,
        "patched": connected,
        "guard_present": _has_guard(text),
        "call_present": _has_call(text),
        "sha256": _sha256(runtime_path),
    }


def connect_openclaw(
    root: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
) -> dict[str, Any]:
    package_root = find_openclaw_root(root)
    runtime_path = _runtime_path(package_root)
    text = runtime_path.read_text(encoding="utf-8")
    guard_path = Path(protect_root or Path(__file__).resolve().parent) / "openclaw_runtime_guard.py"
    patched = _patch_runtime(text, guard_path=guard_path.resolve(strict=False))
    changed = patched != text
    if changed:
        _backup_once(runtime_path, text)
        runtime_path.write_text(patched, encoding="utf-8", newline="")
    result = status_openclaw(package_root)
    result["changed"] = changed
    result["guard_path"] = str(guard_path.resolve(strict=False))
    return result


def disconnect_openclaw(root: str | Path | None = None) -> dict[str, Any]:
    package_root = find_openclaw_root(root)
    runtime_path = _runtime_path(package_root)
    backup = _backup_path(runtime_path)
    if backup.exists():
        runtime_path.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8", newline="")
        restored = True
    else:
        runtime_path.write_text(
            _strip_marked_blocks(runtime_path.read_text(encoding="utf-8")),
            encoding="utf-8",
            newline="",
        )
        restored = False
    result = status_openclaw(package_root)
    result["restored_from_backup"] = restored
    return result


def verify_openclaw(root: str | Path | None = None) -> dict[str, Any]:
    status = status_openclaw(root)
    from openclaw_runtime_guard import audit_openclaw_shell

    result = audit_openclaw_shell(
        {
            "command": "rm -rf .",
            "cwd": ".",
            "sandbox_available": False,
            "sandbox_fallback": "openclaw_host_shell",
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


def find_openclaw_root(root: str | Path | None = None) -> Path:
    if root is None:
        raise OpenClawConnectorError("OpenClaw package root is required.")
    candidate = Path(root).expanduser().resolve(strict=False)
    if (candidate / "package.json").exists() and (candidate / "dist").is_dir():
        return candidate
    raise OpenClawConnectorError(f"not an OpenClaw package root: {candidate}")


def _runtime_path(package_root: Path) -> Path:
    matches = sorted((package_root / "dist").glob(BASH_RUNTIME_GLOB))
    if not matches:
        raise OpenClawConnectorError("could not find OpenClaw bash-tools exec runtime")
    if len(matches) == 1:
        return matches[0]

    runtimes = [
        path
        for path in matches
        if _looks_like_agent_bash_runtime(path.read_text(encoding="utf-8"))
    ]
    if len(runtimes) != 1:
        raise OpenClawConnectorError("could not uniquely identify OpenClaw bash exec runtime")
    return runtimes[0]


def _patch_runtime(text: str, *, guard_path: Path) -> str:
    _raise_on_partial_patch(text)
    if not _has_guard(text):
        guard = _guard_block(guard_path)
        anchor = "async function runExecProcess(opts) {\n"
        if anchor not in text:
            raise OpenClawConnectorError("could not find runExecProcess anchor")
        text = text.replace(anchor, guard + anchor, 1)
    if not _has_call(text):
        lines = text.splitlines(keepends=True)
        index = next(
            (line_index for line_index, line in enumerate(lines) if line.strip() == "let sandboxFinalizeToken;"),
            None,
        )
        if index is None:
            raise OpenClawConnectorError("could not find OpenClaw spawnSpec anchor")
        indent = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
        inner = indent + "        "
        call = (
            f"{indent}// Protect U Back / OpenClaw gate begin\n"
            + f"{indent}await protectUBackOpenClawPreflight({{\n"
            + f"{inner}command: execCommand,\n"
            + f"{inner}cwd: opts.workdir,\n"
            + f"{inner}sandboxAvailable: Boolean(opts.sandbox),\n"
            + f"{inner}sandboxFallback: opts.sandbox ? \"openclaw_sandbox\" : \"openclaw_host_shell\"\n"
            + f"{indent}}});\n"
            + f"{indent}// Protect U Back / OpenClaw gate end\n"
        )
        lines.insert(index + 1, call)
        text = "".join(lines)
    return text


def _guard_block(guard_path: Path) -> str:
    guard_literal = json.dumps(str(guard_path))
    return (
        BLOCK_BEGIN
        + "  async function protectUBackOpenClawPreflight(params) {\n"
        + "          const { spawnSync } = await import(\"node:child_process\");\n"
        + "          const env = globalThis.process?.env ?? {};\n"
        + f"          const guardPath = env.PROTECT_U_BACK_OPENCLAW_GUARD || {guard_literal};\n"
        + "          const python = env.PROTECT_U_BACK_PYTHON || \"python3\";\n"
        + "          const input = JSON.stringify({\n"
        + "                  command: params.command,\n"
        + "                  cwd: params.cwd,\n"
        + "                  sandbox_available: params.sandboxAvailable,\n"
        + "                  sandbox_fallback: params.sandboxFallback\n"
        + "          });\n"
        + "          const result = spawnSync(python, [guardPath], { input, encoding: \"utf8\" });\n"
        + "          if (result.status === 0) return;\n"
        + "          let parsed = null;\n"
        + "          try { parsed = JSON.parse(result.stdout || \"{}\"); } catch {}\n"
        + "          const detail = parsed?.message || result.stderr || result.stdout || String(result.error || \"blocked\");\n"
        + "          throw new Error(detail);\n"
        + "  }\n"
        + BLOCK_END
    )


def _strip_marked_blocks(text: str) -> str:
    for begin, end in ((BLOCK_BEGIN, BLOCK_END), (CALL_BEGIN.strip(), CALL_END.strip())):
        while begin in text:
            start = text.index(begin)
            finish = text.index(end, start) + len(end)
            text = text[:start] + text[finish:]
    return text


def _has_guard(text: str) -> bool:
    return BLOCK_BEGIN in text and BLOCK_END in text


def _has_call(text: str) -> bool:
    return CALL_BEGIN.strip() in text and CALL_END.strip() in text


def _looks_like_agent_bash_runtime(text: str) -> bool:
    return "async function runExecProcess(opts)" in text or (_has_guard(text) and _has_call(text))


def _raise_on_partial_patch(text: str) -> None:
    markers = (
        (BLOCK_BEGIN, BLOCK_END),
        (CALL_BEGIN.strip(), CALL_END.strip()),
    )
    for begin, end in markers:
        if (begin in text) != (end in text):
            raise OpenClawConnectorError("found incomplete Protect U Back OpenClaw patch markers")


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
    parser = argparse.ArgumentParser(description="Connect Protect U Back to local OpenClaw.")
    parser.add_argument("command", choices=("status", "connect", "disconnect", "verify"))
    parser.add_argument("--openclaw-root", required=True)
    parser.add_argument("--protect-root")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    operations = {
        "status": lambda: status_openclaw(args.openclaw_root),
        "connect": lambda: connect_openclaw(args.openclaw_root, protect_root=args.protect_root),
        "disconnect": lambda: disconnect_openclaw(args.openclaw_root),
        "verify": lambda: verify_openclaw(args.openclaw_root),
    }
    try:
        result = operations[args.command]()
    except Exception as exc:
        print(f"OpenClaw connector error: {exc}")
        return 1
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else _format_result(result))
    return 0


def _format_result(result: dict[str, Any]) -> str:
    return "\n".join(f"{key}: {value}" for key, value in result.items())


if __name__ == "__main__":
    raise SystemExit(main())
