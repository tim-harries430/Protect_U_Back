from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


GUARD_DIR_NAME = ".pub_codex_guard"
LAUNCHER_NAME = "codex-pub"
ENTRY_NAME = "pub_shell_entry.py"
BACKUP_SUFFIX = ".protect_u_back.bak"


class CodexConnectorError(RuntimeError):
    pass


def status_codex(
    codex_project: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
    python_bin: str = "python3",
) -> dict[str, Any]:
    project_root = _project_root(codex_project)
    guard_dir = _guard_dir(project_root)
    launcher_path = guard_dir / LAUNCHER_NAME
    entry_path = guard_dir / ENTRY_NAME
    expected_launcher = _launcher_text(
        project_root=project_root,
        protect_root=_protect_root_literal(protect_root),
        python_bin=python_bin,
    )
    expected_entry = _entry_text(protect_root=_protect_root_literal(protect_root))
    return {
        "codex_project": str(project_root),
        "guard_dir": str(guard_dir),
        "launcher_path": str(launcher_path),
        "entry_path": str(entry_path),
        "connected": launcher_path.exists()
        and entry_path.exists()
        and _read_text(launcher_path) == expected_launcher
        and _read_text(entry_path) == expected_entry,
        "launcher_exists": launcher_path.exists(),
        "entry_exists": entry_path.exists(),
        "protect_root": _protect_root_literal(protect_root),
        "python_bin": python_bin,
        "launch_command": str(launcher_path),
        "boundary": "bwrap_shell_entry_bind_mount",
        "can_modify_codex_binary": False,
        "can_grant_permission": False,
    }


def connect_codex(
    codex_project: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
    python_bin: str = "python3",
) -> dict[str, Any]:
    project_root = _project_root(codex_project)
    guard_dir = _guard_dir(project_root)
    guard_dir.mkdir(parents=True, exist_ok=True)
    launcher_path = guard_dir / LAUNCHER_NAME
    entry_path = guard_dir / ENTRY_NAME
    launcher_text = _launcher_text(
        project_root=project_root,
        protect_root=_protect_root_literal(protect_root),
        python_bin=python_bin,
    )
    entry_text = _entry_text(protect_root=_protect_root_literal(protect_root))
    changed = False
    changed |= _write_if_changed(launcher_path, launcher_text)
    changed |= _write_if_changed(entry_path, entry_text)
    _chmod_executable(launcher_path)
    _chmod_executable(entry_path)
    result = status_codex(
        project_root,
        protect_root=protect_root,
        python_bin=python_bin,
    )
    result["changed"] = changed
    result["note"] = (
        "Run the reported launch_command instead of raw codex. It starts Codex "
        "inside a mount namespace where /bin/bash and /bin/sh resolve to the "
        "PUB guard before the real shell."
    )
    return result


def disconnect_codex(codex_project: str | Path | None = None) -> dict[str, Any]:
    project_root = _project_root(codex_project)
    guard_dir = _guard_dir(project_root)
    removed = 0
    for name in (LAUNCHER_NAME, ENTRY_NAME):
        path = guard_dir / name
        if path.exists():
            _backup_once(path)
            path.unlink()
            removed += 1
    result = status_codex(project_root)
    result["removed_file_count"] = removed
    return result


def verify_codex(
    codex_project: str | Path | None = None,
    *,
    protect_root: str | Path | None = None,
    python_bin: str = "python3",
) -> dict[str, Any]:
    project_root = _project_root(codex_project)
    status = status_codex(project_root, protect_root=protect_root, python_bin=python_bin)
    guard = Path(_protect_root_literal(protect_root)) / "codex_bash_guard.py"
    command = [python_bin, str(guard), "-lc", "rm -rf ."]
    env = {
        **os.environ,
        "PUB_CODEX_PROJECT_ROOT": str(project_root),
        "PUB_CODEX_SANDBOX_AVAILABLE": "true",
        "PUB_CODEX_SANDBOX_MODE": "connector_verify_no_io",
        "PUB_CODEX_REAL_SHELL": sys.executable,
        "PUB_CODEX_LOG_DIR": str(project_root / GUARD_DIR_NAME / "verify_logs"),
    }
    completed = subprocess.run(
        command,
        cwd=project_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return {
        **status,
        "preflight_blocked": completed.returncode == 126,
        "verify_exit_code": completed.returncode,
        "verify_stderr": completed.stderr.strip(),
        "io_executed": False,
        "can_execute": False,
        "can_grant_permission": False,
    }


def _launcher_text(*, project_root: Path, protect_root: str, python_bin: str) -> str:
    guard_dir = project_root / GUARD_DIR_NAME
    entry_path = guard_dir / ENTRY_NAME
    return f"""#!/usr/bin/env bash
set -euo pipefail

GUARD_DIR={_sh_quote(str(guard_dir))}
ENTRY={_sh_quote(str(entry_path))}
PROTECT_ROOT={_sh_quote(protect_root)}
PYTHON_BIN={_sh_quote(python_bin)}
CODEX_BIN="${{PUB_CODEX_BIN:-codex}}"

find_bwrap() {{
  if [ -n "${{PUB_CODEX_BWRAP:-}}" ] && [ -x "${{PUB_CODEX_BWRAP}}" ]; then
    printf '%s\\n' "${{PUB_CODEX_BWRAP}}"
    return 0
  fi
  if command -v bwrap >/dev/null 2>&1; then
    command -v bwrap
    return 0
  fi
  local npm_root
  npm_root="$(npm root -g 2>/dev/null || true)"
  if [ -n "$npm_root" ]; then
    local bundled
    bundled="$(find "$npm_root/@openai/codex" -path '*/codex-resources/bwrap' -type f -print -quit 2>/dev/null || true)"
    if [ -n "$bundled" ] && [ -x "$bundled" ]; then
      printf '%s\\n' "$bundled"
      return 0
    fi
  fi
  return 1
}}

BWRAP="$(find_bwrap)" || {{
  echo "PUB_CODEX_CONNECTOR: bwrap not found; refusing unguarded Codex launch." >&2
  exit 127
}}

mkdir -p "$GUARD_DIR/runtime"
REAL_BASH="$GUARD_DIR/runtime/bash.real"
REAL_SH="$GUARD_DIR/runtime/sh.real"
cp -f "$(readlink -f /bin/bash)" "$REAL_BASH"
cp -f "$(readlink -f /bin/sh)" "$REAL_SH"
chmod 700 "$REAL_BASH" "$REAL_SH" "$ENTRY"

BASH_TARGET="$(readlink -f /bin/bash)"
SH_TARGET="$(readlink -f /bin/sh)"

bind_args=(--dev-bind / /)
bind_args+=(--bind "$ENTRY" "$BASH_TARGET")
if [ "$SH_TARGET" != "$BASH_TARGET" ]; then
  bind_args+=(--bind "$ENTRY" "$SH_TARGET")
fi

exec "$BWRAP" \\
  "${{bind_args[@]}}" \\
  --setenv PUB_PROTECT_ROOT "$PROTECT_ROOT" \\
  --setenv PUB_CODEX_PROJECT_ROOT { _sh_quote(str(project_root)) } \\
  --setenv PUB_CODEX_LOG_DIR "$GUARD_DIR/logs" \\
  --setenv PUB_CODEX_SANDBOX_AVAILABLE true \\
  --setenv PUB_CODEX_SANDBOX_MODE pub_codex_bwrap_shell_overlay \\
  --setenv PUB_CODEX_SANDBOX_FALLBACK none \\
  --setenv PUB_CODEX_REAL_BASH "$REAL_BASH" \\
  --setenv PUB_CODEX_REAL_SH "$REAL_SH" \\
  --setenv PYTHONPATH "$PROTECT_ROOT${{PYTHONPATH:+:$PYTHONPATH}}" \\
  -- "$CODEX_BIN" "$@"
"""


def _entry_text(*, protect_root: str) -> str:
    return f"""#!/usr/bin/env python3
from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

protect_root = Path(os.environ.get("PUB_PROTECT_ROOT") or {protect_root!r})
os.environ["PUB_CODEX_INVOKED_SHELL"] = Path(sys.argv[0]).name
sys.path.insert(0, str(protect_root))
target = protect_root / "codex_bash_guard.py"
sys.argv = [str(target), *sys.argv[1:]]
runpy.run_path(str(target), run_name="__main__")
"""


def _project_root(codex_project: str | Path | None) -> Path:
    return Path(codex_project or Path.cwd()).expanduser().resolve(strict=False)


def _guard_dir(project_root: Path) -> Path:
    return project_root / GUARD_DIR_NAME


def _protect_root_literal(protect_root: str | Path | None) -> str:
    if protect_root is None:
        return str(Path(__file__).resolve(strict=False).parent)
    return str(protect_root).strip().strip('"').strip("'")


def _write_if_changed(path: Path, text: str) -> bool:
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    if path.exists():
        _backup_once(path)
    path.write_text(text, encoding="utf-8", newline="\n")
    return True


def _backup_once(path: Path) -> None:
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    if path.exists() and not backup.exists():
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8", newline="")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _chmod_executable(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | 0o111)
    except OSError:
        pass


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Connect Protect U Back to Codex CLI shell execution.")
    parser.add_argument("command", choices=("status", "connect", "disconnect", "verify"))
    parser.add_argument("--codex-project", default=".")
    parser.add_argument("--protect-root")
    parser.add_argument("--python-bin", default="python3")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    operations = {
        "status": lambda: status_codex(
            args.codex_project,
            protect_root=args.protect_root,
            python_bin=args.python_bin,
        ),
        "connect": lambda: connect_codex(
            args.codex_project,
            protect_root=args.protect_root,
            python_bin=args.python_bin,
        ),
        "disconnect": lambda: disconnect_codex(args.codex_project),
        "verify": lambda: verify_codex(
            args.codex_project,
            protect_root=args.protect_root,
            python_bin=args.python_bin,
        ),
    }
    try:
        result = operations[args.command]()
    except Exception as exc:  # noqa: BLE001 - connector CLI reports closed
        print(f"Codex connector error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for key, value in result.items():
            print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
