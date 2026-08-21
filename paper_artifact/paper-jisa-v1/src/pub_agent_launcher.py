from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from claude_code_connector import (
    DEFAULT_PLATFORM,
    PLATFORM_CHOICES,
    connect_claude_code,
    gate_claude_code,
    status_claude_code,
    verify_claude_code,
)
from codex_connector import connect_codex, status_codex, verify_codex
from pub_os_runner import AgentRunPlan, RunnerReceipt, RunnerState, prepare_agent_run, start_agent_run


CODE_ROOT = Path(__file__).resolve(strict=False).parent
DEFAULT_CC_ARGS = ("--permission-mode", "default")
DEFAULT_CD_ARGS = ("--sandbox", "workspace-write", "--approval-policy", "on-request")
PLAN_HOLD_EXIT = 2
START_HOLD_EXIT = 3


class LauncherError(RuntimeError):
    pass


@dataclass(frozen=True)
class LauncherDeps:
    cc_connect: Callable[..., Mapping[str, Any]] = connect_claude_code
    cc_gate: Callable[..., Mapping[str, Any]] = gate_claude_code
    cc_verify: Callable[..., Mapping[str, Any]] = verify_claude_code
    cc_status: Callable[..., Mapping[str, Any]] = status_claude_code
    cd_connect: Callable[..., Mapping[str, Any]] = connect_codex
    cd_verify: Callable[..., Mapping[str, Any]] = verify_codex
    cd_status: Callable[..., Mapping[str, Any]] = status_codex
    prepare: Callable[..., AgentRunPlan] = prepare_agent_run
    start: Callable[..., RunnerReceipt] = start_agent_run
    spawn: Callable[..., Any] | None = None

    def __post_init__(self) -> None:
        if self.spawn is None:
            object.__setattr__(self, "spawn", _spawn_interactive)


def main(argv: Sequence[str] | None = None, *, deps: LauncherDeps | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    runner = deps or LauncherDeps()
    try:
        if args.profile == "cc":
            return run_cc(args, runner)
        if args.profile == "cd":
            return run_cd(args, runner)
    except LauncherError as exc:
        print(f"PUB_AGENT: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(
            f"PUB_AGENT: process wiring failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="PubAgent",
        description="Start a CLI agent only after PUB connector, verify, and runner admission.",
    )
    subparsers = parser.add_subparsers(dest="profile", required=True)

    cc = subparsers.add_parser("cc", help="Connect and start Claude Code under PUB.")
    _add_common_args(cc)
    cc.add_argument("--cc-command", default="claude", help="Claude Code executable.")
    cc.add_argument(
        "--platform",
        choices=PLATFORM_CHOICES,
        default=DEFAULT_PLATFORM,
        help="Platform for Claude Code hook commands.",
    )
    cc.add_argument(
        "--cage",
        action="store_true",
        help="Confine Claude Code in the bwrap cage (Linux/WSL2 only). Fail-closed: if "
             "no cage can be built the launcher STOPS rather than run uncaged.",
    )
    cc.add_argument("agent_args", nargs=argparse.REMAINDER, help="Arguments passed to Claude Code.")

    cd = subparsers.add_parser("cd", help="Connect and start Codex CLI under PUB.")
    _add_common_args(cd, python_default="python3")
    cd.add_argument("agent_args", nargs=argparse.REMAINDER, help="Arguments passed to Codex.")
    return parser


def run_cc(args: argparse.Namespace, deps: LauncherDeps) -> int:
    project_root = _path_arg(args.project_root)
    protect_root = _protect_root(args.protect_root)
    python_bin = args.python_bin
    cc_command = args.cc_command
    platform = args.platform

    if getattr(args, "cage", False):
        # Confine claude in the bwrap cage (Linux/WSL2). Fail-closed (wall-first): if
        # the cage cannot be built we STOP -- never silently fall back to uncaged. Every
        # bind path is derived from the runtime environment, so this reproduces on any
        # customer's Linux/WSL2 box. The cage is Linux, so its hook must be posix.
        from pub_os_cage import CageUnavailable, cage_available, discover_cc_cage_spec, make_cage_spawn

        usable, reason = cage_available()
        if not usable:
            raise LauncherError(
                f"--cage requested but no cage on this host ({reason}). Drop --cage to run "
                f"gate-only (the hook still judges; there is no OS containment on this platform)."
            )
        try:
            spec, claude_bin = discover_cc_cage_spec(project_root, pub_source_dir=protect_root)
        except CageUnavailable as exc:
            raise LauncherError(f"--cage: {exc}")
        cc_command = claude_bin
        platform = "posix"
        deps = replace(deps, spawn=make_cage_spawn(spec))
        _emit("cage", {"state": "CAGE_READY", "reason_code": reason}, args.json)

    if not args.no_connect:
        _emit(
            "connect",
            deps.cc_connect(project_root, protect_root=protect_root, python_bin=python_bin, platform=platform),
            args.json,
        )
        _emit("gate", deps.cc_gate(project_root, enabled=True), args.json)
    if not args.no_verify:
        verify = deps.cc_verify(project_root, protect_root=protect_root, python_bin=python_bin, platform=platform)
        _require_preflight_blocked("cc", verify)
        _emit("verify", verify, args.json)

    plan = deps.prepare(
        "cc",
        project_root=project_root,
        actor_id=args.actor_id,
        session_id=args.session_id,
        cwd=_path_arg(args.cwd) if args.cwd else None,
        agent_args=_cc_args(args.agent_args),
        cc_command=cc_command,
        cc_status_fn=lambda *call_args, **kwargs: deps.cc_status(
            project_root,
            protect_root=protect_root,
            python_bin=python_bin,
            platform=platform,
        ),
        protect_root=protect_root,
        python_bin=python_bin or "python3",
    )
    return _run_plan(plan, args, deps)


def run_cd(args: argparse.Namespace, deps: LauncherDeps) -> int:
    project_root = _path_arg(args.project_root)
    protect_root = _protect_root(args.protect_root)
    python_bin = args.python_bin or "python3"

    if not args.no_connect:
        _emit("connect", deps.cd_connect(project_root, protect_root=protect_root, python_bin=python_bin), args.json)
    if not args.no_verify:
        verify = deps.cd_verify(project_root, protect_root=protect_root, python_bin=python_bin)
        _require_preflight_blocked("cd", verify)
        _emit("verify", verify, args.json)

    plan = deps.prepare(
        "cd",
        project_root=project_root,
        actor_id=args.actor_id,
        session_id=args.session_id,
        cwd=_path_arg(args.cwd) if args.cwd else None,
        agent_args=_cd_args(args.agent_args),
        cd_status_fn=lambda *call_args, **kwargs: deps.cd_status(
            project_root,
            protect_root=protect_root,
            python_bin=python_bin,
        ),
        protect_root=protect_root,
        python_bin=python_bin,
    )
    return _run_plan(plan, args, deps)


def _add_common_args(parser: argparse.ArgumentParser, *, python_default: str | None = None) -> None:
    parser.add_argument("--project-root", default=".", help="Workspace root to put under PUB supervision.")
    parser.add_argument("--cwd", help="Agent working directory. Defaults to --project-root.")
    parser.add_argument("--protect-root", help="PUB source root as seen by the agent.")
    parser.add_argument("--python-bin", default=python_default, help="Python executable as seen by the agent.")
    parser.add_argument("--actor-id", default="pub_cli_agent", help="Actor id for the PUB session.")
    parser.add_argument("--session-id", help="Optional stable session id.")
    parser.add_argument("--no-connect", action="store_true", help="Use existing connector files; runner still fails closed.")
    parser.add_argument("--no-verify", action="store_true", help="Skip destructive-probe preflight verification.")
    parser.add_argument("--dry-run", action="store_true", help="Prepare the runner plan without starting the agent.")
    parser.add_argument("--json", action="store_true", help="Print JSON event records.")


def _run_plan(plan: AgentRunPlan, args: argparse.Namespace, deps: LauncherDeps) -> int:
    _emit("plan", plan.to_dict(), args.json)
    if not plan.ready:
        return PLAN_HOLD_EXIT
    if args.dry_run:
        return 0

    box = _ProcessBox(deps.spawn)
    receipt = deps.start(plan, spawn_fn=box.spawn)
    _emit("start", receipt.to_dict(), args.json)
    if receipt.state != RunnerState.STARTED or box.process is None:
        return START_HOLD_EXIT
    return _wait_child(box.process)


class _ProcessBox:
    def __init__(self, spawn: Callable[..., Any]) -> None:
        self._spawn = spawn
        self.process: Any | None = None

    def spawn(self, argv: Sequence[str], *, cwd: str, env: Mapping[str, str]) -> Any:
        self.process = self._spawn(tuple(argv), cwd=cwd, env=dict(env))
        return self.process


def _spawn_interactive(argv: Sequence[str], *, cwd: str, env: Mapping[str, str]) -> subprocess.Popen[Any]:
    return subprocess.Popen(tuple(argv), cwd=cwd, env=dict(env))


def _wait_child(process: Any) -> int:
    try:
        return int(process.wait())
    except KeyboardInterrupt:
        return 130


def _cc_args(raw_args: Sequence[str]) -> tuple[str, ...]:
    args = _strip_separator(raw_args)
    if _has_option(args, {"--permission-mode"}):
        return args
    return DEFAULT_CC_ARGS + args


def _cd_args(raw_args: Sequence[str]) -> tuple[str, ...]:
    return DEFAULT_CD_ARGS + _strip_separator(raw_args)


def _strip_separator(raw_args: Sequence[str]) -> tuple[str, ...]:
    args = tuple(str(item) for item in raw_args)
    return args[1:] if args[:1] == ("--",) else args


def _has_option(args: Sequence[str], names: set[str]) -> bool:
    lowered = tuple(str(item).lower() for item in args)
    return any(value in names or any(value.startswith(name + "=") for name in names) for value in lowered)


def _require_preflight_blocked(profile: str, result: Mapping[str, Any]) -> None:
    if result.get("preflight_blocked") is not True:
        reason = result.get("reason_code") or result.get("verify_exit_code") or "not_blocked"
        raise LauncherError(f"{profile} connector preflight did not prove blocking: {reason}")


def _emit(phase: str, record: Mapping[str, Any], json_output: bool) -> None:
    if json_output:
        print(json.dumps({"phase": phase, "record": _jsonable(record)}, sort_keys=True, separators=(",", ":")))
        return
    fields = []
    for key in ("state", "reason_code", "connected", "changed", "preflight_blocked", "pid", "root_pid"):
        if key in record:
            fields.append(f"{key}={record[key]}")
    print("PUB_AGENT: " + phase + (" " + " ".join(fields) if fields else ""))


def _jsonable(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, Mapping):
            return {str(key): _jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [_jsonable(item) for item in value]
        return str(value)


def _path_arg(value: str | Path) -> str:
    return str(Path(value).expanduser().resolve(strict=False))


def _protect_root(value: str | Path | None) -> str:
    return str(Path(value).expanduser().resolve(strict=False)) if value else str(CODE_ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
